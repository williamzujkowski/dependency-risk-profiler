"""Registry-first maintenance cadence for the PyPI adapter (#146).

Staleness used to come from the package's repository. That works on healthy
packages and fails on abandoned ones, whose repository is archived, renamed,
deleted, or — for all three fixtures below — never declared at all. The signal
degraded exactly as the risk it measures increased: ``nose``, ``pycrypto``, and
``distribute`` each reported ``staleness=None`` and scored UNKNOWN, while
``pycrypto`` was carrying two CRITICAL advisories.

Recorded responses are trimmed to the keys the adapter reads. Refresh with:
  curl https://pypi.org/pypi/nose/json
  curl https://pypi.org/pypi/pycrypto/json
  curl https://pypi.org/pypi/distribute/json
  curl https://pypi.org/pypi/requests/json
No test here touches the network.
"""

import copy
from datetime import datetime, timezone
from typing import Dict, Optional
from unittest import mock

from signal_floors import (
    assert_abandoned_package_is_scored,
    assert_measures_registry_signals,
    assert_meets_signal_floor,
    mark_transitive_unmeasured,
)

from dependency_risk_profiler.analyzers.python import PythonAnalyzer
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.release_dates import (
    RELEASE_DATE_SOURCE_KEY,
    RELEASE_DATE_SOURCE_REGISTRY,
    SOURCE_REPOSITORY_KEY,
    SOURCE_REPOSITORY_UNDECLARED,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

# Fixed reference point so a decade-old release stays a decade old.
NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)

# Abandoned in 2015. project_urls carries only a Homepage — a readthedocs page,
# not a repository — which is why every repository-derived signal goes quiet.
NOSE_RESPONSE: Dict[str, object] = {
    "info": {
        "name": "nose",
        "version": "1.3.7",
        "summary": "nose extends unittest to make testing easier",
        "license": "GNU LGPL",
        "yanked": False,
        "home_page": "http://readthedocs.org/docs/nose/",
        "project_urls": {"Homepage": "http://readthedocs.org/docs/nose/"},
    },
    "urls": [
        {"upload_time_iso_8601": "2015-06-02T09:12:36.801799Z"},
        {"upload_time_iso_8601": "2015-06-02T09:12:40.570975Z"},
    ],
    "releases": {
        "1.3.6": [{"upload_time_iso_8601": "2015-04-04T11:47:56.362849Z"}],
        "1.3.7": [{"upload_time_iso_8601": "2015-06-02T09:12:40.570975Z"}],
    },
}

# Abandoned in 2014, and the case that should be alarming: an unmaintained
# cryptography library carrying counted CRITICAL advisories.
PYCRYPTO_RESPONSE: Dict[str, object] = {
    "info": {
        "name": "pycrypto",
        "version": "2.6.1",
        "summary": "Cryptographic modules for Python.",
        "license": "Public domain",
        "yanked": False,
        "home_page": "http://www.pycrypto.org/",
        "project_urls": {"Homepage": "http://www.pycrypto.org/"},
    },
    "urls": [{"upload_time_iso_8601": "2014-06-20T08:10:20.813938Z"}],
    "releases": {
        "2.6": [{"upload_time_iso_8601": "2013-10-17T18:23:34.000000Z"}],
        "2.6.1": [{"upload_time_iso_8601": "2014-06-20T08:10:20.813938Z"}],
    },
}

# The reason `urls` alone is not enough: distribute's newest *version* (0.7.3)
# shipped in 2013, but it shipped a patch to the older 0.6 line in 2016. The
# project last published in 2016, and only `releases` says so.
DISTRIBUTE_RESPONSE: Dict[str, object] = {
    "info": {
        "name": "distribute",
        "version": "0.7.3",
        "summary": "distribute legacy wrapper",
        "license": "PSF or ZPL",
        "yanked": False,
        "home_page": "http://packages.python.org/distribute",
        "project_urls": {
            "Download": "UNKNOWN",
            "Homepage": "http://packages.python.org/distribute",
        },
    },
    "urls": [{"upload_time_iso_8601": "2013-07-05T18:19:57.876141Z"}],
    "releases": {
        "0.6.49": [{"upload_time_iso_8601": "2016-01-19T00:08:08.054628Z"}],
        "0.7.3": [{"upload_time_iso_8601": "2013-07-05T18:19:57.876141Z"}],
    },
}

# The live control. home_page is None — PyPI superseded it with project_urls —
# and the repository arrives under "Source".
REQUESTS_RESPONSE: Dict[str, object] = {
    "info": {
        "name": "requests",
        "version": "2.34.2",
        "summary": "Python HTTP for Humans.",
        "license": "Apache-2.0",
        "yanked": False,
        "home_page": None,
        "project_urls": {
            "Documentation": "https://requests.readthedocs.io",
            "Source": "https://github.com/psf/requests",
        },
    },
    "urls": [{"upload_time_iso_8601": "2026-05-14T19:25:27.735762Z"}],
    "releases": {
        "2.34.1": [{"upload_time_iso_8601": "2026-05-13T19:20:24.662635Z"}],
        "2.34.2": [{"upload_time_iso_8601": "2026-05-14T19:25:27.735762Z"}],
    },
}

# Enough of a GitHub repository page for the community analyzer's star scrape.
GITHUB_REPO_HTML = (
    '<a href="/psf/requests/stargazers" '
    'aria-label="53,000 users starred this repository">53k</a>'
)


def _analyze(
    payload: Dict[str, object], installed_version: str = "1.0.0"
) -> DependencyMetadata:
    """Run the PyPI adapter against a recorded response, with no network.

    Args:
        payload: Recorded ``pypi.org/pypi/<name>/json`` response.
        installed_version: Version pinned by the requirement set.

    Returns:
        The analyzed dependency.
    """
    info = payload["info"]
    assert isinstance(info, dict)
    name = str(info["name"])

    analyzer = PythonAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=installed_version)

    def fake_fetch_json(url: str, timeout: int = 30) -> Optional[Dict[str, object]]:
        assert url == f"https://pypi.org/pypi/{name}/json", f"unexpected: {url}"
        return copy.deepcopy(payload)

    with mock.patch(
        "dependency_risk_profiler.analyzers.python.fetch_json",
        side_effect=fake_fetch_json,
    ):
        return analyzer.analyze({name: dep})[name]


def _score_offline(
    payload: Dict[str, object], installed_version: str = "1.0.0"
) -> DependencyRiskScore:
    """Run the whole Python pipeline for one package with the network stubbed.

    Mirrors the analyze command's order — adapter, license, community, scoring
    — with repository cloning off, so the result reflects only what the PyPI
    payload and a public repository page provide.

    Args:
        payload: Recorded ``pypi.org/pypi/<name>/json`` response.
        installed_version: Version pinned by the requirement set.

    Returns:
        The scored dependency.
    """
    dep = _analyze(payload, installed_version)
    dep = analyze_license(dep, payload)
    with mock.patch.object(
        community_analyzer, "fetch_url", return_value=GITHUB_REPO_HTML
    ):
        dep = community_analyzer.analyze_community_metrics(dep, payload)
    return RiskScorer().score_dependency(mark_transitive_unmeasured(dep))


def test_release_dates_come_off_the_registry_payload() -> None:
    """The dates were in the response all along; the adapter never read them."""
    dep = _analyze(NOSE_RESPONSE, "1.3.7")

    assert dep.last_updated is not None
    assert dep.last_updated.date().isoformat() == "2015-06-02"
    assert dep.additional_info[RELEASE_DATE_SOURCE_KEY] == RELEASE_DATE_SOURCE_REGISTRY


def test_newest_upload_across_releases_wins_over_the_newest_version() -> None:
    """The distribute project last shipped in 2016, on an older release line."""
    dep = _analyze(DISTRIBUTE_RESPONSE, "0.7.3")

    assert dep.last_updated is not None
    assert dep.last_updated.date().isoformat() == "2016-01-19"


def test_a_registry_release_date_outranks_repository_activity() -> None:
    """A later commit must not overwrite the date the package actually shipped."""
    dep = _analyze(REQUESTS_RESPONSE, "2.31.0")
    published = dep.last_updated
    assert published is not None

    from dependency_risk_profiler.release_dates import apply_repository_activity_date

    apply_repository_activity_date(dep, datetime(2026, 8, 3, tzinfo=timezone.utc))

    assert dep.last_updated == published


def test_repository_activity_still_fills_a_registry_with_no_date() -> None:
    """Where the registry publishes nothing, a clone's commit date still counts."""
    from dependency_risk_profiler.release_dates import apply_repository_activity_date

    payload = copy.deepcopy(NOSE_RESPONSE)
    payload["urls"] = []
    payload["releases"] = {}

    dep = _analyze(payload, "1.3.7")
    assert dep.last_updated is None
    assert RELEASE_DATE_SOURCE_KEY not in dep.additional_info

    commit_date = datetime(2015, 7, 1, tzinfo=timezone.utc)
    apply_repository_activity_date(dep, commit_date)

    assert dep.last_updated == commit_date


def test_a_registry_with_no_dates_stays_honestly_unmeasured() -> None:
    """No published date means no invented one: the signal is dropped (#74)."""
    payload = copy.deepcopy(NOSE_RESPONSE)
    payload["urls"] = [{"filename": "nose-1.3.7.tar.gz"}]
    payload["releases"] = {"1.3.7": [{"filename": "nose-1.3.7.tar.gz"}]}

    score = _score_offline(payload, "1.3.7")

    assert score.dependency.last_updated is None
    assert score.staleness_score is None
    assert "staleness" in score.unknown_signals


def test_yanked_release_is_marked_deprecated() -> None:
    """A yanked release is PyPI's explicit do-not-use marker, and it was unread."""
    payload = copy.deepcopy(NOSE_RESPONSE)
    info = payload["info"]
    assert isinstance(info, dict)
    info["yanked"] = True

    assert _analyze(payload, "1.3.7").is_deprecated is True


def test_deprecation_is_read_from_the_summary_not_the_readme() -> None:
    """The one line a maintainer writes on purpose, not the whole rendered README."""
    payload = copy.deepcopy(NOSE_RESPONSE)
    info = payload["info"]
    assert isinstance(info, dict)
    info["summary"] = "deprecated sklearn package, use scikit-learn instead"

    assert _analyze(payload, "1.3.7").is_deprecated is True


def test_a_readme_mentioning_deprecation_does_not_deprecate_the_package() -> None:
    """Any project documenting a deprecated API of its own used to trip this."""
    payload = copy.deepcopy(NOSE_RESPONSE)
    info = payload["info"]
    assert isinstance(info, dict)
    info["description"] = (
        "# nose\n\nThe `nose.tools.assert_` helper is deprecated and "
        "unmaintained; use plain asserts instead.\n"
    )

    assert _analyze(payload, "1.3.7").is_deprecated is False


def test_the_summary_check_can_only_add_a_deprecation_verdict() -> None:
    """A clean summary must never clear the verdict `yanked` already set."""
    payload = copy.deepcopy(NOSE_RESPONSE)
    info = payload["info"]
    assert isinstance(info, dict)
    info["yanked"] = True
    info["summary"] = "nose extends unittest to make testing easier"

    assert _analyze(payload, "1.3.7").is_deprecated is True


def test_source_project_url_is_preferred_over_the_homepage() -> None:
    """The repository comes from project_urls; home_page is a last resort."""
    dep = _analyze(REQUESTS_RESPONSE, "2.31.0")

    assert dep.repository_url == "https://github.com/psf/requests"


def test_a_dead_home_page_cannot_stand_in_for_a_missing_source_url() -> None:
    """home_page is None on every modern package and is not a repository here."""
    dep = _analyze(NOSE_RESPONSE, "1.3.7")

    assert dep.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_UNDECLARED


def test_a_hosted_homepage_project_url_still_resolves_a_repository() -> None:
    """Plenty of packages publish the repository under a plain "Homepage" label."""
    payload = copy.deepcopy(NOSE_RESPONSE)
    info = payload["info"]
    assert isinstance(info, dict)
    info["project_urls"] = {"Homepage": "https://github.com/nose-devs/nose"}

    dep = _analyze(payload, "1.3.7")

    assert dep.repository_url == "https://github.com/nose-devs/nose"


def test_a_funding_link_is_not_a_source_repository() -> None:
    """github.com/sponsors/<user> canonicalizes to a repository that never existed."""
    payload = copy.deepcopy(NOSE_RESPONSE)
    info = payload["info"]
    assert isinstance(info, dict)
    info["project_urls"] = {
        "Homepage": "http://readthedocs.org/docs/nose/",
        "Funding": "https://github.com/sponsors/nose-devs",
    }

    dep = _analyze(payload, "1.3.7")

    assert dep.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_UNDECLARED


def test_declaring_no_source_repository_is_a_measured_signal() -> None:
    """It used to be a silent cause of UNKNOWN; it is now a finding."""
    score = _score_offline(NOSE_RESPONSE, "1.3.7")

    assert score.source_repository_score == 1.0
    assert "source_repository" not in score.unknown_signals
    assert "Declares no source repository" in score.factors


def test_declaring_a_source_repository_scores_no_risk() -> None:
    """The healthy case is measured too, not merely absent."""
    score = _score_offline(REQUESTS_RESPONSE, "2.31.0")

    assert score.source_repository_score == 0.0
    assert "Declares no source repository" not in score.factors


def test_abandoned_packages_are_scored_rather_than_shrugged_at() -> None:
    """#146's acceptance: the packages the signal exists to catch now score."""
    for payload, installed in (
        (NOSE_RESPONSE, "1.3.7"),
        (PYCRYPTO_RESPONSE, "2.6.1"),
        (DISTRIBUTE_RESPONSE, "0.7.3"),
    ):
        assert_abandoned_package_is_scored(_score_offline(payload, installed), NOW)


def test_python_meets_minimum_measured_signal_coverage() -> None:
    """Registry metadata alone must carry a package past the insufficient-data bar."""
    assert_meets_signal_floor(_score_offline(REQUESTS_RESPONSE, "2.31.0"), "python")


def test_python_measures_the_signals_the_registry_provides() -> None:
    """Each signal the PyPI payload can answer is measured, not left unknown."""
    assert_measures_registry_signals(
        _score_offline(REQUESTS_RESPONSE, "2.31.0"), "python"
    )


def test_a_failed_registry_lookup_leaves_the_source_signal_unmeasured() -> None:
    """No answer from the registry is not the same as "declares no repository"."""
    analyzer = PythonAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name="does-not-exist", installed_version="1.0.0")

    with mock.patch(
        "dependency_risk_profiler.analyzers.python.fetch_json",
        return_value=None,
    ):
        analyzed = analyzer.analyze({"does-not-exist": dep})["does-not-exist"]

    score = RiskScorer().score_dependency(mark_transitive_unmeasured(analyzed))

    assert SOURCE_REPOSITORY_KEY not in analyzed.additional_info
    assert score.source_repository_score is None
    assert "source_repository" not in score.unknown_signals
