"""Tests for the npm adapter's registry reads (#140).

The npm packument has no top-level ``version`` key — the current release is
published as ``dist-tags.latest``. Reading ``version`` off the packument is why
``latest_version`` was None for 804 of 804 NodeGoat dependencies while every
other signal worked, so these tests pin the response *shape*, not just the
happy path.

The payloads below are **synthetic shape probes**, not coverage evidence. They
exist to drive paths a captured packument cannot reach: a mirror that omits
``dist-tags``, a registry that answers nothing at all, a repository name with
``.git`` inside it. Each one is deliberately minimal, and that is the whole
point — you cannot describe a 404 with a recorded 200.

They used to be described as "trimmed to the keys the adapter reads", and that
sentence was the bug. A fixture trimmed to what the adapter reads cannot, by
construction, contain the key the adapter *should* read and doesn't, which is
the literal mechanism behind four of the five dead reads in #145. Coverage and
per-signal value assertions now run against live-captured payloads in
``test_adapter_conformance`` / ``testing/fixtures/registry/nodejs/``, which keep
every key npm sends. Refresh those with
``python scripts/capture_registry_fixtures.py --ecosystem nodejs``.

No test here touches the network.
"""

import logging
from typing import Dict, Optional
from unittest import mock

import pytest
from signal_floors import (
    SCORES_FROM_REGISTRY_ALONE,
    assert_measures_registry_signals,
    assert_meets_signal_floor,
    mark_transitive_unmeasured,
)

from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer, npm_registry_path
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.release_dates import (
    RELEASE_DATE_SOURCE_KEY,
    RELEASE_DATE_SOURCE_REGISTRY,
    SOURCE_REPOSITORY_DECLARED,
    SOURCE_REPOSITORY_KEY,
    SOURCE_REPOSITORY_UNDECLARED,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

# An unscoped packument: dist-tags carries the release, "repository" is an
# object whose URL is git+-prefixed and .git-suffixed, and deprecation lives
# inside the per-version manifest rather than at the top level.
EXPRESS_PACKUMENT: Dict[str, object] = {
    "name": "express",
    "description": "Fast, unopinionated, minimalist web framework",
    "dist-tags": {"latest": "5.2.1", "latest-4": "4.22.2"},
    "repository": {
        "type": "git",
        "url": "git+https://github.com/expressjs/express.git",
    },
    "homepage": "http://expressjs.com/",
    "license": "MIT",
    "versions": {
        "4.17.1": {"name": "express", "version": "4.17.1"},
        "5.2.1": {"name": "express", "version": "5.2.1"},
    },
    "time": {
        "modified": "2026-06-11T15:12:03.000Z",
        "4.17.1": "2019-05-25T15:41:29.033Z",
        "5.2.1": "2026-06-11T15:12:03.000Z",
    },
}

# A scoped packument. The name reaches the registry as "@cypress%2Fxvfb"; sent
# raw, the slash reads as a path separator and the registry answers 404.
CYPRESS_XVFB_PACKUMENT: Dict[str, object] = {
    "name": "@cypress/xvfb",
    "dist-tags": {"latest": "1.2.4"},
    "repository": {"type": "git", "url": "git+https://github.com/cypress-io/xvfb.git"},
    "versions": {"1.2.4": {"name": "@cypress/xvfb", "version": "1.2.4"}},
}


# Enough of a GitHub repository page for the community analyzer's star scrape.
GITHUB_REPO_HTML = (
    '<a href="/expressjs/express/stargazers" '
    'aria-label="1,234 users starred this repository">1.2k</a>'
)


def _analyzer() -> NodeJSAnalyzer:
    """Return an analyzer with repository cloning off (no network, no git)."""
    analyzer = NodeJSAnalyzer()
    analyzer.clone_repos = False
    return analyzer


def _analyze(
    name: str,
    installed_version: str,
    responses: Dict[str, Optional[Dict[str, object]]],
) -> DependencyMetadata:
    """Run the npm adapter against recorded registry responses.

    Args:
        name: npm package name.
        installed_version: Version pinned by the lockfile.
        responses: Mapping of request URL to recorded payload (None = failure).

    Returns:
        The analyzed dependency.
    """
    analyzer = _analyzer()
    dep = DependencyMetadata(name=name, installed_version=installed_version)

    def fake_fetch_json(url: str, timeout: int = 30) -> Optional[Dict[str, object]]:
        assert url in responses, f"unexpected request: {url}"
        return responses[url]

    with mock.patch(
        "dependency_risk_profiler.analyzers.nodejs.fetch_json",
        side_effect=fake_fetch_json,
    ):
        return analyzer.analyze({name: dep})[name]


def test_scoped_package_names_are_percent_encoded() -> None:
    """The slash in a scoped name is encoded; the leading @ is not."""
    assert npm_registry_path("@cypress/xvfb") == "@cypress%2Fxvfb"
    assert npm_registry_path("express") == "express"


def test_unscoped_package_resolves_latest_from_dist_tags() -> None:
    """dist-tags.latest is the release; the packument has no 'version' key."""
    assert "version" not in EXPRESS_PACKUMENT  # the bug behind #140

    dep = _analyze(
        "express",
        "4.17.1",
        {"https://registry.npmjs.org/express": EXPRESS_PACKUMENT},
    )

    assert dep.latest_version == "5.2.1"
    assert dep.additional_info["ecosystem"] == "nodejs"
    assert dep.repository_url == "https://github.com/expressjs/express"


def test_scoped_package_is_requested_url_encoded_and_resolves() -> None:
    """A scoped package reaches the registry encoded and gets a latest version."""
    dep = _analyze(
        "@cypress/xvfb",
        "1.2.3",
        {"https://registry.npmjs.org/@cypress%2Fxvfb": CYPRESS_XVFB_PACKUMENT},
    )

    assert dep.latest_version == "1.2.4"
    assert dep.repository_url == "https://github.com/cypress-io/xvfb"


def test_packument_without_dist_tags_falls_back_to_the_latest_document() -> None:
    """Mirrors that omit dist-tags still resolve via /<package>/latest."""
    packument = {k: v for k, v in EXPRESS_PACKUMENT.items() if k != "dist-tags"}

    dep = _analyze(
        "express",
        "4.17.1",
        {
            "https://registry.npmjs.org/express": packument,
            "https://registry.npmjs.org/express/latest": {
                "name": "express",
                "version": "5.2.1",
            },
        },
    )

    assert dep.latest_version == "5.2.1"


def test_failed_lookup_leaves_the_signal_unmeasured_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A registry failure is diagnosed, never guessed at (#74)."""
    with caplog.at_level(logging.WARNING):
        dep = _analyze(
            "does-not-exist",
            "1.0.0",
            {"https://registry.npmjs.org/does-not-exist": None},
        )

    assert dep.latest_version is None
    assert dep.installed_version == "1.0.0"
    assert any(
        "does-not-exist" in record.message for record in caplog.records
    ), "a failed npm lookup must be diagnosed, not silent"


def test_unresolvable_latest_version_is_diagnosed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A packument with no latest anywhere warns instead of failing silently."""
    packument = {k: v for k, v in EXPRESS_PACKUMENT.items() if k != "dist-tags"}

    with caplog.at_level(logging.WARNING):
        dep = _analyze(
            "express",
            "4.17.1",
            {
                "https://registry.npmjs.org/express": packument,
                "https://registry.npmjs.org/express/latest": None,
            },
        )

    assert dep.latest_version is None
    assert any("express" in record.message for record in caplog.records)


def test_deprecation_is_read_from_the_version_manifest() -> None:
    """Deprecation is recorded per version manifest, not on the packument."""
    packument: Dict[str, object] = {
        "name": "request",
        "dist-tags": {"latest": "2.88.2"},
        "versions": {
            "2.88.2": {
                "name": "request",
                "version": "2.88.2",
                "deprecated": "request has been deprecated",
            }
        },
    }

    dep = _analyze(
        "request",
        "2.88.0",
        {"https://registry.npmjs.org/request": packument},
    )

    assert dep.latest_version == "2.88.2"
    assert dep.is_deprecated is True


def test_repository_url_survives_a_dot_git_inside_the_repo_name() -> None:
    """Trimming ".git" by substring mangled pages repos; canonicalize instead."""
    packument: Dict[str, object] = {
        "name": "example",
        "dist-tags": {"latest": "2.0.0"},
        "repository": "git+https://github.com/jekyll/jekyll.github.io.git",
    }

    dep = _analyze(
        "example",
        "1.0.0",
        {"https://registry.npmjs.org/example": packument},
    )

    assert dep.repository_url == "https://github.com/jekyll/jekyll.github.io"


def test_resolved_latest_version_produces_a_version_drift_score() -> None:
    """The point of the fix: the drift signal is measured, not None."""
    dep = _analyze(
        "express",
        "4.17.1",
        {"https://registry.npmjs.org/express": EXPRESS_PACKUMENT},
    )

    score = RiskScorer().score_dependency(dep)

    assert score.version_score is not None
    assert score.version_score > 0.0


def test_missing_latest_version_keeps_the_drift_score_unmeasured() -> None:
    """No fabricated drift when the registry publishes nothing (#74)."""
    dep = _analyze(
        "does-not-exist",
        "1.0.0",
        {"https://registry.npmjs.org/does-not-exist": None},
    )

    score = RiskScorer().score_dependency(dep)

    assert score.version_score is None


def test_release_cadence_comes_from_the_latest_tagged_version() -> None:
    """Cadence is the publication date of dist-tags.latest, off the time map (#146)."""
    dep = _analyze(
        "express",
        "4.17.1",
        {"https://registry.npmjs.org/express": EXPRESS_PACKUMENT},
    )

    assert dep.last_updated is not None
    assert dep.last_updated.date().isoformat() == "2026-06-11"
    assert dep.additional_info[RELEASE_DATE_SOURCE_KEY] == RELEASE_DATE_SOURCE_REGISTRY


def test_time_modified_does_not_stand_in_for_a_publication_date() -> None:
    """`request` last shipped in 2020; `modified` moved when it was deprecated.

    Reading ``time.modified`` would score the most famous abandoned package in
    the registry as freshly maintained — crates.io's ``created_at`` trap in
    reverse (#139).
    """
    packument: Dict[str, object] = {
        "name": "request",
        "dist-tags": {"latest": "2.88.2"},
        "versions": {"2.88.2": {"name": "request", "version": "2.88.2"}},
        "time": {
            "modified": "2026-07-17T17:10:13.431Z",
            "created": "2011-01-22T18:26:36.023Z",
            "2.88.2": "2020-02-11T16:35:36.122Z",
        },
    }

    dep = _analyze(
        "request",
        "2.88.2",
        {"https://registry.npmjs.org/request": packument},
    )

    assert dep.last_updated is not None
    assert dep.last_updated.date().isoformat() == "2020-02-11"


def test_a_packument_without_a_time_map_stays_honestly_unmeasured() -> None:
    """No published date means no invented one (#74)."""
    dep = _analyze(
        "@cypress/xvfb",
        "1.2.3",
        {"https://registry.npmjs.org/@cypress%2Fxvfb": CYPRESS_XVFB_PACKUMENT},
    )

    assert dep.last_updated is None
    assert RELEASE_DATE_SOURCE_KEY not in dep.additional_info
    assert RiskScorer().score_dependency(dep).staleness_score is None


def test_a_declared_repository_is_recorded_as_a_measured_signal() -> None:
    """The npm adapter reports the registry's answer, so the signal scores (#146)."""
    dep = _analyze(
        "express",
        "4.17.1",
        {"https://registry.npmjs.org/express": EXPRESS_PACKUMENT},
    )

    assert dep.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_DECLARED
    assert RiskScorer().score_dependency(dep).source_repository_score == 0.0


def test_a_packument_with_no_repository_declares_none() -> None:
    """A package that no longer says where its source lives is a finding."""
    packument: Dict[str, object] = {
        "name": "orphan",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"name": "orphan", "version": "1.0.0"}},
        "time": {"1.0.0": "2016-03-23T02:52:00.000Z"},
    }

    dep = _analyze(
        "orphan",
        "1.0.0",
        {"https://registry.npmjs.org/orphan": packument},
    )

    assert dep.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_UNDECLARED
    score = RiskScorer().score_dependency(dep)
    assert score.source_repository_score == 1.0
    assert "Declares no source repository" in score.factors


def _score_offline(
    name: str,
    installed_version: str,
    responses: Dict[str, Optional[Dict[str, object]]],
) -> DependencyRiskScore:
    """Run the npm pipeline for one package with every network call stubbed.

    Mirrors the analyze command's order — adapter, license, community, scoring
    — with repository cloning off, so the result reflects only what the
    packument and a public repository page provide. npm's transitive set comes
    from a lockfile rather than from the registry, so it is marked unmeasured
    here for the same reason the other registry-only adapters mark it (#141).

    Args:
        name: npm package name.
        installed_version: Version pinned by the lockfile.
        responses: Mapping of request URL to recorded payload (None = failure).

    Returns:
        The scored dependency.
    """
    analyzer = _analyzer()
    dep = DependencyMetadata(name=name, installed_version=installed_version)

    def fake_fetch_json(url: str, timeout: int = 30) -> Optional[Dict[str, object]]:
        assert url in responses, f"unexpected request: {url}"
        return responses[url]

    with mock.patch(
        "dependency_risk_profiler.analyzers.nodejs.fetch_json",
        side_effect=fake_fetch_json,
    ):
        dep = analyzer.analyze({name: dep})[name]

    metadata = analyzer.metadata_cache[name]
    dep = analyze_license(dep, metadata)
    with mock.patch.object(
        community_analyzer, "fetch_url", return_value=GITHUB_REPO_HTML
    ):
        dep = community_analyzer.analyze_community_metrics(dep, metadata)

    return RiskScorer().score_dependency(mark_transitive_unmeasured(dep))


def _express_score() -> DependencyRiskScore:
    """Score the recorded express packument with no clone and no token."""
    return _score_offline(
        "express",
        "4.17.1",
        {"https://registry.npmjs.org/express": EXPRESS_PACKUMENT},
    )


def test_nodejs_meets_minimum_measured_signal_coverage() -> None:
    """The npm floor was recorded but never exercised until #136 wired it up."""
    assert_meets_signal_floor(_express_score(), "nodejs")


def test_nodejs_measures_the_signals_the_registry_provides() -> None:
    """Each signal the packument can answer is measured, not left unknown."""
    assert_measures_registry_signals(_express_score(), "nodejs")


def test_npm_lands_one_signal_short_of_a_verdict_without_a_clone() -> None:
    """The registry publishes no cheap maintainer count, so npm scores UNKNOWN.

    ``SCORES_FROM_REGISTRY_ALONE`` records this as False for nodejs. Asserting
    it here keeps that table honest: if npm ever grows a maintainer read, this
    fails and the table gets updated rather than quietly describing a state
    that no longer exists.
    """
    score = _express_score()

    assert SCORES_FROM_REGISTRY_ALONE["nodejs"] is False
    assert "maintainer" in score.unknown_signals
    assert score.insufficient_data is True
