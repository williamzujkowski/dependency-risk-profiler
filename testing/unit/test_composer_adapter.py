"""Tests for the PHP/Composer adapter: composer.lock parser + analyzer."""

import copy
import json
from pathlib import Path
from typing import Dict, Optional
from unittest import mock

from signal_floors import assert_measures_registry_signals, assert_meets_signal_floor

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.composer import ComposerAnalyzer
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.parsers.composer import ComposerLockParser
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import SourceRepositoryState
from dependency_risk_profiler.vulnerabilities import ecosystems

COMPOSER_LOCK = {
    "packages": [
        {
            "name": "monolog/monolog",
            "version": "2.9.1",
            "source": {"url": "https://github.com/Seldaek/monolog.git"},
        },
        {"name": "psr/log", "version": "v1.1.4"},
    ],
    "packages-dev": [
        {"name": "phpunit/phpunit", "version": "9.6.0"},
    ],
}


def test_composer_lock_parser_extracts_runtime_and_dev(tmp_path: Path) -> None:
    """Both packages and packages-dev are parsed, with the v-prefix stripped."""
    lock = tmp_path / "composer.lock"
    lock.write_text(json.dumps(COMPOSER_LOCK), encoding="utf-8")

    deps = ComposerLockParser(str(lock)).parse()

    assert set(deps) == {"monolog/monolog", "psr/log", "phpunit/phpunit"}
    assert deps["monolog/monolog"].installed_version == "2.9.1"
    assert deps["psr/log"].installed_version == "1.1.4"
    assert (
        deps["monolog/monolog"].repository_url
        == "https://github.com/Seldaek/monolog.git"
    )


def test_composer_lock_dispatches_to_composer_analyzer() -> None:
    """composer.lock routes to the composer ecosystem and analyzer."""
    from dependency_risk_profiler.cli.typer_cli import get_ecosystem_from_manifest

    assert get_ecosystem_from_manifest("some/dir/composer.lock") == "composer"
    assert isinstance(
        BaseAnalyzer.get_analyzer_for_ecosystem("composer"), ComposerAnalyzer
    )


def test_composer_analyzer_sets_ecosystem_and_reads_latest_version() -> None:
    """The analyzer stamps the OSV ecosystem and reads the latest Packagist version."""
    analyzer = ComposerAnalyzer()
    dep = DependencyMetadata(name="monolog/monolog", installed_version="2.0.0")

    payload = {
        "packages": {
            "monolog/monolog": [
                {"version": "dev-main"},
                {"version": "v3.5.0"},
                {"version": "v3.4.0"},
            ]
        }
    }
    with mock.patch("dependency_risk_profiler.analyzers.composer.requests.get") as get:
        get.return_value = mock.Mock(
            status_code=200, json=mock.Mock(return_value=payload)
        )
        result = analyzer.analyze({"monolog/monolog": dep})

    updated = result["monolog/monolog"]
    assert updated.additional_info["ecosystem"] == "composer"
    # The first non-dev version wins (dev-main is skipped).
    assert updated.latest_version == "3.5.0"


def test_composer_ecosystem_routes_to_packagist() -> None:
    """The emitted 'composer' string resolves to Packagist (OSV) / COMPOSER (GHA)."""
    eco = ecosystems.resolve("composer")
    assert eco.osv == "Packagist"
    assert eco.github_advisory == "COMPOSER"
    # deps.dev does not cover Packagist.
    assert eco.deps_dev is None


# --- Signal coverage (#132) -------------------------------------------------
#
# A recorded Packagist p2 release entry, trimmed to the keys the adapter reads
# — a shape probe, not coverage evidence, which is why composer is still
# PENDING in adapter_conformance.CONVERSION_STATUS.
# Refresh with:
#   curl https://repo.packagist.org/p2/symfony/console.json
# The shapes are the point: the license is a *list*, the repository lives under
# source.url with a .git suffix, and `abandoned` names the replacement package
# rather than being a boolean.
CONSOLE_RELEASE: Dict[str, object] = {
    "name": "symfony/console",
    "description": "Eases the creation of testable command line interfaces",
    "homepage": "https://symfony.com",
    "version": "v8.1.2",
    "version_normalized": "8.1.2.0",
    "license": ["MIT"],
    "authors": [
        {"name": "Fabien Potencier", "email": "fabien@symfony.com"},
        {"name": "Symfony Community", "homepage": "https://symfony.com/contributors"},
    ],
    "source": {
        "type": "git",
        "url": "https://github.com/symfony/console.git",
        "reference": "535e18a1b8925f6c01a55b171d157ab66c2ace15",
    },
    "time": "2026-07-27T13:58:19+00:00",
}

# Enough of a GitHub repository page for the community analyzer's star scrape.
GITHUB_REPO_HTML = (
    '<a href="/symfony/console/stargazers" '
    'aria-label="9,809 users starred this repository">9.8k</a>'
)


def _score_package_offline(
    release: Dict[str, object],
    lock_repository_url: Optional[str] = None,
) -> DependencyRiskScore:
    """Run the composer pipeline for one package with every network call stubbed.

    Mirrors the analyze command's order — adapter, license, community, scoring
    — with repository cloning off, so the result reflects only what the
    Packagist payload and a public repository page provide.

    Args:
        release: Recorded Packagist p2 release entry.
        lock_repository_url: ``source.url`` as recorded in composer.lock, which
            the parser sets before the analyzer runs.

    Returns:
        The scored dependency.
    """
    name = str(release.get("name", "symfony/console"))
    analyzer = ComposerAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(
        name=name,
        installed_version="8.0.0",
        repository_url=lock_repository_url,
    )

    with mock.patch.object(
        analyzer, "_get_latest_release", return_value=copy.deepcopy(release)
    ):
        analyzed = analyzer.analyze({name: dep})

    dep = analyzed[name]
    metadata = analyzer.metadata_cache[name]
    dep = analyze_license(dep, metadata)
    with mock.patch.object(
        community_analyzer, "fetch_url", return_value=GITHUB_REPO_HTML
    ):
        dep = community_analyzer.analyze_community_metrics(dep, metadata)

    return RiskScorer().score_dependency(dep)


def test_packagist_metadata_lands_on_the_fields_the_scorer_reads() -> None:
    """Release date, repository root, author count, and license come off the payload."""
    score = _score_package_offline(CONSOLE_RELEASE)
    dep = score.dependency

    assert dep.latest_version == "8.1.2"
    # The recorded source.url carries a .git suffix; only the trimmed root
    # resolves for GitHub lookups and cloning.
    assert dep.repository_url == "https://github.com/symfony/console"
    assert dep.last_updated is not None
    assert dep.last_updated.year == 2026
    assert dep.maintainer_count == 2
    assert dep.license_info is not None
    assert dep.license_info.license_id == "MIT"


def test_abandoned_package_is_marked_deprecated_with_its_replacement() -> None:
    """Packagist's `abandoned` marker names the superseding package."""
    abandoned = copy.deepcopy(CONSOLE_RELEASE)
    abandoned["abandoned"] = "symfony/mailer"

    dep = _score_package_offline(abandoned).dependency

    assert dep.is_deprecated is True
    assert dep.additional_info["abandoned_in_favor_of"] == "symfony/mailer"


def test_boolean_abandoned_marker_is_honored() -> None:
    """`abandoned: true` deprecates without naming a replacement."""
    abandoned = copy.deepcopy(CONSOLE_RELEASE)
    abandoned["abandoned"] = True

    dep = _score_package_offline(abandoned).dependency

    assert dep.is_deprecated is True
    assert "abandoned_in_favor_of" not in dep.additional_info


def test_lock_source_url_resolves_when_packagist_has_no_metadata() -> None:
    """A package missing from Packagist still resolves the repo composer.lock pins."""
    analyzer = ComposerAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(
        name="acme/private",
        installed_version="1.0.0",
        repository_url="git@github.com:acme/private.git",
    )

    with mock.patch.object(analyzer, "_get_latest_release", return_value=None):
        analyzed = analyzer.analyze({"acme/private": dep})

    assert analyzed["acme/private"].repository_url == "https://github.com/acme/private"


def test_package_without_a_repository_stays_honestly_unmeasured() -> None:
    """No published repository means no invented one, and no invented signals."""
    release = copy.deepcopy(CONSOLE_RELEASE)
    del release["source"]
    release["homepage"] = "https://symfony.com"

    score = _score_package_offline(release)

    assert score.dependency.repository_url is None
    assert "health_indicators" in score.unknown_signals


def test_a_dist_only_package_is_scored_rather_than_shrugged_at() -> None:
    """phpstan/phpstan was #132's one residual UNKNOWN: dist-only, no source.

    Declaring no repository is now the measured finding, so the seven signals
    that absence silences no longer add up to "we know nothing" (#146).
    """
    release = copy.deepcopy(CONSOLE_RELEASE)
    del release["source"]
    release["homepage"] = ""

    score = _score_package_offline(release)

    assert score.source_repository_score == 1.0
    assert score.insufficient_data is False
    assert score.risk_level is not RiskLevel.UNKNOWN
    assert "Declares no source repository" in score.factors


def test_a_failed_packagist_lookup_leaves_the_source_signal_unmeasured() -> None:
    """#182: a 404 is not "this package declares no source repository".

    ``_get_latest_release`` swallows a connection error, a non-200 and a body
    that is not JSON alike, and the record used to be written outside the guard
    — so all three came out as a confident 1.0, the highest score the signal
    has. Nobody asked Packagist anything. #146 then made that stamp
    load-bearing: it collapses eight repository-derived signals into one
    explained gap, so a fabricated UNDECLARED also changes whether the package
    reaches a verdict at all.

    The conformance harness cannot prove this — the capture script records only
    200s, on purpose — so it is a synthetic fixture, which is what synthetic
    fixtures are legitimately for.
    """
    analyzer = ComposerAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name="acme/unreachable", installed_version="1.0.0")

    with mock.patch.object(analyzer, "_get_latest_release", return_value=None):
        analyzed = analyzer.analyze({"acme/unreachable": dep})["acme/unreachable"]

    score = RiskScorer().score_dependency(analyzed)

    assert analyzed.source_repository_state is None
    assert score.source_repository_score is None
    assert "source_repository" not in score.unknown_signals
    assert "Declares no source repository" not in score.factors


def test_a_lock_declared_source_is_recorded_even_when_packagist_is_silent() -> None:
    """composer.lock's own source.url is a declaration whatever the registry did.

    The other half of #182: leaving the key unset on every failed lookup would
    throw away a fact the manifest under analysis states outright.
    """
    analyzer = ComposerAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(
        name="acme/private",
        installed_version="1.0.0",
        repository_url="git@github.com:acme/private.git",
    )

    with mock.patch.object(analyzer, "_get_latest_release", return_value=None):
        analyzed = analyzer.analyze({"acme/private": dep})["acme/private"]

    assert analyzed.source_repository_state == SourceRepositoryState.DECLARED


def test_a_non_forge_source_url_is_declared_but_unusable() -> None:
    """#176's middle state in a second ecosystem, not just in maven.

    A package whose ``source.url`` names a self-hosted SVN or a private Gitea
    has said where its source lives. Nobody can read it, and that is a
    different fact from saying nothing.
    """
    release = copy.deepcopy(CONSOLE_RELEASE)
    source = release["source"]
    assert isinstance(source, dict)
    source["url"] = "https://svn.example.org/repos/console/trunk"

    score = _score_package_offline(release)

    assert score.dependency.source_repository_state == SourceRepositoryState.UNUSABLE
    assert score.source_repository_score == 0.75
    assert "Declares no source repository" not in score.factors
    assert (
        "Declares a source repository that is not a reachable git forge"
        in score.factors
    )


def test_package_without_declared_authors_leaves_maintainers_unmeasured() -> None:
    """An absent authors list must not fabricate a maintainer count."""
    release = copy.deepcopy(CONSOLE_RELEASE)
    del release["authors"]

    score = _score_package_offline(release)

    assert score.dependency.maintainer_count is None
    assert "maintainer" in score.unknown_signals


def test_composer_meets_minimum_measured_signal_coverage() -> None:
    """Registry metadata alone must carry a package past the insufficient-data bar."""
    assert_meets_signal_floor(_score_package_offline(CONSOLE_RELEASE), "composer")


def test_composer_measures_the_signals_the_registry_provides() -> None:
    """Each signal the Packagist payload can answer is measured, not left unknown."""
    assert_measures_registry_signals(
        _score_package_offline(CONSOLE_RELEASE), "composer"
    )
