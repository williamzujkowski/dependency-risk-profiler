"""Tests for the PHP/Composer adapter: composer.lock parser + analyzer."""

import json
from pathlib import Path
from unittest import mock

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.composer import ComposerAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.composer import ComposerLockParser
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
