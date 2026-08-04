"""Tests for the npm adapter's registry reads (#140).

The npm packument has no top-level ``version`` key — the current release is
published as ``dist-tags.latest``. Reading ``version`` off the packument is why
``latest_version`` was None for 804 of 804 NodeGoat dependencies while every
other signal worked, so these tests pin the response *shape*, not just the
happy path.

Recorded responses are trimmed to the keys the adapter reads. Refresh with:
  curl https://registry.npmjs.org/express
  curl https://registry.npmjs.org/@cypress%2Fxvfb
  curl https://registry.npmjs.org/express/latest
No test here touches the network.
"""

import logging
from typing import Dict, Optional
from unittest import mock

import pytest

from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer, npm_registry_path
from dependency_risk_profiler.models import DependencyMetadata
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
