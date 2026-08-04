"""Tests that manifests are only ever written inside the scan temp root.

``ManifestRef.path`` is supplied by the GitHub API, so a hostile ``..`` segment
must not let a scanned repo write outside its per-repo temp directory.
"""

from pathlib import Path
from typing import Dict, Iterable, List, Optional

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyRiskScore,
    ManifestRef,
    RepositoryManifestListing,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.scanner import OrgScanRunner


class _DummyClient:
    """Discovery client that satisfies the protocol and answers nothing.

    ``_write_temp_manifest`` never calls it, but a body-less placeholder
    satisfies no structural protocol at all — which is what the deleted
    ``# type: ignore[arg-type]`` here was really hiding (#156).
    """

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return no repositories."""
        return []

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return no repositories."""
        return []

    def list_manifest_paths(
        self,
        repo: RepositoryRef,
    ) -> RepositoryManifestListing:
        """Return no manifest paths."""
        return RepositoryManifestListing(supported=[], unreadable=[])

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Return an empty manifest."""
        return ""


class _DummyProfiler:
    """Profiler that satisfies the protocol and scores nothing."""

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Return no scores."""
        return {}


def _runner() -> OrgScanRunner:
    return OrgScanRunner(_DummyClient(), _DummyProfiler())


def test_write_temp_manifest_writes_within_root(tmp_path: Path) -> None:
    """A normal nested manifest path is written inside the per-repo temp dir."""
    manifest = ManifestRef(
        repo_full_name="org/repo",
        path="services/api/requirements.txt",
        ecosystem="python",
        content="flask==3.0.0",
    )

    written = _runner()._write_temp_manifest(tmp_path, manifest)

    assert written.read_text(encoding="utf-8") == "flask==3.0.0"
    assert tmp_path.resolve() in written.resolve().parents


def test_write_temp_manifest_rejects_parent_traversal(tmp_path: Path) -> None:
    """A ``..``-laden path is refused and nothing is written outside the root."""
    outside = tmp_path.parent / "escaped.txt"
    manifest = ManifestRef(
        repo_full_name="org/repo",
        path="../../escaped.txt",
        ecosystem="python",
        content="pwned",
    )

    with pytest.raises(ValueError, match="escapes temp root"):
        _runner()._write_temp_manifest(tmp_path, manifest)

    assert not outside.exists()


def test_write_temp_manifest_allows_dotdot_that_stays_inside(tmp_path: Path) -> None:
    """A ``..`` that resolves back inside the root is not a false positive."""
    manifest = ManifestRef(
        repo_full_name="org/repo",
        path="a/../requirements.txt",
        ecosystem="python",
        content="requests==2.31.0",
    )

    written = _runner()._write_temp_manifest(tmp_path, manifest)

    assert written.read_text(encoding="utf-8") == "requests==2.31.0"
    assert tmp_path.resolve() in written.resolve().parents
