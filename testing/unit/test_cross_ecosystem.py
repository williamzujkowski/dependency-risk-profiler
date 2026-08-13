"""Name-list parsing for the cross-ecosystem study, tested offline.

A malformed name list does not fail loudly — it produces a sample of names the
registry has never heard of, which shows up as a low resolution rate and looks
like an ecosystem property rather than a parser bug. §5 line 2 of the protocol
gates on that rate for exactly this reason, but the gate is a backstop; these
tests are the actual check.

RubyGems' ``/versions`` is the one with real edge cases: it opens with a
``created_at`` line and a ``---`` separator, and neither is a gem.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RESEARCH = Path(__file__).resolve().parents[2] / "research"
sys.path.insert(0, str(RESEARCH))

from cross_ecosystem import computability  # noqa: E402


class _Session:
    """Never used — every parser below reads from cache."""

    def get(self, url: str, timeout: int = 0) -> None:  # pragma: no cover
        raise AssertionError(f"parser attempted a network call to {url}")


def test_rubygems_header_lines_are_not_gems(tmp_path: Path) -> None:
    (tmp_path / "rubygems-versions.txt").write_text(
        "created_at: 2026-08-13T00:00:00+00:00\n"
        "---\n"
        "rails 7.0.0 abc123\n"
        "rake 13.0.6,13.1.0 def456\n"
        "\n"
    )
    names = computability.rubygems_names(_Session(), tmp_path)  # type: ignore[arg-type]
    assert names == ["rails", "rake"]


def test_rubygems_names_are_deduplicated(tmp_path: Path) -> None:
    """A gem appears once per line, but the file has been seen to repeat."""
    (tmp_path / "rubygems-versions.txt").write_text(
        "---\nrails 7.0.0 a\nrails 7.1.0 b\nrake 13.0.6 c\n"
    )
    assert computability.rubygems_names(_Session(), tmp_path) == ["rails", "rake"]  # type: ignore[arg-type]


def test_pypi_simple_index_yields_project_names(tmp_path: Path) -> None:
    (tmp_path / "pypi-simple.html").write_text(
        "<!DOCTYPE html><html><body>"
        '<a href="/simple/requests/">requests</a>'
        '<a href="/simple/django-allauth/">django-allauth</a>'
        "</body></html>"
    )
    names = computability.pypi_names(_Session(), tmp_path)  # type: ignore[arg-type]
    assert names == ["requests", "django-allauth"]


def test_packagist_list_is_read_from_its_key(tmp_path: Path) -> None:
    (tmp_path / "packagist-list.json").write_text(
        json.dumps({"packageNames": ["symfony/console", "monolog/monolog"]})
    )
    names = computability.packagist_names(_Session(), tmp_path)  # type: ignore[arg-type]
    assert names == ["symfony/console", "monolog/monolog"]


def test_every_ecosystem_has_a_lister_and_a_prober() -> None:
    """The registry table is what the run loop iterates; a gap is silent."""
    assert set(computability.ECOSYSTEMS) == {"npm", "pypi", "packagist", "rubygems"}
    for lister, prober in computability.ECOSYSTEMS.values():
        assert callable(lister) and callable(prober)


def test_the_seed_is_the_registered_one() -> None:
    """§2 fixes it; a changed seed is a different cohort."""
    assert computability.SEED == 20260813


class TestStageTwoSlugExtraction:
    """`_slug` reads URLs from four registries with different conventions.

    A bug here would look like a clone-yield finding: packages whose declared
    URL is perfectly good would be counted `not_github` and depress the
    ecosystem's rate. Stage two keeps URL extraction separate from stage one's
    resolver-based state for the same reason.
    """

    def test_the_git_plus_https_spelling_npm_uses(self) -> None:
        from cross_ecosystem.clone_yield import _slug

        assert _slug("git+https://github.com/axios/axios.git") == "axios/axios"

    def test_the_scp_style_spelling(self) -> None:
        from cross_ecosystem.clone_yield import _slug

        assert _slug("git@github.com:pallets/flask.git") == "pallets/flask"

    def test_a_tagged_subpath_is_trimmed_to_owner_repo(self) -> None:
        """RubyGems commonly points at `.../tree/v2.0.6`."""
        from cross_ecosystem.clone_yield import _slug

        assert _slug("https://github.com/mikel/mail/tree/v2.0.6") == "mikel/mail"

    def test_plain_http_still_resolves(self) -> None:
        """15%+ of gems declare their repository over plain http."""
        from cross_ecosystem.clone_yield import _slug

        assert _slug("http://github.com/rubygems/rubygems") == "rubygems/rubygems"

    def test_a_non_github_forge_is_not_a_slug(self) -> None:
        """GitLab, Bitbucket and self-hosted forges are a real category."""
        from cross_ecosystem.clone_yield import _slug

        assert _slug("https://gitlab.com/gitlab-org/gitlab") is None
        assert _slug("https://bitbucket.org/atlassian/pipelines") is None

    def test_a_bare_owner_with_no_repo_is_not_a_slug(self) -> None:
        from cross_ecosystem.clone_yield import _slug

        assert _slug("https://github.com/sponsors/someone") == "sponsors/someone"
        assert _slug("https://github.com/octocat") is None

    def test_a_missing_or_non_string_url_is_not_a_slug(self) -> None:
        from cross_ecosystem.clone_yield import _slug

        assert _slug(None) is None
        assert _slug("") is None

    def test_the_registered_subsample_size(self) -> None:
        """§8 fixes it at 200; a changed value is a different study."""
        from cross_ecosystem import clone_yield

        assert clone_yield.SUBSAMPLE == 200
