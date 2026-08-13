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
