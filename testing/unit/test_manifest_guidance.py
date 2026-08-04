"""Unit coverage for the refused-manifest guidance table (#125).

The rule the tests hold the module to: say something useful when the input is a
known range-declaring companion or a supported manifest under the wrong name,
and stay quiet — leaving today's generic message — for anything else. A
confident guess about an ecosystem the tool cannot parse would be worse than
the bare message it replaces.
"""

import json
from pathlib import Path

from dependency_risk_profiler.manifest_guidance import unsupported_manifest_guidance

PACKAGE_LOCK = json.dumps(
    {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"left-pad": "1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0"},
        },
    },
    indent=2,
)


def test_package_json_points_at_the_lock_file_and_says_it_is_missing(
    tmp_path: Path,
) -> None:
    """HYPOTHESIS: the message names the companion and where it is not."""
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {}}), encoding="utf-8")

    guidance = unsupported_manifest_guidance(str(manifest))

    assert guidance is not None
    assert "declares version ranges, not resolved versions" in guidance
    assert "package-lock.json" in guidance
    assert f"not found in {tmp_path}" in guidance


def test_package_json_says_when_the_lock_file_is_right_there(tmp_path: Path) -> None:
    """HYPOTHESIS: the message checks for the companion instead of assuming."""
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
    companion = tmp_path / "package-lock.json"
    companion.write_text(PACKAGE_LOCK, encoding="utf-8")

    guidance = unsupported_manifest_guidance(str(manifest))

    assert guidance is not None
    assert f"found alongside it at {companion}" in guidance


def test_gemfile_and_composer_json_have_companions_too(tmp_path: Path) -> None:
    """HYPOTHESIS: the table covers the other same-shaped first-run mistakes."""
    gemfile = tmp_path / "Gemfile"
    gemfile.write_text("source 'https://rubygems.org'\n", encoding="utf-8")
    composer = tmp_path / "composer.json"
    composer.write_text(json.dumps({"require": {}}), encoding="utf-8")

    gem_guidance = unsupported_manifest_guidance(str(gemfile))
    composer_guidance = unsupported_manifest_guidance(str(composer))

    assert gem_guidance is not None and "Gemfile.lock" in gem_guidance
    assert composer_guidance is not None and "composer.lock" in composer_guidance


def test_build_gradle_says_there_is_no_companion_yet(tmp_path: Path) -> None:
    """HYPOTHESIS: with no supported lock file, say so rather than invent one."""
    manifest = tmp_path / "build.gradle"
    manifest.write_text("dependencies { implementation 'a:b:1.+' }\n", encoding="utf-8")

    guidance = unsupported_manifest_guidance(str(manifest))

    assert guidance is not None
    assert "not implemented yet" in guidance
    assert "#101" in guidance


def test_manifest_under_a_nonstandard_name_names_the_parser(tmp_path: Path) -> None:
    """REGRESSION: `railsgoat-Gemfile.lock` is the same bytes as `Gemfile.lock`."""
    manifest = tmp_path / "railsgoat-Gemfile.lock"
    manifest.write_text("GEM\n  specs:\n    rake (13.0.6)\n", encoding="utf-8")

    guidance = unsupported_manifest_guidance(str(manifest))

    assert guidance is not None
    assert "matches manifest filenames exactly" in guidance
    assert "rubygems parser" in guidance
    assert "Rename or copy it to Gemfile.lock" in guidance


def test_lock_file_content_under_an_unrelated_name_names_the_parser(
    tmp_path: Path,
) -> None:
    """HYPOTHESIS: content shape carries the hint when the name gives nothing.

    A pretty-printed package-lock.json is the interesting case: the registry's
    own content probe reads 2KB without DOTALL, so the keys landing on separate
    lines defeat it. The message-only probe still recognizes it.
    """
    manifest = tmp_path / "captured-lock.dat"
    manifest.write_text(PACKAGE_LOCK, encoding="utf-8")

    guidance = unsupported_manifest_guidance(str(manifest))

    assert guidance is not None
    assert "nodejs parser's content pattern" in guidance
    assert "package-lock.json" in guidance


def test_unrelated_files_keep_the_generic_message(tmp_path: Path) -> None:
    """GUARD: no table entry, no lookalike name, no content match — say nothing."""
    manifest = tmp_path / "notes.md"
    manifest.write_text("# just some notes\n", encoding="utf-8")

    assert unsupported_manifest_guidance(str(manifest)) is None


def test_a_missing_file_does_not_raise(tmp_path: Path) -> None:
    """GUARD: guidance is diagnostics; it must never become the failure."""
    assert unsupported_manifest_guidance(str(tmp_path / "gone.md")) is None
