"""Unit coverage for the refused-manifest guidance table (#125, #243).

The rule the tests hold the module to: say something useful when the input is a
known range-declaring companion or a supported manifest under the wrong name,
and stay quiet — leaving today's generic message — for anything else. A
confident guess about an ecosystem the tool cannot parse would be worse than
the bare message it replaces.

#243 added the second job: the table is also the recognizer a directory walk
uses to tell "no dependencies here" from "dependencies I could not read". That
puts two new obligations on it, both asserted below on values rather than
counts — the table must never name a file the registry actually reads, and
every message must name what *is* read for the ecosystem it identified.
"""

import json
from pathlib import Path
from typing import List

import pytest

from dependency_risk_profiler.manifest_guidance import (
    _UNREADABLE_BY_NAME,
    _UNREADABLE_BY_SUFFIX,
    recognise_unreadable_manifest,
    unsupported_manifest_guidance,
)
from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.parsers.registry import EcosystemRegistry

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


def test_build_gradle_no_longer_needs_guidance_because_it_is_parsed(
    tmp_path: Path,
) -> None:
    """REGRESSION: this file used to be refused with a 'not implemented' note.

    #101 made it a supported manifest, so the guidance rule that redirected it
    to pom.xml was deleted rather than left to contradict the parser. The
    dynamic ``1.+`` in the fixture is the interesting half: it is read, named,
    and reported as unmanaged, which is the point — the file being unscannable
    and one version in it being unresolvable are different facts.
    """
    manifest = tmp_path / "build.gradle"
    manifest.write_text("dependencies { implementation 'a:b:1.+' }\n", encoding="utf-8")

    parser = BaseParser.get_parser_for_file(str(manifest))

    assert parser is not None
    assert unsupported_manifest_guidance(str(manifest)) is None
    assert parser.parse()["a:b"].installed_version == ""


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


# ---------------------------------------------------------------------------
# #243: the table as a recognizer
# ---------------------------------------------------------------------------


def _registered_file_names() -> List[str]:
    """Every exact file name the parser registry accepts, lowercased."""
    if not EcosystemRegistry.get_available_ecosystems():
        BaseParser._initialize_registry()
    names: List[str] = []
    for details in EcosystemRegistry.get_ecosystem_details().values():
        for entry in details.get("file_patterns", []):
            if isinstance(entry, str) and entry.startswith("File name: "):
                names.append(entry[len("File name: ") :].lower())
    return names


def _registered_extensions() -> List[str]:
    """Every file extension the parser registry accepts, lowercased."""
    if not EcosystemRegistry.get_available_ecosystems():
        BaseParser._initialize_registry()
    extensions: List[str] = []
    for details in EcosystemRegistry.get_ecosystem_details().values():
        for entry in details.get("file_patterns", []):
            if isinstance(entry, str) and entry.startswith("File extension: "):
                extensions.append(entry[len("File extension: ") :].lower())
    return extensions


def test_the_unreadable_table_never_names_a_file_the_registry_reads() -> None:
    """INVARIANT (#243): claiming we cannot read a file we read is the worst case.

    Asserted against the registry's own public details rather than a copy of
    the list, so adding a parser for `package.json` tomorrow fails this test
    instead of leaving the tool telling users to go find a lock file it no
    longer needs.
    """
    registered_names = set(_registered_file_names())
    registered_extensions = set(_registered_extensions())

    overlapping_names = registered_names & set(_UNREADABLE_BY_NAME)
    overlapping_extensions = registered_extensions & set(_UNREADABLE_BY_SUFFIX)

    assert overlapping_names == set(), overlapping_names
    assert overlapping_extensions == set(), overlapping_extensions


def test_every_table_entry_names_what_is_read_or_says_the_ecosystem_is_not() -> None:
    """INVARIANT (#243): "unsupported format" must never be the whole answer.

    Swept over the table rather than spot-checked, because the defect this
    replaces was one message that named nothing, and a single-entry test would
    let the next entry reintroduce it.
    """
    for file_name, rule in _UNREADABLE_BY_NAME.items():
        recognised = recognise_unreadable_manifest(f"/nowhere/{file_name}")
        assert recognised is not None, file_name
        if rule.ecosystem.inputs:
            named = [
                supported
                for supported in rule.ecosystem.inputs
                if supported in recognised.guidance
            ]
            assert named, f"{file_name}: names no supported input"
        else:
            assert "is not one of the ecosystems this tool reads" in (
                recognised.guidance
            ), file_name


@pytest.mark.parametrize(
    ("file_name", "ecosystem", "expected_input"),
    [
        ("package.json", "npm", "package-lock.json"),
        ("yarn.lock", "npm", "package-lock.json"),
        ("pnpm-lock.yaml", "npm", "package-lock.json"),
        ("Gemfile", "Ruby", "Gemfile.lock"),
        ("demo.gemspec", "Ruby", "Gemfile.lock"),
        ("composer.json", "PHP (Composer)", "composer.lock"),
        ("Pipfile", "Python", "Pipfile.lock"),
        ("poetry.lock", "Python", "pyproject.toml"),
        ("setup.py", "Python", "requirements.txt"),
        ("go.sum", "Go", "go.mod"),
        ("Cargo.lock", "Rust", "Cargo.toml"),
        ("packages.config", ".NET", "packages.lock.json"),
        ("Demo.vbproj", ".NET", "*.csproj"),
        ("settings.gradle", "Gradle", "build.gradle"),
        ("libs.versions.toml", "Gradle", "build.gradle"),
    ],
)
def test_the_cross_ecosystem_sweep_covers_each_near_miss(
    file_name: str, ecosystem: str, expected_input: str
) -> None:
    """REGRESSION (#243): `package.json` was one instance of a general gap.

    Gemfile vs Gemfile.lock, Cargo.toml vs Cargo.lock, composer.json vs
    composer.lock, `*.csproj` vs its VB and F# siblings, and the version
    catalog all have the same shape. Fixing only npm would have left the next
    person to rediscover it one ecosystem at a time.
    """
    recognised = recognise_unreadable_manifest(f"/nowhere/{file_name}")

    assert recognised is not None, file_name
    assert recognised.ecosystem == ecosystem
    assert expected_input in recognised.guidance


def test_recognition_reads_no_file_and_tolerates_one_that_is_not_there() -> None:
    """INVARIANT (#243): a recursive walk calls this per entry; it must be cheap.

    A path under a directory that does not exist proves nothing was opened —
    the recognition still lands, and the companion probe degrades to "not
    found" rather than raising.
    """
    recognised = recognise_unreadable_manifest("/no/such/directory/package.json")

    assert recognised is not None
    assert recognised.ecosystem == "npm"
    assert recognised.supported_input_present is False
    assert "not found in /no/such/directory" in recognised.guidance


def test_a_supported_input_beside_the_file_is_recorded_as_present(
    tmp_path: Path,
) -> None:
    """HYPOTHESIS (#243): the ecosystem *was* read, so this file is not a gap.

    The flag is what keeps a directory scan of a healthy npm project from
    warning about the package.json whose lock file it just scored. It is
    recorded here and acted on by the caller, because the single-file path must
    still answer for a file the user named by hand.
    """
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
    lock = tmp_path / "package-lock.json"
    lock.write_text(PACKAGE_LOCK, encoding="utf-8")

    recognised = recognise_unreadable_manifest(str(manifest))

    assert recognised is not None
    assert recognised.supported_input_present is True
    assert f"found alongside it at {lock}" in recognised.guidance


def test_a_csproj_beside_a_vbproj_counts_as_the_supported_input(
    tmp_path: Path,
) -> None:
    """HYPOTHESIS (#243): the .NET supported input is a glob, and must match as one."""
    vbproj = tmp_path / "Demo.vbproj"
    vbproj.write_text("<Project />", encoding="utf-8")
    csproj = tmp_path / "Demo.csproj"
    csproj.write_text("<Project />", encoding="utf-8")

    recognised = recognise_unreadable_manifest(str(vbproj))

    assert recognised is not None
    assert recognised.supported_input_present is True
    assert str(csproj) in recognised.guidance


def test_an_unparsed_ecosystem_says_so_instead_of_inventing_a_next_step() -> None:
    """GUARD (#243): no parser exists for sbt, and the message must not imply one."""
    recognised = recognise_unreadable_manifest("/nowhere/build.sbt")

    assert recognised is not None
    assert recognised.ecosystem == "Scala (sbt)"
    assert "is not one of the ecosystems this tool reads" in recognised.guidance
    assert "list-ecosystems" in recognised.guidance


def test_an_unrecognized_name_is_not_claimed_as_an_unreadable_manifest() -> None:
    """GUARD (#243): recognition is a table, never a heuristic on file shape."""
    assert recognise_unreadable_manifest("/nowhere/notes.md") is None
    assert recognise_unreadable_manifest("/nowhere/config.toml") is None
