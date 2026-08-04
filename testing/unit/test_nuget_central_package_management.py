"""Central Package Management resolution for .csproj manifests (#129).

eShopOnWeb — Microsoft's own reference application — declares every version in a
``Directory.Packages.props`` and none in the project files, which is the
recommended layout for a multi-project solution. Reading only the inline
``Version`` attribute produced eighteen dependencies with an empty version, no
version-drift signal, and eighteen UNKNOWN risk levels.

The fixtures under ``testing/manifests/nuget/`` mirror that layout on disk, so
the whole walk-up-and-resolve path is exercised without a network or a checkout.
"""

from pathlib import Path

import pytest

from dependency_risk_profiler.parsers.nuget import NuGetParser
from dependency_risk_profiler.parsers.nuget_cpm import (
    CENTRAL_PROPS_FILENAME,
    collect_properties,
    concrete_version,
    expand_properties,
    find_central_props,
    read_central_versions,
)
from dependency_risk_profiler.parsers.version_sources import (
    VERSION_SOURCE_CENTRAL,
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
    VERSION_SOURCE_OVERRIDE,
    VERSION_SOURCE_UNMANAGED,
)
from dependency_risk_profiler.parsers.xml_utils import read_xml_root

MANIFESTS = Path(__file__).resolve().parents[1] / "manifests" / "nuget"
CENTRAL_PROJECT = MANIFESTS / "central-managed" / "src" / "Web" / "Web.csproj"
INLINE_PROJECT = MANIFESTS / "inline-versions" / "App.csproj"
DISABLED_PROJECT = MANIFESTS / "central-disabled" / "App.csproj"
BARE_PROJECT = MANIFESTS / "no-props" / "Web.csproj"


def _parse(path: Path) -> dict:
    """Parse a fixture project and return its dependency map."""
    return NuGetParser(str(path)).parse()


def test_versions_resolve_from_a_props_file_two_directories_up() -> None:
    """The whole point of the issue: no inline Version still yields a version."""
    deps = _parse(CENTRAL_PROJECT)

    assert deps["MediatR"].installed_version == "12.0.1"
    assert deps["MediatR"].additional_info[VERSION_SOURCE_KEY] == (
        VERSION_SOURCE_CENTRAL
    )


def test_property_references_in_the_props_file_are_expanded() -> None:
    """`Version="$(AspNetVersion)"` is how a real props file pins a family."""
    deps = _parse(CENTRAL_PROJECT)

    assert deps["Microsoft.AspNetCore.Identity.UI"].installed_version == "8.0.2"
    # And a property defined in terms of another property still resolves.
    assert deps["Serilog"].installed_version == "3.1.1"


def test_version_override_beats_the_central_declaration() -> None:
    """An explicit VersionOverride is the escape hatch, and it wins outright."""
    override = _parse(CENTRAL_PROJECT)["Newtonsoft.Json"]

    # 13.0.3 on the reference, not the 12.0.3 the props file declares.
    assert override.installed_version == "13.0.3"
    assert override.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_OVERRIDE


def test_inline_versions_still_win_inside_a_centrally_managed_tree() -> None:
    """A project that pins one package inline keeps that pin."""
    deps = _parse(CENTRAL_PROJECT)

    assert deps["xunit"].installed_version == "2.6.6"
    assert deps["xunit"].additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_DECLARED
    # A property the project itself defines is expanded against the project.
    assert deps["FluentAssertions"].installed_version == "2.4.2"
    # Version as a child element, alongside other item metadata.
    assert deps["Microsoft.EntityFrameworkCore.Tools"].installed_version == "8.0.2"


def test_an_inclusive_lower_bound_is_the_version_restore_installs() -> None:
    """`[4.0.1,5.0.0)` resolves to 4.0.1, which is what restore picks."""
    guard = _parse(CENTRAL_PROJECT)["Ardalis.GuardClauses"]

    assert guard.installed_version == "4.0.1"
    assert guard.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_CENTRAL


@pytest.mark.parametrize(
    "package",
    ["Azure.Identity", "Polly", "Missing.Package"],
    ids=["floating-version", "undefined-property", "not-declared-centrally"],
)
def test_unresolvable_versions_are_unmanaged_not_empty(package: str) -> None:
    """Anything a static read cannot establish says so, rather than guessing.

    A floating ``1.10.*`` and an undefined ``$(PollyVersion)`` both name a
    version that only a restore could produce; a package with no central
    declaration has none at all. All three leave the version-drift signal
    unmeasured (#74) instead of scoring a fabricated zero.
    """
    dependency = _parse(CENTRAL_PROJECT)[package]

    assert dependency.installed_version == ""
    assert dependency.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED


def test_inline_version_project_does_not_regress() -> None:
    """A project that pins everything inline is unaffected by any of this."""
    deps = _parse(INLINE_PROJECT)

    assert deps["Newtonsoft.Json"].installed_version == "13.0.1"
    assert deps["Serilog"].installed_version == "2.10.0"
    # An exact-version range is a pin, spelled the other way.
    assert deps["Ardalis.GuardClauses"].installed_version == "4.0.1"
    assert all(
        dep.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_DECLARED
        for dep in deps.values()
    )


def test_a_bare_csproj_with_no_reachable_props_reports_unmanaged() -> None:
    """The common case for a single manifest fetched in isolation.

    This is the fallback the honest option buys: an unreachable props file
    yields ``unmanaged``, which the formatter renders as ``unmanaged → 2.22.1``
    and the scorer excludes from both numerator and denominator, rather than the
    bare arrow an empty string used to produce.
    """
    deps = _parse(BARE_PROJECT)

    assert set(deps) == {"MediatR", "Serilog"}
    for dependency in deps.values():
        assert dependency.installed_version == ""
        assert dependency.additional_info[VERSION_SOURCE_KEY] == (
            VERSION_SOURCE_UNMANAGED
        )


def test_manage_package_versions_centrally_false_is_respected() -> None:
    """An explicit opt-out means the PackageVersion entries do not apply."""
    mediatr = _parse(DISABLED_PROJECT)["MediatR"]

    assert mediatr.installed_version == ""
    assert mediatr.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED


def test_a_project_can_opt_out_even_when_the_props_file_opts_in(
    tmp_path: Path,
) -> None:
    """The project's own property switches central management off for itself."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>"
        "</PropertyGroup><ItemGroup>"
        '<PackageVersion Include="MediatR" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        "<Project><PropertyGroup>"
        "<ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>"
        "</PropertyGroup><ItemGroup>"
        '<PackageReference Include="MediatR" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    mediatr = _parse(project)["MediatR"]

    assert mediatr.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED


def test_the_nearest_props_file_wins(tmp_path: Path) -> None:
    """The first file found walking up wins, rather than a merge of them all."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        '<Project><ItemGroup><PackageVersion Include="MediatR" Version="1.0.0" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    nested = tmp_path / "src" / "Web"
    nested.mkdir(parents=True)
    (nested.parent / CENTRAL_PROPS_FILENAME).write_text(
        '<Project><ItemGroup><PackageVersion Include="MediatR" Version="2.0.0" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = nested / "Web.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    assert _parse(project)["MediatR"].installed_version == "2.0.0"


def test_package_ids_match_case_insensitively(tmp_path: Path) -> None:
    """Package ids are case-insensitive in NuGet, so the lookup must be too."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        '<Project><ItemGroup><PackageVersion Include="mediatr" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    assert _parse(project)["MediatR"].installed_version == "12.0.1"


def test_an_inline_only_project_never_looks_for_a_props_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project that pins everything stays on its own manifest."""
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    def explode(_: Path) -> None:
        raise AssertionError("the props lookup must not run for a pinned project")

    monkeypatch.setattr(
        "dependency_risk_profiler.parsers.nuget.find_central_props", explode
    )

    assert _parse(project)["MediatR"].installed_version == "12.0.1"


def test_find_central_props_stops_at_the_filesystem_root(tmp_path: Path) -> None:
    """A tree with no props file terminates rather than walking forever."""
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)

    # tmp_path itself is guaranteed clean; anything found would be above it.
    found = find_central_props(nested)

    assert found is None or CENTRAL_PROPS_FILENAME in str(found)


def test_props_file_declarations_are_read_with_properties_expanded() -> None:
    """The props reader is usable on its own, and states what it enabled."""
    central = read_central_versions(
        MANIFESTS / "central-managed" / CENTRAL_PROPS_FILENAME
    )

    assert central is not None
    assert central.manage_centrally is True
    assert central.version_for("MEDIATR") == "12.0.1"
    assert central.version_for("Microsoft.AspNetCore.Identity.UI") == "8.0.2"
    # A child-element Version is read the same as the attribute form.
    assert central.version_for("AutoMapper") == "12.0.1"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3", "1.2.3"),
        ("8.0.2-preview.1", "8.0.2-preview.1"),
        ("[4.0.1]", "4.0.1"),
        ("[4.0.1,5.0.0)", "4.0.1"),
        ("  12.0.1  ", "12.0.1"),
        ("1.2.*", None),
        ("*", None),
        ("(1.0,)", None),
        ("[1.0,", None),
        ("$(Unresolved)", None),
        ("", None),
        (None, None),
    ],
)
def test_concrete_version_names_a_version_or_declines(raw: str, expected: str) -> None:
    """Only an inclusive lower bound names the version restore will install."""
    assert concrete_version(raw) == expected


def test_property_expansion_terminates_on_a_cycle() -> None:
    """Two properties defined in terms of each other must not hang the parse."""
    properties = {"a": "$(B)", "b": "$(A)"}

    expanded = expand_properties("$(A)", properties)

    assert "$(" in expanded


def test_unknown_properties_are_left_visible_rather_than_blanked() -> None:
    """An unexpandable reference stays a reference so it can be rejected."""
    assert expand_properties("$(Nope)", {}) == "$(Nope)"


def test_property_names_are_matched_case_insensitively(tmp_path: Path) -> None:
    """Property names ignore case in MSBuild; so does the expander."""
    props = tmp_path / CENTRAL_PROPS_FILENAME
    props.write_text(
        "<Project><PropertyGroup><AspNetVersion>8.0.2</AspNetVersion>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    root = read_xml_root(props)
    assert root is not None

    assert expand_properties("$(ASPNETVERSION)", collect_properties(root)) == "8.0.2"


def test_a_malformed_props_file_degrades_to_unmanaged(tmp_path: Path) -> None:
    """Unparseable XML above the project must not take the whole scan down."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text("<Project", encoding="utf-8")
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    mediatr = _parse(project)["MediatR"]

    assert mediatr.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED


def test_props_files_resolve_no_external_entities(tmp_path: Path) -> None:
    """A Directory.Packages.props is untrusted XML; XXE must not be possible."""
    secret = tmp_path / "secret.txt"
    secret.write_text("s3cret", encoding="utf-8")
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<?xml version='1.0'?>"
        f"<!DOCTYPE Project [<!ENTITY xxe SYSTEM 'file://{secret}'>]>"
        '<Project><ItemGroup><PackageVersion Include="MediatR" Version="&xxe;" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    mediatr = _parse(project)["MediatR"]

    # ElementTree raises on the undefined entity, so the file is dropped whole
    # and the version is honestly unmanaged. The secret never appears.
    assert "s3cret" not in mediatr.installed_version
    assert mediatr.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED
