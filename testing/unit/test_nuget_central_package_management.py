"""Central Package Management resolution for .csproj manifests (#129).

eShopOnWeb — Microsoft's own reference application — declares every version in a
``Directory.Packages.props`` and none in the project files, which is the
recommended layout for a multi-project solution. Reading only the inline
``Version`` attribute produced eighteen dependencies with an empty version, no
version-drift signal, and eighteen UNKNOWN risk levels.

The fixtures under ``testing/manifests/nuget/`` mirror that layout on disk, so
the whole walk-up-and-resolve path is exercised without a network or a checkout.

#151 added the two things #129 left out, and they are tested here the way
``test_gradle_parser`` splits its own coverage: the *captured* half — Dapper and
Newtonsoft.Json, real repositories, parsed and then scored against recorded
nuget.org bytes — lives in ``adapter_conformance``, and this file holds the
branches a captured project happens not to contain plus the ones whose whole
content is a refusal. A synthetic fixture cannot prove a reader matches the
world; it can prove a reader declines when it should, which is most of what is
below.
"""

from pathlib import Path

import pytest

from dependency_risk_profiler.parsers.nuget import NuGetParser
from dependency_risk_profiler.parsers.nuget_cpm import (
    BUILD_DEPENDENCY_KEY,
    BUILD_PROPS_FILENAME,
    CENTRAL_PROPS_FILENAME,
    collect_properties,
    concrete_version,
    expand_properties,
    find_build_props,
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


def test_an_inline_only_project_still_reads_the_props_file(tmp_path: Path) -> None:
    """#129's shortcut for a pinned project did not survive #151.

    #129 skipped the props lookup entirely when every reference carried its own
    version, so a fully pinned project touched no file but its own manifest.
    A ``<GlobalPackageReference>`` is a dependency of every project under the
    file *including* the pinned ones, and there is no way to know one is there
    without reading the file. So the lookup now always runs, and the property
    the old test pinned is gone deliberately rather than by accident. What must
    not change is the answer for the pins themselves.
    """
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<PackageVersion Include="MediatR" Version="9.9.9" />'
        '<GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.6.133" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    deps = _parse(project)

    # The inline pin still wins over the central declaration, unchanged.
    assert deps["MediatR"].installed_version == "12.0.1"
    assert deps["MediatR"].additional_info[VERSION_SOURCE_KEY] == (
        VERSION_SOURCE_DECLARED
    )
    assert deps["Nerdbank.GitVersioning"].installed_version == "3.6.133"


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


# --- <GlobalPackageReference>: dependencies with nothing in the project ------
#
# The captured case is Dapper, in ``adapter_conformance``: one
# ``<GlobalPackageReference Include="ReferenceTrimmer">`` in the repository's
# Directory.Packages.props, nothing in Dapper.csproj, and a package that was
# entirely invisible to the scanner before #151. What follows is the rest of the
# shape — the declarations a real repository does not happen to contain, and the
# cases where the honest answer is to decline.


def test_a_global_package_reference_is_a_dependency_of_the_project(
    tmp_path: Path,
) -> None:
    """The whole of gap 1: a package the .csproj never mentions."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<GlobalPackageReference Include="ReferenceTrimmer" Version="3.5.7" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    trimmer = _parse(project)["ReferenceTrimmer"]

    assert trimmer.installed_version == "3.5.7"
    assert trimmer.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_CENTRAL


def test_a_global_package_is_marked_as_a_build_dependency(tmp_path: Path) -> None:
    """Build-time and runtime are not merged silently.

    The marker is the same key ``parsers/toml.py`` writes for pyproject's
    ``build-system.requires``, so nothing new is invented here. It stops at the
    Python API: the unified ``ScoredDependency`` (#205) has no field for a
    dependency's kind, and ``additional_info`` reaches neither reporter, which
    is recorded in ``nuget_cpm`` rather than papered over with a contract field
    this issue was not asked to add.
    """
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<GlobalPackageReference Include="StyleCop.Analyzers" '
        'Version="1.2.0-beta.556" />'
        '<PackageVersion Include="MediatR" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    deps = _parse(project)

    assert deps["StyleCop.Analyzers"].additional_info[BUILD_DEPENDENCY_KEY] == "true"
    assert deps["StyleCop.Analyzers"].installed_version == "1.2.0-beta.556"
    # A package the project does reference is not marked, and that asymmetry is
    # the entire point of marking anything.
    assert BUILD_DEPENDENCY_KEY not in deps["MediatR"].additional_info


def test_a_csproj_with_no_package_references_still_gets_its_global_packages(
    tmp_path: Path,
) -> None:
    """The extreme of the same fact: every dependency comes from above."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<GlobalPackageReference Include="Microsoft.SourceLink.GitHub" '
        'Version="8.0.0" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )

    deps = _parse(project)

    assert set(deps) == {"Microsoft.SourceLink.GitHub"}
    assert deps["Microsoft.SourceLink.GitHub"].installed_version == "8.0.0"


@pytest.mark.parametrize(
    "declaration",
    [
        '<GlobalPackageReference Include="Polly" Version="$(Nope)" />',
        '<GlobalPackageReference Include="Polly" Version="1.2.*" />',
        '<GlobalPackageReference Include="Polly" />',
    ],
    ids=["undefined-property", "floating-version", "no-version-at-all"],
)
def test_an_unresolvable_global_package_is_unmanaged_not_dropped(
    tmp_path: Path, declaration: str
) -> None:
    """A global package with no readable version is still a dependency.

    Dropping it would hide a package that ships in the build; inventing a
    version would be worse. It is reported with the same ``unmanaged`` contract
    every other unresolvable NuGet version gets (#74, #141).
    """
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        f"<Project><ItemGroup>{declaration}</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text("<Project />", encoding="utf-8")

    polly = _parse(project)["Polly"]

    assert polly.installed_version == ""
    assert polly.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED
    assert polly.additional_info[BUILD_DEPENDENCY_KEY] == "true"


def test_the_projects_own_reference_wins_over_a_global_declaration(
    tmp_path: Path,
) -> None:
    """A project that does both is rejected by NuGet; the specific one is kept."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<GlobalPackageReference Include="MediatR" Version="1.0.0" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="mediatr" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    deps = _parse(project)

    # Matched case-insensitively, so the global does not arrive under a second
    # spelling of the same package.
    assert set(deps) == {"mediatr"}
    assert deps["mediatr"].installed_version == "12.0.1"
    assert BUILD_DEPENDENCY_KEY not in deps["mediatr"].additional_info


def test_global_packages_do_not_apply_when_central_management_is_off(
    tmp_path: Path,
) -> None:
    """``GlobalPackageReference`` is a Central Package Management item.

    Switch the feature off and MSBuild ignores the item, so reporting it would
    be reporting a dependency the build does not have.
    """
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>"
        "</PropertyGroup><ItemGroup>"
        '<GlobalPackageReference Include="ReferenceTrimmer" Version="3.5.7" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="MediatR" Version="12.0.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    assert set(_parse(project)) == {"MediatR"}


def test_a_repeated_global_package_is_declared_once(tmp_path: Path) -> None:
    """First declaration wins, matching how a repeated PackageVersion resolves."""
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<GlobalPackageReference Include="ReferenceTrimmer" Version="3.5.7" />'
        '<GlobalPackageReference Include="referencetrimmer" Version="1.0.0" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text("<Project />", encoding="utf-8")

    deps = _parse(project)

    assert set(deps) == {"ReferenceTrimmer"}
    assert deps["ReferenceTrimmer"].installed_version == "3.5.7"


def test_the_props_reader_reports_global_packages_on_its_own() -> None:
    """The reader is usable directly, and says nothing when there are none."""
    central = read_central_versions(
        MANIFESTS / "central-managed" / CENTRAL_PROPS_FILENAME
    )

    assert central is not None
    assert central.global_packages == ()


# --- Directory.Build.props as a property source ------------------------------
#
# The captured case is Newtonsoft.Json, in ``adapter_conformance``: seven
# ``PackageReference`` items whose versions are all
# ``$(SomethingPackageVersion)`` and a Src/Directory.Build.props one directory
# up that defines every one of them. All seven read as ``unmanaged`` before
# #151. Below is the precedence, which a single repository cannot demonstrate,
# and the failure modes.


def test_a_version_property_defined_one_directory_up_resolves(tmp_path: Path) -> None:
    """Gap 2, in its smallest form."""
    (tmp_path / BUILD_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<SerilogPackageVersion>3.1.1</SerilogPackageVersion>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    nested = tmp_path / "src" / "App"
    nested.mkdir(parents=True)
    project = nested / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" '
        'Version="$(SerilogPackageVersion)" /></ItemGroup></Project>',
        encoding="utf-8",
    )

    serilog = _parse(project)["Serilog"]

    assert serilog.installed_version == "3.1.1"
    # The project stated the version; where the *property* came from is a
    # different question from where the version came from, and the vocabulary
    # answers the second one.
    assert serilog.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_DECLARED


def test_the_project_overrides_a_property_it_inherits(tmp_path: Path) -> None:
    """The project wins, because MSBuild imports Directory.Build.props first.

    This is the precedence half of "resolve conservatively": getting it
    backwards produces a confident version that the build would never install,
    which is worse than the ``unmanaged`` this replaced.
    """
    (tmp_path / BUILD_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<SerilogPackageVersion>1.0.0</SerilogPackageVersion>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        "<Project><PropertyGroup>"
        "<SerilogPackageVersion>3.1.1</SerilogPackageVersion>"
        "</PropertyGroup><ItemGroup>"
        '<PackageReference Include="Serilog" Version="$(SerilogPackageVersion)" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    assert _parse(project)["Serilog"].installed_version == "3.1.1"


def test_the_packages_props_overrides_a_property_it_inherits(tmp_path: Path) -> None:
    """Directory.Packages.props is imported after Directory.Build.props."""
    (tmp_path / BUILD_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<SerilogPackageVersion>1.0.0</SerilogPackageVersion>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<SerilogPackageVersion>3.1.1</SerilogPackageVersion>"
        "</PropertyGroup><ItemGroup>"
        '<PackageVersion Include="Serilog" Version="$(SerilogPackageVersion)" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    serilog = _parse(project)["Serilog"]

    assert serilog.installed_version == "3.1.1"
    assert serilog.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_CENTRAL


def test_an_inherited_property_resolves_a_central_declaration(tmp_path: Path) -> None:
    """The props file may reference a property only the build props defines."""
    (tmp_path / BUILD_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<SerilogPackageVersion>3.1.1</SerilogPackageVersion>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<PackageVersion Include="Serilog" Version="$(SerilogPackageVersion)" />'
        '<GlobalPackageReference Include="Nerdbank.GitVersioning" '
        'Version="$(SerilogPackageVersion)" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    deps = _parse(project)

    assert deps["Serilog"].installed_version == "3.1.1"
    assert deps["Nerdbank.GitVersioning"].installed_version == "3.1.1"


def test_central_management_can_be_switched_off_from_the_build_props(
    tmp_path: Path,
) -> None:
    """A property source is a property source, including for this property.

    ``ManagePackageVersionsCentrally`` is an ordinary MSBuild property and
    Dapper's real repository sets it in Directory.Build.props. Reading the file
    for versions and not for the switch that decides whether those versions
    apply would be the confidently-wrong answer the walk exists to avoid.
    """
    (tmp_path / BUILD_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup>"
        "<ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    (tmp_path / CENTRAL_PROPS_FILENAME).write_text(
        "<Project><ItemGroup>"
        '<PackageVersion Include="Serilog" Version="3.1.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    serilog = _parse(project)["Serilog"]

    assert serilog.installed_version == ""
    assert serilog.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED


def test_the_nearest_build_props_wins(tmp_path: Path) -> None:
    """First hit walking up, the same rule the packages props gets."""
    (tmp_path / BUILD_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup><SerilogVersion>1.0.0</SerilogVersion>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    nested = tmp_path / "src" / "App"
    nested.mkdir(parents=True)
    (nested.parent / BUILD_PROPS_FILENAME).write_text(
        "<Project><PropertyGroup><SerilogVersion>2.0.0</SerilogVersion>"
        "</PropertyGroup></Project>",
        encoding="utf-8",
    )
    project = nested / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" '
        'Version="$(SerilogVersion)" /></ItemGroup></Project>',
        encoding="utf-8",
    )

    assert _parse(project)["Serilog"].installed_version == "2.0.0"


def test_a_malformed_build_props_leaves_the_version_unmanaged(tmp_path: Path) -> None:
    """Unparseable XML above the project must not take the scan down."""
    (tmp_path / BUILD_PROPS_FILENAME).write_text("<Project", encoding="utf-8")
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" '
        'Version="$(SerilogPackageVersion)" /></ItemGroup></Project>',
        encoding="utf-8",
    )

    serilog = _parse(project)["Serilog"]

    assert serilog.installed_version == ""
    assert serilog.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED


def test_build_props_resolve_no_external_entities(tmp_path: Path) -> None:
    """A Directory.Build.props is untrusted XML too; XXE must not be possible."""
    secret = tmp_path / "secret.txt"
    secret.write_text("s3cret", encoding="utf-8")
    (tmp_path / BUILD_PROPS_FILENAME).write_text(
        "<?xml version='1.0'?>"
        f"<!DOCTYPE Project [<!ENTITY xxe SYSTEM 'file://{secret}'>]>"
        "<Project><PropertyGroup><SerilogPackageVersion>&xxe;"
        "</SerilogPackageVersion></PropertyGroup></Project>",
        encoding="utf-8",
    )
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" '
        'Version="$(SerilogPackageVersion)" /></ItemGroup></Project>',
        encoding="utf-8",
    )

    serilog = _parse(project)["Serilog"]

    assert "s3cret" not in serilog.installed_version
    assert serilog.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED


def test_find_build_props_stops_at_the_filesystem_root(tmp_path: Path) -> None:
    """The walk is bounded for both filenames, not just the one #129 added."""
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)

    found = find_build_props(nested)

    assert found is None or BUILD_PROPS_FILENAME in str(found)
