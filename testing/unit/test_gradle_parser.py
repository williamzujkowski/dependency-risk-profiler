"""Unit coverage for the Gradle build-script parser (#101).

The captured, end-to-end gate lives in ``adapter_conformance``: two real
projects, parsed for real, scored against captured Maven Central bytes. This
file is the other half, and it is what a synthetic fixture is legitimately for
(``registry_fixtures`` draws that line): the branches a captured project happens
not to contain, and the ones whose whole content is a *refusal*.

The refusals are the point. A Gradle build script is a Groovy or Kotlin program,
so a parser for it is a parser for the declarative subset and a set of honest
'no's for everything else. A test suite that only checked the yes-cases would be
measuring the wrong thing entirely — it is trivial to raise the yes-rate by
guessing, and every guess here becomes a confident wrong version in somebody's
risk report. So each test below names which side of that line it is holding.

The rule the whole file enforces: **a version this file cannot establish is
reported as unmanaged, never as a number and never as silence.** That is #141's
contract for Maven's inherited versions and #199's fail-closed default, reached
from a third direction.
"""

from pathlib import Path
from typing import Dict

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.parsers.gradle import GradleParser
from dependency_risk_profiler.parsers.gradle_catalog import (
    find_version_catalog,
    normalize_alias,
    read_version_catalog,
)
from dependency_risk_profiler.parsers.gradle_dsl import concrete_version
from dependency_risk_profiler.parsers.registry import EcosystemRegistry
from dependency_risk_profiler.parsers.version_sources import (
    VERSION_SOURCE_CATALOG,
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
    VERSION_SOURCE_UNMANAGED,
)
from dependency_risk_profiler.vulnerabilities import ecosystems

CATALOG = """
[versions]
okio = "3.9.0"
junit = { require = "5.10.2" }
floating = "1.+"

[libraries]
square-okio = { module = "com.squareup.okio:okio", version.ref = "okio" }
junit-api = { module = "org.junit.jupiter:junit-jupiter-api", version.ref = "junit" }
agp = { group = "com.android.tools.build", name = "gradle", version = "8.5.0" }
shorthand = "com.google.guava:guava:33.2.0-jre"
unversioned = { module = "org.example:managed-elsewhere" }
dynamic = { module = "org.example:moving", version.ref = "floating" }

[bundles]
testing = ["junit-api", "square-okio"]

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "okio" }
"""


def _write_project(root: Path, script: str, name: str = "build.gradle.kts") -> Path:
    """Write a one-module project with the shared catalog and return its script."""
    catalog = root / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(CATALOG, encoding="utf-8")
    module = root / "app"
    module.mkdir(parents=True, exist_ok=True)
    path = module / name
    path.write_text(script, encoding="utf-8")
    return path


def _parse(
    root: Path, script: str, name: str = "build.gradle.kts"
) -> Dict[str, DependencyMetadata]:
    """Parse a script written into a project that has the shared catalog."""
    return GradleParser(str(_write_project(root, script, name))).parse()


def _source(dependencies: Dict[str, DependencyMetadata], name: str) -> str:
    """Return how a dependency's version was established."""
    return dependencies[name].additional_info[VERSION_SOURCE_KEY]


# --- What is read ----------------------------------------------------------


def test_the_kotlin_and_groovy_string_forms_read_the_same(tmp_path: Path) -> None:
    """The two DSLs differ by parentheses, and the reader must not care."""
    kotlin = _parse(
        tmp_path / "kts",
        'dependencies {\n  implementation("com.squareup.okio:okio:3.9.0")\n}\n',
    )
    groovy = _parse(
        tmp_path / "groovy",
        "dependencies {\n  implementation 'com.squareup.okio:okio:3.9.0'\n}\n",
        name="build.gradle",
    )

    assert kotlin.keys() == groovy.keys() == {"com.squareup.okio:okio"}
    assert kotlin["com.squareup.okio:okio"].installed_version == "3.9.0"
    assert groovy["com.squareup.okio:okio"].installed_version == "3.9.0"


def test_a_version_catalog_alias_resolves_through_version_ref(tmp_path: Path) -> None:
    """The shape #101 waited for: the version is in neither the file nor the line.

    ``libs.square.okio`` names an alias, the alias names a ``version.ref``, and
    the ref names an entry in ``[versions]``. Two indirections and one file
    away, which is the same distance NuGet's ``Directory.Packages.props`` (#129)
    and Maven's parent ``<dependencyManagement>`` (#141) put it at.
    """
    dependencies = _parse(
        tmp_path, "dependencies {\n  implementation(libs.square.okio)\n}\n"
    )

    assert dependencies["com.squareup.okio:okio"].installed_version == "3.9.0"
    assert _source(dependencies, "com.squareup.okio:okio") == VERSION_SOURCE_CATALOG


def test_the_catalog_source_is_the_shared_constant_not_a_gradle_spelling() -> None:
    """#164's actual requirement: reuse the vocabulary, do not fork it.

    Gradle is the third ecosystem to declare versions away from the manifest.
    The concept had to already exist in two before a third was allowed to land,
    so that it would consume ``version_sources`` rather than become a third
    one-off. This asserts the reuse rather than trusting it: every constant the
    Gradle parser records is defined in the shared module, and the two that mean
    the same thing everywhere are the identical objects.
    """
    from dependency_risk_profiler.parsers import maven, nuget, version_sources

    assert VERSION_SOURCE_CATALOG == version_sources.VERSION_SOURCE_CATALOG
    assert VERSION_SOURCE_KEY is maven.VERSION_SOURCE_KEY is nuget.VERSION_SOURCE_KEY
    assert (
        VERSION_SOURCE_UNMANAGED
        is maven.VERSION_SOURCE_UNMANAGED
        is nuget.VERSION_SOURCE_UNMANAGED
    )


def test_every_catalog_entry_spelling_gradle_accepts_is_read(tmp_path: Path) -> None:
    """group/name, the string shorthand and an inline version all resolve."""
    dependencies = _parse(
        tmp_path,
        "dependencies {\n"
        "  implementation(libs.agp)\n"
        "  implementation(libs.shorthand)\n"
        "}\n",
    )

    assert dependencies["com.android.tools.build:gradle"].installed_version == "8.5.0"
    assert dependencies["com.google.guava:guava"].installed_version == "33.2.0-jre"


def test_a_bundle_expands_to_every_library_it_names(tmp_path: Path) -> None:
    """One accessor, several dependencies; counting it as one would understate."""
    dependencies = _parse(
        tmp_path, "dependencies {\n  testImplementation(libs.bundles.testing)\n}\n"
    )

    assert set(dependencies) == {
        "org.junit.jupiter:junit-jupiter-api",
        "com.squareup.okio:okio",
    }
    assert (
        dependencies["org.junit.jupiter:junit-jupiter-api"].installed_version
        == "5.10.2"
    )


def test_an_ext_property_is_expanded_into_the_coordinate(tmp_path: Path) -> None:
    """The RxJava shape, reduced: the version is in the file, not in the line."""
    dependencies = _parse(
        tmp_path,
        'ext {\n  okioVersion = "3.9.0"\n}\n'
        "dependencies {\n"
        '  implementation "com.squareup.okio:okio:$okioVersion"\n'
        '  implementation "org.example:braced:${okioVersion}"\n'
        "}\n",
        name="build.gradle",
    )

    assert dependencies["com.squareup.okio:okio"].installed_version == "3.9.0"
    assert dependencies["org.example:braced"].installed_version == "3.9.0"
    assert _source(dependencies, "org.example:braced") == VERSION_SOURCE_DECLARED


def test_gradle_properties_answers_a_version_the_script_does_not(
    tmp_path: Path,
) -> None:
    """A property set in gradle.properties is as declared as one set inline."""
    (tmp_path / "gradle.properties").write_text("okioVersion=3.9.0\n", encoding="utf-8")
    dependencies = _parse(
        tmp_path,
        'dependencies {\n  implementation "com.squareup.okio:okio:$okioVersion"\n}\n',
        name="build.gradle",
    )

    assert dependencies["com.squareup.okio:okio"].installed_version == "3.9.0"


def test_a_nested_source_set_dependencies_block_is_read(tmp_path: Path) -> None:
    """Kotlin Multiplatform keeps every declaration four blocks deep.

    A reader that only looks at the top level finds nothing in okhttp at all,
    which is not a small miss: it is the whole file.
    """
    dependencies = _parse(
        tmp_path,
        "kotlin {\n"
        "  sourceSets {\n"
        "    commonMain {\n"
        "      dependencies {\n"
        "        api(libs.square.okio)\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )

    assert set(dependencies) == {"com.squareup.okio:okio"}


def test_map_notation_reads_in_both_spellings(tmp_path: Path) -> None:
    """Groovy's ``name: 'x'`` and Kotlin's ``name = "x"`` are the same fact."""
    groovy = _parse(
        tmp_path / "groovy",
        "dependencies {\n"
        "  implementation group: 'org.example', name: 'thing', version: '1.2'\n"
        "}\n",
        name="build.gradle",
    )
    kotlin = _parse(
        tmp_path / "kts",
        "dependencies {\n"
        '  implementation(group = "org.example", name = "thing", version = "1.2")\n'
        "}\n",
    )

    assert groovy["org.example:thing"].installed_version == "1.2"
    assert kotlin["org.example:thing"].installed_version == "1.2"


def test_a_platform_wrapper_reports_the_bom_it_names(tmp_path: Path) -> None:
    """A BOM is a published artifact with its own advisories, so it is reported."""
    dependencies = _parse(
        tmp_path,
        "dependencies {\n"
        '  implementation(platform("org.example:bom:2024.0.1"))\n'
        "  implementation(enforcedPlatform(libs.square.okio))\n"
        "}\n",
    )

    assert dependencies["org.example:bom"].installed_version == "2024.0.1"
    assert dependencies["com.squareup.okio:okio"].installed_version == "3.9.0"


def test_a_configuration_the_parser_has_never_heard_of_still_counts(
    tmp_path: Path,
) -> None:
    """The RxJava build declares ``signature`` and ``jmh``; a list drops both.

    Custom configurations are ordinary, and the ``@signature`` artifact-type
    suffix on the coordinate is ordinary too. Matching the *shape* of a
    declaration rather than an allowlist of configuration names is what keeps
    both readable.
    """
    dependencies = _parse(
        tmp_path,
        "dependencies {\n"
        "  signature 'org.codehaus.mojo.signature:java18:1.0@signature'\n"
        "}\n",
        name="build.gradle",
    )

    assert dependencies["org.codehaus.mojo.signature:java18"].installed_version == "1.0"


def test_groovy_accepts_several_coordinates_on_one_configuration(
    tmp_path: Path,
) -> None:
    """Reading only the first literal would silently drop a real dependency."""
    dependencies = _parse(
        tmp_path,
        "dependencies {\n  implementation 'org.a:one:1.0', 'org.b:two:2.0'\n}\n",
        name="build.gradle",
    )

    assert set(dependencies) == {"org.a:one", "org.b:two"}


def test_a_declaration_with_a_configuration_block_is_not_swallowed(
    tmp_path: Path,
) -> None:
    """``implementation(x) { exclude(...) }`` opens a block; the header is a fact."""
    dependencies = _parse(
        tmp_path,
        "dependencies {\n"
        '  implementation("org.example:thing:1.2") {\n'
        '    exclude(group = "org.unwanted", module = "noisy")\n'
        "  }\n"
        "}\n",
    )

    assert set(dependencies) == {"org.example:thing"}
    assert dependencies["org.example:thing"].installed_version == "1.2"


def test_kotlin_sugar_names_the_artifact_it_cannot_version(tmp_path: Path) -> None:
    """``kotlin("reflect")`` has a recoverable coordinate and no findable version.

    Dropping it would understate the dependency count, which is the worse of the
    two errors: an unmanaged version costs one signal, an unreported dependency
    costs every signal and the advisory lookup with them.
    """
    dependencies = _parse(
        tmp_path, 'dependencies {\n  implementation(kotlin("reflect"))\n}\n'
    )

    assert dependencies["org.jetbrains.kotlin:kotlin-reflect"].installed_version == ""
    assert (
        _source(dependencies, "org.jetbrains.kotlin:kotlin-reflect")
        == VERSION_SOURCE_UNMANAGED
    )


# --- What is refused -------------------------------------------------------


@pytest.mark.parametrize(
    "version",
    ["1.+", "2.3.+", "[1.0,2.0)", "latest.release", "latest.integration", "$computed"],
)
def test_a_version_only_a_resolution_could_pick_is_not_a_version(version: str) -> None:
    """Dynamic versions name what Gradle *would* resolve, not what is declared.

    Same judgement as NuGet's floating ``1.2.*`` (#129): the number only exists
    after a resolution this scan does not perform, so reporting one would be
    reporting a guess.
    """
    assert concrete_version(version) is None


def test_a_dynamic_version_is_reported_unmanaged_rather_than_dropped(
    tmp_path: Path,
) -> None:
    """The dependency is real even when its version is not knowable."""
    dependencies = _parse(
        tmp_path, "dependencies {\n  implementation('org.example:moving:1.+')\n}\n"
    )

    assert dependencies["org.example:moving"].installed_version == ""
    assert _source(dependencies, "org.example:moving") == VERSION_SOURCE_UNMANAGED


def test_a_catalog_entry_with_a_dynamic_ref_is_unmanaged_too(tmp_path: Path) -> None:
    """The refusal has to survive the indirection, or the catalog launders it."""
    dependencies = _parse(
        tmp_path,
        "dependencies {\n"
        "  implementation(libs.dynamic)\n"
        "  implementation(libs.unversioned)\n"
        "}\n",
    )

    assert _source(dependencies, "org.example:moving") == VERSION_SOURCE_UNMANAGED
    assert (
        _source(dependencies, "org.example:managed-elsewhere")
        == VERSION_SOURCE_UNMANAGED
    )


def test_an_unreachable_catalog_leaves_the_declaration_unnamed(tmp_path: Path) -> None:
    """An alias with no catalog is not a dependency yet; it is a name for one.

    This is the one case where nothing is reported at all, and the reason is
    narrow: ``libs.square.okio`` does not state a ``groupId:artifactId``
    anywhere. Emitting a placeholder would invent a package that does not exist,
    which is a worse failure than an honest gap — so the parser logs it and
    reports the dependencies it *can* name.
    """
    module = tmp_path / "app"
    module.mkdir(parents=True)
    script = module / "build.gradle.kts"
    script.write_text(
        "dependencies {\n"
        "  implementation(libs.square.okio)\n"
        '  implementation("org.example:named:1.0")\n'
        "}\n",
        encoding="utf-8",
    )

    dependencies = GradleParser(str(script)).parse()

    assert set(dependencies) == {"org.example:named"}


def test_a_computed_coordinate_is_counted_not_invented(tmp_path: Path) -> None:
    """The honest blind spot, and it has to be visible rather than silent."""
    from dependency_risk_profiler.parsers.gradle_dsl import read_script

    script = read_script(
        "dependencies {\n"
        '  implementation("$group:$name:$version")\n'
        "  implementation(someHelper())\n"
        '  implementation("org.example:real:1.0")\n'
        "}\n"
    )

    assert script.unreadable == 2
    assert [declaration.key for declaration in script.declarations] == [
        "org.example:real"
    ]


def test_buildscript_and_constraints_blocks_are_not_project_dependencies(
    tmp_path: Path,
) -> None:
    """Build tooling is Maven's ``<build><plugins>``, which the POM reader skips.

    A constraint is worse than irrelevant: it states a version for a dependency
    somebody else declares, so counting it would double-count the dependency.
    """
    dependencies = _parse(
        tmp_path,
        "buildscript {\n"
        "  dependencies {\n"
        '    classpath("com.android.tools.build:gradle:8.5.0")\n'
        "  }\n"
        "}\n"
        "dependencies {\n"
        '  implementation("org.example:real:1.0")\n'
        "  constraints {\n"
        '    implementation("org.example:real:9.9.9")\n'
        "  }\n"
        "}\n",
    )

    assert set(dependencies) == {"org.example:real"}
    assert dependencies["org.example:real"].installed_version == "1.0"


def test_project_and_file_dependencies_are_skipped(tmp_path: Path) -> None:
    """None of these has a registry, so none of them has a risk profile."""
    dependencies = _parse(
        tmp_path,
        "dependencies {\n"
        '  implementation(project(":core"))\n'
        "  implementation(projects.core)\n"
        '  implementation(files("libs/vendor.jar"))\n'
        '  implementation(fileTree("libs"))\n'
        "  implementation(gradleApi())\n"
        "}\n",
    )

    assert dependencies == {}


def test_a_brace_inside_a_string_does_not_open_a_block(tmp_path: Path) -> None:
    """The scanner reads string literals as units, or block tracking desynchronises."""
    dependencies = _parse(
        tmp_path,
        'val note = "a { brace } in a string"\n'
        "dependencies {\n"
        '  implementation("org.example:real:1.0")\n'
        "}\n",
    )

    assert set(dependencies) == {"org.example:real"}


def test_a_commented_out_declaration_is_not_a_dependency(tmp_path: Path) -> None:
    """Both comment forms, including one wrapped around a live line."""
    dependencies = _parse(
        tmp_path,
        "dependencies {\n"
        '  // implementation("org.example:commented:1.0")\n'
        '  /* implementation("org.example:blocked:1.0") */\n'
        '  implementation("org.example:real:1.0")\n'
        "}\n",
    )

    assert set(dependencies) == {"org.example:real"}


# --- Routing ---------------------------------------------------------------


def test_both_build_script_names_route_to_the_gradle_parser(tmp_path: Path) -> None:
    """The registry matches manifest filenames exactly, so both need registering."""
    BaseParser._initialize_registry()
    for name in ("build.gradle", "build.gradle.kts"):
        path = tmp_path / name
        path.write_text("dependencies { }\n", encoding="utf-8")

        assert EcosystemRegistry.detect_ecosystem(path) == "gradle"
        assert isinstance(BaseParser.get_parser_for_file(str(path)), GradleParser)


def test_gradle_routes_to_the_maven_ecosystem_rather_than_a_tenth_entry() -> None:
    """Gradle is a build tool; the packages it names are Maven packages.

    An advisory against ``com.squareup.okio:okio`` does not become a different
    advisory because a Kotlin project declared it, so "gradle" is an alias onto
    the maven registry entry — one line — and every source's coverage comes with
    it. A new ``Ecosystem`` would have needed its own OSV name, its own GitHub
    Advisory name and its own CPE prefix, and getting any of them wrong is #66:
    a confident zero advisories.
    """
    resolved = ecosystems.resolve("gradle")

    assert resolved.key == "maven"
    assert resolved.osv == "Maven"
    assert resolved.purl_type == "maven"


def test_the_maven_analyzer_serves_gradle_dependencies() -> None:
    """The route the conformance case exercises end to end, asserted directly."""
    from dependency_risk_profiler.analyzers.base import BaseAnalyzer
    from dependency_risk_profiler.analyzers.maven import MavenAnalyzer

    assert isinstance(BaseAnalyzer.get_analyzer_for_ecosystem("gradle"), MavenAnalyzer)


# --- Catalog mechanics -----------------------------------------------------


@pytest.mark.parametrize(
    "alias,expected",
    [
        ("square-okio", "square.okio"),
        ("square_okio", "square.okio"),
        ("square.okio", "square.okio"),
        ("gradlePlugin-android", "gradlePlugin.android"),
    ],
)
def test_the_three_alias_separators_are_interchangeable(
    alias: str, expected: str
) -> None:
    """Gradle generates the same accessor for all three, so the lookup must too.

    Case is *not* folded: ``gradlePlugin-android`` generates
    ``libs.gradlePlugin.android``, and lowercasing would merge aliases Gradle
    keeps apart.
    """
    assert normalize_alias(alias) == expected


def test_the_catalog_search_walks_up_from_the_module(tmp_path: Path) -> None:
    """Gradle resolves the conventional catalog from the settings directory."""
    script = _write_project(tmp_path, "dependencies { }\n")

    found = find_version_catalog(script.parent)

    assert found == tmp_path / "gradle" / "libs.versions.toml"


def test_a_malformed_catalog_is_a_missing_one_not_a_crash(tmp_path: Path) -> None:
    """Untrusted input: an unparseable catalog degrades, it does not raise."""
    catalog = tmp_path / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir(parents=True)
    catalog.write_text("[versions\nbroken = ", encoding="utf-8")

    assert read_version_catalog(catalog) is None


def test_a_plugin_accessor_is_not_a_dependency(tmp_path: Path) -> None:
    """``libs.plugins.x`` names a Gradle plugin, not an artifact on the classpath."""
    dependencies = _parse(
        tmp_path, "dependencies {\n  implementation(libs.plugins.kotlin.jvm)\n}\n"
    )

    assert dependencies == {}
