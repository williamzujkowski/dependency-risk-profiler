"""A Python constraint is not an installed version (#275).

``requests>=2.20.0`` says the project accepts 2.20.0 *and everything after it*.
Until this change both Python readers wrote the bound into
``installed_version``, so that line produced a record byte-identical to
``requests==2.20.0``: the same ``known_vulnerable: true`` decided from four
advisories fixed in 2.20.1, and a version-drift signal reporting ``measured``
against a number nobody stated. ``billiard>=4.2.1,<5.0`` reported ``measured``
off the string ``"4.2.1,<5.0"``.

The assertions here are on **values**, not counts, because a count cannot tell
"always read correctly" from "always read wrong" — which is the whole of #145
and the reason AGENTS.md rule 6 says so out loud. Every one of them runs the
production parser and, for the scoring cases, the production
:class:`~dependency_risk_profiler.scoring.risk_scorer.RiskScorer` and
:func:`~dependency_risk_profiler.vulnerabilities.affected_ranges.evaluate_applicability`.
No double reimplements the subject.

Two fixture sets, kept apart on purpose (AGENTS.md rule 5)
----------------------------------------------------------
**Captured.** ``testing/fixtures/registry/python-manifests/`` holds four real,
published manifests, fetched by ``scripts/capture_registry_fixtures.py`` from
version-pinned URLs and provenance-dated: celery's compound constraints, httpx's
extras and marker-differentiated pins, django's PEP 621 tables, and warehouse's
``pip-compile --generate-hashes`` output. They were not written for this test
and do not know what it looks for. celery and django are where the defect
lived; httpx and warehouse are the control — 42 pins between them that must
survive a parser rewrite unchanged.

No captured manifest exercises PEP 503 name *folding*, and the first draft of
this file claimed one did: it asserted ``"zope.interface" not in states``
against warehouse's lockfile, which pip-compile had already normalized to
``zope-interface`` before it was ever committed. The assertion could not fail
and was removed rather than left to look like a gate. Folding is covered by the
``folded-name`` case in the authored set below, where the unnormalized spelling
is put in on purpose.

**Authored, and labelled as such.** The shapes below the captured section:
``!=``, ``===``, ``==1.2.*``, a name that is not a requirement at all. A
cooperating publisher does not ship these, so they cannot be captured, and
that is exactly the carve-out rule 5 makes for adversarial input.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple

import pytest
from registry_fixtures import load_fixture

from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.parsers.python import PythonParser
from dependency_risk_profiler.parsers.python_requirements import (
    DeclaredRequirement,
    read_requirement,
    requirement_lines,
)
from dependency_risk_profiler.parsers.toml import TomlParser
from dependency_risk_profiler.parsers.version_sources import (
    DECLARED_CONSTRAINT_KEY,
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
    VERSION_SOURCE_UNMANAGED,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import SIGNAL_VERSION, MeasurementState
from dependency_risk_profiler.vulnerabilities.affected_ranges import (
    AffectedRange,
    AffectedVersions,
    Applicability,
    VersionConstraint,
    VersionScheme,
    evaluate_applicability,
)

# --- Helpers ---------------------------------------------------------------


def _materialize(fixture_name: str, file_name: str, tmp_path: Path) -> Path:
    """Write one captured manifest to disk under the name its reader expects.

    The parser dispatches on the file name, so the fixture has to land as
    ``requirements.txt`` or ``pyproject.toml`` rather than as its fixture id.

    Args:
        fixture_name: The fixture id declared in the fixture manifest.
        file_name: The name the parser routes on.
        tmp_path: pytest's per-test directory.

    Returns:
        The path the manifest was written to.
    """
    fixture = load_fixture("python-manifests", fixture_name)
    assert isinstance(fixture.payload, str), (
        f"{fixture.slug} is declared as text; a non-string payload means the "
        "capture format changed"
    )
    directory = tmp_path / fixture_name
    directory.mkdir()
    path = directory / file_name
    path.write_text(fixture.payload, encoding="utf-8")
    return path


def _states(
    dependencies: Dict[str, DependencyMetadata],
) -> Dict[str, Tuple[str, str, str]]:
    """Reduce a parse to the three facts #275 is about, per dependency.

    Args:
        dependencies: What a parser returned.

    Returns:
        ``name -> (installed_version, version_source, declared_constraint)``,
        with the empty string standing for an absent constraint.
    """
    return {
        name: (
            metadata.installed_version,
            metadata.additional_info.get(VERSION_SOURCE_KEY, ""),
            metadata.additional_info.get(DECLARED_CONSTRAINT_KEY, ""),
        )
        for name, metadata in dependencies.items()
    }


# --- 1. Captured manifests -------------------------------------------------


def test_celerys_compound_constraints_name_no_installed_version(
    tmp_path: Path,
) -> None:
    """celery pins nothing, and the tool no longer pretends otherwise.

    Every line in ``requirements/default.txt`` is a range. The old reader wrote
    ``billiard -> "4.2.1,<5.0"`` and ``vine -> "5.1.0,<6.0"`` into
    ``installed_version`` and scored drift against them; ``click-didyoumean``
    and friends became the sentinel string ``latest``, which then rendered as
    ``latest → 0.3.1 · behind latest``.
    """
    path = _materialize("celery.default.txt", "requirements.txt", tmp_path)

    states = _states(PythonParser(str(path)).parse())

    assert states["billiard"] == ("", VERSION_SOURCE_UNMANAGED, "<5.0,>=4.2.1")
    assert states["vine"] == ("", VERSION_SOURCE_UNMANAGED, "<6.0,>=5.1.0")
    assert states["click"] == ("", VERSION_SOURCE_UNMANAGED, "<9.0,>=8.1.2")
    assert states["click-didyoumean"] == ("", VERSION_SOURCE_UNMANAGED, ">=0.3.0")
    assert states["python-dateutil"] == ("", VERSION_SOURCE_UNMANAGED, ">=2.8.2")
    # Not one line in this file states a version, so not one installed version
    # comes out of it.
    assert {installed for installed, _, _ in states.values()} == {""}
    assert {source for _, source, _ in states.values()} == {VERSION_SOURCE_UNMANAGED}


def test_httpxs_extras_and_markers_resolve_to_the_project_and_the_pin(
    tmp_path: Path,
) -> None:
    """httpx is the control: 15 pins that a parser rewrite must not disturb.

    Two shapes here are the ones the old chain mangled. ``coverage[toml]``
    reached PyPI as a project literally named ``coverage[toml]``, found
    nothing, and landed UNKNOWN with 2 of 15 signals — the only unscored
    dependency in the file. And ``-e .[brotli,cli,http2,socks,zstd]`` is an
    editable install of the project itself, which names no dependency.
    """
    path = _materialize("httpx.requirements.txt", "requirements.txt", tmp_path)

    dependencies = PythonParser(str(path)).parse()
    states = _states(dependencies)

    assert "coverage[toml]" not in states
    assert states["coverage"] == ("7.6.1", VERSION_SOURCE_DECLARED, "")
    assert states["cryptography"] == ("44.0.0", VERSION_SOURCE_DECLARED, "")
    assert states["build"] == ("1.2.2.post1", VERSION_SOURCE_DECLARED, "")
    # The editable self-install names no package and contributes none.
    assert not [name for name in states if name.startswith("-")]
    assert "." not in states
    # Every entry in this file is an `==` pin, so every one carries a version.
    assert "" not in {installed for installed, _, _ in states.values()}
    assert {source for _, source, _ in states.values()} == {VERSION_SOURCE_DECLARED}


def test_httpx_keeps_the_last_of_two_marker_differentiated_pins(
    tmp_path: Path,
) -> None:
    """A finding, recorded rather than smoothed over.

    httpx declares ``trustme==1.1.0; python_version < '3.9'`` and
    ``trustme==1.2.0; python_version >= '3.9'``. The parser returns a mapping
    keyed by name, so the second entry replaces the first and 1.1.0 is lost.
    That is pre-existing and out of #275's scope: this test states the current
    behaviour so a later marker-aware change has to come past it deliberately
    rather than by accident.
    """
    path = _materialize("httpx.requirements.txt", "requirements.txt", tmp_path)

    states = _states(PythonParser(str(path)).parse())

    assert states["trustme"] == ("1.2.0", VERSION_SOURCE_DECLARED, "")


def test_djangos_pyproject_tables_all_state_bounds_and_none_a_version(
    tmp_path: Path,
) -> None:
    """django's own manifest, across three PEP 621 tables.

    ``asgiref>=3.8.1`` and ``sqlparse>=0.5.0`` used to score with
    ``signals.version.state == "measured"`` and report
    ``known_vulnerable: true`` off advisories the advisory layer had already
    marked incomparable. ``tzdata; sys_platform == 'win32'`` arrived as a
    dependency named ``tzdata; sys_platform`` at version ``=='win32'``, which
    is no part of either.
    """
    path = _materialize("django.pyproject.toml", "pyproject.toml", tmp_path)

    dependencies = TomlParser(str(path)).parse()
    states = _states(dependencies)

    assert states["asgiref"] == ("", VERSION_SOURCE_UNMANAGED, ">=3.8.1")
    assert states["sqlparse"] == ("", VERSION_SOURCE_UNMANAGED, ">=0.3.1")
    # A marker is severed from the name and the dependency is kept. It states
    # no version, so it carries none and no constraint either.
    assert states["tzdata"] == ("", VERSION_SOURCE_UNMANAGED, "")
    assert "tzdata; sys_platform" not in states
    # build-system.requires is PEP 508 too, and reads the same way.
    assert states["setuptools"] == ("", VERSION_SOURCE_UNMANAGED, "<69.3.0,>=61.0.0")
    assert (
        dependencies["setuptools"].additional_info["section"] == "build-system.requires"
    )
    # project.optional-dependencies, including a bare name with no specifier.
    assert states["argon2-cffi"] == ("", VERSION_SOURCE_UNMANAGED, ">=19.1.0")
    assert states["bcrypt"] == ("", VERSION_SOURCE_UNMANAGED, "")
    assert "latest" not in {installed for installed, _, _ in states.values()}


def test_a_pip_compile_lockfile_still_pins_every_one_of_its_packages(
    tmp_path: Path,
) -> None:
    """The case that must not regress, and the one nothing used to read.

    ``pip-compile --generate-hashes`` writes ``pkg==1.2.3 \\`` followed by
    indented ``--hash=sha256:…`` continuation lines. Read one line at a time
    that yields an installed version of ``"1.2.3 \\"`` and one dependency named
    ``--hash=sha256`` per hash in the file. This is the most thoroughly pinned
    manifest Python has, and it is the one where a version genuinely is known.
    """
    path = _materialize("warehouse.dev.txt", "requirements.txt", tmp_path)

    states = _states(PythonParser(str(path)).parse())

    assert states["pyramid"] == ("2.1", VERSION_SOURCE_DECLARED, "")
    assert states["packaging"] == ("26.2", VERSION_SOURCE_DECLARED, "")
    assert states["zope-interface"] == ("8.5", VERSION_SOURCE_DECLARED, "")
    # Not one hash line, comment, or `--option` became a package.
    assert not [name for name in states if name.startswith(("-", "#"))]
    assert {source for _, source, _ in states.values()} == {VERSION_SOURCE_DECLARED}
    assert "" not in {installed for installed, _, _ in states.values()}


# --- 2. Authored adversarial shapes ----------------------------------------
#
# Hostile and malformed input, which no cooperating publisher ships and which
# therefore cannot be captured. Kept apart from the captured set above and
# labelled here, per AGENTS.md rule 5's explicit carve-out.


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # The four shapes the old operator-scan chain got wrong outright.
        ("requests!=2.0", DeclaredRequirement("requests", None, "!=2.0")),
        (
            'requests; python_version < "3.9"',
            DeclaredRequirement("requests", None, None),
        ),
        ("coverage[toml]==7.10.6", DeclaredRequirement("coverage", "7.10.6", None)),
        ("tzlocal", DeclaredRequirement("tzlocal", None, None)),
        # A prefix match names a family, not a member of it.
        ("pkg==1.2.*", DeclaredRequirement("pkg", None, "==1.2.*")),
        # `===` matches its operand as a literal string. When the operand is a
        # version it pins; when it is not, there is nothing to compare.
        ("pkg===1.2.3", DeclaredRequirement("pkg", "1.2.3", None)),
        ("pkg===fixture-build", DeclaredRequirement("pkg", None, "===fixture-build")),
        # A local version is still one version.
        ("torch==2.0.0+cu118", DeclaredRequirement("torch", "2.0.0+cu118", None)),
        # More than one clause admits more than one version, even when one of
        # them is an equality.
        ("pkg==1.0,!=1.0.post1", DeclaredRequirement("pkg", None, "!=1.0.post1,==1.0")),
        # PEP 503 folding of the name, with the extras and the marker gone.
        (
            'Zope.Interface[test]>=5; sys_platform == "win32"',
            DeclaredRequirement("zope-interface", None, ">=5"),
        ),
        # A direct reference. The filename carries something version-shaped;
        # reading it would be a guess about a naming convention.
        (
            "foo @ https://example.invalid/foo-1.0.tar.gz",
            DeclaredRequirement("foo", None, "https://example.invalid/foo-1.0.tar.gz"),
        ),
    ],
    ids=[
        "not-equal",
        "bare-with-marker",
        "extras-pin",
        "bare",
        "prefix-match",
        "arbitrary-equality-version",
        "arbitrary-equality-nonversion",
        "local-version",
        "two-clauses",
        "folded-name",
        "direct-reference",
    ],
)
def test_adversarial_requirement_shapes_read_to_a_pin_or_a_constraint(
    line: str, expected: DeclaredRequirement
) -> None:
    """AUTHORED FIXTURE. Each shape lands as a pin or as a constraint, never both."""
    assert read_requirement(line) == expected


@pytest.mark.parametrize(
    "line",
    ["", "==1.0", "[extras]", "@ https://example.invalid/x.tar.gz", "!!!"],
    ids=["empty", "operator-only", "extras-only", "url-only", "punctuation"],
)
def test_an_unreadable_line_names_no_package(line: str) -> None:
    """AUTHORED FIXTURE. A line pip rejects does not become a dependency.

    The old chain named a package after whatever survived a regex substitution,
    which is how ``requests-toolbelt!`` reached a PyPI lookup.
    """
    assert read_requirement(line) is None


def test_a_declared_requirement_cannot_hold_a_pin_and_a_constraint_at_once() -> None:
    """AUTHORED FIXTURE. Rule 4, enforced at construction rather than by habit.

    ``Measurement`` makes a value-without-a-measurement unrepresentable; this
    makes a bound-in-the-version-slot unrepresentable the same way.
    """
    with pytest.raises(ValueError, match="must not also carry a constraint"):
        DeclaredRequirement(name="pkg", pinned_version="1.0", constraint=">=1.0")

    with pytest.raises(ValueError, match="is not a version"):
        DeclaredRequirement(name="pkg", pinned_version=">=1.0", constraint=None)

    with pytest.raises(ValueError, match="must name a project"):
        DeclaredRequirement(name="", pinned_version=None, constraint=None)


def test_requirement_lines_drops_options_comments_and_joins_continuations() -> None:
    """AUTHORED FIXTURE. The file grammar, separately from the requirement grammar."""
    text = (
        "# a leading comment\n"
        "-r other.txt\n"
        "--index-url https://example.invalid/simple\n"
        "requests==2.32.5 \\\n"
        "    --hash=sha256:aaaa \\\n"
        "    --hash=sha256:bbbb\n"
        "flask==1.0  # trailing comment\n"
        "\n"
        "-e .[dev]\n"
    )

    assert requirement_lines(text) == ["requests==2.32.5", "flask==1.0"]


def test_a_pipfile_lock_star_is_not_a_version(tmp_path: Path) -> None:
    """AUTHORED FIXTURE. ``"*"`` is the ``latest`` sentinel wearing a lock file.

    Pipfile.lock is where a pin is expected, and most entries are one. An entry
    pinned by ``git``/``ref`` instead records ``"*"``, and an editable entry may
    carry no ``version`` key at all. Neither names a version.
    """
    path = tmp_path / "Pipfile.lock"
    path.write_text(
        '{"default": {"requests": {"version": "==2.28.0"},'
        ' "wildcard": "*",'
        ' "ranged": {"version": ">=1.0"},'
        ' "vcs": {"git": "https://example.invalid/x.git", "ref": "abc"}},'
        ' "develop": {"pytest": {"version": "==7.0.0"}}}',
        encoding="utf-8",
    )

    states = _states(PythonParser(str(path)).parse())

    assert states["requests"] == ("2.28.0", VERSION_SOURCE_DECLARED, "")
    assert states["pytest"] == ("7.0.0", VERSION_SOURCE_DECLARED, "")
    assert states["wildcard"] == ("", VERSION_SOURCE_UNMANAGED, "*")
    assert states["ranged"] == ("", VERSION_SOURCE_UNMANAGED, ">=1.0")
    assert states["vcs"] == ("", VERSION_SOURCE_UNMANAGED, "")


def test_the_two_python_readers_agree_on_the_same_requirement(
    tmp_path: Path,
) -> None:
    """AUTHORED FIXTURE. One ecosystem, one reading.

    ``parsers/python.py`` stripped the operator (``"3.12.1"``) and
    ``parsers/toml.py`` kept it (``">=3.12.1"``), so the same declaration
    produced two different wrong answers depending on which file it was written
    in. Both now go through ``read_requirement``.
    """
    lines = ["asgiref>=3.12.1", "coverage[toml]==7.10.6", "tzlocal"]

    requirements = tmp_path / "requirements.txt"
    requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")

    pyproject = tmp_path / "pyproject.toml"
    entries = ", ".join(f'"{line}"' for line in lines)
    pyproject.write_text(
        f"[project]\nname = 'x'\ndependencies = [{entries}]\n", encoding="utf-8"
    )

    from_requirements = _states(PythonParser(str(requirements)).parse())
    from_pyproject = _states(TomlParser(str(pyproject)).parse())

    assert from_requirements == from_pyproject
    assert from_requirements["asgiref"] == ("", VERSION_SOURCE_UNMANAGED, ">=3.12.1")


# --- 3. What the scorer and the advisory layer then do ---------------------


def _score(installed_version: str, latest_version: str) -> DependencyRiskScore:
    """Score one dependency through the production scorer.

    Args:
        installed_version: What the parser produced.
        latest_version: What the registry reported.

    Returns:
        The scored dependency.
    """
    dependency = DependencyMetadata(
        name="requests",
        installed_version=installed_version,
        latest_version=latest_version,
        last_updated=datetime.now(timezone.utc) - timedelta(days=10),
    )
    return RiskScorer().score_dependency(dependency)


def test_an_unpinned_requirement_leaves_version_drift_unmeasured() -> None:
    """The signal that made this a leading indicator, reported honestly.

    Not a lower value and not a zero: absent from both the numerator and the
    denominator, which is the #74 contract NuGet, Maven and Gradle already get
    for an unresolved version.
    """
    unpinned = _score("", "2.34.2")
    pinned = _score("2.20.0", "2.34.2")

    assert unpinned.measurements[SIGNAL_VERSION].state is MeasurementState.UNMEASURED
    assert unpinned.measurements[SIGNAL_VERSION].value is None
    assert SIGNAL_VERSION in unpinned.unknown_signals

    # The pinned case is untouched: still measured, still carrying its value.
    assert pinned.measurements[SIGNAL_VERSION].state is MeasurementState.MEASURED
    assert pinned.measurements[SIGNAL_VERSION].value == 0.5
    assert SIGNAL_VERSION not in pinned.unknown_signals
    assert pinned.measured_signal_count == unpinned.measured_signal_count + 1


def test_an_advisory_against_an_unpinned_requirement_is_unknown_not_decided() -> None:
    """AC 3, and where the brief's expectation and the tool's contract part.

    CVE-2018-18074 affects ``requests < 2.20.0`` and is fixed in 2.20.0. Handed
    the bound ``>=2.20.0`` as though it were an installed version, the matcher
    used to answer NOT_AFFECTED or AFFECTED with confidence depending on which
    advisory it was. It now answers UNKNOWN with ``installed version unknown``,
    which is the same verdict the NuGet path already produced for an
    unresolvable ``$(Property)`` version.

    The advisory is still *counted* — that is #61's deliberate fail-closed
    call, and it is why ``known_vulnerable`` stays true. What changed is the
    claim behind it: from "you are running an affected version" to "nobody
    stated a version, so this could not be decided".
    """
    affected = AffectedVersions(
        ranges=(
            AffectedRange(
                constraints=(VersionConstraint(operator="<", version="2.20.0"),)
            ),
        )
    )

    unpinned = evaluate_applicability(affected, "", VersionScheme.PEP440)
    assert unpinned.status is Applicability.UNKNOWN
    assert unpinned.reason == "installed version unknown"

    # A pin still decides, in both directions.
    assert (
        evaluate_applicability(affected, "2.19.1", VersionScheme.PEP440).status
        is Applicability.AFFECTED
    )
    assert (
        evaluate_applicability(affected, "2.32.5", VersionScheme.PEP440).status
        is Applicability.NOT_AFFECTED
    )
