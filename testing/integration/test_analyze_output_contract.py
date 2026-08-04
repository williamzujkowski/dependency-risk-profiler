"""The output contract `analyze` owes its callers.

Two invariants live here, both of them about a run that *succeeded* still being
usable by the thing that ran it:

* **#147** — if the process exits 0 in JSON mode, stdout is parseable JSON.
  Not "usually", not "when there were dependencies": always. The test is written
  as a sweep over every path that can end a run early, because the original bug
  was one such path emitting nothing at all.
* **#125** — a refused manifest names a next step, and a run that scored nothing
  because it refused everything does not exit 0.

The empty-directory case deliberately keeps exit 0 (#20, #68): "nothing to do"
and "I would not accept what you gave me" are different outcomes.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Protocol, Tuple

import pytest
from typer.testing import CliRunner

from dependency_risk_profiler.cli.typer_cli import app
from dependency_risk_profiler.models import DependencyMetadata


def _make_runner() -> CliRunner:
    """Return a runner whose ``stdout`` really is stdout.

    The invariant under test is about stdout alone, so the streams must stay
    apart. Click below 8.2 folds stderr into stdout unless told not to; 8.2
    removed the flag and always separates them. Without this, the Python 3.9
    job saw the status lines that correctly went to stderr and reported them as
    JSON corruption.
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


runner = _make_runner()

# The keys an automated consumer is promised on every JSON run.
# `unreadable_manifests` is here rather than only on the paths that populate it:
# a key that appears only when it is non-empty cannot be branched on, because
# its absence would mean both "nothing went unread" and "old version" (#243).
REQUIRED_KEYS = {
    "manifest_path",
    "ecosystem",
    "scan_time",
    "dependency_count",
    "dependencies",
    "overall_risk_score",
    "manifests",
    "unreadable_manifests",
    "warnings",
}


class MonkeyPatchFixture(Protocol):
    """Subset of pytest's monkeypatch fixture used by these tests."""

    def setattr(self, target: str, value: object) -> None:
        """Set a dotted attribute path for the duration of a test."""


class OfflineAnalyzer:
    """Analyzer test double that preserves parser output without network calls."""

    metadata_cache: Dict[str, Dict[str, object]] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Return dependencies unchanged."""
        return dependencies


def _patch_offline_analysis(monkeypatch: MonkeyPatchFixture) -> None:
    """Keep the CLI off the network so these tests measure output, not lookups."""

    def get_offline_analyzer(ecosystem: str) -> OfflineAnalyzer:
        return OfflineAnalyzer()

    def analyze_transitive_dependencies(
        dependencies: Dict[str, DependencyMetadata], manifest_path: str
    ) -> Dict[str, DependencyMetadata]:
        return dependencies

    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.BaseAnalyzer.get_analyzer_for_ecosystem",
        get_offline_analyzer,
    )
    monkeypatch.setattr(
        (
            "dependency_risk_profiler.transitive.analyzer_enhanced."
            "analyze_transitive_dependencies_enhanced"
        ),
        analyze_transitive_dependencies,
    )


PACKAGE_LOCK = json.dumps(
    {
        "name": "demo-project",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo-project", "dependencies": {"left-pad": "1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0"},
        },
    },
    indent=2,
)


def _build_cases(root: Path) -> List[Tuple[str, Path]]:
    """Create one directory per early-return path and return (id, target) pairs."""
    cases: List[Tuple[str, Path]] = []

    empty_dir = root / "empty-dir"
    empty_dir.mkdir()
    cases.append(("no-manifests", empty_dir))

    unsupported = root / "unsupported"
    unsupported.mkdir()
    (unsupported / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.13.4"}}), encoding="utf-8"
    )
    cases.append(("unsupported-manifest", unsupported / "package.json"))

    with_companion = root / "with-companion"
    with_companion.mkdir()
    (with_companion / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.13.4"}}), encoding="utf-8"
    )
    (with_companion / "package-lock.json").write_text(PACKAGE_LOCK, encoding="utf-8")
    cases.append(("unsupported-with-companion", with_companion / "package.json"))

    misnamed = root / "misnamed"
    misnamed.mkdir()
    (misnamed / "project-Gemfile.lock").write_text(
        "GEM\n  specs:\n    rake (13.0.6)\n", encoding="utf-8"
    )
    cases.append(("misnamed-manifest", misnamed / "project-Gemfile.lock"))

    no_deps = root / "no-deps"
    no_deps.mkdir()
    (no_deps / "requirements.txt").write_text(
        "# nothing pinned here\n", encoding="utf-8"
    )
    cases.append(("manifest-with-no-dependencies", no_deps / "requirements.txt"))

    single = root / "single"
    single.mkdir()
    (single / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    cases.append(("single-manifest", single / "requirements.txt"))

    multiple = root / "multiple"
    multiple.mkdir()
    (multiple / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (multiple / "package-lock.json").write_text(PACKAGE_LOCK, encoding="utf-8")
    cases.append(("directory-of-manifests", multiple))

    # A directory where every manifest is refused: nothing to score, and the
    # reason is refusal rather than absence.
    all_refused = root / "all-refused"
    all_refused.mkdir()
    (all_refused / "pom.xml").write_text("this is not xml at all", encoding="utf-8")
    cases.append(("directory-of-refused-manifests", all_refused))

    return cases


# Rich hard-wraps to the terminal width, so a guidance sentence arrives with
# newlines inside it. Widen the console and flatten whitespace before asserting
# on prose; the wrapping is presentation, not content.
WIDE_TERMINAL = {"COLUMNS": "400"}


def _flat(text: str) -> str:
    """Collapse rich's line wrapping so prose assertions test the message."""
    return " ".join(text.split())


def _run_json(target: Path, *, recursive: bool = False) -> Tuple[int, object]:
    """Run analyze in JSON mode and return (exit code, parsed stdout)."""
    argv = ["analyze", str(target), "--output", "json", "--disable-osv", "--no-color"]
    if recursive:
        argv.append("--recursive")
    result = runner.invoke(app, argv)
    assert result.stdout, (
        f"JSON mode wrote nothing to stdout for {target}; "
        f"exit={result.exit_code}\n{result.output}"
    )
    return result.exit_code, json.loads(result.stdout)


def test_json_mode_always_writes_one_parseable_document(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """INVARIANT (#147): every analyze path emits exactly one JSON document.

    Swept across every early-return path rather than checked on one of them,
    because the defect was a path that returned before writing anything.
    """
    _patch_offline_analysis(monkeypatch)

    for case_id, target in _build_cases(tmp_path):
        exit_code, payload = _run_json(target)
        assert isinstance(payload, dict), case_id
        assert REQUIRED_KEYS <= set(
            payload
        ), f"{case_id}: missing {REQUIRED_KEYS - set(payload)}"
        assert isinstance(payload["dependencies"], list), case_id
        assert isinstance(payload["warnings"], list), case_id
        assert isinstance(payload["manifests"], list), case_id
        assert payload["dependency_count"] == len(payload["dependencies"]), case_id
        # An exit code is allowed to be non-zero; silence on stdout is not.
        assert exit_code in (0, 1), f"{case_id}: unexpected exit {exit_code}"


def test_json_mode_on_empty_directory_is_a_successful_empty_document(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """REGRESSION (#147): the original 0-byte case. Exit 0, and still parseable."""
    _patch_offline_analysis(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()

    exit_code, payload = _run_json(empty)

    assert exit_code == 0
    assert isinstance(payload, dict)
    assert payload["dependency_count"] == 0
    assert payload["dependencies"] == []
    assert payload["ecosystem"] is None
    # Not 0.0: nothing was measured, and 0.0 would read as "perfectly safe".
    assert payload["overall_risk_score"] is None
    assert payload["warnings"] == ["No supported manifest files found"]


def test_json_mode_over_several_manifests_is_one_document_not_a_concatenation(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """REGRESSION (#147): a directory scan used to print N documents back to back."""
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (project / "package-lock.json").write_text(PACKAGE_LOCK, encoding="utf-8")

    exit_code, payload = _run_json(project)

    assert exit_code == 0
    assert isinstance(payload, dict)
    assert payload["dependency_count"] >= 2
    manifests = payload["manifests"]
    assert isinstance(manifests, list)
    assert len(manifests) == 2
    # Mixed ecosystems have no single answer, so the field says so.
    assert payload["ecosystem"] is None


@pytest.mark.parametrize(
    "companion_present",
    [False, True],
    ids=["companion-missing", "companion-present"],
)
def test_unsupported_manifest_names_its_resolved_companion(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture, companion_present: bool
) -> None:
    """REGRESSION (#125): 'Unsupported manifest file' must name the next step."""
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    manifest = project / "package.json"
    manifest.write_text(
        json.dumps({"dependencies": {"express": "^4.13.4"}}), encoding="utf-8"
    )
    if companion_present:
        (project / "package-lock.json").write_text(PACKAGE_LOCK, encoding="utf-8")

    result = runner.invoke(
        app, ["analyze", str(manifest), "--no-color"], env=WIDE_TERMINAL
    )
    output = _flat(result.output)

    assert "package-lock.json" in output
    assert "declares version ranges, not resolved versions" in output
    if companion_present:
        assert "found alongside it" in output
    else:
        assert "not found in" in output
    # Nothing was scored because the only input was refused.
    assert result.exit_code == 1, result.output


def test_manifest_under_a_nonstandard_name_names_the_parser_that_would_accept_it(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """REGRESSION (#125 comment): same bytes, wrong filename, silent rejection."""
    _patch_offline_analysis(monkeypatch)
    manifest = tmp_path / "railsgoat-Gemfile.lock"
    manifest.write_text("GEM\n  specs:\n    rake (13.0.6)\n", encoding="utf-8")

    result = runner.invoke(
        app, ["analyze", str(manifest), "--no-color"], env=WIDE_TERMINAL
    )
    output = _flat(result.output)

    assert "matches manifest filenames exactly" in output
    assert "rubygems parser" in output
    assert "Rename or copy it to Gemfile.lock" in output
    assert result.exit_code == 1, result.output


def test_real_process_stdout_is_json_on_the_paths_that_need_no_network(
    tmp_path: Path,
) -> None:
    """INVARIANT (#147), measured on a real process rather than a test runner.

    `CliRunner` has folded stderr into stdout depending on the click version,
    which is exactly the confusion this invariant exists to rule out. These
    three paths reach no registry and no network, so they can be run for real:
    whatever a subprocess sees on fd 1 is what an agent would see.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    unsupported = tmp_path / "package.json"
    unsupported.write_text(
        json.dumps({"dependencies": {"express": "^4.13.4"}}), encoding="utf-8"
    )
    misnamed = tmp_path / "project-Gemfile.lock"
    misnamed.write_text("GEM\n  specs:\n    rake (13.0.6)\n", encoding="utf-8")

    for target in (empty, unsupported, misnamed):
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "dependency_risk_profiler",
                "analyze",
                str(target),
                "--output",
                "json",
                "--disable-osv",
                "--no-color",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        payload = json.loads(completed.stdout)
        assert isinstance(payload, dict), target
        assert REQUIRED_KEYS <= set(payload), target
        assert payload["dependencies"] == [], target


def test_empty_directory_still_exits_zero(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """GUARD (#20, #68): 'nothing to do' is not the same as 'I refused you'."""
    _patch_offline_analysis(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()

    result = runner.invoke(app, ["analyze", str(empty), "--no-color"])

    assert result.exit_code == 0, result.output


def test_manifest_declaring_no_dependencies_still_exits_zero(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """GUARD: a manifest that parsed fine and declares nothing is not a refusal."""
    _patch_offline_analysis(monkeypatch)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("# no pins here\n", encoding="utf-8")

    result = runner.invoke(app, ["analyze", str(requirements), "--no-color"])

    assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# #243: a scan that read nothing is not a scan that found nothing
# ---------------------------------------------------------------------------


def test_a_directory_of_only_unreadable_manifests_is_not_a_clean_zero(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """REGRESSION (#243): the silent zero. `package.json` only, exit 0, no deps.

    A project whose npm half the tool could not read reported the same thing as
    a project with no dependencies: `dependency_count: 0`, an empty
    `dependencies` list, and exit 0. That reads as "nothing to worry about"
    when the truth is "I could not read your project".
    """
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.2"}}), encoding="utf-8"
    )

    exit_code, payload = _run_json(project)

    assert isinstance(payload, dict)
    # The exit code is the half a shell script sees.
    assert exit_code == 1
    # The structural half: a key a consumer can branch on, distinct from
    # dependency_count, that says a manifest went unread.
    unreadable = payload["unreadable_manifests"]
    assert isinstance(unreadable, list)
    assert len(unreadable) == 1
    entry = unreadable[0]
    assert entry["manifest_path"] == str(project / "package.json")
    assert entry["ecosystem"] == "npm"
    assert "package-lock.json" in entry["guidance"]


def test_an_empty_directory_reports_nothing_unread(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """INVARIANT (#243): the other side of the distinction, asserted on values.

    An empty directory and a directory of unreadable manifests must not
    serialize the same. Both carry `dependency_count: 0`; only one carries an
    empty `unreadable_manifests`, and only one exits 0.
    """
    _patch_offline_analysis(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()

    exit_code, payload = _run_json(empty)

    assert isinstance(payload, dict)
    assert exit_code == 0
    assert payload["dependency_count"] == 0
    assert payload["unreadable_manifests"] == []


def test_the_terminal_summary_says_what_it_could_not_read(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """REGRESSION (#243): 'No supported manifest files found' named no next step.

    The human output said the same thing for an empty directory and for an npm
    project, and then listed every supported ecosystem — which is a catalogue,
    not an answer to "what do I do about this file".
    """
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.2"}}), encoding="utf-8"
    )

    result = runner.invoke(
        app, ["analyze", str(project), "--recursive", "--no-color"], env=WIDE_TERMINAL
    )
    output = _flat(result.output)

    assert result.exit_code == 1, result.output
    assert "look like dependency manifests but could not be read" in output
    assert "npm projects are read from package-lock.json" in output
    assert "Run `npm install` to generate one." in output
    assert "Analyzed 0 of 1 manifest file(s); nothing was scored." in output


def test_a_partly_readable_directory_still_names_the_unread_half(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """HYPOTHESIS (#243): scoring something does not license silence about the rest.

    Exit stays 0 — the run did produce a real answer — but the answer covers
    only the Python half, and the report says which half it is rather than
    letting the npm dependencies read as absent.
    """
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.2"}}), encoding="utf-8"
    )

    exit_code, payload = _run_json(project)

    assert isinstance(payload, dict)
    assert exit_code == 0
    assert payload["dependency_count"] >= 1
    unreadable = payload["unreadable_manifests"]
    assert isinstance(unreadable, list)
    assert [entry["ecosystem"] for entry in unreadable] == ["npm"]


def test_a_package_json_beside_its_lock_file_is_not_reported_as_unread(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """GUARD (#243): a warning that fires on healthy projects stops being read.

    The npm dependencies were read — from the lock file sitting right there —
    so the range-declaring sibling is not a gap in coverage and must not be
    reported as one.
    """
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "^1.3.0"}}), encoding="utf-8"
    )
    (project / "package-lock.json").write_text(PACKAGE_LOCK, encoding="utf-8")

    exit_code, payload = _run_json(project)

    assert isinstance(payload, dict)
    assert exit_code == 0
    assert payload["unreadable_manifests"] == []
    assert payload["dependency_count"] >= 1


def test_installed_dependencies_are_not_reported_as_unreadable_manifests(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """GUARD (#243): node_modules holds one package.json per installed package.

    Recognizing `package.json` without pruning vendored directories turns a
    recursive scan of any real npm project into thousands of warnings, which is
    a different way of telling the user nothing. Run with `--recursive`, because
    that is the only mode that descends far enough to hit the problem.
    """
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    for package in ("left-pad", "express", "lodash"):
        installed = project / "node_modules" / package
        installed.mkdir(parents=True)
        (installed / "package.json").write_text(
            json.dumps({"name": package, "version": "1.0.0"}), encoding="utf-8"
        )

    exit_code, payload = _run_json(project, recursive=True)

    assert isinstance(payload, dict)
    assert exit_code == 0
    assert payload["unreadable_manifests"] == []


def test_a_single_refused_file_reports_itself_as_unread_in_json(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """INVARIANT (#243): exit 1 and an empty unread list is a self-contradiction.

    `analyze package.json` already exited 1 (#125). Its JSON still said no
    manifest went unread, so a consumer reading the document alone saw a clean
    zero — the same defect as the directory case, one path over.
    """
    _patch_offline_analysis(monkeypatch)
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps({"dependencies": {"express": "^4.18.2"}}), encoding="utf-8"
    )

    exit_code, payload = _run_json(manifest)

    assert isinstance(payload, dict)
    assert exit_code == 1
    unreadable = payload["unreadable_manifests"]
    assert isinstance(unreadable, list)
    assert [entry["manifest_path"] for entry in unreadable] == [str(manifest)]


def test_an_unsupported_ecosystem_says_so_rather_than_scoring_zero(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """HYPOTHESIS (#243): a Scala project has dependencies; this tool reads none.

    "You have no dependencies" and "I do not read sbt" are different answers,
    and only one of them is true here.
    """
    _patch_offline_analysis(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "build.sbt").write_text(
        'libraryDependencies += "org.typelevel" %% "cats-core" % "2.10.0"\n',
        encoding="utf-8",
    )

    exit_code, payload = _run_json(project)

    assert isinstance(payload, dict)
    assert exit_code == 1
    unreadable = payload["unreadable_manifests"]
    assert isinstance(unreadable, list)
    assert [entry["ecosystem"] for entry in unreadable] == ["Scala (sbt)"]
    assert "list-ecosystems" in unreadable[0]["guidance"]
