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
REQUIRED_KEYS = {
    "manifest_path",
    "ecosystem",
    "scan_time",
    "dependency_count",
    "dependencies",
    "overall_risk_score",
    "manifests",
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


def _run_json(target: Path) -> Tuple[int, object]:
    """Run analyze in JSON mode and return (exit code, parsed stdout)."""
    result = runner.invoke(
        app,
        ["analyze", str(target), "--output", "json", "--disable-osv", "--no-color"],
    )
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
