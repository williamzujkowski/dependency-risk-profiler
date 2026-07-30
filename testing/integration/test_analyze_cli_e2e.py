"""End-to-end coverage for the active Typer analyze command."""

import json
import re
from pathlib import Path
from typing import Dict, List, Protocol, TypedDict

from typer.testing import CliRunner

from dependency_risk_profiler.cli.typer_cli import app
from dependency_risk_profiler.models import DependencyMetadata

runner = CliRunner()


class MonkeyPatchFixture(Protocol):
    """Subset of pytest's monkeypatch fixture used by these tests."""

    def setattr(self, target: str, value: object) -> None:
        """Set a dotted attribute path for the duration of a test."""


class DependencyPayload(TypedDict):
    """Dependency entry from analyze JSON output."""

    name: str


class AnalyzePayload(TypedDict):
    """Analyze JSON output fields asserted by these tests."""

    dependency_count: int
    dependencies: List[DependencyPayload]


class OfflineAnalyzer:
    """Analyzer test double that preserves parser output without network calls."""

    metadata_cache: Dict[str, Dict[str, object]] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Return dependencies unchanged."""
        return dependencies


def _patch_offline_analysis(monkeypatch: MonkeyPatchFixture) -> None:
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


def _dependency_count(output: str) -> int:
    match = re.search(r"Total dependencies analyzed:\s*(\d+)", output)
    assert match, output
    return int(match.group(1))


def _parse_analyze_payload(output: str) -> AnalyzePayload:
    decoded: object = json.loads(output)
    assert isinstance(decoded, dict), output

    dependency_count = decoded.get("dependency_count")
    dependencies = decoded.get("dependencies")
    assert isinstance(dependency_count, int), output
    assert isinstance(dependencies, list), output

    parsed_dependencies: List[DependencyPayload] = []
    for dependency in dependencies:
        assert isinstance(dependency, dict), output
        name = dependency.get("name")
        assert isinstance(name, str), output
        parsed_dependencies.append({"name": name})

    return {
        "dependency_count": dependency_count,
        "dependencies": parsed_dependencies,
    }


def test_analyze_requirements_reports_parsed_dependencies(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """Regression: timed parse success must continue into analyze/score/output."""
    _patch_offline_analysis(monkeypatch)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\nflask==2.0.0\n", encoding="utf-8")

    result = runner.invoke(
        app, ["analyze", str(requirements), "--disable-osv", "--no-color"]
    )

    assert result.exit_code == 0, result.output
    assert "Successfully analyzed: 1" in result.stdout
    assert _dependency_count(result.stdout) >= 2


def test_analyze_package_lock_v3_reports_parsed_dependencies(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """Regression: package-lock v3 dependencies must be analyzed, not dropped."""
    _patch_offline_analysis(monkeypatch)
    package_lock = tmp_path / "package-lock.json"
    package_lock.write_text(
        json.dumps(
            {
                "name": "demo-project",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {
                        "name": "demo-project",
                        "dependencies": {"left-pad": "1.3.0"},
                    },
                    "node_modules/left-pad": {"version": "1.3.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["analyze", str(package_lock), "--disable-osv", "--no-color"]
    )

    assert result.exit_code == 0, result.output
    assert "Successfully analyzed: 1" in result.stdout
    assert _dependency_count(result.stdout) >= 1


def test_analyze_json_stdout_is_valid_json_with_dependencies(
    tmp_path: Path, monkeypatch: MonkeyPatchFixture
) -> None:
    """JSON mode stdout should contain only the formatter payload."""
    _patch_offline_analysis(monkeypatch)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\nflask==2.0.0\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "analyze",
            str(requirements),
            "--output",
            "json",
            "--disable-osv",
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = _parse_analyze_payload(result.stdout)
    assert payload["dependency_count"] >= 2
    assert {dep["name"] for dep in payload["dependencies"]} >= {"requests", "flask"}
