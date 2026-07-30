"""Regression tests for parser and analyzer routing correctness."""

from pathlib import Path
from typing import Dict

from _pytest.monkeypatch import MonkeyPatch

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.crates import CratesIOAnalyzer
from dependency_risk_profiler.analyzers.python import PythonAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.parsers.golang import GoParser


class StubCratesIOAnalyzer(CratesIOAnalyzer):
    """Crates analyzer test double with an in-memory crates.io response."""

    def _get_crate_info(self, crate_name: str) -> Dict[str, object]:
        """Return deterministic crates.io metadata without network calls."""
        return {
            "crate": {
                "name": crate_name,
                "max_version": "1.0.200",
                "repository": f"https://github.com/example/{crate_name}",
                "license": "MIT OR Apache-2.0",
            }
        }


def test_go_parser_ignores_block_require_opener(tmp_path: Path) -> None:
    """REGRESSION: block require openers are not inline dependencies."""
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        """
module example.com/service

go 1.22

require github.com/sirupsen/logrus v1.9.3

require (
    github.com/gin-gonic/gin v1.10.0
    github.com/stretchr/testify v1.9.0 // indirect
)
""",
        encoding="utf-8",
    )

    dependencies = GoParser(str(go_mod)).parse()

    assert set(dependencies) == {
        "github.com/gin-gonic/gin",
        "github.com/stretchr/testify",
        "github.com/sirupsen/logrus",
    }
    assert dependencies["github.com/sirupsen/logrus"].installed_version == "v1.9.3"
    assert dependencies["github.com/gin-gonic/gin"].installed_version == "v1.10.0"
    assert "(" not in dependencies
    assert ")" not in dependencies
    assert "require" not in dependencies


def test_cargo_toml_routes_to_crates_analyzer_without_pypi(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """REGRESSION: Cargo.toml dependencies are Rust crates, not PyPI packages."""
    cargo_toml = tmp_path / "Cargo.toml"
    cargo_toml.write_text(
        """
[package]
name = "rust-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
""",
        encoding="utf-8",
    )

    parser = BaseParser.get_parser_for_file(str(cargo_toml))
    assert parser is not None
    dependencies = parser.parse()
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem("cargo")

    assert isinstance(analyzer, CratesIOAnalyzer)
    assert not isinstance(analyzer, PythonAnalyzer)

    def get_stub_analyzer(ecosystem: str) -> StubCratesIOAnalyzer:
        return StubCratesIOAnalyzer()

    monkeypatch.setattr(BaseAnalyzer, "get_analyzer_for_ecosystem", get_stub_analyzer)
    routed_analyzer = BaseAnalyzer.get_analyzer_for_ecosystem("cargo")
    assert routed_analyzer is not None
    analyzed = routed_analyzer.analyze(dependencies)

    assert analyzed["serde"].latest_version == "1.0.200"
    assert analyzed["serde"].additional_info["ecosystem"] == "cargo"
    assert analyzed["serde"].additional_info["source"] == "crates.io"
    assert analyzed["serde"].repository_url == "https://github.com/example/serde"
    assert "pypi.org" not in (analyzed["serde"].repository_url or "")


def test_pyproject_toml_still_routes_to_python_analyzer(tmp_path: Path) -> None:
    """REGRESSION: pyproject.toml still receives Python analyzer enrichment."""
    pyproject_toml = tmp_path / "pyproject.toml"
    pyproject_toml.write_text(
        """
[project]
name = "python-project"
version = "0.1.0"
dependencies = [
    "requests>=2.25.0",
]
""",
        encoding="utf-8",
    )

    parser = BaseParser.get_parser_for_file(str(pyproject_toml))
    assert parser is not None
    dependencies = parser.parse()
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem("pyproject")

    assert isinstance(analyzer, PythonAnalyzer)
    assert isinstance(dependencies["requests"], DependencyMetadata)
    assert (
        dependencies["requests"].repository_url == "https://pypi.org/project/requests/"
    )
