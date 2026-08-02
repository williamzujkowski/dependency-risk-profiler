"""Tests for the .NET/NuGet adapter: packages.lock.json + .csproj parser + analyzer."""

import json
from pathlib import Path
from unittest import mock

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.nuget import NuGetAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.nuget import NuGetParser
from dependency_risk_profiler.vulnerabilities import ecosystems

PACKAGES_LOCK = {
    "version": 1,
    "dependencies": {
        "net6.0": {
            "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
            "Serilog": {"type": "Transitive", "resolved": "2.10.0"},
        }
    },
}

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference>
  </ItemGroup>
</Project>
"""


def test_packages_lock_json_parser(tmp_path: Path) -> None:
    """Resolved versions are read per framework from packages.lock.json."""
    lock = tmp_path / "packages.lock.json"
    lock.write_text(json.dumps(PACKAGES_LOCK), encoding="utf-8")

    deps = NuGetParser(str(lock)).parse()

    assert set(deps) == {"Newtonsoft.Json", "Serilog"}
    assert deps["Newtonsoft.Json"].installed_version == "13.0.1"


def test_csproj_parser_reads_package_references(tmp_path: Path) -> None:
    """<PackageReference> entries are read (Version attribute or child element)."""
    proj = tmp_path / "App.csproj"
    proj.write_text(CSPROJ, encoding="utf-8")

    deps = NuGetParser(str(proj)).parse()

    assert set(deps) == {"Newtonsoft.Json", "Serilog"}
    assert deps["Newtonsoft.Json"].installed_version == "13.0.1"
    assert deps["Serilog"].installed_version == "2.10.0"


def test_nuget_manifests_dispatch_to_nuget_analyzer() -> None:
    """Both NuGet manifest kinds route to the nuget ecosystem and analyzer."""
    from dependency_risk_profiler.cli.typer_cli import get_ecosystem_from_manifest

    assert get_ecosystem_from_manifest("a/packages.lock.json") == "nuget"
    assert get_ecosystem_from_manifest("a/App.csproj") == "nuget"
    assert isinstance(BaseAnalyzer.get_analyzer_for_ecosystem("nuget"), NuGetAnalyzer)


def test_nuget_analyzer_sets_ecosystem_and_reads_latest_stable() -> None:
    """The analyzer stamps the OSV ecosystem and reads the newest stable version."""
    analyzer = NuGetAnalyzer()
    dep = DependencyMetadata(name="Newtonsoft.Json", installed_version="12.0.0")

    payload = {"versions": ["12.0.0", "13.0.1", "13.0.2-beta1"]}
    with mock.patch("dependency_risk_profiler.analyzers.nuget.requests.get") as get:
        get.return_value = mock.Mock(
            status_code=200, json=mock.Mock(return_value=payload)
        )
        result = analyzer.analyze({"Newtonsoft.Json": dep})

    updated = result["Newtonsoft.Json"]
    assert updated.additional_info["ecosystem"] == "nuget"
    # Newest stable (13.0.1) wins over the pre-release 13.0.2-beta1.
    assert updated.latest_version == "13.0.1"
    # The flat-container index uses the lowercased id.
    assert "newtonsoft.json" in get.call_args[0][0]


def test_nuget_ecosystem_routes_correctly() -> None:
    """The emitted 'nuget' string resolves to NuGet (OSV/GHA) and deps.dev."""
    eco = ecosystems.resolve("nuget")
    assert eco.osv == "NuGet"
    assert eco.github_advisory == "NUGET"
    assert eco.deps_dev == "nuget"
