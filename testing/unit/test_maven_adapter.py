"""Tests for the Java/Maven adapter: pom.xml parser + analyzer."""

from pathlib import Path
from unittest import mock

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.maven import MavenAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.maven import MavenPomParser
from dependency_risk_profiler.vulnerabilities import ecosystems

POM_XML = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <junit.version>4.13.2</junit.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.managed</groupId>
        <artifactId>managed-only</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${junit.version}</version>
    </dependency>
  </dependencies>
</project>
"""

MAVEN_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <versioning>
    <latest>33.0.0-jre</latest>
    <release>32.1.3-jre</release>
  </versioning>
</metadata>
"""


def test_pom_parser_reads_direct_deps_and_resolves_properties(tmp_path: Path) -> None:
    """Direct <dependencies> are parsed with ${property} resolution.

    The <dependencyManagement> block is a constraint set, not direct deps, and
    is excluded.
    """
    pom = tmp_path / "pom.xml"
    pom.write_text(POM_XML, encoding="utf-8")

    deps = MavenPomParser(str(pom)).parse()

    assert set(deps) == {"com.google.guava:guava", "junit:junit"}
    assert "org.managed:managed-only" not in deps  # dependencyManagement excluded
    assert deps["com.google.guava:guava"].installed_version == "31.1-jre"
    assert deps["junit:junit"].installed_version == "4.13.2"  # ${junit.version}


CHAINED_EMBEDDED_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <a>${b}</a>
    <b>1.2.3</b>
    <lib.version>4.5.6</lib.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.chain</groupId>
      <artifactId>chained</artifactId>
      <version>${a}</version>
    </dependency>
    <dependency>
      <groupId>com.embed</groupId>
      <artifactId>embedded</artifactId>
      <version>${lib.version}-RELEASE</version>
    </dependency>
  </dependencies>
</project>
"""


def test_pom_resolves_chained_and_embedded_properties(tmp_path: Path) -> None:
    """Chained (${a}->${b}->value) and embedded (${x}-suffix) refs resolve."""
    pom = tmp_path / "pom.xml"
    pom.write_text(CHAINED_EMBEDDED_POM, encoding="utf-8")

    deps = MavenPomParser(str(pom)).parse()

    # ${a} -> ${b} -> 1.2.3 (chained, multi-level).
    assert deps["com.chain:chained"].installed_version == "1.2.3"
    # ${lib.version}-RELEASE -> 4.5.6-RELEASE (embedded reference).
    assert deps["com.embed:embedded"].installed_version == "4.5.6-RELEASE"


def test_pom_dispatches_to_maven_analyzer() -> None:
    """pom.xml routes to the maven ecosystem and analyzer."""
    from dependency_risk_profiler.cli.typer_cli import get_ecosystem_from_manifest

    assert get_ecosystem_from_manifest("a/pom.xml") == "maven"
    assert isinstance(BaseAnalyzer.get_analyzer_for_ecosystem("maven"), MavenAnalyzer)


def test_maven_analyzer_sets_ecosystem_and_reads_release_version() -> None:
    """The analyzer stamps the ecosystem and prefers <release> over <latest>."""
    analyzer = MavenAnalyzer()
    dep = DependencyMetadata(
        name="com.google.guava:guava", installed_version="31.1-jre"
    )

    with mock.patch("dependency_risk_profiler.analyzers.maven.requests.get") as get:
        get.return_value = mock.Mock(
            status_code=200, content=MAVEN_METADATA.encode("utf-8")
        )
        result = analyzer.analyze({"com.google.guava:guava": dep})

    updated = result["com.google.guava:guava"]
    assert updated.additional_info["ecosystem"] == "maven"
    assert updated.latest_version == "32.1.3-jre"  # <release>, not <latest>
    # groupId dots become path separators.
    assert "com/google/guava/guava/maven-metadata.xml" in get.call_args[0][0]


def test_maven_ecosystem_routes_correctly() -> None:
    """The emitted 'maven' string resolves to Maven (OSV/GHA) and deps.dev."""
    eco = ecosystems.resolve("maven")
    assert eco.osv == "Maven"
    assert eco.github_advisory == "MAVEN"
    assert eco.deps_dev == "maven"
