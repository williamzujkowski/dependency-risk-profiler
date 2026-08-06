"""Tests for the Java/Maven adapter: pom.xml parser + analyzer."""

from pathlib import Path
from typing import Optional
from unittest import mock

import pytest
from registry_fixtures import RecordedResponse
from test_maven_version_resolution import MirrorClient

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.maven import (
    TRANSITIVE_SOURCE_MAVEN_POM,
    MavenAnalyzer,
    normalize_scm_url,
)
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.maven import MavenPomParser
from dependency_risk_profiler.parsers.maven_repositories import (
    CENTRAL,
    MavenRepositoryClient,
)
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


def _offline_analyzer() -> MavenAnalyzer:
    """Return an analyzer that reads no POMs and clones nothing."""
    analyzer = MavenAnalyzer(client=MavenRepositoryClient(enabled=False))
    analyzer.clone_repos = False
    return analyzer


def _serve_metadata(body: str) -> "mock._patch[mock.MagicMock]":
    """Patch the repository transport to answer every URL with one document.

    Patched at ``parsers.maven_repositories`` because that is where the fetch
    lives: since #278 the analyzer holds no transport of its own, so both the
    metadata lookup and the POM read go through the one client. A test that
    patched the analyzer's module would stub nothing and reach the network.

    Args:
        body: The XML to serve.

    Returns:
        The unentered patch, so the caller can inspect the call arguments.
    """
    return mock.patch(
        "dependency_risk_profiler.parsers.maven_repositories.requests.get",
        side_effect=lambda url, **_kwargs: RecordedResponse(
            url, body.encode("utf-8")
        ),
    )


def test_maven_analyzer_sets_ecosystem_and_reads_release_version() -> None:
    """The analyzer stamps the ecosystem and prefers <release> over <latest>."""
    analyzer = _offline_analyzer()
    dep = DependencyMetadata(
        name="com.google.guava:guava", installed_version="31.1-jre"
    )

    analyzer.client.enabled = True
    analyzer.client.repositories = (CENTRAL,)
    with _serve_metadata(MAVEN_METADATA) as get:
        result = analyzer.analyze({"com.google.guava:guava": dep})

    updated = result["com.google.guava:guava"]
    assert updated.additional_info["ecosystem"] == "maven"
    assert updated.latest_version == "32.1.3-jre"  # <release>, not <latest>
    # groupId dots become path separators.
    requested = [call.args[0] for call in get.call_args_list]
    assert (
        "https://repo1.maven.org/maven2/com/google/guava/guava/maven-metadata.xml"
        in requested
    )


def test_maven_analyzer_reads_repo_license_and_deps_from_the_artifact_pom() -> None:
    """REGRESSION #128: the artifact's own POM is where the signals come from.

    Before this, the Maven analyzer collected a latest version and nothing else,
    so every repo-derived signal — staleness, health, the Scorecard checks,
    community, license — was permanently unmeasured and every dependency scored
    UNKNOWN.
    """
    analyzer = MavenAnalyzer(client=MirrorClient())
    analyzer.clone_repos = False
    dep = DependencyMetadata(
        name="com.google.guava:guava", installed_version="33.0.0-jre"
    )

    with _serve_metadata(MAVEN_METADATA):
        result = analyzer.analyze({"com.google.guava:guava": dep})

    updated = result["com.google.guava:guava"]
    # <scm> gives the repository, which is what unlocks every cloned signal.
    assert updated.repository_url == "https://github.com/google/guava"
    # <licenses> feeds the license signal through the shared metadata cache.
    assert analyzer.metadata_cache["com.google.guava:guava"]["licenses"] == [
        "Apache License, Version 2.0"
    ]
    assert analyze_license(updated, analyzer.metadata_cache[updated.name]).license_info
    # The artifact's own shipped dependencies are a measured transitive signal;
    # the test-scoped one is not part of a consumer's runtime surface.
    assert updated.transitive_dependencies == {
        "com.google.guava:failureaccess",
        "com.google.code.findbugs:jsr305",
    }
    assert updated.transitive_source == TRANSITIVE_SOURCE_MAVEN_POM


def test_an_unreadable_pom_leaves_the_source_signal_unmeasured() -> None:
    """#182's rule in maven: no POM read is no answer about the artifact.

    ``_offline_analyzer`` reads no POMs at all, which is the same shape as an
    artifact whose POM 404s or whose coordinate has no colon in it. Recording
    UNDECLARED off that would stamp "declares no source repository" on a
    question nobody got to ask.
    """
    analyzer = _offline_analyzer()
    dep = DependencyMetadata(
        name="com.google.guava:guava", installed_version="31.1-jre"
    )

    with _serve_metadata(MAVEN_METADATA):
        result = analyzer.analyze({"com.google.guava:guava": dep})

    assert result["com.google.guava:guava"].source_repository_state is None


def test_maven_analyzer_clones_each_repository_once() -> None:
    """Twelve starters share one repo; the clone is shared, not repeated."""
    analyzer = MavenAnalyzer(client=MavenRepositoryClient(enabled=False))
    shared = "https://github.com/spring-projects/spring-boot"
    dependencies = {
        f"org.springframework.boot:starter-{index}": DependencyMetadata(
            name=f"org.springframework.boot:starter-{index}",
            installed_version="4.1.0",
            repository_url=shared,
        )
        for index in range(3)
    }
    dependencies["org.jsoup:jsoup"] = DependencyMetadata(
        name="org.jsoup:jsoup",
        installed_version="1.17.2",
        repository_url="https://github.com/jhy/jsoup",
    )

    with (
        mock.patch("dependency_risk_profiler.analyzers.maven.cloned_repo") as clone,
        mock.patch(
            "dependency_risk_profiler.analyzers.maven.analyze_repository"
        ) as analyze,
        mock.patch(
            "dependency_risk_profiler.parsers.maven_repositories.requests.get",
            side_effect=lambda url, **_kwargs: RecordedResponse(
                url, b"", status_code=404
            ),
        ),
    ):
        clone.return_value.__enter__.return_value = ("/tmp/clone", "repo")
        analyzer.analyze(dependencies)

    assert clone.call_count == 2  # two distinct repositories, not four artifacts
    assert analyze.call_count == 4  # every artifact still gets analyzed


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            "scm:git:git://github.com/spring-projects/spring-boot.git",
            "https://github.com/spring-projects/spring-boot",
        ),
        (
            "scm:git:ssh://git@github.com/google/guava.git",
            "https://github.com/google/guava",
        ),
        ("git@github.com:jhy/jsoup.git", "https://github.com/jhy/jsoup"),
        (
            "https://github.com/apache/commons-io/",
            "https://github.com/apache/commons-io",
        ),
        ("http://github.com/x/y", "https://github.com/x/y"),
        ("scm:svn:https://svn.example.org/trunk", "https://svn.example.org/trunk"),
        ("https://example.org", None),  # host only, no repository path
        ("mailto:someone@example.org", None),
        ("", None),
        (None, None),
    ],
)
def test_scm_urls_normalize_to_plain_https(
    raw: Optional[str], expected: Optional[str]
) -> None:
    """Maven SCM values arrive in four shapes; only https survives."""
    assert normalize_scm_url(raw) == expected


def test_maven_ecosystem_routes_correctly() -> None:
    """The emitted 'maven' string resolves to Maven (OSV/GHA) and deps.dev."""
    eco = ecosystems.resolve("maven")
    assert eco.osv == "Maven"
    assert eco.github_advisory == "MAVEN"
    assert eco.deps_dev == "maven"
