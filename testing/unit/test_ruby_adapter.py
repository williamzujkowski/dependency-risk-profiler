"""Tests for the RubyGems adapter (#78): Gemfile.lock parser + analyzer."""

from pathlib import Path
from unittest import mock

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.ruby import RubyGemsAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.ruby import GemfileLockParser
from dependency_risk_profiler.vulnerabilities import ecosystems

GEMFILE_LOCK = """\
GIT
  remote: https://github.com/example/widget.git
  revision: abc123
  specs:
    widget (0.3.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      rack (~> 2.0)
      rack-test (>= 0.6.3)
    nokogiri (1.13.9)
    rack (2.2.4)

PLATFORMS
  ruby

DEPENDENCIES
  actionpack
  nokogiri
"""


def test_gemfile_lock_parser_extracts_top_level_gems(tmp_path: Path) -> None:
    """Top-level resolved gems are parsed; their transitive requirements aren't."""
    lock = tmp_path / "Gemfile.lock"
    lock.write_text(GEMFILE_LOCK, encoding="utf-8")

    deps = GemfileLockParser(str(lock)).parse()

    # actionpack/nokogiri/rack from GEM, widget from the GIT source; the
    # six-space "rack (~> 2.0)" requirement lines are not separate entries.
    assert set(deps) == {"widget", "actionpack", "nokogiri", "rack"}
    assert deps["actionpack"].installed_version == "7.0.4"
    assert deps["rack"].installed_version == "2.2.4"


def test_gemfile_lock_registered_and_dispatches_to_ruby_analyzer() -> None:
    """A Gemfile.lock routes to the RubyGems ecosystem and analyzer."""
    from dependency_risk_profiler.cli.typer_cli import get_ecosystem_from_manifest

    assert get_ecosystem_from_manifest("some/dir/Gemfile.lock") == "rubygems"
    assert isinstance(
        BaseAnalyzer.get_analyzer_for_ecosystem("rubygems"), RubyGemsAnalyzer
    )


def test_ruby_analyzer_sets_ecosystem_and_reads_metadata() -> None:
    """The analyzer stamps the OSV ecosystem and fills version/repo from the API."""
    analyzer = RubyGemsAnalyzer()
    dep = DependencyMetadata(name="rails", installed_version="7.0.0")

    payload = {
        "version": "7.1.3",
        "source_code_uri": "https://github.com/rails/rails",
        "homepage_uri": "https://rubyonrails.org",
    }
    with mock.patch.object(analyzer, "_get_gem_info", return_value=payload):
        result = analyzer.analyze({"rails": dep})

    updated = result["rails"]
    assert updated.additional_info["ecosystem"] == "rubygems"
    assert updated.latest_version == "7.1.3"
    assert updated.repository_url == "https://github.com/rails/rails"


def test_ruby_ecosystem_routes_to_rubygems_everywhere() -> None:
    """The emitted 'rubygems' string resolves to RubyGems across all sources."""
    eco = ecosystems.resolve("rubygems")
    assert eco.osv == "RubyGems"
    assert eco.github_advisory == "RUBYGEMS"
    assert eco.deps_dev == "rubygems"
