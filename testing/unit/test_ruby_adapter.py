"""Tests for the RubyGems adapter (#78): Gemfile.lock parser + analyzer."""

import copy
from pathlib import Path
from typing import Dict, List, Optional
from unittest import mock

from signal_floors import (
    assert_measures_registry_signals,
    assert_meets_signal_floor,
    mark_transitive_unmeasured,
)

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.ruby import RubyGemsAnalyzer
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.license.analyzer import (
    analyze_license,
    extract_license_info,
)
from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.parsers.ruby import GemfileLockParser
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
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


# --- Signal coverage (#127) -------------------------------------------------
#
# Recorded rubygems.org responses, trimmed to the keys the adapter reads.
# Refresh with:
#   curl https://rubygems.org/api/v1/gems/tzinfo.json
#   curl https://rubygems.org/api/v1/gems/tzinfo/owners.json
# The shapes are the point: the license is a *list* under "licenses" (there is
# no "license" key at all), and source_code_uri is pinned to the released tag.
TZINFO_GEM_RESPONSE: Dict[str, object] = {
    "name": "tzinfo",
    "downloads": 1290042037,
    "version": "2.0.6",
    "version_created_at": "2023-01-28T20:27:53.927Z",
    "platform": "ruby",
    "authors": "Philip Ross",
    "licenses": ["MIT"],
    "metadata": {
        "homepage_uri": "https://tzinfo.github.io",
        "source_code_uri": "https://github.com/tzinfo/tzinfo/tree/v2.0.6",
    },
    "yanked": False,
    "homepage_uri": "https://tzinfo.github.io",
    "source_code_uri": "https://github.com/tzinfo/tzinfo/tree/v2.0.6",
}

TZINFO_OWNERS_RESPONSE: List[Dict[str, object]] = [
    {"id": 2981, "handle": "PhilRoss", "role": "owner"},
]

# Enough of a GitHub repository page for the community analyzer's star scrape.
GITHUB_REPO_HTML = (
    '<a href="/tzinfo/tzinfo/stargazers" '
    'aria-label="1,234 users starred this repository">1.2k</a>'
)

# The measured-signal floor now lives in signal_floors.MIN_MEASURED_SIGNALS,
# shared with the cargo and composer adapter tests (#132).


def _score_gem_offline(gem_response: Dict[str, object]) -> DependencyRiskScore:
    """Run the rubygems pipeline for one gem with every network call stubbed.

    Mirrors the analyze command's order — adapter, license, community, scoring
    — with repository cloning off, so the result reflects only what the
    registry payload and a public repository page provide.

    Args:
        gem_response: Recorded rubygems.org gem payload.

    Returns:
        The scored dependency.
    """
    name = str(gem_response["name"])
    analyzer = RubyGemsAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version="1.0.0")

    responses: Dict[str, object] = {
        f"https://rubygems.org/api/v1/gems/{name}.json": copy.deepcopy(gem_response),
        f"https://rubygems.org/api/v1/gems/{name}/owners.json": copy.deepcopy(
            TZINFO_OWNERS_RESPONSE
        ),
    }

    def fake_get_json(url: str) -> Optional[object]:
        return responses.get(url)

    with mock.patch.object(analyzer, "_get_json", side_effect=fake_get_json):
        analyzed = analyzer.analyze({name: dep})

    dep = analyzed[name]
    metadata = analyzer.metadata_cache[name]
    dep = analyze_license(dep, metadata)
    with mock.patch.object(
        community_analyzer, "fetch_url", return_value=GITHUB_REPO_HTML
    ):
        dep = community_analyzer.analyze_community_metrics(dep, metadata)

    return RiskScorer().score_dependency(mark_transitive_unmeasured(dep))


def test_gem_license_is_read_from_the_licenses_list() -> None:
    """Gems publish a list under 'licenses'; it must not be skipped."""
    license_info = extract_license_info(TZINFO_GEM_RESPONSE)

    assert license_info is not None
    assert license_info.license_id == "MIT"


def test_string_license_fields_still_resolve() -> None:
    """The npm/PyPI string spellings keep working alongside the list shape."""
    assert extract_license_info({"license": "Apache-2.0"}) is not None
    assert extract_license_info({"info": {"license": "MIT"}}) is not None
    assert extract_license_info({"licenses": []}) is None
    assert extract_license_info({"license": None}) is None


def test_registry_metadata_lands_on_the_fields_the_scorer_reads() -> None:
    """Release date, repository root, and owner count come off the payload."""
    score = _score_gem_offline(TZINFO_GEM_RESPONSE)
    dep = score.dependency

    assert dep.latest_version == "2.0.6"
    # The recorded source_code_uri points at /tree/v2.0.6; only the trimmed
    # root resolves for GitHub lookups and cloning.
    assert dep.repository_url == "https://github.com/tzinfo/tzinfo"
    assert dep.last_updated is not None
    assert dep.last_updated.year == 2023
    assert dep.maintainer_count == len(TZINFO_OWNERS_RESPONSE)
    assert dep.license_info is not None and dep.license_info.license_id == "MIT"


def test_yanked_gem_is_marked_deprecated() -> None:
    """A yanked release is RubyGems' explicit do-not-use marker."""
    yanked = copy.deepcopy(TZINFO_GEM_RESPONSE)
    yanked["yanked"] = True

    assert _score_gem_offline(yanked).dependency.is_deprecated is True


def test_rubygems_meets_minimum_measured_signal_coverage() -> None:
    """Registry metadata alone must carry a gem past the insufficient-data bar."""
    assert_meets_signal_floor(_score_gem_offline(TZINFO_GEM_RESPONSE), "rubygems")


def test_rubygems_measures_the_signals_the_registry_provides() -> None:
    """Each signal the gem payload can answer is measured, not left unknown."""
    assert_measures_registry_signals(
        _score_gem_offline(TZINFO_GEM_RESPONSE), "rubygems"
    )
