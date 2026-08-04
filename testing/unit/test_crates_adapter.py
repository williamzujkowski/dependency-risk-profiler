"""Signal coverage for the cargo adapter (#132): crates.io metadata -> scorer."""

import copy
from typing import Dict, List, Optional
from unittest import mock

from signal_floors import assert_meets_signal_floor, mark_transitive_unmeasured

from dependency_risk_profiler.analyzers.crates import CratesIOAnalyzer
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

# Recorded crates.io responses, trimmed to the keys the adapter reads. Refresh
# with:
#   curl https://crates.io/api/v1/crates/anyhow
#   curl https://crates.io/api/v1/crates/anyhow/owners
# The split is the point: the `crate` object carries the repository and the
# version pointers, but the license and the release timestamp live only on the
# `versions` entries, and `crate.created_at` is when the crate was *first*
# published (2019) rather than when it last shipped.
ANYHOW_CRATE_RESPONSE: Dict[str, object] = {
    "crate": {
        "id": "anyhow",
        "name": "anyhow",
        "created_at": "2019-10-05T19:52:26.646502Z",
        "updated_at": "2026-07-18T20:59:37.656167Z",
        "downloads": 846524820,
        "max_version": "1.0.104",
        "newest_version": "1.0.104",
        "max_stable_version": "1.0.104",
        "description": "Flexible concrete Error type built on std::error::Error",
        "homepage": None,
        "documentation": "https://docs.rs/anyhow",
        "repository": "https://github.com/dtolnay/anyhow",
        "yanked": False,
    },
    "versions": [
        {
            "num": "1.0.104",
            "created_at": "2026-07-18T20:59:37.656167Z",
            "updated_at": "2026-07-18T20:59:37.656167Z",
            "yanked": False,
            "license": "MIT OR Apache-2.0",
            "rust_version": "1.68",
        },
        {
            "num": "1.0.103",
            "created_at": "2026-06-30T00:22:07.301449Z",
            "yanked": False,
            "license": "MIT OR Apache-2.0",
        },
    ],
}

ANYHOW_OWNERS_RESPONSE: Dict[str, object] = {
    "users": [
        {"id": 3618, "login": "dtolnay", "kind": "user", "name": "David Tolnay"},
    ]
}

# Enough of a GitHub repository page for the community analyzer's star scrape.
GITHUB_REPO_HTML = (
    '<a href="/dtolnay/anyhow/stargazers" '
    'aria-label="1,234 users starred this repository">1.2k</a>'
)


def _score_crate_offline(
    crate_response: Dict[str, object],
    owners_response: Optional[Dict[str, object]] = None,
) -> DependencyRiskScore:
    """Run the cargo pipeline for one crate with every network call stubbed.

    Mirrors the analyze command's order — adapter, license, community, scoring
    — with repository cloning off, so the result reflects only what the
    crates.io payload and a public repository page provide.

    Args:
        crate_response: Recorded crates.io ``/crates/<name>`` payload.
        owners_response: Recorded ``/crates/<name>/owners`` payload.

    Returns:
        The scored dependency.
    """
    crate = crate_response["crate"]
    assert isinstance(crate, dict)
    name = str(crate["name"])

    analyzer = CratesIOAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version="1.0.0")

    responses: Dict[str, object] = {
        f"https://crates.io/api/v1/crates/{name}": copy.deepcopy(crate_response),
        f"https://crates.io/api/v1/crates/{name}/owners": copy.deepcopy(
            ANYHOW_OWNERS_RESPONSE if owners_response is None else owners_response
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


def test_registry_metadata_lands_on_the_fields_the_scorer_reads() -> None:
    """Release date, repository root, owner count, and license come off the payload."""
    score = _score_crate_offline(ANYHOW_CRATE_RESPONSE)
    dep = score.dependency

    assert dep.latest_version == "1.0.104"
    assert dep.repository_url == "https://github.com/dtolnay/anyhow"
    # The newest release, not the crate's 2019 first-publication date.
    assert dep.last_updated is not None
    assert dep.last_updated.year == 2026
    assert dep.maintainer_count == 1
    # crates.io publishes SPDX expressions; the existing parser resolves the
    # dual-licence form to its first recognized term.
    assert dep.license_info is not None
    assert dep.license_info.license_id == "MIT"


def test_workspace_subdirectory_repository_is_trimmed_to_its_root() -> None:
    """Crates pointing at their own subdirectory still resolve to a cloneable repo."""
    payload = copy.deepcopy(ANYHOW_CRATE_RESPONSE)
    crate = payload["crate"]
    assert isinstance(crate, dict)
    crate["repository"] = "https://github.com/rust-lang/regex/tree/master/regex-syntax"

    score = _score_crate_offline(payload)

    assert score.dependency.repository_url == "https://github.com/rust-lang/regex"


def test_repository_falls_back_to_a_hosted_homepage() -> None:
    """A crate publishing only a homepage on a git host still resolves a repo."""
    payload = copy.deepcopy(ANYHOW_CRATE_RESPONSE)
    crate = payload["crate"]
    assert isinstance(crate, dict)
    crate["repository"] = None
    crate["homepage"] = "git+https://github.com/dtolnay/anyhow.git"

    score = _score_crate_offline(payload)

    assert score.dependency.repository_url == "https://github.com/dtolnay/anyhow"


def test_a_crate_without_a_repository_stays_honestly_unmeasured() -> None:
    """No published repository means no invented one, and no invented signals."""
    payload = copy.deepcopy(ANYHOW_CRATE_RESPONSE)
    crate = payload["crate"]
    assert isinstance(crate, dict)
    crate["repository"] = None
    crate["documentation"] = "https://docs.rs/anyhow"

    score = _score_crate_offline(payload)

    assert score.dependency.repository_url is None
    assert "health_indicators" in score.unknown_signals


def test_yanked_release_is_marked_deprecated() -> None:
    """A yanked release is crates.io's explicit do-not-use marker."""
    payload = copy.deepcopy(ANYHOW_CRATE_RESPONSE)
    versions = payload["versions"]
    assert isinstance(versions, list)
    newest = versions[0]
    assert isinstance(newest, dict)
    newest["yanked"] = True

    assert _score_crate_offline(payload).dependency.is_deprecated is True


def test_owners_without_users_leave_the_maintainer_count_alone() -> None:
    """An unreadable owners response must not fabricate a maintainer count."""
    score = _score_crate_offline(ANYHOW_CRATE_RESPONSE, owners_response={})

    assert score.dependency.maintainer_count is None
    assert "maintainer" in score.unknown_signals


def test_cargo_meets_minimum_measured_signal_coverage() -> None:
    """Registry metadata alone must carry a crate past the insufficient-data bar."""
    assert_meets_signal_floor(_score_crate_offline(ANYHOW_CRATE_RESPONSE), "cargo")


def test_cargo_measures_the_signals_the_registry_provides() -> None:
    """Each signal the crates.io payload can answer is measured, not left unknown."""
    score = _score_crate_offline(ANYHOW_CRATE_RESPONSE)

    registry_backed = {"staleness", "maintainer", "version", "license", "community"}
    assert registry_backed.isdisjoint(score.unknown_signals)


def test_missing_versions_entry_does_not_break_the_adapter() -> None:
    """A payload with no version entries degrades to the crate object alone."""
    payload: Dict[str, object] = {
        "crate": copy.deepcopy(ANYHOW_CRATE_RESPONSE)["crate"]
    }

    score = _score_crate_offline(payload)

    assert score.dependency.latest_version == "1.0.104"
    # Falls back to the crate's own last-publish timestamp, never its 2019
    # first-publication date.
    assert score.dependency.last_updated is not None
    assert score.dependency.last_updated.year == 2026


def test_recorded_owners_shape_is_a_list_of_users() -> None:
    """Guard the recorded fixture against silent drift in what the adapter counts."""
    users = ANYHOW_OWNERS_RESPONSE["users"]
    assert isinstance(users, list)
    assert all(isinstance(user, dict) for user in users)
    owners: List[object] = users
    assert owners
