"""One vulnerability counts once, however many records describe it (#274).

OSV re-scopes an advisory by publishing a **second** record and listing each in
the other's ``aliases``. Deduplicating by exact ``id`` counted both, so
``lodash 4.17.15`` reported six advisories for four vulnerabilities — and every
number downstream inherited the inflation: ``counted_in_score``, the
``N scored`` column, the ``Known security issues (N counted, ...)`` risk factor
and the #242 verdict floor.

The recordings are captured OSV bodies (rule 5). Nothing here re-implements the
grouping: each test drives ``OSVSource.lookup`` over recorded bytes and reads
what the shipped aggregator produced.
"""

import json
import time
from pathlib import Path
from typing import Dict, List

import pytest
from osv_replay import advisories_for, annotated_dependency, counted_ids

from dependency_risk_profiler.models import RiskLevel
from dependency_risk_profiler.scoring.risk_scorer import verdict_floor_for
from dependency_risk_profiler.vulnerabilities.aggregator import merge_alias_duplicates
from dependency_risk_profiler.vulnerabilities.cache import (
    CACHE_SCHEMA_VERSION,
    VulnerabilityCache,
)


def _aliases(advisory: Dict[str, object]) -> List[str]:
    """Return an advisory record's alias list.

    Args:
        advisory: One record from the aggregator.

    Returns:
        The other identifiers the record answers to.
    """
    aliases = advisory["aliases"]
    assert isinstance(aliases, list)
    return [str(alias) for alias in aliases]


#: The four vulnerabilities OSV holds against lodash 4.17.15, one ID per alias
#: group, each the lexicographically first ID in its group. Written out rather
#: than counted so the test asserts *which* advisories survived, not how many:
#: a count cannot tell "collapsed the right pairs" from "dropped two records".
LODASH_4_17_15_COUNTED = [
    "GHSA-29mw-wpgm-hmr9",
    "GHSA-35jh-r3h4-6jhm",
    "GHSA-f23m-r3pf-42rh",
    "GHSA-p6mc-m468-83gw",
]


def test_lodash_4_17_15_counts_four_vulnerabilities_not_six(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESSION (#274): six records, four vulnerabilities, six counted."""
    dependency = annotated_dependency(
        monkeypatch,
        fixture="npm_lodash.json",
        package_name="lodash",
        ecosystem="nodejs",
        installed_version="4.17.15",
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert counted_ids(dependency) == LODASH_4_17_15_COUNTED
    assert metrics.counted_vulnerability_count == 4


def test_the_collapsed_pairs_are_the_ones_that_alias_each_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two records dropped are exactly the two that named their twin.

    ``GHSA-r5fr-rjxr-66jc`` and ``GHSA-35jh-r3h4-6jhm`` are both
    CVE-2021-23337; ``GHSA-xxjr-mmjv-4gpg`` and ``GHSA-f23m-r3pf-42rh`` are
    both CVE-2025-13465. Neither pair is a coincidence of prefix or of date,
    and asserting the surviving IDs by value is what distinguishes collapsing
    the right pair from collapsing any pair.
    """
    advisories = advisories_for(
        monkeypatch,
        fixture="npm_lodash.json",
        package_name="lodash",
        ecosystem="nodejs",
    )
    by_id: Dict[str, Dict[str, object]] = {
        str(advisory["id"]): advisory for advisory in advisories
    }

    assert "GHSA-r5fr-rjxr-66jc" not in by_id
    assert "GHSA-xxjr-mmjv-4gpg" not in by_id
    # The collapsed IDs are not lost: the surviving record answers to them.
    survivor = _aliases(by_id["GHSA-35jh-r3h4-6jhm"])
    assert "GHSA-r5fr-rjxr-66jc" in survivor
    assert "CVE-2021-23337" in survivor


def test_a_group_keeps_the_worst_severity_any_record_stated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESSION (#274): CVE-2020-7754 was counted twice, at HIGH and at LOW.

    ``npm-user-validate 0.1.5`` is the case where collapsing could *lower* a
    verdict: OSV publishes CVE-2020-7754 as ``GHSA-pw54-mh39-w3hc`` (HIGH, with
    a CVSS vector) and ``GHSA-xgh6-85xh-479p`` (LOW, with none). The survivor
    must carry HIGH — a merge that took the representative's own severity would
    be picking by alphabet.
    """
    dependency = annotated_dependency(
        monkeypatch,
        fixture="npm_npm_user_validate.json",
        package_name="npm-user-validate",
        ecosystem="nodejs",
        installed_version="0.1.5",
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert counted_ids(dependency) == ["GHSA-pw54-mh39-w3hc"]
    assert metrics.counted_vulnerability_count == 1
    assert metrics.max_vulnerability_severity == "HIGH"

    floor = verdict_floor_for(dependency, RiskLevel.LOW)
    assert floor is not None
    assert floor.max_counted_severity == "HIGH"
    assert floor.advisory_id == "GHSA-pw54-mh39-w3hc"
    assert floor.floor_level is RiskLevel.MEDIUM


def test_collapsing_never_drops_an_advisory_a_member_would_have_counted() -> None:
    """ADVERSARIAL (authored, not captured): the fail-open a merge could add.

    No cooperating registry publishes the pair below, which is why this one is
    written by hand and kept away from the recordings. Two records for one
    vulnerability disagree about the installed version: one says it is out of
    range, the other carries no range data at all. Taking the first record's
    ranges would filter an advisory that, on its own, was counted — #274
    pointing the wrong way. The group must come out undecided and counted.
    """
    merged = merge_alias_duplicates(
        [
            {
                "id": "GHSA-aaaa-aaaa-aaaa",
                "source": "OSV",
                "aliases": ["CVE-2026-0001"],
                "severity": "HIGH",
                "normalized_severity": "HIGH",
                "cvss_score": 8.0,
                "withdrawn": False,
                "confidence": "HIGH",
                "fixed_versions": ["2.0.0"],
                "affected_versions": {
                    "ranges": [
                        {
                            "constraints": [
                                {"operator": ">=", "version": "1.0.0"},
                                {"operator": "<", "version": "1.5.0"},
                            ]
                        }
                    ],
                    "versions": [],
                },
                "references": [],
            },
            {
                "id": "CVE-2026-0001",
                "source": "NVD",
                "aliases": [],
                "severity": None,
                "normalized_severity": "UNKNOWN",
                "cvss_score": None,
                "withdrawn": False,
                "confidence": "MEDIUM",
                "fixed_versions": [],
                "affected_versions": None,
                "references": [],
            },
        ]
    )

    assert len(merged) == 1
    assert merged[0]["id"] == "CVE-2026-0001"
    assert merged[0]["affected_versions"] is None
    assert merged[0]["normalized_severity"] == "HIGH"


def test_a_group_stands_unless_every_record_is_withdrawn() -> None:
    """ADVERSARIAL (authored, not captured): one live record keeps the group.

    A withdrawal is a statement about a record, not about a vulnerability. If
    one publisher retracts its record and another's still stands, the finding
    stands — taking the representative's own flag would let alphabetical luck
    retract a live advisory.
    """
    merged = merge_alias_duplicates(
        [
            {
                "id": "GHSA-bbbb-bbbb-bbbb",
                "aliases": ["CVE-2026-0002"],
                "normalized_severity": "HIGH",
                "cvss_score": None,
                "withdrawn": True,
                "confidence": "HIGH",
                "affected_versions": None,
            },
            {
                "id": "CVE-2026-0002",
                "aliases": [],
                "normalized_severity": "MEDIUM",
                "cvss_score": None,
                "withdrawn": False,
                "confidence": "HIGH",
                "affected_versions": None,
            },
        ]
    )

    assert len(merged) == 1
    assert merged[0]["withdrawn"] is False


def test_records_join_a_group_through_a_third_identifier() -> None:
    """ADVERSARIAL (authored, not captured): the closure has to be transitive.

    Two GHSA records that both alias one CVE and never name each other are the
    same vulnerability. A pairwise rule keyed on "does A list B" misses them,
    which is precisely the shape of lodash's CVE-2021-23337 pair.
    """
    merged = merge_alias_duplicates(
        [
            {"id": "GHSA-cccc-cccc-cccc", "aliases": ["CVE-2026-0003"]},
            {"id": "GHSA-dddd-dddd-dddd", "aliases": ["CVE-2026-0003"]},
        ]
    )

    assert len(merged) == 1
    assert merged[0]["id"] == "GHSA-cccc-cccc-cccc"
    assert merged[0]["aliases"] == ["CVE-2026-0003", "GHSA-dddd-dddd-dddd"]


def test_an_inflated_cache_entry_is_not_served_after_the_fix(
    tmp_path: Path,
) -> None:
    """The schema bump is the fix's reach backwards into caches already on disk.

    Every version-4 entry holds one record per advisory rather than one per
    vulnerability, and carries no ``aliases`` to group on. Read back under the
    fix it would go on reporting six where there are four, as a measurement,
    for the rest of its 24-hour TTL.
    """
    cache = VulnerabilityCache(cache_dir=tmp_path / "vuln_cache")
    entry = cache._get_cache_path("lodash", "nodejs")
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(
        json.dumps(
            {
                "data": [
                    {"id": "GHSA-35jh-r3h4-6jhm"},
                    {"id": "GHSA-r5fr-rjxr-66jc"},
                ],
                "timestamp": time.time(),
                "package": "lodash",
                "ecosystem": "nodejs",
                "schema_version": 4,
            }
        ),
        encoding="utf-8",
    )

    assert cache.get("lodash", "nodejs") is None
    assert CACHE_SCHEMA_VERSION == 5


def test_grouping_does_not_depend_on_the_order_records_arrive_in() -> None:
    """The representative is the lexicographically first ID, not the first seen.

    ``_worst_counted_advisory_id`` already holds the report to that rule so a
    verdict's recorded cause does not move when a source answers faster. A
    deduplication that picked first-seen would reintroduce the dependence one
    layer up.
    """
    records: List[Dict[str, object]] = [
        {"id": "GHSA-ffff-ffff-ffff", "aliases": ["CVE-2026-0004"]},
        {"id": "GHSA-eeee-eeee-eeee", "aliases": ["CVE-2026-0004"]},
    ]

    forward = merge_alias_duplicates(records)
    backward = merge_alias_duplicates(list(reversed(records)))

    assert forward[0]["id"] == "GHSA-eeee-eeee-eeee"
    assert backward[0]["id"] == "GHSA-eeee-eeee-eeee"
    assert forward[0]["aliases"] == backward[0]["aliases"]
