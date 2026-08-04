"""Advisories are counted only when they affect the installed version (#61).

The tool used to count every advisory ever published for a package against
whatever version happened to be installed, because the OSV ``affected`` block
was fetched and then dropped. Django 4.2 read as carrying a live CRITICAL that
had been fixed in 4.0.4, two minor releases earlier.

The Django cases below are recorded OSV payloads (``testing/fixtures/
osv_django_advisories.json``), pinned exactly as issue #61 recorded them. No
network.
"""

import json
from pathlib import Path
from typing import Dict, List

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.versioning import VersionScheme
from dependency_risk_profiler.vulnerabilities import affected_ranges
from dependency_risk_profiler.vulnerabilities.affected_ranges import (
    NOT_AFFECTED_FILTER_REASON,
    REASON_INSTALLED_UNPARSEABLE,
    REASON_NO_INSTALLED_VERSION,
    REASON_NO_RANGE_DATA,
    Applicability,
)
from dependency_risk_profiler.vulnerabilities.aggregator import (
    OSVSource,
    _update_dependency_with_vulnerabilities,
    annotate_vulnerabilities_for_scoring,
)

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "osv_django_advisories.json"
)

# Recorded verbatim from issue #61: every one of these was counted against
# Django 4.2 despite having been fixed before 4.2 existed.
FIXED_BEFORE_4_2 = {
    "GHSA-2655-q453-22f9": "1.3.4, 1.4.2",
    "GHSA-296w-6qhq-gf92": "1.4.14, 1.5.9, 1.6.6",
    "GHSA-2f9x-5v75-3qv4": "2.0.3, 1.11.11, 1.8.19",
    "GHSA-2gwj-7jmv-h26r": "2.2.28, 3.2.13, 4.0.4",
    "GHSA-2hrw-hx67-34x6": "3.2.18, 4.1.7, 4.0.10",
}

# The control group: advisories whose fix landed on the 4.2 line, so 4.2 is
# genuinely exposed to them. Without these the fix could be "filter everything".
AFFECTS_4_2 = {
    "GHSA-9jmf-237g-qf46": "4.2.14",
    "GHSA-jh75-99hh-qvx9": "4.2.15",
    "GHSA-mmwr-2jhp-mc7j": "4.2.30",
}


def _recorded_django_advisories() -> List[Dict[str, object]]:
    """Return the recorded OSV payloads, normalized as the OSV source would."""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return OSVSource()._normalize_results(raw, "django")


def _django(installed_version: str) -> DependencyMetadata:
    """Build a Django dependency pinned at a version."""
    return DependencyMetadata(
        name="django",
        installed_version=installed_version,
        additional_info={"ecosystem": "python"},
    )


# --------------------------------------------------------------------------
# The regression: Django 4.2
# --------------------------------------------------------------------------


def test_affected_versions_are_populated_not_dropped() -> None:
    """Every recorded advisory carries an affected range; #61 recorded 0/153."""
    advisories = _recorded_django_advisories()
    assert len(advisories) == len(FIXED_BEFORE_4_2) + len(AFFECTS_4_2)
    assert all(record["affected_versions"] is not None for record in advisories)


@pytest.mark.parametrize("advisory_id", sorted(FIXED_BEFORE_4_2))
def test_advisories_fixed_before_4_2_are_filtered(advisory_id: str) -> None:
    """An advisory fixed before 4.2 existed cannot apply to 4.2."""
    annotated = annotate_vulnerabilities_for_scoring(
        _recorded_django_advisories(), "LOW", "4.2", "python"
    )
    record = next(item for item in annotated if item["id"] == advisory_id)
    assert record["version_match"] == Applicability.NOT_AFFECTED.value
    assert record["counted_in_score"] is False
    assert NOT_AFFECTED_FILTER_REASON in record["filter_reasons"]


@pytest.mark.parametrize("advisory_id", sorted(AFFECTS_4_2))
def test_advisories_fixed_after_4_2_are_counted(advisory_id: str) -> None:
    """A 4.2-line fix means 4.2 is genuinely exposed and must stay counted."""
    annotated = annotate_vulnerabilities_for_scoring(
        _recorded_django_advisories(), "LOW", "4.2", "python"
    )
    record = next(item for item in annotated if item["id"] == advisory_id)
    assert record["version_match"] == Applicability.AFFECTED.value
    assert record["counted_in_score"] is True


def test_the_critical_from_the_issue_no_longer_drives_the_score() -> None:
    """GHSA-2gwj-7jmv-h26r is CRITICAL, fixed in 4.0.4, and must not count."""
    dependency = _update_dependency_with_vulnerabilities(
        _django("4.2"), _recorded_django_advisories()
    )
    metrics = dependency.security_metrics
    assert metrics is not None
    counted_ids = {
        record["id"]
        for record in metrics.vulnerability_details
        if record["counted_in_score"] is True
    }
    assert "GHSA-2gwj-7jmv-h26r" not in counted_ids
    assert counted_ids == set(AFFECTS_4_2)
    assert metrics.max_vulnerability_severity == "HIGH"  # not the 4.0.4 CRITICAL
    assert metrics.filtered_vulnerability_reasons[NOT_AFFECTED_FILTER_REASON] == len(
        FIXED_BEFORE_4_2
    )


def test_a_fully_patched_pin_has_no_known_exploits() -> None:
    """4.2.30 post-dates every recorded fix, so nothing applies to it."""
    dependency = _update_dependency_with_vulnerabilities(
        _django("4.2.30"), _recorded_django_advisories()
    )
    metrics = dependency.security_metrics
    assert metrics is not None
    assert metrics.counted_vulnerability_count == 0
    assert metrics.max_vulnerability_severity is None
    assert dependency.has_known_exploits is False


# Which of the eight recorded advisories each pin is actually exposed to.
# Before the fix every row read identically: all eight, CRITICAL, exploited.
PIN_EXPOSURE = [
    ("1.3", ["GHSA-2655-q453-22f9", "GHSA-296w-6qhq-gf92"]),
    ("1.3.4", ["GHSA-296w-6qhq-gf92"]),
    ("2.2", ["GHSA-2gwj-7jmv-h26r"]),
    ("4.0", ["GHSA-2gwj-7jmv-h26r", "GHSA-2hrw-hx67-34x6"]),
    ("4.2", sorted(AFFECTS_4_2)),
    ("4.2.30", []),
]


@pytest.mark.parametrize("installed_version,expected_ids", PIN_EXPOSURE)
def test_each_pin_counts_only_what_reaches_it(
    installed_version: str, expected_ids: List[str]
) -> None:
    """Upgrading must change the reading; that is the whole point of #61."""
    dependency = _update_dependency_with_vulnerabilities(
        _django(installed_version), _recorded_django_advisories()
    )
    metrics = dependency.security_metrics
    assert metrics is not None
    counted = sorted(
        str(record["id"])
        for record in metrics.vulnerability_details
        if record["counted_in_score"] is True
    )
    assert counted == expected_ids
    assert dependency.has_known_exploits is bool(expected_ids)


# --------------------------------------------------------------------------
# Honest unknown (#74): count it, but say why
# --------------------------------------------------------------------------


def test_missing_installed_version_counts_with_a_reason() -> None:
    """No pin to compare against means unknown, not safe and not vulnerable."""
    dependency = _update_dependency_with_vulnerabilities(
        _django(""), _recorded_django_advisories()
    )
    metrics = dependency.security_metrics
    assert metrics is not None
    assert metrics.counted_vulnerability_count == 8
    assert metrics.applicability_unknown_count == 8
    assert metrics.applicability_unknown_reasons == {REASON_NO_INSTALLED_VERSION: 8}


def test_unparseable_installed_version_counts_with_a_reason() -> None:
    """A pin the ecosystem cannot order is reported, not silently resolved."""
    dependency = _update_dependency_with_vulnerabilities(
        _django("main-branch"), _recorded_django_advisories()
    )
    metrics = dependency.security_metrics
    assert metrics is not None
    assert metrics.counted_vulnerability_count == 8
    assert metrics.applicability_unknown_reasons == {REASON_INSTALLED_UNPARSEABLE: 8}


def test_advisory_without_range_data_counts_with_a_reason() -> None:
    """An NVD-style advisory carrying no range stays counted, with the reason."""
    dependency = _update_dependency_with_vulnerabilities(
        _django("4.2"),
        [
            {
                "id": "CVE-0000-0000",
                "source": "NVD",
                "severity": "HIGH",
                "normalized_severity": "HIGH",
                "affected_versions": None,
            }
        ],
    )
    metrics = dependency.security_metrics
    assert metrics is not None
    assert metrics.counted_vulnerability_count == 1
    assert metrics.applicability_unknown_reasons == {REASON_NO_RANGE_DATA: 1}


def test_unknown_ranges_do_not_leak_into_the_filter_histogram() -> None:
    """Only genuinely-ruled-out advisories carry the not-affected filter reason."""
    dependency = _update_dependency_with_vulnerabilities(
        _django("main-branch"), _recorded_django_advisories()
    )
    metrics = dependency.security_metrics
    assert metrics is not None
    assert NOT_AFFECTED_FILTER_REASON not in metrics.filtered_vulnerability_reasons


# --------------------------------------------------------------------------
# OSV affected-block shapes
# --------------------------------------------------------------------------


def test_open_ended_range_affects_every_later_version() -> None:
    """An advisory with no fix affects everything from its introduction on."""
    affected = affected_ranges.affected_versions_from_osv(
        {
            "affected": [
                {
                    "package": {"name": "pkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}]}
                    ],
                }
            ]
        },
        "pkg",
    )
    for version, expected in (
        ("1.9", Applicability.NOT_AFFECTED),
        ("2.0", Applicability.AFFECTED),
        ("99.0", Applicability.AFFECTED),
    ):
        result = affected_ranges.evaluate_applicability(
            affected, version, VersionScheme.PEP440
        )
        assert result.status is expected


def test_last_affected_bound_is_inclusive() -> None:
    """``last_affected`` includes its own version; ``fixed`` excludes it."""
    affected = affected_ranges.affected_versions_from_osv(
        {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"last_affected": "1.5"}],
                        }
                    ]
                }
            ]
        },
        None,
    )
    assert (
        affected_ranges.evaluate_applicability(
            affected, "1.5", VersionScheme.PEP440
        ).status
        is Applicability.AFFECTED
    )
    assert (
        affected_ranges.evaluate_applicability(
            affected, "1.5.1", VersionScheme.PEP440
        ).status
        is Applicability.NOT_AFFECTED
    )


def test_multiple_intervals_in_one_event_stream() -> None:
    """Backport lines: 1.x is fixed, 2.x reopens the hole, 2.3 closes it."""
    affected = affected_ranges.affected_versions_from_osv(
        {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0"},
                                {"fixed": "1.5"},
                                {"introduced": "2.0"},
                                {"fixed": "2.3"},
                            ],
                        }
                    ]
                }
            ]
        },
        None,
    )
    verdicts = {
        version: affected_ranges.evaluate_applicability(
            affected, version, VersionScheme.PEP440
        ).status
        for version in ("1.4", "1.5", "2.1", "2.3")
    }
    assert verdicts == {
        "1.4": Applicability.AFFECTED,
        "1.5": Applicability.NOT_AFFECTED,
        "2.1": Applicability.AFFECTED,
        "2.3": Applicability.NOT_AFFECTED,
    }


# Modelled on GHSA-6c3j-c64m-qhgq, which lists jQuery on four ecosystems
# alongside two Django ranges. Applying the jQuery bounds to a Django pin is
# how Django 4.2.30 briefly read as vulnerable to a jQuery bug.
MULTI_PACKAGE_ADVISORY = {
    "affected": [
        {
            "package": {"name": "jquery", "ecosystem": "npm"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "1.1.4"}, {"fixed": "3.4.0"}],
                }
            ],
        },
        {
            "package": {"name": "jquery-rails", "ecosystem": "RubyGems"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "4.3.4"}],
                }
            ],
        },
        {
            "package": {"name": "django", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.0a1"}, {"fixed": "2.1.9"}],
                }
            ],
        },
    ]
}


def test_other_packages_in_a_multi_package_advisory_are_ignored() -> None:
    """Only our package's entry may bound our version."""
    affected = affected_ranges.affected_versions_from_osv(
        MULTI_PACKAGE_ADVISORY, "django", "PyPI"
    )
    assert affected.ranges == (
        affected_ranges.AffectedRange(
            constraints=(
                affected_ranges.VersionConstraint(">=", "2.0a1"),
                affected_ranges.VersionConstraint("<", "2.1.9"),
            )
        ),
    )
    assert (
        affected_ranges.evaluate_applicability(
            affected, "4.2.30", VersionScheme.PEP440
        ).status
        is Applicability.NOT_AFFECTED
    )


def test_same_name_in_another_ecosystem_is_ignored() -> None:
    """A name collision across ecosystems must not import the wrong bounds."""
    payload = {
        "affected": [
            {
                "package": {"name": "jquery", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "9.9.9"}],
                    }
                ],
            },
            {
                "package": {"name": "jquery", "ecosystem": "NuGet"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                    }
                ],
            },
        ]
    }
    affected = affected_ranges.affected_versions_from_osv(payload, "jQuery", "NuGet")
    assert (
        affected_ranges.evaluate_applicability(
            affected, "2.0.0", VersionScheme.NUGET
        ).status
        is Applicability.NOT_AFFECTED
    )


def test_git_ranges_are_not_fed_to_a_version_comparator() -> None:
    """Commit hashes are not versions; a GIT-only advisory stays unknown."""
    affected = affected_ranges.affected_versions_from_osv(
        {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://example.invalid/pkg",
                            "events": [
                                {"introduced": "0" * 40},
                                {"fixed": "a" * 40},
                            ],
                        }
                    ]
                }
            ]
        },
        None,
    )
    assert affected.is_empty()
    result = affected_ranges.evaluate_applicability(
        affected, "1.0", VersionScheme.SEMVER
    )
    assert result.status is Applicability.UNKNOWN
    assert result.reason == REASON_NO_RANGE_DATA


def test_enumerated_versions_match_across_spellings() -> None:
    """The explicit OSV enumeration is matched with the ecosystem's ordering."""
    affected = affected_ranges.affected_versions_from_osv(
        {"affected": [{"versions": ["1.2.0", "1.3.0"]}]}, None
    )
    assert (
        affected_ranges.evaluate_applicability(
            affected, "1.2", VersionScheme.PEP440
        ).status
        is Applicability.AFFECTED
    )
    assert (
        affected_ranges.evaluate_applicability(
            affected, "1.4", VersionScheme.PEP440
        ).status
        is Applicability.NOT_AFFECTED
    )


# --------------------------------------------------------------------------
# GitHub Advisory ranges
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "range_text,version,expected",
    [
        (">= 4.0, < 4.0.4", "4.0.2", Applicability.AFFECTED),
        (">= 4.0, < 4.0.4", "4.0.4", Applicability.NOT_AFFECTED),
        (">= 4.0, < 4.0.4", "3.9", Applicability.NOT_AFFECTED),
        ("<= 1.0.8", "1.0.8", Applicability.AFFECTED),
        ("<= 1.0.8", "1.0.9", Applicability.NOT_AFFECTED),
        ("= 0.2.0", "0.2.0", Applicability.AFFECTED),
        ("= 0.2.0", "0.2.1", Applicability.NOT_AFFECTED),
        ("< 0.1.11", "0.1.10", Applicability.AFFECTED),
    ],
)
def test_github_vulnerable_version_ranges(
    range_text: str, version: str, expected: Applicability
) -> None:
    """One comma-separated conjunction, as GitHub writes it; parse, don't drop."""
    affected = affected_ranges.affected_versions_from_github_range(range_text)
    result = affected_ranges.evaluate_applicability(
        affected, version, VersionScheme.PEP440
    )
    assert result.status is expected


def test_unparseable_github_range_is_not_guessed_at() -> None:
    """An unrecognized range shape yields no data rather than a wrong bound."""
    assert affected_ranges.affected_versions_from_github_range("~> 1.2").is_empty()
    assert affected_ranges.affected_versions_from_github_range(None).is_empty()
    assert affected_ranges.affected_versions_from_github_range("").is_empty()


# --------------------------------------------------------------------------
# Per-ecosystem range matching
# --------------------------------------------------------------------------


ECOSYSTEM_CASES = [
    # (ecosystem, introduced, fixed, installed, expected)
    ("python", "1.0", "1.10", "1.9", Applicability.AFFECTED),
    ("python", "1.0", "1.10", "1.10", Applicability.NOT_AFFECTED),
    ("python", "0", "2.0", "2.0rc1", Applicability.AFFECTED),
    ("python", "0", "2.0", "2.0.post1", Applicability.NOT_AFFECTED),
    ("nodejs", "1.0.0", "1.10.0", "1.9.0", Applicability.AFFECTED),
    ("nodejs", "0", "2.0.0", "2.0.0-rc.1", Applicability.AFFECTED),
    ("nodejs", "0", "2.0.0", "2.0.0", Applicability.NOT_AFFECTED),
    ("ruby", "0", "1.0.0", "1.0.0.beta", Applicability.AFFECTED),
    ("ruby", "0", "1.0.0", "1.0.0", Applicability.NOT_AFFECTED),
    ("maven", "0", "1.0", "1.0-alpha", Applicability.AFFECTED),
    ("maven", "0", "1.0", "1.0", Applicability.NOT_AFFECTED),
    ("maven", "0", "1.0", "1.0-sp", Applicability.NOT_AFFECTED),
    ("nuget", "0", "1.0.0", "1.0.0-Beta", Applicability.AFFECTED),
    ("nuget", "0", "1.0.0", "1.0.0.0", Applicability.NOT_AFFECTED),
]


@pytest.mark.parametrize(
    "ecosystem,introduced,fixed,installed,expected", ECOSYSTEM_CASES
)
def test_range_matching_uses_each_ecosystems_ordering(
    ecosystem: str,
    introduced: str,
    fixed: str,
    installed: str,
    expected: Applicability,
) -> None:
    """The same range shape resolves differently per ecosystem, correctly."""
    advisory = {
        "id": "TEST-1",
        "source": "OSV",
        "severity": "HIGH",
        "normalized_severity": "HIGH",
        "affected_versions": affected_ranges.affected_versions_from_osv(
            {
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": introduced},
                                    {"fixed": fixed},
                                ],
                            }
                        ]
                    }
                ]
            },
            None,
        ).to_payload(),
    }
    annotated = annotate_vulnerabilities_for_scoring(
        [advisory], "LOW", installed, ecosystem
    )
    assert annotated[0]["version_match"] == expected.value
