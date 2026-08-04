"""The one output contract both reporters owe their callers (#164, #162, #57).

Before schema v2, ``analyze --output json`` and ``scan-org`` described the same
concept and agreed on five keys out of about twenty-one. Everything here is a
guard against that coming back, plus the three defects #162 catalogued inside
the old contract that a purely mechanical unification would have preserved.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, cast

from dependency_risk_profiler.cli.formatter import JsonFormatter
from dependency_risk_profiler.cli.json_v1 import JsonFormatterV1
from dependency_risk_profiler.contract import (
    SCHEMA_VERSION,
    RemediationAction,
    remediation,
    safe_version,
)
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    LicenseCategory,
    LicenseInfo,
    ProjectRiskProfile,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.org_scan.models import (
    AggregatedDependency,
    DependencyKey,
    OrgScanReport,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.report import report_to_dict
from dependency_risk_profiler.org_scan.report_v1 import report_to_dict_v1
from dependency_risk_profiler.signals import (
    SIGNAL_EXPLOIT,
    SIGNAL_MAINTAINED,
    SIGNAL_STALENESS,
    Measurement,
    UnmeasuredReason,
)

#: The keys every ``ScoredDependency`` carries, on either path.
SHARED_KEYS = {
    "name",
    "ecosystem",
    "installed_version",
    "latest_version",
    "last_updated",
    "repository_url",
    "is_deprecated",
    "known_vulnerable",
    "maintainer_count",
    "risk_level",
    # Additive in schema 2 (#242): whether ``risk_level`` is where the weighted
    # mean left it or where a counted advisory held it.
    "verdict_floor",
    "risk_score",
    "risk_factors",
    "insufficient_data",
    "license",
    "community",
    "health",
    "transitive_dependency_count",
    "advisories",
    "signals",
    "field_sources",
    "unknown_signals",
    "measured_signal_count",
    "total_signal_count",
    "extensions",
}

#: Deleted in v2 rather than carried forward: three string formatters over
#: fields already present, and one derivable count.
DELETED_KEYS = {
    "display_name",
    "versions_display",
    "key_signals",
    "unknown_signal_count",
    # The renames v2 collapsed. Their presence would mean a path kept a private
    # spelling of a shared field.
    "version",
    "component_scores",
    "scores",
    "has_known_exploits",
    "vulnerabilities",
    "vulnerability_summary",
    "metadata",
}


def _metadata() -> DependencyMetadata:
    """Build a dependency with every fact an analyze run actually computes.

    Returns:
        The populated metadata.
    """
    return DependencyMetadata(
        name="jinja2",
        installed_version="3.1.2",
        latest_version="3.1.6",
        last_updated=datetime(2024, 3, 1, 12, 0, 0),
        maintainer_count=2,
        is_deprecated=False,
        has_known_exploits=True,
        repository_url="https://github.com/pallets/jinja",
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=None,
        license_info=LicenseInfo(
            license_id="BSD-3-Clause",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            url="https://example.invalid/license",
            risk_level=RiskLevel.LOW,
        ),
        community_metrics=CommunityMetrics(
            star_count=10_000,
            contributor_count=300,
            commit_frequency=4.5,
            last_release_date=datetime(2024, 3, 1),
            installed_release_date=datetime(2022, 4, 1),
        ),
        security_metrics=SecurityMetrics(
            vulnerability_count=3,
            counted_vulnerability_count=1,
            filtered_vulnerability_count=1,
            filtered_vulnerability_reasons={"withdrawn": 1},
            applicability_unknown_count=1,
            applicability_unknown_reasons={"no_affected_ranges": 1},
            max_cvss_score=7.5,
            max_vulnerability_severity="HIGH",
            vulnerability_details=[
                {
                    "id": "GHSA-xxxx",
                    "counted_in_score": True,
                    "fixed_versions": ["3.1.4"],
                }
            ],
        ),
    )


def _score() -> DependencyRiskScore:
    """Build a scored dependency with one measured zero and one unmeasured signal.

    Returns:
        The risk score.
    """
    return DependencyRiskScore(
        dependency=_metadata(),
        staleness_score=0.0,
        exploit_score=1.0,
        total_score=3.2,
        risk_level=RiskLevel.MEDIUM,
        factors=["Known security issues (1 counted, max severity HIGH)"],
        unknown_signals=[SIGNAL_MAINTAINED],
        measured_signal_count=2,
        total_signal_count=3,
        weighted_signals=(
            # A signal somebody measured, and the answer was zero.
            (SIGNAL_STALENESS, Measurement.measured(0.0), 0.25),
            (SIGNAL_EXPLOIT, Measurement.measured(1.0), 0.5),
            # A signal nobody could measure, with the reason preserved.
            (
                SIGNAL_MAINTAINED,
                Measurement.unmeasured(UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE),
                0.2,
            ),
        ),
    )


def _profile() -> ProjectRiskProfile:
    """Wrap the scored dependency in a one-manifest profile.

    Returns:
        The profile.
    """
    return ProjectRiskProfile(
        manifest_path="/tmp/requirements.txt",
        ecosystem="python",
        dependencies=[_score()],
        medium_risk_dependencies=1,
        unknown_signal_count=1,
        scan_time=datetime(2026, 8, 4, 9, 0, 0),
    )


def _org_report() -> OrgScanReport:
    """Wrap the same scored dependency in a one-repository org report.

    Returns:
        The org scan report.
    """
    key = DependencyKey(ecosystem="python", name="jinja2", version="3.1.2")
    aggregate = AggregatedDependency(
        key=key,
        risk_score=_score(),
        repositories={"acme/web"},
        manifests={"acme/web:requirements.txt"},
        repo_refs={
            "acme/web": RepositoryRef(
                full_name="acme/web",
                name="web",
                default_branch="main",
                html_url="https://github.com/acme/web",
                archived=False,
                fork=False,
            )
        },
        manifest_paths_by_repo={"acme/web": {"requirements.txt"}},
        advisory_summary="1 scored / 1 filtered",
        version_specs={">=3.1.2", "3.1.2"},
    )
    return OrgScanReport(
        org="acme",
        account_type="organization",
        generated_at=datetime(2026, 8, 4, 9, 0, 0),
        repositories_scanned=["acme/web"],
        manifests_scanned=["acme/web:requirements.txt"],
        unique_dependency_count=1,
        parse_failures=[],
        unreadable_manifests=[],
        inventory=[aggregate],
        most_exposed_risky_dependencies=[aggregate],
        riskiest_repositories=[],
        high_risk_dependency_count=0,
        high_risk_exposed_repository_count=0,
        headline="1 known-vulnerable · 0 high-risk · 1 dependency across 1 repo",
    )


def _analyze_dependency() -> Dict[str, object]:
    """Return the analyze path's serialized dependency.

    Returns:
        The ``ScoredDependency`` entry.
    """
    profile = _profile()
    document = JsonFormatter()._profile_dict(profile)
    return cast(List[Dict[str, object]], document["dependencies"])[0]


def _org_dependency() -> Dict[str, object]:
    """Return the org path's serialized dependency.

    Returns:
        The ``ScoredDependency`` entry.
    """
    document = report_to_dict(_org_report())
    return cast(List[Dict[str, object]], document["inventory"])[0]


def test_both_paths_serialize_the_same_shape() -> None:
    """INVARIANT (#164): one concept, one parser.

    The whole justification for this work is API stability, so the guard is on
    the key set rather than on a sample of keys: a path that grows a private
    spelling of a shared field fails here.
    """
    analyze_keys = set(_analyze_dependency())
    org_keys = set(_org_dependency())

    assert analyze_keys == SHARED_KEYS
    assert org_keys == SHARED_KEYS


def test_neither_path_keeps_a_renamed_or_derivable_field() -> None:
    """REGRESSION: the renames and the four deletions stay deleted."""
    for entry in (_analyze_dependency(), _org_dependency()):
        assert DELETED_KEYS.isdisjoint(entry)


def test_shared_values_agree_across_paths() -> None:
    """INVARIANT: the same score serializes to the same shared values."""
    analyze_entry = _analyze_dependency()
    org_entry = _org_dependency()

    for key in SHARED_KEYS - {"extensions"}:
        assert analyze_entry[key] == org_entry[key], key


def test_analyze_serializes_the_licence_it_computed() -> None:
    """REGRESSION (#162.1): a licence score with no licence is not actionable.

    ``analyze`` called ``analyze_license`` on every dependency, emitted
    ``scores.license_score`` and never said which licence produced it.
    """
    licence = cast(Dict[str, object], _analyze_dependency()["license"])

    assert licence["id"] == "BSD-3-Clause"
    assert licence["category"] == "PERMISSIVE"
    assert licence["is_approved"] is True
    assert licence["risk_level"] == "LOW"


def test_analyze_serializes_the_community_metrics_it_computed() -> None:
    """REGRESSION (#162.1): same defect, the other half of the payload."""
    community = cast(Dict[str, object], _analyze_dependency()["community"])

    assert community["star_count"] == 10_000
    assert community["contributor_count"] == 300
    assert community["commit_frequency"] == 4.5
    assert community["last_release_date"] == "2024-03-01T00:00:00"


def test_the_advisory_list_is_emitted_exactly_once() -> None:
    """REGRESSION (#162.2): v1 carried one list under two top-level keys.

    Two keys pointing at one object is a divergence bug that has not happened
    yet, and a consumer cannot tell from the payload that they are the same.
    """
    for entry in (_analyze_dependency(), _org_dependency()):
        advisories = cast(Dict[str, object], entry["advisories"])
        details = advisories["details"]
        holders = [key for key, value in entry.items() if value == details]

        assert holders == [], holders
        assert isinstance(details, list)
        assert len(details) == 1


def test_applicability_unknown_survives_both_paths() -> None:
    """REGRESSION (#162.3): scan-org dropped the honest-unknown counts (#61)."""
    for entry in (_analyze_dependency(), _org_dependency()):
        advisories = cast(Dict[str, object], entry["advisories"])

        assert advisories["applicability_unknown"] == 1
        assert advisories["applicability_unknown_reasons"] == {"no_affected_ranges": 1}


def test_unmeasured_is_structurally_distinct_from_a_measured_zero() -> None:
    """INVARIANT (#164, #198): a consumer must never confuse the two.

    v1 flattened both to a bare ``null`` or a bare number, so "we measured 0"
    and "we could not measure" were indistinguishable and the reason was lost
    entirely at the scorer boundary.
    """
    for entry in (_analyze_dependency(), _org_dependency()):
        signals = cast(Dict[str, Dict[str, object]], entry["signals"])

        measured_zero = signals[SIGNAL_STALENESS]
        assert measured_zero == {"state": "measured", "value": 0.0, "reason": None}

        unmeasured = signals[SIGNAL_MAINTAINED]
        assert unmeasured == {
            "state": "unmeasured",
            "value": None,
            # Not just "absent": *why* it is absent.
            "reason": "source_repository_unreadable",
        }


def test_org_only_concepts_live_under_a_declared_extension() -> None:
    """INVARIANT (#164): an extension adds keys and never renames a shared one."""
    org_entry = _org_dependency()
    extensions = cast(Dict[str, object], org_entry["extensions"])
    org_scan = cast(Dict[str, object], extensions["org_scan"])

    assert set(extensions) == {"org_scan"}
    assert set(org_scan) == {"blast_radius", "usage", "version_specs", "remediation"}
    # Nothing in the extension shadows a shared field name.
    assert SHARED_KEYS.isdisjoint(org_scan)
    # version_specs is kept, not deleted: it is the set of raw specifiers the
    # manifests declared, and no formatting reconstructs it from one version.
    assert org_scan["version_specs"] == [">=3.1.2", "3.1.2"]

    assert _analyze_dependency()["extensions"] == {}


def test_remediation_is_an_enum_an_agent_can_branch_on() -> None:
    """INVARIANT (#164 step 7): a structured action, not a sentence to regex."""
    org_scan = cast(
        Dict[str, object],
        cast(Dict[str, object], _org_dependency()["extensions"])["org_scan"],
    )
    block = cast(Dict[str, object], org_scan["remediation"])

    assert block["action"] == RemediationAction.UPGRADE_TO_FIXED_VERSION.value
    assert block["fix_versions"] == ["3.1.4"]
    assert block["target_version"] == "3.1.4"
    assert isinstance(block["detail"], str) and block["detail"]


def test_remediation_target_version_abstains_when_several_fixes_apply() -> None:
    """GUARD: picking among fix versions needs range resolution we do not do."""
    block = remediation(_metadata(), fix_versions=["3.1.4", "3.2.0"])

    assert block.action is RemediationAction.UPGRADE_TO_FIXED_VERSION
    assert block.fix_versions == ("3.1.4", "3.2.0")
    assert block.target_version is None


def test_remediation_escapes_rather_than_guessing_an_action() -> None:
    """INVARIANT (#164, architect's condition): no force-fitted enum value.

    A vulnerable dependency whose every published fix version is unsafe to
    publish is unclassifiable. Saying so beats naming a neighbouring action.
    """
    block = remediation(_metadata(), fix_versions=["3.1.4; rm -rf /"])

    assert block.action is RemediationAction.UNCLASSIFIED
    assert block.fix_versions == ()
    assert block.target_version is None
    # And the prose the CSV prints is derived from that same structure, so the
    # rejected string does not reach a human-facing report either.
    assert "rm -rf" not in block.sentence()


def test_fix_versions_are_treated_as_untrusted_registry_data() -> None:
    """INVARIANT (#164 binding security condition).

    These strings come from advisory payloads and this contract is documented
    as agent-facing. Nothing that could not be a version is published as one.
    """
    assert safe_version("3.1.4") == "3.1.4"
    assert safe_version("1.0.0-rc.1+build_2") == "1.0.0-rc.1+build_2"
    assert safe_version("3.1.4; rm -rf /") is None
    assert safe_version("$(id)") is None
    assert safe_version("../../etc/passwd") is None
    assert safe_version("3.1.4 && curl evil") is None
    assert safe_version("v" * 500) is None
    assert safe_version("") is None
    assert safe_version(None) is None
    assert safe_version(3.14) is None


def test_no_action_is_distinct_from_unclassified() -> None:
    """GUARD: "nothing to do" and "we cannot say" are different answers."""
    clean = DependencyMetadata(name="clean", installed_version="1.0.0")

    block = remediation(clean, fix_versions=[])

    assert block.action is RemediationAction.NO_ACTION


def test_deprecation_without_an_advisory_is_a_replace() -> None:
    """GUARD: a deprecated package needs a different package, not a bump."""
    deprecated = DependencyMetadata(
        name="old", installed_version="1.0.0", is_deprecated=True
    )

    block = remediation(deprecated, fix_versions=[])

    assert block.action is RemediationAction.REPLACE


def test_both_envelopes_declare_the_schema_version() -> None:
    """INVARIANT (#164, #57): a consumer can tell which contract it is holding."""
    analyze_document = JsonFormatter()._profile_dict(_profile())
    org_document = report_to_dict(_org_report())

    assert analyze_document["schema_version"] == SCHEMA_VERSION
    assert org_document["schema_version"] == SCHEMA_VERSION


def test_known_vulnerable_has_one_definition_across_both_paths() -> None:
    """REGRESSION: v1 called this ``has_known_exploits`` on one path only."""
    assert _analyze_dependency()["known_vulnerable"] is True
    assert _org_dependency()["known_vulnerable"] is True


def test_a_merged_directory_run_keeps_each_dependency_s_ecosystem() -> None:
    """IMPROVEMENT: v1's merged document set ``ecosystem`` to null for a mix."""
    node = ProjectRiskProfile(
        manifest_path="/tmp/package-lock.json",
        ecosystem="nodejs",
        dependencies=[_score()],
        scan_time=datetime(2026, 8, 4, 9, 0, 0),
    )
    document = JsonFormatter()._report_dict([_profile(), node], "/tmp")

    dependencies = cast(List[Dict[str, object]], document["dependencies"])
    assert document["ecosystem"] is None
    assert [dep["ecosystem"] for dep in dependencies] == ["python", "nodejs"]


def test_schema_v1_still_emits_the_pre_unification_shape(tmp_path: Path) -> None:
    """COMPAT: ``--schema v1`` routes to the frozen writers, unchanged.

    The byte-identical guarantee is demonstrated against ``origin/main`` in the
    pull request; this is the shape assertion that keeps the frozen writers
    from being quietly modernized.
    """
    analyze_document = JsonFormatterV1()._profile_dict(_profile())
    analyze_entry = cast(List[Dict[str, object]], analyze_document["dependencies"])[0]

    assert "schema_version" not in analyze_document
    assert analyze_entry["installed_version"] == "3.1.2"
    assert analyze_entry["has_known_exploits"] is True
    assert "scores" in analyze_entry
    assert analyze_entry["unknown_signal_count"] == 1
    summary = cast(Dict[str, object], analyze_entry["vulnerability_summary"])
    assert analyze_entry["vulnerabilities"] == summary["advisories"]

    org_document = report_to_dict_v1(_org_report())
    org_entry = cast(List[Dict[str, object]], org_document["inventory"])[0]

    assert "schema_version" not in org_document
    assert org_entry["version"] == "3.1.2"
    assert org_entry["display_name"] == "python:jinja2@3.1.2"
    assert org_entry["versions_display"] == ">=3.1.2, 3.1.2"
    assert org_entry["key_signals"]
    assert isinstance(org_entry["remediation"], str)
    assert "component_scores" in org_entry
