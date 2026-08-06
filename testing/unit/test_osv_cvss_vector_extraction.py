"""What the aggregator makes of the CVSS vectors OSV actually sends (#273).

``severity[].score`` is a vector string. Reading it as a number answered None
for every OSV record ever fetched, so ``max_counted_cvss_score`` was
``severity_to_score`` of the label — 3.0, 5.0, 8.0 or 10.0 and nothing else,
and wrong against GitHub's published base score for all six advisories the
sweep checked.

Every advisory named here comes out of a **captured** recording in
``testing/fixtures/osv`` (rule 5), and every expected score is the base score
its publisher states, not one this suite computed. The pipeline under test is
the shipped one from ``requests.post`` down — ``osv_replay`` substitutes the
transport and nothing else, because a test double that re-derived the score
would prove only that the double works (rule 6).
"""

from __future__ import annotations

from typing import Dict

import pytest
from osv_replay import (
    advisories_for,
    annotated_dependency,
    normalized_advisories,
)

from dependency_risk_profiler.models import SecurityMetrics
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import AdvisoryLookupState
from dependency_risk_profiler.vulnerabilities.aggregator import (
    CVSS_NOT_PUBLISHED_REASON,
    CVSS_UNSUPPORTED_VERSION_REASON,
    MALICIOUS_SEVERITY,
    exploit_score_from_cvss,
    exploit_score_from_severity,
    severity_to_score,
)

#: The four values ``max_counted_cvss_score`` could take before #273, being the
#: representative score of each tier that names a CVSS band.
TIER_CONSTANTS = {
    severity_to_score(tier) for tier in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
}


def _certifi(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Dict[str, object]]:
    """Return certifi's captured advisories, keyed by ID.

    Args:
        monkeypatch: pytest's patcher, used only on the HTTP transport.

    Returns:
        Every advisory in the recording, by advisory ID.
    """
    return {
        str(advisory["id"]): advisory
        for advisory in normalized_advisories(
            monkeypatch,
            fixture="pypi_certifi.json",
            package_name="certifi",
            ecosystem="python",
        )
    }


class TestTheVectorIsDecodedToItsPublishedBaseScore:
    """Conformance: the extracted value equals the score its publisher gave."""

    def test_a_v3_vector_yields_the_base_score_github_publishes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GHSA-xqr8-7jwr-rhp7: 7.5, where the tool used to report 8.0.

        One of the six advisories the #273 sweep checked against GitHub's API.
        Its ``database_specific.severity`` is HIGH, so the old code published
        ``severity_to_score("HIGH")`` — 8.0 — for an advisory GitHub scores at
        7.5. The vector says ``AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N``, and that
        is 7.5.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        advisory = _certifi(monkeypatch)["GHSA-xqr8-7jwr-rhp7"]

        assert advisory["cvss_score"] == 7.5
        assert advisory["severity"] == "HIGH"

    def test_the_extracted_score_is_not_the_tier_constant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """7.5 rather than 8.0 is the whole finding, so it is asserted twice.

        A value assertion, not a count: "119 scores extracted" cannot tell a
        corpus of real base scores from a corpus of four tier constants, which
        is precisely how this went unnoticed.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        advisory = _certifi(monkeypatch)["GHSA-xqr8-7jwr-rhp7"]

        assert advisory["cvss_score"] not in TIER_CONSTANTS
        assert advisory["cvss_score"] != severity_to_score(str(advisory["severity"]))


class TestAnUnscoreableVersionIsNamedRatherThanApproximated:
    """Rule 4: "we cannot score this" is not "the score is the older one"."""

    def test_a_v4_entry_is_not_scored_from_the_v3_entry_beside_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GHSA-43fp-rhv2-5gv8 ships both, and neither number is published.

        Its v3.1 vector computes to 6.8 and its v4.0 vector is one this code
        cannot score. Reaching past the v4 entry to publish 6.8 would put a
        number in the report that the record's own label does not follow: a
        publisher that has rescored an advisory under v4.0 sets the label from
        the v4 score, and 41 of the 161 dual-scored advisories in the survey
        have a v3 band that contradicts their label for exactly that reason.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        advisory = _certifi(monkeypatch)["GHSA-43fp-rhv2-5gv8"]

        assert advisory["cvss_score"] is None
        assert advisory["cvss_score"] != 6.8
        assert advisory["cvss_unknown_reason"] == (
            f"{CVSS_UNSUPPORTED_VERSION_REASON}: CVSS:4.0"
        )

    def test_no_severity_block_reads_as_not_published(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GHSA-248v-346w-9cwc has a LOW label and no CVSS at all.

        The label survives untouched. What it does not do is become a number.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        advisory = _certifi(monkeypatch)["GHSA-248v-346w-9cwc"]

        assert advisory["cvss_score"] is None
        assert advisory["cvss_unknown_reason"] == CVSS_NOT_PUBLISHED_REASON
        assert advisory["severity"] == "LOW"
        assert advisory["normalized_severity"] == "LOW"


class TestTheSeverityFallbackIsReachableAgain:
    """Acceptance criterion 2: a vector with no label now states a severity."""

    def test_an_unlabelled_advisory_takes_its_severity_from_its_vector(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PYSEC-2024-230: a CVSS vector, no ``database_specific.severity``.

        ``normalize_vulnerability_severity`` has always had a CVSS fallback for
        exactly this record shape, and it had been unreachable for as long as
        the score arrived None: the advisory normalized to UNKNOWN, and an
        UNKNOWN advisory states no severity, floors no verdict and lands in
        ``severity_unknown_count``. 207 of the 723 advisories in the survey are
        in this state, all of them PYSEC records — *not* RUSTSEC, which
        publishes no severity block at all.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        advisory = _certifi(monkeypatch)["PYSEC-2024-230"]

        assert advisory["severity"] is None
        assert advisory["cvss_score"] == 7.5
        assert advisory["normalized_severity"] == "HIGH"


class TestTheDependencyMetricsStopClaimingAMeasurement:
    """The field, end to end through the real annotator."""

    def test_the_maximum_is_a_score_a_publisher_computed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """certifi 2022.9.24: 7.5, and it is not any tier's constant.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        dependency = annotated_dependency(
            monkeypatch,
            fixture="pypi_certifi.json",
            package_name="certifi",
            ecosystem="python",
            installed_version="2022.9.24",
        )
        metrics = dependency.security_metrics

        assert metrics is not None
        assert metrics.max_cvss_score == 7.5
        assert metrics.max_cvss_score not in TIER_CONSTANTS
        assert metrics.max_vulnerability_severity == "HIGH"

    def test_the_unscored_advisories_are_counted_and_explained(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A null maximum is readable only beside the count it excludes.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        dependency = annotated_dependency(
            monkeypatch,
            fixture="pypi_certifi.json",
            package_name="certifi",
            ecosystem="python",
            installed_version="2022.9.24",
        )
        metrics = dependency.security_metrics

        assert metrics is not None
        assert metrics.cvss_unknown_count is not None
        assert metrics.cvss_unknown_count > 0
        assert set(metrics.cvss_unknown_reasons) <= {
            CVSS_NOT_PUBLISHED_REASON,
            f"{CVSS_UNSUPPORTED_VERSION_REASON}: CVSS:4.0",
        }
        assert sum(metrics.cvss_unknown_reasons.values()) == metrics.cvss_unknown_count


class TestOtherEcosystemsDecodeTheSameWay:
    """The same read, on recordings captured for other issues entirely."""

    @pytest.mark.parametrize(
        ("fixture", "package_name", "ecosystem", "advisory_id", "base_score"),
        [
            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
            ("npm_fsevents.json", "fsevents", "nodejs", "GHSA-8r6j-v8pm-fqw3", 9.8),
            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
            (
                "npm_npm_user_validate.json",
                "npm-user-validate",
                "nodejs",
                "GHSA-pw54-mh39-w3hc",
                7.5,
            ),
            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
            ("npm_lodash.json", "lodash", "nodejs", "GHSA-29mw-wpgm-hmr9", 5.3),
            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
            (
                "go_golang_org_x_net.json",
                "golang.org/x/net",
                "golang",
                "GHSA-2wp2-chmh-r934",
                7.5,
            ),
        ],
    )
    def test_a_captured_advisory_yields_its_published_base_score(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fixture: str,
        package_name: str,
        ecosystem: str,
        advisory_id: str,
        base_score: float,
    ) -> None:
        """Each expected value is the base score the vector encodes.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
            fixture: The captured recording to replay.
            package_name: The package the recording was taken for.
            ecosystem: The tool's ecosystem key.
            advisory_id: The advisory to look at.
            base_score: The base score its vector states.
        """
        advisories = {
            str(advisory["id"]): advisory
            for advisory in normalized_advisories(
                monkeypatch,
                fixture=fixture,
                package_name=package_name,
                ecosystem=ecosystem,
            )
        }

        assert advisories[advisory_id]["cvss_score"] == base_score

    def test_no_captured_advisory_scores_a_tier_constant_by_derivation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The corpus-level shape that made #273 visible, inverted.

        Before the fix, every score in a run came from ``severity_to_score``
        and so took one of four values. After it, the scores are spread across
        the scale — this asserts the spread, because a corpus that collapsed
        back onto four values is the defect returning whatever the per-advisory
        tests say.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        measured = {
            advisory["cvss_score"]
            for advisory in normalized_advisories(
                monkeypatch,
                fixture="go_golang_org_x_net.json",
                package_name="golang.org/x/net",
                ecosystem="golang",
            )
            if isinstance(advisory["cvss_score"], float)
        }

        assert len(measured) > len(TIER_CONSTANTS)
        assert measured - TIER_CONSTANTS


class TestAMergedGroupKeepsScoreAndReasonTogether:
    """#274's merge takes the worst record's severity evidence — all of it."""

    def test_the_reason_travels_with_the_score_it_explains(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """certifi's GHSA and PYSEC records for one vulnerability, collapsed.

        ``_merge_advisory_group`` copies ``severity``, ``normalized_severity``
        and ``cvss_score`` from the worst-scored member and the rest of the
        record from the lexicographically first one. Leaving
        ``cvss_unknown_reason`` behind in the second group would produce a
        record holding one member's score beside another member's explanation
        for having none — measured and unmeasured at once, which is the state
        rule 4 exists to make unrepresentable.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        merged = advisories_for(
            monkeypatch,
            fixture="pypi_certifi.json",
            package_name="certifi",
            ecosystem="python",
        )

        contradictions = [
            advisory
            for advisory in merged
            if advisory.get("cvss_score") is not None
            and advisory.get("cvss_unknown_reason") is not None
        ]
        assert contradictions == []
        assert any(
            advisory.get("cvss_score") is None
            and advisory.get("cvss_unknown_reason") is not None
            for advisory in merged
        )


class TestMaliciousAdvisoriesAreUntouched:
    """#285's tier survives: malware has nothing to score and is not scored."""

    def test_a_malicious_advisory_is_malicious_and_carries_no_cvss(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MAL-2023-462 in the fsevents recording.

        ``MALICIOUS`` sits above ``CRITICAL`` with no CVSS at all, deliberately.
        Nothing in this change may hand it one — least of all the 10.0 the tier
        ladder would have produced for it, which is why ``MALICIOUS`` was kept
        out of ``CVSS_SEVERITY_TIERS`` in the first place.

        fsevents 1.2.9 carries a scored advisory as well, so the dependency's
        maximum is a real 9.8 from GHSA-8r6j-v8pm-fqw3. That is the case worth
        pinning: the malware record contributes nothing to it, and the tier it
        sets is unmoved by the score beside it.

        Args:
            monkeypatch: pytest's patcher, used only on the HTTP transport.
        """
        advisories = {
            str(advisory["id"]): advisory
            for advisory in normalized_advisories(
                monkeypatch,
                fixture="npm_fsevents.json",
                package_name="fsevents",
                ecosystem="nodejs",
            )
        }
        assert advisories["MAL-2023-462"]["cvss_score"] is None
        assert (
            advisories["MAL-2023-462"]["cvss_unknown_reason"]
            == CVSS_NOT_PUBLISHED_REASON
        )

        dependency = annotated_dependency(
            monkeypatch,
            fixture="npm_fsevents.json",
            package_name="fsevents",
            ecosystem="nodejs",
            installed_version="1.2.9",
        )
        metrics = dependency.security_metrics

        assert metrics is not None
        assert metrics.max_vulnerability_severity == MALICIOUS_SEVERITY
        assert metrics.max_cvss_score == 9.8
        assert metrics.cvss_unknown_count == 1


class TestTheExploitSignalStopsReadingAnIncompleteMaximum:
    """The consequence of the fix, handled where it lands.

    Until #273, ``max_counted_cvss_score`` covered every counted advisory:
    anything the source did not score had its tier's representative number
    written in. Nothing could be missing from it, so the exploit signal read it
    alone and took the CVSS branch whenever it was set.

    It is now a maximum over the advisories a publisher *did* score. On a real
    29-package corpus, keeping the old CVSS-first-and-stop order would have
    **lowered** the exploit signal for five of them — pillow and
    ``github.com/docker/docker`` from 1.0 to 0.75, activesupport, flask and the
    openssl crate from 0.75 to 0.45 — because each has a worst advisory scored
    only under CVSS v4.0 and a second-worst scored under v3.1. A fix for a
    field that lied is not allowed to make the tool report less risk.
    """

    def test_a_higher_label_beats_a_lower_measured_maximum(self) -> None:
        """The openssl-crate shape: MEDIUM measured, CRITICAL published.

        The maximum CVSS is real; it is just not the worst advisory's, because
        the worst advisory's CVSS could not be decoded. The severity label is
        what covers all of them.
        """
        metrics = SecurityMetrics(
            counted_vulnerability_count=2,
            max_cvss_score=5.5,
            cvss_unknown_count=1,
            max_vulnerability_severity="CRITICAL",
        )

        score = RiskScorer()._calculate_exploit_score(
            True, metrics, AdvisoryLookupState.COMPLETE
        )

        assert score == exploit_score_from_severity("CRITICAL")
        assert score != exploit_score_from_cvss(5.5)

    def test_a_higher_measured_maximum_still_beats_a_lower_label(self) -> None:
        """The guard is a maximum, not a swap: neither side wins by position."""
        metrics = SecurityMetrics(
            counted_vulnerability_count=1,
            max_cvss_score=9.5,
            cvss_unknown_count=0,
            max_vulnerability_severity="MEDIUM",
        )

        score = RiskScorer()._calculate_exploit_score(
            True, metrics, AdvisoryLookupState.COMPLETE
        )

        assert score == exploit_score_from_cvss(9.5)

    def test_a_malicious_package_is_still_decided_by_its_tier_alone(self) -> None:
        """#285 is untouched: ``MALICIOUS`` short-circuits above all of this.

        A malware advisory that shares an alias group with a CVSS-scored one
        must not be scored off that CVSS — a statement about a vulnerability is
        not a statement about the malware.
        """
        metrics = SecurityMetrics(
            counted_vulnerability_count=2,
            max_cvss_score=2.0,
            cvss_unknown_count=1,
            max_vulnerability_severity=MALICIOUS_SEVERITY,
        )

        score = RiskScorer()._calculate_exploit_score(
            True, metrics, AdvisoryLookupState.COMPLETE
        )

        assert score == exploit_score_from_severity(MALICIOUS_SEVERITY)
