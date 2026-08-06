"""The CVSS vector decoder, against scores their publishers computed.

#273: OSV's ``severity[].score`` is a CVSS vector string, so every read of it as
a number answered ``None`` and ``max_counted_cvss_score`` was the severity tier
run through ``severity_to_score`` — 3.0, 5.0, 8.0 or 10.0, and wrong against
GitHub's own base score for all six advisories the sweep checked.

Decoding the vector is only an improvement if the arithmetic is exactly right,
so the conformance set here is not a table this repository wrote. It is every
distinct ``(vectorString, baseScore)`` pair in
``testing/fixtures/cvss/nvd_v3_reference_vectors.json``, captured from NVD,
which publishes the vector and the score it computed from that vector side by
side. 498 pairs, 356 of them v3.1 and 142 v3.0 — the two differ only in the
rounding function, and the split is what proves both are exercised.

Assertions are on the **value** (rule 6). A count of "498 vectors parsed" cannot
tell "always right" from "always wrong by 0.1".

The adversarial cases below are **authored**, and labelled as such: a
cooperating registry does not publish a vector with a duplicated metric or an
impossible value, so rule 5's capture requirement does not reach them.
"""

from __future__ import annotations

import itertools
import json
import math
from pathlib import Path
from typing import Dict, Iterator, List

import pytest

from dependency_risk_profiler.vulnerabilities import cvss

REFERENCE_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "cvss"
    / "nvd_v3_reference_vectors.json"
)


def _reference_vectors() -> List[Dict[str, object]]:
    """Return the captured NVD (vector, base score) pairs.

    Returns:
        Every recorded reference vector.
    """
    document = json.loads(REFERENCE_FIXTURE.read_text(encoding="utf-8"))
    rows = document["reference_vectors"]
    assert isinstance(rows, list)
    return rows


REFERENCE_VECTORS = _reference_vectors()


def _every_base_metric_combination() -> Iterator[str]:
    """Yield all 2592 combinations of the eight CVSS v3 base metrics.

    Yields:
        A metric string, e.g. ``AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``.
    """
    for (
        attack_vector,
        complexity,
        privileges,
        interaction,
        scope,
        c,
        i,
        a,
    ) in itertools.product("NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"):
        yield (
            f"AV:{attack_vector}/AC:{complexity}/PR:{privileges}"
            f"/UI:{interaction}/S:{scope}/C:{c}/I:{i}/A:{a}"
        )


def _v3_0_base_score(metrics: str) -> float:
    """Score base metrics the CVSS **v3.0** way, for the rounding comparison.

    A second implementation on purpose, and only for the one question the
    captured NVD corpus cannot answer: whether v3.0's ``ceil(x * 10) / 10``
    ever lands somewhere other than v3.1's integer rounding. NVD's published
    pairs remain the oracle for the formula itself; this exists so the deleted
    v3.0 branch is a measured no-op instead of a claimed one.

    Args:
        metrics: A metric string from :func:`_every_base_metric_combination`.

    Returns:
        The v3.0 base score.
    """
    values = dict(part.split(":", 1) for part in metrics.split("/"))
    attack = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[values["AV"]]
    complexity = {"L": 0.77, "H": 0.44}[values["AC"]]
    changed = values["S"] == "C"
    privileges = (
        {"N": 0.85, "L": 0.68, "H": 0.5}
        if changed
        else {"N": 0.85, "L": 0.62, "H": 0.27}
    )[values["PR"]]
    interaction = {"N": 0.85, "R": 0.62}[values["UI"]]
    impacts = [{"H": 0.56, "L": 0.22, "N": 0.0}[values[name]] for name in "CIA"]

    sub_score = 1.0 - (1.0 - impacts[0]) * (1.0 - impacts[1]) * (1.0 - impacts[2])
    if changed:
        impact = 7.52 * (sub_score - 0.029) - 3.25 * (sub_score - 0.02) ** 15
    else:
        impact = 6.42 * sub_score
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * attack * complexity * privileges * interaction
    combined = impact + exploitability
    if changed:
        combined *= 1.08
    return math.ceil(min(combined, 10.0) * 10.0) / 10.0


class TestCapturedReferenceVectors:
    """Conformance: the decoder reproduces NVD's published base scores."""

    @pytest.mark.parametrize(
        "row",
        REFERENCE_VECTORS,
        ids=[str(row["vector"]) for row in REFERENCE_VECTORS],
    )
    def test_the_decoder_reproduces_the_published_base_score(
        self, row: Dict[str, object]
    ) -> None:
        """Every captured vector decodes to the score its publisher gave it.

        Args:
            row: One captured ``{vector, base_score, cve}`` record.
        """
        assert cvss.base_score(row["vector"]) == pytest.approx(
            row["base_score"], abs=1e-9
        ), f"{row['cve']}: {row['vector']}"

    def test_both_minor_versions_are_exercised(self) -> None:
        """The corpus covers 3.0 and 3.1, which round differently.

        Not a coverage assertion dressed up: v3.1 exists because v3.0's
        ``ceil(x * 10) / 10`` rounded some scores a decimal too high, so a
        corpus of one version would leave the other's rounding untested and
        every 3.0 advisory silently a tenth out.
        """
        versions = {str(row["vector"]).split("/", 1)[0] for row in REFERENCE_VECTORS}
        assert versions == {"CVSS:3.0", "CVSS:3.1"}

    def test_v3_0_rounding_would_change_no_base_score_anywhere(self) -> None:
        """Why there is one rounding function and not two.

        v3.1 replaced v3.0's ``ceil(x * 10) / 10`` with integer arithmetic
        because floating point made the former round some values a decimal too
        high. The natural reading is that a v3.0 vector must therefore be
        rounded v3.0's way — and it is wrong: over **all 2592** combinations of
        the eight base metrics, the two disagree on nothing. The v3.0 defect
        needs an unrounded value the base formula alone never produces.

        This computes v3.0's published expression independently and asserts the
        agreement across the whole space, so the deleted branch is a proven
        no-op rather than an assumed one. If temporal or environmental scoring
        is ever added, this is the test that fails and says a v3.0 rounding
        path is now real.
        """
        disagreements = []
        checked = 0
        for metrics in _every_base_metric_combination():
            shipped = cvss.base_score(f"CVSS:3.0/{metrics}")
            checked += 1
            if _v3_0_base_score(metrics) != shipped:
                disagreements.append(metrics)
        assert checked == 2592
        assert disagreements == []


class TestVersionsThisModuleDoesNotScore:
    """A version we cannot compute is named, not approximated."""

    def test_a_v4_vector_is_not_scored(self) -> None:
        """CVSS v4.0 base scoring is not implemented and does not pretend."""
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert cvss.base_score(vector) is None

    def test_a_v4_vector_still_states_its_version(self) -> None:
        """The caller can tell "v4, unsupported" from "not a CVSS at all"."""
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert cvss.declared_version(vector) == "CVSS:4.0"
        assert cvss.is_scoreable("CVSS:4.0") is False

    def test_a_v2_vector_is_not_scored(self) -> None:
        """CVSS v2 vectors carry no ``CVSS:`` prefix and are not read."""
        assert cvss.base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
        assert cvss.declared_version("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None


class TestAuthoredAdversarialVectors:
    """AUTHORED, not captured: malformed input a registry never sends."""

    @pytest.mark.parametrize(
        "vector",
        [
            "",
            "CVSS:3.1",
            "CVSS:3.1/",
            # Mandatory metric missing: A is absent.
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            # Value the specification does not define for that metric.
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
            # Metric stated twice, with different values.
            "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            # A metric name that is not CVSS at all.
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q",
            # A segment with no colon in it.
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/junk",
            # The right shape under a version that does not exist.
            "CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ],
    )
    def test_a_malformed_vector_scores_nothing(self, vector: str) -> None:
        """Malformed input yields no score rather than a partial one.

        Args:
            vector: An authored malformed vector string.
        """
        assert cvss.base_score(vector) is None

    @pytest.mark.parametrize(
        "value", [None, True, False, 9.8, 0, [], {}, {"score": 9.8}]
    )
    def test_a_non_string_payload_value_scores_nothing(self, value: object) -> None:
        """A JSON value that is not a string is not a vector.

        ``9.8`` is the interesting one: a float *is* a plausible CVSS score,
        and accepting it here would re-open the read this module replaced.

        Args:
            value: A non-string JSON value from a registry payload.
        """
        assert cvss.base_score(value) is None
        assert cvss.declared_version(value) is None

    def test_trailing_temporal_metrics_do_not_change_the_base_score(self) -> None:
        """Temporal metrics may follow the base metrics and are ignored.

        Not hypothetical: two of the 595 ``CVSS_V3`` vectors in the OSV survey
        carry a trailing ``/E:...``. The base score is a function of the eight
        base metrics alone, so appending one must not move it — and must not
        make the vector unreadable either, which is the other way to lose it.
        """
        base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert cvss.base_score(base) == 9.8
        assert cvss.base_score(base + "/E:U") == 9.8
        assert cvss.base_score(base + "/E:U/RL:O/RC:C") == 9.8

    def test_a_zero_impact_vector_scores_a_measured_zero(self) -> None:
        """No impact is a base score of 0.0, which is a measurement.

        The distinction this whole issue turns on: 0.0 here is what the vector
        says, not the absence of an answer.
        """
        assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0

    def test_the_lowest_and_highest_scores_are_reachable(self) -> None:
        """The ends of the scale come out as the specification states them."""
        assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
        assert cvss.base_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L") == 1.6
