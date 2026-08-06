"""Recover a CVSS base score from the vector string a publisher shipped.

OSV's ``severity[].score`` is **not a number**. The OSV schema defines it as the
CVSS vector string for the stated ``type`` — ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/
S:U/C:H/I:H/A:H`` — and a survey of 723 advisories across ten ecosystems plus
Debian and Alpine found 837 severity entries, **zero** of them numeric. Handing
that string to ``normalize_cvss_score`` returns ``None`` every time, which is
the #273 dead read.

The vector is not a lossy summary of the score: it *is* the score, written out
metric by metric. CVSS v3.0 and v3.1 base scores are a closed-form function of
the eight base metrics, published in the specification, so recovering the number
is decoding rather than estimating. That is the whole justification for parsing
it here instead of recording the score as unmeasured — nothing is inferred, and
a vector this module cannot decode gets no number at all.

**Scope: CVSS v3.0 and v3.1 only.** v4.0 base scoring is not a formula; it is a
270-entry MacroVector lookup table plus an interpolation over the maximal
vectors of the neighbouring equivalence classes, and NVD publishes only 164
distinct v4 (vector, score) pairs to check an implementation against — far too
few to cover that table. Landing it here would be a table transcribed by hand
and verified on the fraction of itself that a corpus happens to exercise, which
is AGENTS.md rule 2's "the whole shape with the hard parts hollowed out". It is
filed separately with its own acceptance criteria. A v4.0 vector is reported
**unscored**, never approximated from the v3 vector alongside it.

**No new dependency.** The ``cvss`` package on PyPI does this, and AGENTS.md
rule 8 allows an argued exception — but the argument does not get off the ground
here: the v3.x base formula is thirty lines of arithmetic with no security-
sensitive primitive in it, and the crypto carve-out that motivates the exception
path explicitly does not extend to parsing.

**Verification.** ``testing/unit/test_cvss_vector_scoring.py`` replays every
distinct ``(vectorString, baseScore)`` pair NVD publishes in
``testing/fixtures/cvss/nvd_v3_reference_vectors.json`` — captured, not
authored (rule 5) — and asserts the value, not a count.
"""

from __future__ import annotations

import math
from typing import Dict, Mapping, Optional, Tuple

#: The two vector prefixes this module can score. ``CVSS_V3`` in OSV covers
#: both: the type names the major version and the vector names the minor one,
#: and 3.0 and 3.1 differ in exactly one place — the rounding function.
CVSS_V3_0 = "CVSS:3.0"
CVSS_V3_1 = "CVSS:3.1"
SCOREABLE_VERSIONS = frozenset({CVSS_V3_0, CVSS_V3_1})

# Metric values, verbatim from the CVSS v3.1 specification (section 7.4). They
# are identical in v3.0.
_ATTACK_VECTOR: Mapping[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY: Mapping[str, float] = {"L": 0.77, "H": 0.44}
_PRIVILEGES_REQUIRED_UNCHANGED: Mapping[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_REQUIRED_CHANGED: Mapping[str, float] = {"N": 0.85, "L": 0.68, "H": 0.5}
_USER_INTERACTION: Mapping[str, float] = {"N": 0.85, "R": 0.62}
_IMPACT: Mapping[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}
_SCOPE_VALUES = frozenset({"U", "C"})

#: The eight metrics the base score is a function of. All eight are mandatory:
#: a vector missing one states no base score, and guessing the omitted metric
#: would be the same fabrication this module exists to remove.
_BASE_METRICS: Tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

#: Temporal and environmental metrics. They may follow the base metrics in a
#: vector and they cannot change the base score, so they are skipped rather
#: than rejected — but only by name. Two of the 595 CVSS_V3 vectors in the
#: survey carry a trailing ``/E:...``, which is exactly the key diversity a
#: hand-written fixture would have left out (rule 5).
_NON_BASE_METRICS = frozenset(
    {
        "E",
        "RL",
        "RC",
        "CR",
        "IR",
        "AR",
        "MAV",
        "MAC",
        "MPR",
        "MUI",
        "MS",
        "MC",
        "MI",
        "MA",
    }
)


def declared_version(vector: object) -> Optional[str]:
    """Return the CVSS version a vector string declares.

    Read separately from :func:`base_score` so a caller can tell *this is a
    CVSS v4.0 vector and we do not score those yet* from *this is not a CVSS
    vector at all*. Both produce no number; they are different facts, and
    AGENTS.md rule 4 is that they must not arrive indistinguishable.

    Args:
        vector: A registry payload field, which may be any JSON value.

    Returns:
        The declared version prefix, e.g. ``"CVSS:3.1"``, or None when the
        value is not a string that opens with one.
    """
    if not isinstance(vector, str):
        return None
    prefix = vector.strip().split("/", 1)[0].upper()
    if not prefix.startswith("CVSS:"):
        return None
    return prefix


def is_scoreable(version: Optional[str]) -> bool:
    """Return whether this module can compute a base score for a version.

    Args:
        version: A version prefix from :func:`declared_version`.

    Returns:
        True for the CVSS v3.x prefixes, False for everything else including
        None.
    """
    return version in SCOREABLE_VERSIONS


def base_score(vector: object) -> Optional[float]:
    """Return the CVSS base score a v3.x vector string encodes.

    Args:
        vector: A registry payload field, which may be any JSON value.

    Returns:
        The base score in 0.0-10.0, or None when the value is not a CVSS v3.x
        vector this module can read. None is never a score: a vector that fails
        here leaves the advisory's CVSS unmeasured rather than defaulted.
    """
    version = declared_version(vector)
    if not is_scoreable(version) or not isinstance(vector, str):
        return None

    metrics = _parse_metrics(vector)
    if metrics is None:
        return None

    return _base_score_from_metrics(metrics)


def _parse_metrics(vector: str) -> Optional[Dict[str, str]]:
    """Split a v3.x vector into its base metrics, or None if it is malformed.

    Rejects rather than repairs. A duplicated metric, an unrecognised metric
    name, a value the specification does not define for that metric, and a
    missing mandatory metric all mean the same thing here: the publisher did
    not state a base score this code can read.

    Args:
        vector: The vector string, already known to declare a v3.x version.

    Returns:
        The eight base metrics, or None.
    """
    metrics: Dict[str, str] = {}
    fields = vector.strip().split("/")
    for field in fields[1:]:
        name, separator, value = field.partition(":")
        if not separator:
            return None
        name = name.upper()
        value = value.upper()
        if name in metrics:
            return None
        if name in _NON_BASE_METRICS:
            # Recorded as seen so a duplicate is still rejected, then ignored:
            # no temporal or environmental metric participates in the base
            # score.
            metrics[name] = value
            continue
        if name not in _BASE_METRICS:
            return None
        metrics[name] = value

    for name in _BASE_METRICS:
        if name not in metrics:
            return None

    if metrics["AV"] not in _ATTACK_VECTOR:
        return None
    if metrics["AC"] not in _ATTACK_COMPLEXITY:
        return None
    if metrics["PR"] not in _PRIVILEGES_REQUIRED_UNCHANGED:
        return None
    if metrics["UI"] not in _USER_INTERACTION:
        return None
    if metrics["S"] not in _SCOPE_VALUES:
        return None
    for name in ("C", "I", "A"):
        if metrics[name] not in _IMPACT:
            return None

    return metrics


def _base_score_from_metrics(metrics: Mapping[str, str]) -> float:
    """Compute the base score from validated v3.x base metrics.

    The formula is CVSS v3.1 specification section 7.1, which is identical to
    v3.0's except for the rounding function applied at the end — and there is
    no separate v3.0 path here because that difference is not observable on a
    base score. See :func:`_round_up`.

    Args:
        metrics: The eight validated base metrics.

    Returns:
        The base score in 0.0-10.0.
    """
    scope_changed = metrics["S"] == "C"
    privileges = (
        _PRIVILEGES_REQUIRED_CHANGED
        if scope_changed
        else _PRIVILEGES_REQUIRED_UNCHANGED
    )

    impact_sub_score = 1.0 - (
        (1.0 - _IMPACT[metrics["C"]])
        * (1.0 - _IMPACT[metrics["I"]])
        * (1.0 - _IMPACT[metrics["A"]])
    )
    if scope_changed:
        impact = (
            7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02) ** 15
        )
    else:
        impact = 6.42 * impact_sub_score

    if impact <= 0:
        return 0.0

    exploitability = (
        8.22
        * _ATTACK_VECTOR[metrics["AV"]]
        * _ATTACK_COMPLEXITY[metrics["AC"]]
        * privileges[metrics["PR"]]
        * _USER_INTERACTION[metrics["UI"]]
    )

    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08

    return _round_up(min(combined, 10.0))


def _round_up(value: float) -> float:
    """Round up to one decimal, CVSS v3.1's way.

    v3.1 replaced v3.0's ``ceil(x * 10) / 10`` because binary floating point
    made that expression round some values a decimal too high. The
    integer-arithmetic version in the v3.1 specification is reproduced exactly.

    **There is deliberately no v3.0 branch.** The obvious implementation has
    one, and it would never execute differently: enumerating all 2592
    combinations of the eight base metrics finds the two rounding functions
    returning the same score for every one of them, because the v3.0 defect
    needs an unrounded value that the base formula alone cannot produce — it
    takes the temporal or environmental multipliers this module does not
    compute. A branch that cannot change an answer is dead code wearing a
    fidelity costume (AGENTS.md rule 3), so the claim is checked by exhaustive
    enumeration in ``test_cvss_vector_scoring.py`` instead of encoded as a
    branch nobody can observe. Adding temporal or environmental scoring is
    where the v3.0 rounding becomes real, and that test is what will say so.

    Args:
        value: The unrounded score.

    Returns:
        The score rounded up to one decimal place.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0
