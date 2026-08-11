"""Stage 3: reconstruct the six signals for the whole resolvable arm.

§9's gate for this stage is a measurement rate: **a signal measured for under
half the subsample is reported unmeasured rather than imputed.** Imputation is
the failure mode being guarded against — a signal filled in at its mean, or at
a confident ``False``, is a signal that discriminates nothing while looking
like it might, and #141 and #218 are both that bug.

Measurement rates are reported against the studied arm (the packages with a
resolvable repository) and against the whole cohort, because those two
denominators answer different questions and quoting only the flattering one is
how coverage stops being a result.
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .clone import clone_directory
from .signals_at_t import POPULARITY_UNMEASURED_REASON, RepoSignals, reconstruct

#: The six signals §4 leaves testable, in the order they are reported.
SIGNALS: Tuple[str, ...] = (
    "health_indicators",
    "security_policy",
    "dependency_update",
    "community_activity",
    "maintained",
    "community_popularity",
)

#: §9 stage 3's gate.
MEASUREMENT_GATE = 0.50


def _measured(signals: RepoSignals, name: str) -> bool:
    """Return whether one signal came back measured for one repository.

    Args:
        signals: The reconstruction.
        name: A member of :data:`SIGNALS`.

    Returns:
        True when the signal has a value.

    Raises:
        ValueError: On an unknown signal name.
    """
    if name == "health_indicators":
        # Production returns None only when all three indicators are None,
        # which for a readable tree cannot happen.
        return signals.has_tests is not None
    if name == "security_policy":
        return signals.has_security_policy is not None
    if name == "dependency_update":
        return signals.has_dependency_update_tools is not None
    if name == "community_activity":
        return signals.commit_frequency is not None
    if name == "maintained":
        return signals.is_maintained is not None
    if name == "community_popularity":
        return False
    raise ValueError(f"unknown signal {name}")


def run(
    slugs: Sequence[str], root: Path, moment: datetime, workers: int
) -> Dict[str, RepoSignals]:
    """Reconstruct every resolved repository.

    Args:
        slugs: Slugs whose clone succeeded.
        root: Clone directory.
        moment: T.
        workers: Concurrent git reads.

    Returns:
        Signals per slug.
    """

    def one(slug: str) -> RepoSignals:
        return reconstruct(clone_directory(root, slug), slug, moment)

    out: Dict[str, RepoSignals] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(one, slugs):
            out[result.slug] = result
    return out


def summarise(
    signals: Dict[str, RepoSignals],
    declarations: Sequence[Dict[str, object]],
    resolved: Sequence[str],
    cohort_size: int,
) -> Dict[str, object]:
    """Assemble stage 3's report.

    Args:
        signals: Reconstruction per slug.
        declarations: Stage 2's per-package declarations.
        resolved: Slugs whose clone succeeded.
        cohort_size: The full cohort, as a second denominator.

    Returns:
        The report document.
    """
    studied = [
        d
        for d in declarations
        if isinstance(d.get("slug"), str) and d["slug"] in set(resolved)
    ]
    errors: Dict[str, int] = {}
    for record in signals.values():
        if record.error is not None:
            errors[record.error] = errors.get(record.error, 0) + 1

    rates: Dict[str, Dict[str, object]] = {}
    for name in SIGNALS:
        packages = sum(
            1
            for d in studied
            if _measured(signals[str(d["slug"])], name)
        )
        repos = sum(1 for record in signals.values() if _measured(record, name))
        rate = packages / len(studied) if studied else 0.0
        rates[name] = {
            "packages_measured": packages,
            "repositories_measured": repos,
            "rate_of_studied_arm": rate,
            "rate_of_cohort": packages / cohort_size if cohort_size else 0.0,
            "passes_gate": rate >= MEASUREMENT_GATE,
            "reported": "measured" if rate >= MEASUREMENT_GATE else "unmeasured",
        }
    rates["community_popularity"]["reason"] = POPULARITY_UNMEASURED_REASON

    # Descriptive, so the reader can see what the tree reads actually found
    # rather than only that they succeeded.
    positives: Dict[str, Optional[float]] = {}
    for label, getter in (
        ("has_tests", lambda r: r.has_tests),
        ("has_ci", lambda r: r.has_ci),
        ("has_contribution_guidelines", lambda r: r.has_contribution_guidelines),
        ("has_security_policy", lambda r: r.has_security_policy),
        ("has_dependency_update_tools", lambda r: r.has_dependency_update_tools),
        ("is_maintained", lambda r: r.is_maintained),
    ):
        values = [getter(r) for r in signals.values() if getter(r) is not None]
        positives[label] = (
            sum(1 for v in values if v) / len(values) if values else None
        )

    return {
        "studied_packages": len(studied),
        "resolved_repositories": len(resolved),
        "repository_read_errors": errors,
        "measurement_gate": MEASUREMENT_GATE,
        "per_signal": rates,
        "signals_reported_unmeasured": [
            name for name in SIGNALS if not rates[name]["passes_gate"]
        ],
        "positive_fraction_over_repositories": positives,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stage 3.

    Args:
        argv: Command line, for tests.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clone-root", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--T", dest="moment", default="2024-08-01")
    args = parser.parse_args(argv)

    moment = datetime.fromisoformat(args.moment).replace(tzinfo=timezone.utc)
    with (args.data / "clones.json").open(encoding="utf-8") as handle:
        clones = json.load(handle)
    with (args.data / "declarations.json").open(encoding="utf-8") as handle:
        declarations = json.load(handle)
    with (args.data / "stage2.json").open(encoding="utf-8") as handle:
        stage2 = json.load(handle)

    resolved = sorted(s for s, v in clones.items() if v["status"] == "ok")
    signals = run(resolved, args.clone_root, moment, args.workers)

    with (args.data / "signals.json").open("w", encoding="utf-8") as handle:
        json.dump(
            {
                slug: {
                    "head_at_t": r.head_at_t,
                    "has_tests": r.has_tests,
                    "has_ci": r.has_ci,
                    "has_contribution_guidelines": r.has_contribution_guidelines,
                    "has_security_policy": r.has_security_policy,
                    "has_dependency_update_tools": r.has_dependency_update_tools,
                    "commit_frequency": r.commit_frequency,
                    "is_maintained": r.is_maintained,
                    "error": r.error,
                }
                for slug, r in sorted(signals.items())
            },
            handle,
            indent=1,
        )

    report = summarise(signals, declarations, resolved, int(stage2["cohort_size"]))
    with (args.data / "stage3.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
    print(json.dumps(report, indent=1, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
