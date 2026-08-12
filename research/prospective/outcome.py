"""Read the cohort's outcome from the registry. **Network.**

Written now, in 2026, because in 2027-08 nobody will remember how this was
meant to be read — and a readout invented after the outcome is visible is the
forking-paths hole §8 exists to close. Registered as frozen alongside the
analysis script.

Two modes, and the difference is the whole point:

- ``--interim`` (§8.1, at 3/6/9 months): cumulative quiet rate and cohort
  integrity **only**. No AUC, no arm compared, no verdict. These exist so a
  base-rate surprise surfaces at month three rather than month twelve, and they
  license no claim whatsoever.
- ``--final`` (at T+12): joins the outcome onto the frozen T-record and emits
  the file ``analyse.py`` reads.

The outcome is *published no release in (T, T+12]*, registry-only, so it cannot
fail for want of a repository that has since disappeared. §4's four edge cases
are censored rather than folded into "quiet": an unpublished package, a name
taken by npm's security holder, and an unresolvable document all have an
**undefined** outcome, not a negative one.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prospective.base_rate_pilot import reduce_packument  # noqa: E402

logger = logging.getLogger(__name__)

REGISTRY = "https://registry.npmjs.org"

#: npm parks names it has taken over on this account. A package here did not go
#: quiet; it was removed, which is a different event (§4).
SECURITY_HOLDER = "npm"


def observe(name: str, t: datetime, session: requests.Session) -> dict:
    """Did ``name`` publish anything after ``t``?"""
    try:
        resp = session.get(f"{REGISTRY}/{quote(name, safe='@')}", timeout=30)
    except requests.RequestException as exc:  # pragma: no cover - network
        return {"name": name, "quiet": None, "censored": "error", "detail": str(exc)}
    if resp.status_code == 404:
        return {"name": name, "quiet": None, "censored": "unresolvable"}
    if resp.status_code != 200:
        return {"name": name, "quiet": None, "censored": "http"}
    try:
        doc = resp.json()
    except ValueError:
        return {"name": name, "quiet": None, "censored": "unparseable"}

    reduced = reduce_packument(name, doc)
    if reduced["status"] == "unpublished":
        return {"name": name, "quiet": None, "censored": "unpublished"}
    if reduced["status"] != "ok":
        return {"name": name, "quiet": None, "censored": reduced["status"]}

    maintainers = {
        m.get("name") for m in (doc.get("maintainers") or []) if isinstance(m, dict)
    }
    if maintainers == {SECURITY_HOLDER}:
        return {"name": name, "quiet": None, "censored": "security_holder"}

    latest = datetime.fromisoformat(reduced["last_publish"].replace("Z", "+00:00"))
    # Deprecation is not a release: a package whose every version is deprecated
    # but which published nothing in the window is quiet, per §4.
    return {
        "name": name,
        "quiet": latest <= t,
        "censored": None,
        "last_publish": reduced["last_publish"],
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scored", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--interim", action="store_true")
    mode.add_argument("--final", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    record = json.loads(args.scored.read_text())
    t = datetime.fromisoformat(record["scored_at"])
    rows = record["packages"]

    session = requests.Session()
    session.headers["user-agent"] = "drp-prospective-outcome (research; via github)"
    with ThreadPoolExecutor(max_workers=10) as executor:
        observations = list(executor.map(lambda r: observe(r["name"], t, session), rows))

    by_name = {o["name"]: o for o in observations}
    resolved = [o for o in observations if o["censored"] is None]
    quiet = sum(1 for o in resolved if o["quiet"])

    summary: Dict[str, object] = {
        "read_at": datetime.now(timezone.utc).isoformat(),
        "t": record["scored_at"],
        "cohort_sha256": record["cohort_sha256"],
        "n": len(rows),
        "resolved": len(resolved),
        "quiet": quiet,
        "quiet_rate": (quiet / len(resolved)) if resolved else None,
        "censored": {
            reason: sum(1 for o in observations if o["censored"] == reason)
            for reason in sorted(
                {o["censored"] for o in observations if o["censored"]}
            )
        },
    }

    if args.interim:
        # §8.1. Deliberately no arms, no AUC, no verdict -- an interim read that
        # compared anything would contaminate the pre-registration it exists to
        # protect.
        summary["mode"] = "interim"
        summary["licenses_no_claim"] = True
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(summary, indent=1))
        print(json.dumps(summary, indent=1))
        return 0

    joined = []
    for row in rows:
        observation = by_name.get(row["name"], {"quiet": None, "censored": "missing"})
        joined.append({**row, "quiet": observation["quiet"]})

    summary["mode"] = "final"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "packages": joined}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
