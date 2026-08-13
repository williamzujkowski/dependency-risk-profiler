"""Re-fetch the download comparator, which the harvest recorded as 97% missing.

`downloads` is the registered first comparator for the 2027-08 readout (§1).
The harvest recorded it for **60 of 2,000** packages. Two causes, both mine:

- ``quote(name, safe='@')`` percent-encoded the ``/`` in scoped names, so
  ``@scope/pkg`` became ``@scope%2Fpkg`` and 404'd. 747 packages.
- No backoff. 2,000 requests at ten workers rate-limited the endpoint, and
  every 429 was silently stored as ``None``. 1,193 unscoped names.

A comparator that is 97% absent would have made the 2027 comparison
meaningless, and nothing would have noticed until the readout — the record
carried a number for every package, it was simply ``0``.

Legitimate to fix now: no outcome exists until 2027-08, so this is the same
pre-outcome correction as the enrichment in §14. The 30-day window shifts by a
day against the frozen T, which is immaterial next to 97% missingness and is
recorded rather than hidden.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

API = "https://api.npmjs.org/downloads/point/last-month"

#: Modest, because the endpoint rate-limits and the whole point of this module
#: is that the first run did not respect that.
WORKERS = 3
MAX_ATTEMPTS = 5


def fetch(name: str, session: requests.Session) -> Optional[int]:
    """Downloads for one package, or None when the API never answered.

    ``safe='@/'`` keeps the slash in a scoped name unencoded -- the bug that
    lost 747 packages. A 429 is retried with backoff rather than recorded as an
    absence, which is what lost the other 1,193.
    """
    url = f"{API}/{quote(name, safe='@/')}"
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = session.get(url, timeout=30)
        except requests.RequestException:
            time.sleep(2**attempt)
            continue
        if resp.status_code == 429:
            time.sleep(2**attempt)
            continue
        if resp.status_code == 404:
            # A real answer: the package has no download record.
            return 0
        if resp.status_code != 200:
            time.sleep(2**attempt)
            continue
        try:
            value = resp.json().get("downloads")
        except ValueError:
            return None
        return int(value) if isinstance(value, (int, float)) else None
    return None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cohort", type=Path, required=True)
    ap.add_argument("--canonical", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    names = [r["name"] for r in json.loads(args.cohort.read_text())]

    session = requests.Session()
    session.headers["user-agent"] = "drp-downloads-refetch (research; via github)"
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        values = list(pool.map(lambda n: fetch(n, session), names))

    by_name = dict(zip(names, values))
    resolved = sum(1 for v in values if v is not None)
    logger.info("resolved %d/%d (was 60/2000)", resolved, len(values))

    record = json.loads(args.canonical.read_text())
    patched = 0
    for row in record["packages"]:
        value = by_name.get(row["name"])
        if value is not None:
            row["downloads"] = value
            patched += 1
    record["downloads_refetched"] = {
        "resolved": resolved,
        "of": len(values),
        "patched": patched,
        "note": (
            "The harvest recorded 60/2000; see refetch_downloads.py for the two "
            "causes. Window shifts one day against the frozen T."
        ),
    }
    args.out.write_text(json.dumps(record, indent=1, default=str))
    logger.info("patched %d rows", patched)
    return 0


if __name__ == "__main__":
    sys.exit(main())
