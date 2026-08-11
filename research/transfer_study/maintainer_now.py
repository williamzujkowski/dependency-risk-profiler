"""Harvest the current top-level maintainer set, which is what the tool reads.

`docs/band-crossing-protocol.md`. The only module in this study that opens a
socket, and it fetches exactly three facts per package:

- the packument's **top-level** `maintainers` — npm's *current* owner list, the
  field the shipped tool reads and the one `npm owner add/rm` mutates with no
  publish
- `time.modified`, whose being later than the newest release is snapshot-visible
  evidence that *something* changed without a publish
- the newest release timestamp, to decide whether a package has gone quiet

It deliberately does **not** fetch version documents. Those are in the pinned
snapshot already, and re-reading them today would replace a frozen as-of-T fact
with a current one — the leak every study here is built to avoid.

Unauthenticated: the registry serves packuments without credentials, and asking
for none means there is no token to leak into a log.
"""

from __future__ import annotations

import argparse
import gzip
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REGISTRY = "https://registry.npmjs.org"
USER_AGENT = "drp-band-crossing (research; contact via repository issues)"

#: npm serves an abbreviated packument for this Accept type, but it omits
#: top-level `maintainers` -- the one field this study exists to read. So the
#: full document is requested, and the reduction happens here rather than
#: being delegated to a header that silently drops the subject.
ACCEPT = "application/json"


def fetch_one(name: str, timeout: int = 30) -> Dict[str, object]:
    """Fetch and reduce one packument. Never raises; failures are recorded."""
    quoted = urllib.parse.quote(name, safe="@")
    request = urllib.request.Request(
        f"{REGISTRY}/{quoted}",
        headers={
            "Accept": ACCEPT,
            "Accept-Encoding": "gzip",
            "User-Agent": USER_AGENT,
        },
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                if response.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                document = json.loads(raw)
                break
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return {"name": name, "status": 404}
            if attempt == 0 and error.code in (429, 503):
                time.sleep(10)
                continue
            return {"name": name, "status": error.code}
        except Exception:  # noqa: BLE001 - a transport failure is data here
            if attempt == 0:
                time.sleep(3)
                continue
            return {"name": name, "status": 0}
    else:
        return {"name": name, "status": 0}

    maintainers = document.get("maintainers")
    logins: List[str] = []
    if isinstance(maintainers, list):
        for entry in maintainers:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                logins.append(entry["name"])
            elif isinstance(entry, str):
                logins.append(entry)

    times = document.get("time") if isinstance(document.get("time"), dict) else {}
    release_times = [
        value
        for key, value in times.items()
        if key not in ("created", "modified") and isinstance(value, str)
    ]

    return {
        "name": name,
        "status": 200,
        "maintainers": sorted(set(logins)),
        "modified": times.get("modified"),
        "newest_release": max(release_times) if release_times else None,
    }


def harvest(names: Sequence[str], workers: int = 8) -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, record in enumerate(pool.map(fetch_one, names)):
            out.append(record)
            if index % 200 == 0:
                print(f"  {index}/{len(names)}", flush=True)
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--names", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args(argv)

    names = json.loads(args.names.read_text())
    records = harvest(list(names), args.workers)
    resolved = sum(1 for r in records if r.get("status") == 200)
    args.out.write_text(json.dumps(records, indent=1) + "\n")
    print(f"{resolved}/{len(records)} resolved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
