#!/usr/bin/env python3
"""Capture live registry payloads as adapter-conformance fixtures (#73, #145).

Fixtures for the adapter-conformance harness are **captured, never authored**.
A hand-written fixture cannot detect a dead read, because it encodes the same
assumption the parser makes: the key the adapter looks for is present in the
fixture and absent from the registry. Five confirmed dead reads survived that
way (#145), and the npm ``deprecated`` key in #142 survived it for the life of
the adapter.

This script is the only thing in the repository that talks to a registry. It is
**never run by CI** — the test suite replays what is recorded here and fails on
any request it has no recording for. Run it by hand (or from the
``registry-fixtures`` dispatch workflow), review the diff, and commit it.

    python scripts/capture_registry_fixtures.py            # everything
    python scripts/capture_registry_fixtures.py --ecosystem nodejs
    python scripts/capture_registry_fixtures.py --check    # report staleness only

What to capture is declared in ``testing/fixtures/registry/manifest.json``,
which the harness reads too, so the two cannot drift.

Trimming rule
-------------
Reducers may remove **volume** and must never remove **key diversity**. Dropping
190 of 200 ``versions`` entries is volume. Dropping a key the adapter does not
yet parse is key diversity, and those are precisely the keys that reveal the
next dead read — the ``versions[<latest>].deprecated`` that #142 needed was one
of them. So: no reducer deletes a schema key, ever. Long string *values* are
truncated (the key survives, and every value the adapters read is short), and
version-keyed collections are sampled down to the entries the adapters resolve
against plus the oldest and newest.

Untrusted input
---------------
Captured payloads are untrusted data (#160's security condition). This script
only fetches ``https`` URLs whose host is in the manifest allowlist, caps the
response it will read, redacts anything that looks like a credential, and
writes only to ``testing/fixtures/registry/<ecosystem>/<fixture>.json`` with
both path segments validated against a strict pattern. Nothing in a fetched
payload is ever used to build a path or a URL.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "testing" / "fixtures" / "registry"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"

USER_AGENT = "dependency-risk-profiler (conformance fixture capture)"
REQUEST_TIMEOUT = 30
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Fixture and ecosystem ids become path segments, so they are validated rather
# than trusted. No dots-only names, no separators, no traversal.
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Key names whose values are redacted before anything is written to disk. No
# public registry document should carry these; the point is that a private or
# proxying registry cannot leak one into the repository.
SECRET_KEY_TOKENS: Tuple[str, ...] = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "passwd",
    "secret",
    "session",
    "token",
    "api_key",
    "apikey",
    "private_key",
)
REDACTED = "[redacted-by-capture]"

# How many entries of npm's ``users`` (who starred the package) to keep.
_USERS_SAMPLE = 5

# Value shapes that look like credentials wherever they appear.
SECRET_VALUE_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"://[^/\s:@]+:[^/\s@]+@"),  # userinfo in a URL
)


class CaptureError(RuntimeError):
    """Raised when a capture cannot be completed safely."""


def load_manifest() -> Dict[str, object]:
    """Return the fixture manifest.

    Returns:
        The parsed ``manifest.json``.
    """
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        manifest: Dict[str, object] = json.load(handle)
    return manifest


def fixture_path(ecosystem: str, name: str) -> Path:
    """Return the on-disk path for a fixture, refusing anything outside the root.

    Args:
        ecosystem: Ecosystem key from the manifest.
        name: Fixture id from the manifest.

    Returns:
        The resolved path under the fixture root.

    Raises:
        CaptureError: If either id fails validation or escapes the root.
    """
    for segment in (ecosystem, name):
        if not SAFE_ID.match(segment):
            raise CaptureError(f"unsafe fixture id: {segment!r}")
    root = FIXTURE_ROOT.resolve()
    path = (root / ecosystem / f"{name}.json").resolve()
    if root not in path.parents:
        raise CaptureError(f"fixture path escapes the fixture root: {path}")
    return path


def fetch(url: str, allowed_hosts: List[str]) -> object:
    """Fetch one registry document.

    Args:
        url: Absolute ``https`` URL from the manifest.
        allowed_hosts: Hosts the capture is permitted to contact.

    Returns:
        The decoded JSON document.

    Raises:
        CaptureError: On a disallowed URL, a non-200, an oversized body, or a
            body that is not JSON.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise CaptureError(f"refusing to fetch {url!r}: not an allowlisted https host")

    response = requests.get(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
        stream=True,
    )
    if response.status_code != 200:
        raise CaptureError(f"{url} answered {response.status_code}")

    body = response.raw.read(MAX_RESPONSE_BYTES + 1, decode_content=True)
    if len(body) > MAX_RESPONSE_BYTES:
        raise CaptureError(f"{url} exceeded the {MAX_RESPONSE_BYTES}-byte read cap")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CaptureError(f"{url} did not answer JSON: {exc}") from exc


def redact(value: object, key: Optional[str] = None) -> object:
    """Return the value with anything credential-shaped replaced.

    Args:
        value: Decoded JSON value.
        key: The mapping key this value was found under, when there is one.

    Returns:
        The value with secret-shaped keys and values redacted.
    """
    if key is not None and any(token in key.lower() for token in SECRET_KEY_TOKENS):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and any(p.search(value) for p in SECRET_VALUE_PATTERNS):
        return REDACTED
    return value


def truncate_strings(value: object, limit: int, counter: List[int]) -> object:
    """Cap long string values, leaving every key in place.

    Args:
        value: Decoded JSON value.
        limit: Maximum characters to keep in any single string.
        counter: Single-element list used to count truncations.

    Returns:
        The value with long strings shortened.
    """
    if isinstance(value, dict):
        return {k: truncate_strings(v, limit, counter) for k, v in value.items()}
    if isinstance(value, list):
        return [truncate_strings(item, limit, counter) for item in value]
    if isinstance(value, str) and len(value) > limit:
        counter[0] += 1
        return value[:limit] + "…[truncated-by-capture]"
    return value


def reduce_none(payload: object, _limit: int) -> Tuple[object, List[str]]:
    """Return the payload unchanged.

    Args:
        payload: Decoded registry document.
        _limit: Unused string cap.

    Returns:
        The payload and an empty list of trimming notes.
    """
    return payload, []


def reduce_npm_packument(payload: object, limit: int) -> Tuple[object, List[str]]:
    """Sample an npm packument's version-keyed collections down to size.

    The retained set is every version any dist-tag points at, plus the oldest
    and newest by publication time. Retained entries keep **all** of their keys,
    and every top-level key of the packument survives — including the ones no
    adapter reads yet.

    Args:
        payload: Decoded ``registry.npmjs.org/<package>`` packument.
        limit: Maximum characters to keep in any single string.

    Returns:
        The reduced packument and human-readable notes about what was dropped.
    """
    if not isinstance(payload, dict):
        return payload, []

    versions = payload.get("versions")
    times = payload.get("time")
    if not isinstance(versions, dict):
        return payload, []

    keep = {v for v in (payload.get("dist-tags") or {}).values() if isinstance(v, str)}
    if isinstance(times, dict):
        dated = sorted(
            (str(v), k)
            for k, v in times.items()
            if k in versions and isinstance(v, str)
        )
        if dated:
            keep.add(dated[0][1])
            keep.add(dated[-1][1])
    keep &= set(versions)
    if not keep:
        keep = {sorted(versions)[-1]}

    notes: List[str] = []
    dropped_versions = len(versions) - len(keep)
    if dropped_versions > 0:
        notes.append(
            f"versions: kept {sorted(keep)}, dropped {dropped_versions} other "
            f"release manifests (volume only; retained manifests keep every key)"
        )
    reduced = dict(payload)
    reduced["versions"] = {v: versions[v] for v in sorted(keep)}

    if isinstance(times, dict):
        kept_times = {k: v for k, v in times.items() if k not in versions or k in keep}
        dropped_times = len(times) - len(kept_times)
        if dropped_times > 0:
            notes.append(
                f"time: dropped {dropped_times} per-version timestamps for "
                f"releases no longer present; created/modified retained"
            )
        reduced["time"] = kept_times

    # ``users`` is the who-starred-it map: thousands of usernames, none of them
    # a schema key. Sampled, not dropped — the key itself has to stay visible.
    users = payload.get("users")
    if isinstance(users, dict) and len(users) > _USERS_SAMPLE:
        sample = sorted(users)[:_USERS_SAMPLE]
        notes.append(
            f"users: kept {_USERS_SAMPLE} of {len(users)} starrer entries "
            f"(volume only; the key is retained)"
        )
        reduced["users"] = {name: users[name] for name in sample}

    counter = [0]
    reduced = truncate_strings(reduced, limit, counter)
    if counter[0]:
        notes.append(f"truncated {counter[0]} string values to {limit} characters")
    return reduced, notes


def reduce_pypi_project(payload: object, limit: int) -> Tuple[object, List[str]]:
    """Sample a PyPI project document's ``releases`` map down to size.

    ``releases`` maps every version to its uploaded files, and requests carries
    163 of them. The retained set is the version ``info`` names as current, the
    oldest release by upload date, and the release holding the **newest** upload
    of any version — that last one is load-bearing, because the adapter derives
    the release cadence from the newest ``upload_time_iso_8601`` anywhere in the
    payload and distribute's newest upload sits on an older line than its final
    version. Retained releases keep all of their files and all of their keys,
    and every top-level key survives, ``ownership`` and ``vulnerabilities``
    included.

    Args:
        payload: Decoded ``pypi.org/pypi/<name>/json`` document.
        limit: Maximum characters to keep in any single string.

    Returns:
        The reduced document and human-readable notes about what was dropped.
    """
    if not isinstance(payload, dict):
        return payload, []

    releases = payload.get("releases")
    notes: List[str] = []
    reduced = dict(payload)

    if isinstance(releases, dict):
        keep = set()
        info = payload.get("info")
        if isinstance(info, dict):
            current = info.get("version")
            if isinstance(current, str):
                keep.add(current)

        dated: List[Tuple[str, str]] = []
        for name, files in releases.items():
            if not isinstance(files, list):
                continue
            stamps = [
                entry["upload_time_iso_8601"]
                for entry in files
                if isinstance(entry, dict)
                and isinstance(entry.get("upload_time_iso_8601"), str)
            ]
            if stamps:
                dated.append((max(stamps), str(name)))
        if dated:
            dated.sort()
            keep.add(dated[0][1])
            keep.add(dated[-1][1])

        keep &= set(releases)
        if not keep and releases:
            keep = {sorted(releases)[-1]}

        dropped = len(releases) - len(keep)
        if dropped > 0:
            notes.append(
                f"releases: kept {sorted(keep)}, dropped {dropped} other "
                f"per-version file lists (volume only; retained releases keep "
                f"every key, including the newest upload the cadence reads)"
            )
        reduced["releases"] = {name: releases[name] for name in sorted(keep)}

    counter = [0]
    result = truncate_strings(reduced, limit, counter)
    if counter[0]:
        notes.append(f"truncated {counter[0]} string values to {limit} characters")
    return result, notes


def reduce_crates_io(payload: object, limit: int) -> Tuple[object, List[str]]:
    """Sample a crates.io crate document's ``versions`` list down to size.

    serde publishes 316 release entries and the raw document is 432 KB, over
    the fixture bound. The retained set is the entry ``crate.max_version``
    points at, the entry ``crate.default_version`` names, the newest and oldest
    by ``created_at``, and the list's first entry — which is the one the
    adapter falls back to when ``max_version`` resolves to nothing, as it does
    on a fully yanked crate. Original order is preserved so that fallback still
    lands on the same release. Retained entries keep every key, ``yanked``,
    ``yank_message`` and ``audit_actions`` included.

    Args:
        payload: Decoded ``crates.io/api/v1/crates/<name>`` document.
        limit: Maximum characters to keep in any single string.

    Returns:
        The reduced document and human-readable notes about what was dropped.
    """
    if not isinstance(payload, dict):
        return payload, []

    versions = payload.get("versions")
    notes: List[str] = []
    reduced = dict(payload)

    if isinstance(versions, list):
        entries = [entry for entry in versions if isinstance(entry, dict)]
        crate = payload.get("crate")
        summary: Dict[str, object] = crate if isinstance(crate, dict) else {}

        keep = set()
        for key in ("max_version", "default_version", "newest_version"):
            pointer = summary.get(key)
            if isinstance(pointer, str):
                keep.add(pointer)
        dated = sorted(
            (entry["created_at"], entry["num"])
            for entry in entries
            if isinstance(entry.get("created_at"), str)
            and isinstance(entry.get("num"), str)
        )
        if dated:
            keep.add(dated[0][1])
            keep.add(dated[-1][1])
        if entries and isinstance(entries[0].get("num"), str):
            keep.add(str(entries[0]["num"]))

        kept = [entry for entry in entries if entry.get("num") in keep]
        if not kept:
            kept = entries[:1]

        dropped = len(versions) - len(kept)
        if dropped > 0:
            notes.append(
                f"versions: kept {sorted(str(e.get('num')) for e in kept)}, "
                f"dropped {dropped} other release entries (volume only; "
                f"retained entries keep every key and their original order)"
            )
        reduced["versions"] = kept

    counter = [0]
    result = truncate_strings(reduced, limit, counter)
    if counter[0]:
        notes.append(f"truncated {counter[0]} string values to {limit} characters")
    return result, notes


REDUCERS = {
    "none": reduce_none,
    "npm-packument": reduce_npm_packument,
    "pypi-project": reduce_pypi_project,
    "crates-io": reduce_crates_io,
}


def capture_one(
    ecosystem: str,
    name: str,
    spec: Dict[str, str],
    manifest: Dict[str, object],
) -> Path:
    """Capture a single fixture and write it to disk.

    Args:
        ecosystem: Ecosystem key from the manifest.
        name: Fixture id from the manifest.
        spec: The fixture's manifest entry (``url`` and ``reducer``).
        manifest: The whole manifest, for the shared limits.

    Returns:
        The path written.

    Raises:
        CaptureError: If the reducer is unknown or the result exceeds the size
            bound the harness enforces at load time.
    """
    reducer = REDUCERS.get(spec["reducer"])
    if reducer is None:
        raise CaptureError(f"unknown reducer {spec['reducer']!r} for {name}")

    raw = fetch(spec["url"], manifest["allowed_hosts"])
    payload, notes = reducer(redact(raw), manifest["max_string_chars"])

    document = {
        "provenance": {
            "source_url": spec["url"],
            "captured_at": dt.datetime.now(dt.timezone.utc).date().isoformat(),
            "captured_by": "scripts/capture_registry_fixtures.py",
            "reducer": spec["reducer"],
            "trimming": notes,
        },
        "payload": payload,
    }
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    encoded = serialized.encode("utf-8")
    if len(encoded) > manifest["max_fixture_bytes"]:
        raise CaptureError(
            f"{ecosystem}/{name} is {len(encoded)} bytes, over the "
            f"{manifest['max_fixture_bytes']}-byte fixture bound; tighten the "
            f"reducer's volume sampling rather than dropping keys"
        )

    path = fixture_path(ecosystem, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")
    return path


def report_staleness(manifest: Dict[str, object]) -> int:
    """Print each fixture's age against the manifest thresholds.

    Args:
        manifest: The parsed manifest.

    Returns:
        Process exit code: 1 when any fixture is past the failure threshold.
    """
    today = dt.date.today()
    worst = 0
    for ecosystem, entry in sorted(manifest["ecosystems"].items()):
        for name in sorted(entry["fixtures"]):
            path = fixture_path(ecosystem, name)
            if not path.exists():
                print(f"MISSING {ecosystem}/{name}")
                worst = 1
                continue
            with path.open(encoding="utf-8") as handle:
                captured = json.load(handle)["provenance"]["captured_at"]
            age = (today - dt.date.fromisoformat(captured)).days
            if age > manifest["fail_after_days"]:
                state, worst = "STALE  ", 1
            elif age > manifest["warn_after_days"]:
                state = "AGEING "
            else:
                state = "OK     "
            print(f"{state} {ecosystem}/{name}: captured {captured} ({age} days ago)")
    return worst


def main() -> int:
    """Run the capture.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ecosystem", help="capture only this ecosystem")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report fixture ages without touching the network",
    )
    args = parser.parse_args()

    manifest = load_manifest()
    if args.check:
        return report_staleness(manifest)

    ecosystems = manifest["ecosystems"]
    if args.ecosystem:
        if args.ecosystem not in ecosystems:
            print(f"unknown ecosystem: {args.ecosystem}", file=sys.stderr)
            return 2
        ecosystems = {args.ecosystem: ecosystems[args.ecosystem]}

    failures = 0
    for ecosystem, entry in sorted(ecosystems.items()):
        for name, spec in sorted(entry["fixtures"].items()):
            try:
                path = capture_one(ecosystem, name, spec, manifest)
            except (CaptureError, requests.RequestException) as exc:
                print(f"FAILED  {ecosystem}/{name}: {exc}", file=sys.stderr)
                failures += 1
                continue
            print(f"CAPTURED {ecosystem}/{name} -> {path.relative_to(Path.cwd())}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
