"""The pinned registry snapshot: its record shape, and how it is read.

Everything downstream of this module is offline. A snapshot is a gzipped JSONL
file of reduced npm packuments plus a ``MANIFEST.json`` carrying a SHA-256 for
each file, and :func:`load_snapshot` refuses a file whose digest does not match
the manifest. That is what makes a rerun a rerun rather than a fresh
measurement against a registry that has moved.

**Why the record is reduced rather than raw.** A full packument for a popular
package runs to megabytes, almost all of it ``dist`` blocks and shasums this
experiment never reads. The reduction keeps the release table and run-length
encodes the four per-version facts the pilot uses, so a cohort fits in a
repository instead of an object store. The reducer drops volume, never key
diversity: a per-version field is either kept for every version or absent from
the schema entirely.

**Run-length, keyed on release index.** ``maintainers``, ``repository``,
``license`` and ``dep_count`` are recorded only where they change, as
``[first_release_index, value]``. npm freezes these inside each version
document at publish time, so the sequence is a step function and storing every
step separately would be storing the same answer eighty times.

**Release times are stored to the day, delta-encoded.** ``days`` holds the
epoch-day of the first release followed by the gap in days to each subsequent
one. Full ISO timestamps cost twelve times as much compressed and buy precision
nothing here uses: every threshold in this experiment is denominated in days or
years. The releases are *ordered* by the registry's full-precision timestamp at
harvest, so day resolution loses the clock time and never the order.

The one place the resolution has to be handled rather than shrugged at is the
boundary at T, and :meth:`PackageRecord.release_index_at` handles it by reading
a release as available only if its day is **strictly** before T's. A release
published at 23:00 on the day of T would otherwise round down to midnight and
be read as available twelve hours before it existed, which is leakage — small,
silent, and in the direction that flatters the model.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, TypeVar

#: Name of the manifest inside a snapshot directory.
MANIFEST_NAME = "MANIFEST.json"

#: Name of the reduced-packument file inside a snapshot directory.
PACKAGES_NAME = "packages.jsonl.gz"

#: Name of the download-count file inside a snapshot directory.
DOWNLOADS_NAME = "downloads.json.gz"

#: Name of the repository-star file inside a snapshot directory.
STARS_NAME = "stars.json.gz"

#: Name of the selection ledger: every sampled name and what happened to it.
LEDGER_NAME = "ledger.json.gz"

#: Name of the release-silence file. Release days only, for **every** sampled
#: package with at least two releases, whether or not it is cohort-eligible.
#: N is chosen from this population and not from the cohort's, because the
#: cohort is required to be live at T and therefore contains almost no silence
#: that never ended — which is exactly the observation the hazard needs.
SILENCES_NAME = "silences.jsonl.gz"


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in chunks.

    Args:
        path: File to digest.

    Returns:
        Lowercase hex digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_registry_time(value: str) -> datetime:
    """Parse an npm registry timestamp into an aware UTC datetime.

    npm writes ``2018-09-05T05:27:47.219Z``. ``datetime.fromisoformat`` accepts
    the trailing ``Z`` only from Python 3.11, and this repository supports 3.10.

    Args:
        value: Timestamp as the registry published it.

    Returns:
        The same instant, timezone-aware in UTC.
    """
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class PackageRecord:
    """One package's release history, reduced to what the pilot reads.

    Releases are ordered by publication time, oldest first. The four run-length
    fields index into that order.
    """

    name: str
    #: ``(version, published_at)`` oldest first.
    releases: Tuple[Tuple[str, datetime], ...]
    #: ``(first_release_index, maintainer usernames)`` at each change.
    maintainers: Tuple[Tuple[int, Tuple[str, ...]], ...]
    #: ``(first_release_index, declared repository URL or None)`` at each change.
    repository: Tuple[Tuple[int, Optional[str]], ...]
    #: ``(first_release_index, declared license string or None)`` at each change.
    license: Tuple[Tuple[int, Optional[str]], ...]
    #: ``(first_release_index, runtime dependency count)`` at each change.
    dep_count: Tuple[Tuple[int, int], ...]
    #: SHA-256 of the packument body this record was reduced from.
    raw_sha256: str

    def release_index_at(self, moment: datetime) -> Optional[int]:
        """Return the index of the newest release published strictly before ``moment``.

        Strictly, because release times are stored to the day. See the module
        docstring: at day resolution, "at or before T" would hand the model
        everything published during T's own day.

        Args:
            moment: The as-of instant, T.

        Returns:
            The release index, or None when the package had no release yet.
        """
        found: Optional[int] = None
        for index, (_, published) in enumerate(self.releases):
            if published < moment:
                found = index
            else:
                break
        return found


StepValue = TypeVar("StepValue")


def _step_value_at(
    steps: Sequence[Tuple[int, StepValue]], index: int
) -> Optional[StepValue]:
    """Return the run-length value covering ``index``.

    Args:
        steps: ``(first_release_index, value)`` pairs in ascending index order.
        index: The release index to resolve.

    Returns:
        The value in force at ``index``, or None when no step starts at or
        before it — which for these fields means the early version documents
        carried no such key at all.
    """
    value: Optional[StepValue] = None
    for start, step_value in steps:
        if start <= index:
            value = step_value
        else:
            break
    return value


def maintainers_at(record: PackageRecord, index: int) -> Optional[Tuple[str, ...]]:
    """Return the maintainer set frozen into the release at ``index``.

    Args:
        record: The package record.
        index: A release index.

    Returns:
        Maintainer usernames, or None when no version document at or before
        ``index`` carried a ``maintainers`` array.
    """
    return _step_value_at(record.maintainers, index)


def repository_at(record: PackageRecord, index: int) -> Optional[str]:
    """Return the repository URL declared by the release at ``index``, if any.

    Args:
        record: The package record.
        index: A release index.

    Returns:
        The declared URL, or None when the release declares none.
    """
    return _step_value_at(record.repository, index)


def license_at(record: PackageRecord, index: int) -> Optional[str]:
    """Return the license string declared by the release at ``index``, if any.

    Args:
        record: The package record.
        index: A release index.

    Returns:
        The declared license, or None when the release declares none.
    """
    return _step_value_at(record.license, index)


def dep_count_at(record: PackageRecord, index: int) -> Optional[int]:
    """Return the runtime dependency count of the release at ``index``.

    Args:
        record: The package record.
        index: A release index.

    Returns:
        The count, or None when no version document at or before ``index``
        recorded one.
    """
    return _step_value_at(record.dep_count, index)


def record_from_json(payload: Dict[str, object]) -> PackageRecord:
    """Build a :class:`PackageRecord` from one decoded JSONL line.

    Args:
        payload: The decoded object.

    Returns:
        The record.

    Raises:
        ValueError: If a required key is missing or carries the wrong shape.
    """
    name = payload.get("name")
    versions_raw = payload.get("versions")
    days_raw = payload.get("days")
    raw_sha256 = payload.get("raw_sha256")
    if not isinstance(name, str) or not isinstance(versions_raw, list):
        raise ValueError("snapshot record needs a string name and a version list")
    if not isinstance(days_raw, list) or len(days_raw) != len(versions_raw):
        raise ValueError(f"snapshot record for {name} has mismatched versions and days")
    if not isinstance(raw_sha256, str):
        raise ValueError(f"snapshot record for {name} carries no raw_sha256")
    for version, delta in zip(versions_raw, days_raw):
        if not isinstance(version, str) or not isinstance(delta, int):
            raise ValueError(f"malformed release entry in {name}")
    releases = list(
        zip(
            [str(version) for version in versions_raw],
            decode_days([int(delta) for delta in days_raw]),
        )
    )

    def steps(key: str) -> List[Tuple[int, object]]:
        raw = payload.get(key)
        if not isinstance(raw, list):
            raise ValueError(f"snapshot record for {name} has no {key} steps")
        out: List[Tuple[int, object]] = []
        for entry in raw:
            if not isinstance(entry, list) or len(entry) != 2:
                raise ValueError(f"malformed {key} step in {name}")
            start, value = entry
            if not isinstance(start, int):
                raise ValueError(f"malformed {key} step in {name}")
            out.append((start, value))
        return out

    maintainers: List[Tuple[int, Tuple[str, ...]]] = []
    for start, value in steps("maintainers"):
        if not isinstance(value, list):
            raise ValueError(f"malformed maintainers step in {name}")
        maintainers.append((start, tuple(str(item) for item in value)))

    repository: List[Tuple[int, Optional[str]]] = []
    for start, value in steps("repository"):
        repository.append((start, value if isinstance(value, str) else None))

    licenses: List[Tuple[int, Optional[str]]] = []
    for start, value in steps("license"):
        licenses.append((start, value if isinstance(value, str) else None))

    dep_counts: List[Tuple[int, int]] = []
    for start, value in steps("dep_count"):
        if not isinstance(value, int):
            raise ValueError(f"malformed dep_count step in {name}")
        dep_counts.append((start, value))

    return PackageRecord(
        name=name,
        releases=tuple(releases),
        maintainers=tuple(maintainers),
        repository=tuple(repository),
        license=tuple(licenses),
        dep_count=tuple(dep_counts),
        raw_sha256=raw_sha256,
    )


@dataclass(frozen=True)
class Snapshot:
    """A verified snapshot directory, loaded into memory."""

    directory: Path
    manifest: Dict[str, object]
    packages: Tuple[PackageRecord, ...]
    #: Release-time sequences for every sampled package with two or more
    #: releases, cohort-eligible or not. The population N is chosen from.
    silences: Tuple[Tuple[datetime, ...], ...]
    #: T (as ``YYYY-MM-DD``) -> package name -> downloads in the 30 days
    #: ending at that T, for every package npm answered for.
    downloads: Dict[str, Dict[str, int]]
    #: Package name -> stargazer count of the declared repository, read today.
    stars: Dict[str, int]

    @property
    def harvested_at(self) -> datetime:
        """Return the instant the harvest ran."""
        value = self.manifest.get("harvested_at")
        if not isinstance(value, str):
            raise ValueError("manifest carries no harvested_at")
        return parse_registry_time(value)


def _read_json_gz(path: Path) -> object:
    """Decode a gzipped JSON document."""
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def decode_days(days: Sequence[int]) -> Tuple[datetime, ...]:
    """Turn a delta-encoded epoch-day list into aware UTC datetimes.

    Args:
        days: The first release's epoch-day, then the gap in days to each
            subsequent release.

    Returns:
        Publication instants, oldest first, at midnight UTC.
    """
    out: List[datetime] = []
    epoch_day = 0
    for position, delta in enumerate(days):
        epoch_day = delta if position == 0 else epoch_day + delta
        out.append(datetime.fromtimestamp(epoch_day * 86400, tz=timezone.utc))
    return tuple(out)


def iter_release_histories(path: Path) -> Iterator[Tuple[datetime, ...]]:
    """Yield one release-time sequence per line of a silences file.

    Args:
        path: The ``silences.jsonl.gz`` file.

    Yields:
        Publication instants per package, oldest first.

    Raises:
        ValueError: If a line is not an object carrying a ``days`` list.
    """
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError(f"{path} contains a non-object line")
            days = payload.get("days")
            if not isinstance(days, list):
                raise ValueError(f"{path} has a line with no days list")
            yield decode_days([int(value) for value in days])


def iter_packages(path: Path) -> Iterator[PackageRecord]:
    """Yield every package record in a gzipped JSONL file.

    Args:
        path: The ``packages.jsonl.gz`` file.

    Yields:
        One record per line.
    """
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError(f"{path} contains a non-object line")
            yield record_from_json(payload)


def verify_checksums(directory: Path) -> None:
    """Check every file the manifest names against its recorded digest.

    Args:
        directory: Snapshot directory.

    Raises:
        FileNotFoundError: If the manifest or a file it names is absent.
        ValueError: If a digest does not match.
    """
    manifest_path = directory / MANIFEST_NAME
    with manifest_path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError(f"{manifest_path} carries no files table")
    for filename, entry in sorted(files.items()):
        if not isinstance(entry, dict):
            raise ValueError(f"{manifest_path} has a malformed entry for {filename}")
        expected = entry.get("sha256")
        actual = sha256_file(directory / filename)
        if actual != expected:
            raise ValueError(
                f"{filename} digest {actual} does not match the pinned {expected}: "
                "the snapshot has changed, so nothing computed from it reproduces"
            )


def load_snapshot(directory: Path) -> Snapshot:
    """Load a snapshot, verifying every pinned digest first.

    Args:
        directory: Snapshot directory holding ``MANIFEST.json``.

    Returns:
        The loaded snapshot.

    Raises:
        ValueError: If a digest does not match, or a file is malformed.
    """
    verify_checksums(directory)
    with (directory / MANIFEST_NAME).open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("manifest is not an object")

    downloads_raw = _read_json_gz(directory / DOWNLOADS_NAME)
    stars_raw = _read_json_gz(directory / STARS_NAME)
    if not isinstance(downloads_raw, dict) or not isinstance(stars_raw, dict):
        raise ValueError("downloads and stars must each be a name -> count object")

    downloads = {
        str(moment): {str(name): int(count) for name, count in table.items()}
        for moment, table in downloads_raw.items()
        if isinstance(table, dict)
    }
    stars = {str(k): int(v) for k, v in stars_raw.items() if v is not None}

    return Snapshot(
        directory=directory,
        manifest=manifest,
        packages=tuple(iter_packages(directory / PACKAGES_NAME)),
        silences=tuple(iter_release_histories(directory / SILENCES_NAME)),
        downloads=downloads,
        stars=stars,
    )
