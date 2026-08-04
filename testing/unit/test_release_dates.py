"""The registry-first cadence resolver shared by every adapter (#146).

The ordering rule lives in one module so a fix to one ecosystem is a fix to all
of them. These tests pin the rule itself; the adapter tests pin the reads that
feed it.
"""

from datetime import datetime, timezone

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.release_dates import (
    RELEASE_DATE_SOURCE_KEY,
    RELEASE_DATE_SOURCE_REGISTRY,
    RELEASE_DATE_SOURCE_REPOSITORY,
    SOURCE_REPOSITORY_DECLARED,
    SOURCE_REPOSITORY_KEY,
    SOURCE_REPOSITORY_UNDECLARED,
    apply_registry_release_date,
    apply_repository_activity_date,
    newest_timestamp,
    parse_registry_timestamp,
    record_source_repository,
)

REGISTRY_DATE = datetime(2015, 6, 2, tzinfo=timezone.utc)
COMMIT_DATE = datetime(2026, 8, 3, tzinfo=timezone.utc)


def _dependency() -> DependencyMetadata:
    """Return a bare dependency to apply cadence dates to."""
    return DependencyMetadata(name="example", installed_version="1.0.0")


def test_registry_date_wins_over_later_repository_activity() -> None:
    """The inversion #146 is about: the registry answers, the repo refines."""
    dep = _dependency()

    apply_registry_release_date(dep, REGISTRY_DATE)
    apply_repository_activity_date(dep, COMMIT_DATE)

    assert dep.last_updated == REGISTRY_DATE
    assert dep.additional_info[RELEASE_DATE_SOURCE_KEY] == RELEASE_DATE_SOURCE_REGISTRY


def test_repository_activity_fills_a_registry_that_published_nothing() -> None:
    """Repository activity is the fallback, not the discarded option."""
    dep = _dependency()

    apply_registry_release_date(dep, None)
    apply_repository_activity_date(dep, COMMIT_DATE)

    assert dep.last_updated == COMMIT_DATE
    assert (
        dep.additional_info[RELEASE_DATE_SOURCE_KEY] == RELEASE_DATE_SOURCE_REPOSITORY
    )


def test_no_date_from_either_source_leaves_the_signal_unmeasured() -> None:
    """Never substitute a default date: unmeasured stays unmeasured (#74)."""
    dep = _dependency()

    apply_registry_release_date(dep, None)
    apply_repository_activity_date(dep, None)

    assert dep.last_updated is None
    assert RELEASE_DATE_SOURCE_KEY not in dep.additional_info


def test_repository_activity_can_be_refined_by_a_later_registry_read() -> None:
    """Order of calls must not matter: the registry answer is authoritative."""
    dep = _dependency()

    apply_repository_activity_date(dep, COMMIT_DATE)
    apply_registry_release_date(dep, REGISTRY_DATE)

    assert dep.last_updated == REGISTRY_DATE


def test_timestamps_parse_across_the_spellings_registries_publish() -> None:
    """Zulu suffixes, offsets, and any fractional-second width all resolve."""
    parsed = [
        parse_registry_timestamp("2015-06-02T09:12:40.570975Z"),
        parse_registry_timestamp("2026-01-02T08:56:05+00:00"),
        parse_registry_timestamp("2026-06-11T15:12:03.431Z"),
        parse_registry_timestamp("2020-01-01T00:00:00.0000000+00:00"),
        parse_registry_timestamp("2013-10-17T18:23:34"),
    ]

    assert all(value is not None for value in parsed)


def test_unusable_timestamps_are_none_rather_than_now() -> None:
    """A registry that publishes junk leaves the signal unmeasured."""
    for value in (None, "", "never", 1465000000, {"time": "2020-01-01"}):
        assert parse_registry_timestamp(value) is None


def test_newest_timestamp_picks_the_latest_and_ignores_the_unparseable() -> None:
    """The newest upload wins even when it belongs to an older release line."""
    newest = newest_timestamp(
        [
            "2013-07-05T18:19:57.876141Z",
            "UNKNOWN",
            "2016-01-19T00:08:08.054628Z",
            None,
        ]
    )

    assert newest is not None
    assert newest.date().isoformat() == "2016-01-19"


def test_newest_timestamp_of_nothing_is_none() -> None:
    """An empty or wholly unparseable set publishes no date."""
    assert newest_timestamp([]) is None
    assert newest_timestamp(["UNKNOWN", None]) is None


def test_a_declared_repository_is_recorded_only_when_it_is_one() -> None:
    """A docs site or a project landing page is not a source repository."""
    declared = _dependency()
    record_source_repository(declared, "https://github.com/psf/requests")
    assert declared.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_DECLARED

    for not_a_repo in (None, "", "http://readthedocs.org/docs/nose/"):
        dep = _dependency()
        record_source_repository(dep, not_a_repo)
        assert (
            dep.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_UNDECLARED
        )


def test_a_tagged_subpath_still_counts_as_a_declared_repository() -> None:
    """Registries point inside repositories; the root is what matters here."""
    dep = _dependency()

    record_source_repository(dep, "https://github.com/tzinfo/tzinfo/tree/v2.0.6")

    assert dep.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_DECLARED
