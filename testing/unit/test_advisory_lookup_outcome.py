"""A vulnerability source that failed must not read as one that found nothing.

The deliverable #219 asks for is the outage test, not the fix alone: force OSV
down for the duration of a scan and assert that every dependency's advisory
signal reads *unmeasured, with a reason* — and that nothing from that run
reached the cache. The cache half is what separates this from an ordinary
fail-open. An empty list written to disk survives the outage and is served back
as a measurement until the TTL expires, so an hour of OSV being unreachable
becomes a day of every package reading advisory-clean.

The counterpart matters just as much and is asserted alongside every outage
case: a genuinely clean package still reads clean, and still caches.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, cast
from unittest import mock

import pytest
import requests

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    AdvisoryLookupState,
    MeasurementState,
    UnmeasuredReason,
)
from dependency_risk_profiler.vulnerabilities import aggregator, aggregator_async
from dependency_risk_profiler.vulnerabilities.aggregator import (
    GitHubAdvisorySource,
    NVDSource,
    OSVSource,
    SourceLookup,
    SourceState,
    combine_source_lookups,
)
from dependency_risk_profiler.vulnerabilities.cache import (
    CACHE_SCHEMA_VERSION,
    VulnerabilityCache,
)

SCANNED_PACKAGES = ("flask", "requests", "urllib3")


@pytest.fixture
def isolated_cache(tmp_path: Path) -> Iterator[VulnerabilityCache]:
    """Point every advisory cache at an empty directory of our own.

    Both caches, deliberately. ``cache_data`` writes to the disk cache *and* an
    in-memory dict, and a test that only inspected the directory would pass
    while the run's verdict sat in the process for the next dependency to
    collect.

    Yields:
        The disk cache the aggregator will use.
    """
    cache = VulnerabilityCache(cache_dir=tmp_path / "vuln_cache")
    saved_memory = dict(aggregator.VULNERABILITY_CACHE)
    aggregator.VULNERABILITY_CACHE.clear()
    with (
        mock.patch.object(aggregator, "disk_cache", cache),
        mock.patch.object(aggregator, "USE_DISK_CACHE", True),
        mock.patch.dict(os.environ, {"DEPENDENCY_RISK_DISABLE_CACHE": "0"}),
    ):
        yield cache
    aggregator.VULNERABILITY_CACHE.clear()
    aggregator.VULNERABILITY_CACHE.update(saved_memory)


def cached_entries(cache: VulnerabilityCache) -> List[Path]:
    """Return every file the disk cache holds.

    Args:
        cache: The cache to inspect.

    Returns:
        Its entries, in no particular order.
    """
    if not cache.cache_dir.exists():
        return []
    return list(cache.cache_dir.glob("*.json"))


def scan_manifest(
    osv_response: Optional[Dict[str, object]],
) -> Dict[str, DependencyMetadata]:
    """Run the scan's advisory stage over a small manifest, with OSV stubbed.

    The stub sits at the HTTP client, not at the source, so the source's own
    "did this answer?" logic is under test rather than mocked away. ``None`` is
    exactly what ``AsyncHTTPClient.post`` returns once its retries are spent.

    Args:
        osv_response: The decoded body OSV returns, or None for an outage.

    Returns:
        The scanned dependencies, keyed by name.
    """
    dependencies = {
        name: DependencyMetadata(
            name=name,
            installed_version="1.0.0",
            additional_info={"ecosystem": "python"},
        )
        for name in SCANNED_PACKAGES
    }

    async def _post(
        self: object, url: str, json_data: object, headers: object = None
    ) -> Optional[Dict[str, object]]:
        return osv_response

    with mock.patch("dependency_risk_profiler.async_http.AsyncHTTPClient.post", _post):
        updated, _ = aggregator_async.aggregate_vulnerability_data_async(
            dependencies,
            api_keys={},
            enable_osv=True,
            enable_nvd=False,
            enable_github=False,
            minimum_severity="LOW",
        )
    return updated


# --- The deliverable -------------------------------------------------------


def test_an_osv_outage_leaves_every_package_unmeasured_and_uncached(
    isolated_cache: VulnerabilityCache,
) -> None:
    """The #219 acceptance case, both halves of it."""
    scanned = scan_manifest(osv_response=None)

    scorer = RiskScorer()
    for name in SCANNED_PACKAGES:
        dependency = scanned[name]
        assert dependency.advisory_lookup_state is AdvisoryLookupState.FAILED
        assert dependency.advisory_sources_unavailable == ("OSV",)

        score = scorer.score_dependency(dependency)
        measurement = score.measurements["exploit"]
        assert measurement.state is MeasurementState.UNMEASURED, (
            f"{name}: an OSV outage scored a value. That value is 0.0 and it "
            f"is indistinguishable from a clean package (#219)."
        )
        assert measurement.reason is UnmeasuredReason.SOURCE_LOOKUP_FAILED
        assert "exploit" in score.unknown_signals
        assert any("did not answer" in factor for factor in score.factors)

        # No fabricated counts came with it.
        assert dependency.security_metrics is not None
        assert dependency.security_metrics.counted_vulnerability_count is None
        assert dependency.security_metrics.vulnerability_count is None

    assert cached_entries(isolated_cache) == [], (
        "the outage was written to disk. That is what makes this worse than an "
        "ordinary fail-open: the wrong answer outlives the outage until the "
        "TTL expires (#219)."
    )
    assert aggregator.VULNERABILITY_CACHE == {}


def test_a_genuinely_clean_package_still_reads_clean_and_still_caches(
    isolated_cache: VulnerabilityCache,
) -> None:
    """The other half: the fix must not turn every clean package into a gap."""
    scanned = scan_manifest(osv_response={"vulns": []})

    scorer = RiskScorer()
    for name in SCANNED_PACKAGES:
        dependency = scanned[name]
        assert dependency.advisory_lookup_state is AdvisoryLookupState.COMPLETE
        assert dependency.advisory_sources_unavailable == ()

        score = scorer.score_dependency(dependency)
        measurement = score.measurements["exploit"]
        assert measurement.state is MeasurementState.MEASURED
        assert measurement.value == 0.0
        assert "exploit" not in score.unknown_signals

        assert dependency.security_metrics is not None
        assert dependency.security_metrics.counted_vulnerability_count == 0

    assert len(cached_entries(isolated_cache)) == len(SCANNED_PACKAGES)


def test_the_second_run_after_an_outage_does_not_serve_the_first_run_s_verdict(
    isolated_cache: VulnerabilityCache,
) -> None:
    """Nothing cached means nothing served: the lie cannot outlive the outage."""
    scan_manifest(osv_response=None)
    assert cached_entries(isolated_cache) == []

    # OSV comes back, and the second run measures rather than replaying.
    scanned = scan_manifest(osv_response={"vulns": []})
    for name in SCANNED_PACKAGES:
        assert scanned[name].advisory_lookup_state is AdvisoryLookupState.COMPLETE
    assert len(cached_entries(isolated_cache)) == len(SCANNED_PACKAGES)


def test_a_clean_verdict_written_before_the_fix_is_not_served_after_it(
    isolated_cache: VulnerabilityCache,
) -> None:
    """The schema bump is the fix's reach backwards into caches already on disk.

    Every version-3 entry was written by the code that could not tell an outage
    from a clean package, so every empty one of them is a claim that cannot be
    checked. Without the bump those claims would go on being served, as
    measurements, for the rest of their TTL.
    """
    entry = isolated_cache._get_cache_path("flask", "python")
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(
        json.dumps(
            {
                "data": [],
                "timestamp": time.time(),
                "package": "flask",
                "ecosystem": "python",
                "schema_version": 3,
            }
        ),
        encoding="utf-8",
    )

    assert isolated_cache.get("flask", "python") is None
    assert CACHE_SCHEMA_VERSION == 5


# --- Per-source classification ---------------------------------------------


def _osv_lookup(post: mock.Mock) -> SourceLookup:
    """Ask OSV once against a stubbed ``requests.post``.

    Args:
        post: The stub to install.

    Returns:
        What the source made of it.
    """
    with mock.patch("requests.post", post):
        return OSVSource().lookup("some-package", "python")


def _response(**attributes: Any) -> mock.Mock:
    """Build a stub ``requests`` response.

    Args:
        **attributes: Nested mock attributes, dotted.

    Returns:
        The stub.
    """
    response = mock.Mock()
    response.raise_for_status.return_value = None
    response.configure_mock(**attributes)
    return response


def test_osv_classifies_each_way_of_not_answering_as_a_failure() -> None:
    """Six facts, six answers. Five of them are not "the package is clean"."""
    unreachable = _osv_lookup(mock.Mock(side_effect=requests.ConnectionError("down")))
    assert unreachable.state is SourceState.FAILED

    not_found = mock.Mock()
    not_found.raise_for_status.side_effect = requests.HTTPError(
        response=mock.Mock(status_code=404)
    )
    assert _osv_lookup(mock.Mock(return_value=not_found)).state is SourceState.FAILED

    junk = _response(**{"json.return_value": ["not", "an", "object"]})
    assert _osv_lookup(mock.Mock(return_value=junk)).state is SourceState.FAILED

    unparseable = _response(**{"json.side_effect": ValueError("no JSON here")})
    assert _osv_lookup(mock.Mock(return_value=unparseable)).state is SourceState.FAILED

    clean = _response(**{"json.return_value": {"vulns": []}})
    measured = _osv_lookup(mock.Mock(return_value=clean))
    assert measured.state is SourceState.ANSWERED
    assert measured.vulnerabilities == ()


def test_a_graphql_error_block_is_a_refusal_rather_than_an_empty_advisory_list() -> (
    None
):
    """An "errors" block is a refusal to answer, not an answer of "nothing"."""
    response = _response(
        **{"json.return_value": {"errors": [{"message": "Bad credentials"}]}}
    )

    with mock.patch("requests.post", mock.Mock(return_value=response)):
        lookup = GitHubAdvisorySource(api_token="t").lookup("flask", "python")

    assert lookup.state is SourceState.FAILED


def test_a_source_that_does_not_cover_the_ecosystem_abstains_rather_than_fails() -> (
    None
):
    """An uncovered ecosystem is not an outage, and it is not a clean answer.

    #164's ratified position, applied: no NOT_APPLICABLE is invented. The
    source records that it was never asked, and the aggregate decides what that
    means from whether anybody else answered.
    """
    with mock.patch.object(NVDSource, "_get_cpe_prefix", return_value=""):
        lookup = NVDSource().lookup("some-package", "obscure-ecosystem")
    assert lookup.state is SourceState.ABSTAINED

    without_token = GitHubAdvisorySource(api_token=None).lookup("flask", "python")
    assert without_token.state is SourceState.ABSTAINED


# --- The partial-failure rule ----------------------------------------------


def _combine(
    *pairs: Tuple[aggregator.VulnerabilitySource, SourceLookup],
) -> aggregator.AggregateOutcome:
    """Fold source answers into an outcome.

    Args:
        *pairs: Each source with what it answered.

    Returns:
        The combined outcome.
    """
    return combine_source_lookups(list(pairs))


ADVISORY: Dict[str, object] = {"id": "GHSA-xxxx", "source": "GitHub Advisory"}


def test_a_package_is_not_clean_because_two_sources_of_three_answered() -> None:
    """OSV down, the rest quiet: the absence claim is gone, so it is unmeasured."""
    outcome = _combine(
        (OSVSource(), SourceLookup.failed("unreachable")),
        (NVDSource(), SourceLookup.answered([])),
    )

    assert outcome.state is AdvisoryLookupState.FAILED
    assert outcome.sources_unavailable == ("OSV",)
    assert not outcome.cacheable


def test_a_slow_nvd_does_not_make_the_scan_unmeasured() -> None:
    """NVD is reached by keyword search; a miss there was never an answer."""
    outcome = _combine(
        (OSVSource(), SourceLookup.answered([])),
        (NVDSource(), SourceLookup.failed("timed out")),
    )

    assert outcome.state is AdvisoryLookupState.PARTIAL
    assert outcome.sources_unavailable == ("NVD",)
    assert not outcome.cacheable, (
        "the advisory set is incomplete, and an incomplete set read back "
        "tomorrow is indistinguishable from a complete one"
    )


def test_an_advisory_found_survives_an_outage_in_another_source() -> None:
    """Nothing un-finds a finding. It is reported as a floor, not suppressed."""
    outcome = _combine(
        (OSVSource(), SourceLookup.failed("unreachable")),
        (GitHubAdvisorySource(api_token="t"), SourceLookup.answered([ADVISORY])),
    )

    assert outcome.state is AdvisoryLookupState.PARTIAL
    assert outcome.vulnerabilities == [ADVISORY]
    assert not outcome.cacheable


def test_every_source_abstaining_is_not_attempted_rather_than_clean() -> None:
    """Nobody was asked, so nobody answered, so nothing is known."""
    outcome = _combine(
        (OSVSource(enabled=False), SourceLookup.abstained("disabled")),
        (GitHubAdvisorySource(api_token=None), SourceLookup.abstained("no token")),
    )

    assert outcome.state is AdvisoryLookupState.NOT_ATTEMPTED
    assert outcome.sources_unavailable == ()
    assert not outcome.cacheable


def test_every_source_answering_is_the_only_cacheable_outcome() -> None:
    """The cache holds complete measurements and nothing weaker."""
    outcome = _combine(
        (OSVSource(), SourceLookup.answered([])),
        (NVDSource(), SourceLookup.answered([])),
    )

    assert outcome.state is AdvisoryLookupState.COMPLETE
    assert outcome.cacheable


# --- The recorder's invariants ---------------------------------------------


def test_a_failed_lookup_cannot_decline_to_say_what_failed() -> None:
    """An unexplained failure is the empty list wearing a different hat."""
    dependency = DependencyMetadata(name="flask", installed_version="1.0.0")

    with pytest.raises(ValueError):
        dependency.record_advisory_lookup(
            AdvisoryLookupState.FAILED, sources_unavailable=()
        )

    with pytest.raises(ValueError):
        dependency.record_advisory_lookup(
            AdvisoryLookupState.COMPLETE, sources_unavailable=("OSV",)
        )

    # A string that happens to spell a member's value is not a member. The
    # runtime check is the half mypy cannot do: an untyped caller — a plugin, a
    # REPL, a fixture — is otherwise one assignment from a state nobody chose.
    with pytest.raises(TypeError):
        dependency.record_advisory_lookup(
            cast(AdvisoryLookupState, "failed"), sources_unavailable=("OSV",)
        )

    # Every rejected call left the state where it started, and where it starts
    # is the one an unasked question deserves.
    assert dependency.advisory_lookup_state is AdvisoryLookupState.NOT_ATTEMPTED


def test_the_constructor_is_held_to_the_recorder_s_rule() -> None:
    """A state set at construction gets no weaker check than a recorded one.

    The recorder is the writer, but a dataclass field is settable at
    construction too, and that is the shape a deserializer takes: read a state
    out of a stored record and hand it to the constructor. If only the recorder
    validated, that path would be the way back to a failure that cannot say
    what failed — #219's defect arriving through the back door instead of the
    front.

    The last case is the one that matters most and is easiest to miss: a
    dependency built with nothing said about advisories must come out claiming
    nothing, rather than inheriting a state that reads as a measurement (#321).
    """
    with pytest.raises(ValueError):
        DependencyMetadata(
            name="flask",
            installed_version="1.0.0",
            advisory_lookup_state=AdvisoryLookupState.FAILED,
        )

    with pytest.raises(ValueError):
        DependencyMetadata(
            name="flask",
            installed_version="1.0.0",
            advisory_lookup_state=AdvisoryLookupState.COMPLETE,
            advisory_sources_unavailable=("OSV",),
        )

    with pytest.raises(TypeError):
        DependencyMetadata(
            name="flask",
            installed_version="1.0.0",
            advisory_lookup_state=cast(AdvisoryLookupState, "complete"),
        )

    silent = DependencyMetadata(name="flask", installed_version="1.0.0")
    assert silent.advisory_lookup_state is AdvisoryLookupState.NOT_ATTEMPTED
    assert silent.advisory_sources_unavailable == ()
