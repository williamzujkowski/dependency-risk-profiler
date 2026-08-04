"""Replay a captured OSV response through the real advisory pipeline.

The recordings in ``testing/fixtures/osv`` are bodies OSV actually answered
with (rule 5: conformance fixtures are captured, never authored). This module
feeds one to the production code and stops there — it parses nothing, counts
nothing and classifies nothing itself.

That restraint is the point. This repository has shipped a test suite green
against a fixture client that reimplemented the subject, so deleting the
classifier from the *production* client left seventeen tests passing. The only
thing substituted here is the transport: ``requests.post`` is replaced by an
object that hands back recorded bytes. Everything downstream of it —
``OSVSource.lookup``'s response handling, ``_normalize_results``,
``merge_alias_duplicates``, ``combine_source_lookups``,
``annotate_vulnerabilities_for_scoring`` and the metric accounting in
``_update_dependency_with_vulnerabilities`` — is the shipped code, reached the
way the shipped code reaches it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.vulnerabilities import aggregator

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "osv"


class RecordedResponse:
    """The two methods ``OSVSource.lookup`` calls on a ``requests`` response."""

    def __init__(self, payload: object) -> None:
        """Hold one recorded response body.

        Args:
            payload: The decoded body OSV answered with.
        """
        self._payload = payload

    def raise_for_status(self) -> None:
        """Accept the response, as ``requests`` does for a 200."""
        return None

    def json(self) -> object:
        """Return the recorded body.

        Returns:
            The decoded body OSV answered with.
        """
        return self._payload


def recorded_query(fixture: str) -> Dict[str, object]:
    """Return one captured OSV response body.

    Args:
        fixture: File name under ``testing/fixtures/osv``.

    Returns:
        The recorded ``/v1/query`` body.
    """
    document = json.loads((FIXTURE_DIR / fixture).read_text(encoding="utf-8"))
    payload = document["payload"]
    assert isinstance(payload, dict)
    return payload


def advisories_for(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fixture: str,
    package_name: str,
    ecosystem: str,
) -> List[Dict[str, object]]:
    """Return what the aggregator makes of one recorded OSV answer.

    Args:
        monkeypatch: pytest's patcher, used only on the HTTP transport.
        fixture: File name under ``testing/fixtures/osv``.
        package_name: The package the recording was taken for.
        ecosystem: The tool's ecosystem key, e.g. ``nodejs``.

    Returns:
        The advisory records ``combine_source_lookups`` produced.
    """
    payload = recorded_query(fixture)

    def recorded_post(
        url: str,
        json: Optional[Dict[str, object]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> RecordedResponse:
        return RecordedResponse(payload)

    monkeypatch.setattr(aggregator.requests, "post", recorded_post)
    source = aggregator.OSVSource()
    lookup = source.lookup(package_name, ecosystem)
    assert lookup.state is aggregator.SourceState.ANSWERED
    outcome = aggregator.combine_source_lookups([(source, lookup)])
    return outcome.vulnerabilities


def annotated_dependency(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fixture: str,
    package_name: str,
    ecosystem: str,
    installed_version: str,
    minimum_severity: str = "LOW",
) -> DependencyMetadata:
    """Score one recorded package/version pair through the real annotator.

    Args:
        monkeypatch: pytest's patcher, used only on the HTTP transport.
        fixture: File name under ``testing/fixtures/osv``.
        package_name: The package the recording was taken for.
        ecosystem: The tool's ecosystem key, e.g. ``nodejs``.
        installed_version: The version to decide applicability against.
        minimum_severity: The ``--minimum-vulnerability-severity`` threshold.

    Returns:
        The dependency, with its advisory metrics written.
    """
    advisories = advisories_for(
        monkeypatch,
        fixture=fixture,
        package_name=package_name,
        ecosystem=ecosystem,
    )
    dependency = DependencyMetadata(
        name=package_name,
        installed_version=installed_version,
        additional_info={"ecosystem": ecosystem},
    )
    return aggregator._update_dependency_with_vulnerabilities(
        dependency, advisories, minimum_severity
    )


def counted_ids(dependency: DependencyMetadata) -> List[str]:
    """Return the IDs of the advisories that counted toward the score.

    Args:
        dependency: A dependency the annotator has run over.

    Returns:
        The counted advisory IDs, sorted.
    """
    metrics = dependency.security_metrics
    assert metrics is not None
    return sorted(
        str(detail["id"])
        for detail in metrics.vulnerability_details
        if detail.get("counted_in_score") is True
    )
