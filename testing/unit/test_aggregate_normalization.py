"""#74's honest-unknown rule, applied across dependencies rather than across
signals (#276).

``test_score_normalization`` pins the rule one layer down: inside a single
dependency's score, an unmeasured signal leaves both the numerator and the
denominator. That is why a package this tool knows three things about does not
read as safer than one it knows fifteen things about.

The mean *across* dependencies did not do the same. A dependency the scan could
not resolve carries ``total_score = 0.0`` and ``insufficient_data: True``, and
the project mean divided by every dependency including those — so the headline
number fell every time the scan failed to resolve a package. One HIGH-risk
package in a manifest scored 2.46; the same package with four unresolvable ones
appended scored 0.49. An 80% improvement bought with ignorance, on the first
line of the report and the sort key of the manifest ranking.

Every test here drives the production scorer and the production writers. The
defect's whole history is aggregates that agreed with a fixture rather than
with the code, so nothing below hands a profile a score to assert back.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, cast

from dependency_risk_profiler.cli.formatter import JsonFormatter, TerminalFormatter
from dependency_risk_profiler.cli.json_v1 import JsonFormatterV1
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    LicenseCategory,
    LicenseInfo,
    ProjectRiskProfile,
    SecurityMetrics,
)
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyProfiler,
    RepositoryManifestListing,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.report import report_to_dict
from dependency_risk_profiler.org_scan.scanner import (
    GitHubDiscoveryClient,
    OrgScanOptions,
    OrgScanRunner,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import AdvisoryLookupState, SourceRepositoryState


def _resolvable(name: str) -> DependencyMetadata:
    """Return metadata rich enough for the scorer to reach a verdict on.

    Deliberately built out of the fields the adapters populate rather than out
    of a hand-set ``insufficient_data``: whether this dependency counts as
    scored is the production scorer's judgment, not this module's.

    Args:
        name: The package name.

    Returns:
        Metadata the scorer can measure most of its signals from.
    """
    return DependencyMetadata(
        name=name,
        installed_version="1.0.0",
        latest_version="2.0.0",
        last_updated=datetime.now() - timedelta(days=400),
        maintainer_count=1,
        is_deprecated=False,
        has_known_exploits=False,
        repository_url=f"https://github.com/acme/{name}",
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
        license_info=LicenseInfo(license_id="MIT", category=LicenseCategory.PERMISSIVE),
        community_metrics=CommunityMetrics(
            star_count=100, contributor_count=4, commit_frequency=2.0
        ),
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
            is_maintained=True,
            vulnerability_count=0,
            counted_vulnerability_count=0,
            filtered_vulnerability_count=0,
        ),
        source_repository_state=SourceRepositoryState.DECLARED,
        transitive_source="lockfile",
        advisory_lookup_state=AdvisoryLookupState.COMPLETE,
    )


def _resolvable_and_deprecated(name: str) -> DependencyMetadata:
    """Return :func:`_resolvable` metadata for a package marked deprecated.

    Scores materially higher than its clean sibling, so a weighted mean over
    the two cannot come out the same under both weightings by coincidence.

    Args:
        name: The package name.

    Returns:
        Measurable metadata with the deprecation signal set.
    """
    metadata = _resolvable(name)
    metadata.is_deprecated = True
    return metadata


def _unresolvable(name: str) -> DependencyMetadata:
    """Return metadata for a package no registry answered about.

    What a private-index package, an offline run, or a typo'd name produces:
    a name and a pinned version, and nothing else. The scorer measures two of
    its sixteen signals and reports ``insufficient_data``.

    Args:
        name: The package name.

    Returns:
        Metadata with nothing measurable in it.
    """
    return DependencyMetadata(name=name, installed_version="1.0.0")


def _profile(*dependencies: DependencyMetadata) -> ProjectRiskProfile:
    """Score dependencies into a manifest profile through the real scorer.

    Args:
        dependencies: The metadata to score, in manifest order.

    Returns:
        The profile the production scorer produces.
    """
    return RiskScorer().create_project_profile(
        "/tmp/requirements.txt",
        "python",
        {dependency.name: dependency for dependency in dependencies},
    )


def test_appending_unresolvable_dependencies_does_not_move_the_project_score() -> None:
    """REGRESSION #276: the headline number improved as the scan learned less.

    The acceptance criterion, as a value assertion rather than a direction
    assertion: the two means are *equal*, not merely "the second is no lower".
    """
    one = _profile(_resolvable("measurable"))
    five = _profile(
        _resolvable("measurable"),
        _unresolvable("gone-a"),
        _unresolvable("gone-b"),
        _unresolvable("gone-c"),
        _unresolvable("gone-d"),
    )

    assert one.overall_risk_score is not None
    assert five.overall_risk_score == one.overall_risk_score
    # The four appended packages are in the report; they are not in the mean.
    assert len(five.dependencies) == 5
    assert five.insufficient_data_dependencies == 4
    assert five.scored_dependency_count == 1


def test_a_manifest_nothing_could_be_scored_in_reports_no_score() -> None:
    """REGRESSION #276: five unresolvable packages reported ``0.0``.

    ``None`` is the state the contract already had for a manifest with no
    dependencies at all. A manifest whose every dependency was unresolvable is
    the same state and never reached it.
    """
    profile = _profile(_unresolvable("gone-a"), _unresolvable("gone-b"))

    assert profile.overall_risk_score is None
    assert profile.scored_dependency_count == 0
    assert len(profile.dependencies) == 2


def test_the_project_score_travels_with_the_count_it_covers() -> None:
    """INVARIANT #276: the mean cannot be read out of the payload alone.

    ``2.46`` and ``2.46 across one dependency in five`` are different claims,
    and a consumer must not have to know this tool's exclusion rule to tell
    which one it is holding.
    """
    document = JsonFormatter()._profile_dict(
        _profile(
            _resolvable("measurable"),
            _unresolvable("gone-a"),
            _unresolvable("gone-b"),
            _unresolvable("gone-c"),
            _unresolvable("gone-d"),
        )
    )

    assert document["dependency_count"] == 5
    assert document["scored_dependency_count"] == 1
    assert document["overall_risk_score"] is not None


def test_the_json_payload_says_no_score_rather_than_zero() -> None:
    """REGRESSION #276: ``overall_risk_score: 0.0`` on a wholly unread manifest."""
    document = JsonFormatter()._profile_dict(
        _profile(_unresolvable("gone-a"), _unresolvable("gone-b"))
    )

    assert document["overall_risk_score"] is None
    assert document["dependency_count"] == 2
    assert document["scored_dependency_count"] == 0


def test_the_terminal_headline_states_its_coverage() -> None:
    """INVARIANT #276: the first line a user reads carries the denominator."""
    partial = TerminalFormatter(color=False).format_profile(
        _profile(_resolvable("measurable"), _unresolvable("gone-a"))
    )
    none_scored = TerminalFormatter(color=False).format_profile(
        _profile(_unresolvable("gone-a"), _unresolvable("gone-b"))
    )

    assert "across 1 of 2 scored" in partial.splitlines()[1]
    assert "overall not scored" in none_scored.splitlines()[1]
    assert "0 of 2 dependencies could be scored" in none_scored.splitlines()[1]


def test_a_fully_measured_manifest_prints_no_coverage_caveat() -> None:
    """A mean over everything is still just a mean over everything.

    The caveat has to be absent when it does not apply, or it becomes noise
    and stops being read where it does.
    """
    output = TerminalFormatter(color=False).format_profile(
        _profile(_resolvable("measurable"), _resolvable("also-measurable"))
    )

    assert "across" not in output.splitlines()[1]
    assert "overall 1.1 / 5.0" in output.splitlines()[1]


def test_a_directory_run_weights_manifests_by_their_scored_dependencies() -> None:
    """REGRESSION #276: the merged mean re-imported the defect as a weight.

    Each manifest's mean is over its scored dependencies; the run's mean used
    to weight those by each manifest's *total* dependency count. A manifest of
    one scored package and four unresolvable ones would have counted its honest
    score five times, out-voting a fully-measured manifest beside it.
    """
    diluted = _profile(
        _resolvable_and_deprecated("deprecated"),
        _unresolvable("gone-a"),
        _unresolvable("gone-b"),
        _unresolvable("gone-c"),
    )
    measured = _profile(_resolvable("other"))
    document = JsonFormatter()._report_dict([diluted, measured], "/tmp")

    # Each manifest contributed exactly one scored dependency, so the run mean
    # is the plain average of the two — not the four-to-one weighting the
    # dependency counts would have given the diluted manifest. The two scores
    # differ, so the two weightings cannot agree by accident.
    diluted_score = diluted.overall_risk_score
    measured_score = measured.overall_risk_score
    assert diluted_score is not None and measured_score is not None
    assert diluted_score != measured_score
    assert document["overall_risk_score"] == (diluted_score + measured_score) / 2
    assert document["dependency_count"] == 5
    assert document["scored_dependency_count"] == 2


def test_a_directory_run_of_unresolvable_manifests_reports_no_score() -> None:
    """REGRESSION #276: the merged mean over nothing measurable was ``0.0``."""
    document = JsonFormatter()._report_dict(
        [_profile(_unresolvable("gone-a")), _profile(_unresolvable("gone-b"))],
        "/tmp",
    )

    assert document["overall_risk_score"] is None
    assert document["scored_dependency_count"] == 0
    assert document["dependency_count"] == 2


def test_the_frozen_v1_writer_inherits_the_corrected_mean() -> None:
    """DECISION #276: v1's shape is frozen; a wrong number is not part of it.

    ``--schema v1`` is still selectable in this release, so leaving it
    publishing a project score that improves with ignorance would ship the
    defect under a flag. The key keeps its name and its ``number | null``
    shape, and does not gain v2's ``scored_dependency_count``.
    """
    profile = _profile(
        _resolvable("measurable"),
        _unresolvable("gone-a"),
        _unresolvable("gone-b"),
    )
    document = JsonFormatterV1()._profile_dict(profile)

    assert document["overall_risk_score"] == profile.overall_risk_score
    assert "scored_dependency_count" not in document


class _OneRepositoryClient(GitHubDiscoveryClient):
    """One offline repository whose manifest lists the given packages."""

    def __init__(self, names: List[str]) -> None:
        """Build the fixture repository.

        Args:
            names: Package names to write into the fixture manifest.
        """
        self._repo = RepositoryRef(
            full_name="acme/api",
            name="api",
            default_branch="main",
            html_url="https://github.com/acme/api",
            archived=False,
            fork=False,
        )
        self._manifest = "".join(f"{name}==1.0.0\n" for name in names)

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return the fixture repository."""
        return [self._repo]

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
        include_collaborations: bool = False,
    ) -> List[RepositoryRef]:
        """Return the fixture repository."""
        return [self._repo]

    def list_manifest_paths(self, repo: RepositoryRef) -> RepositoryManifestListing:
        """Return the single fixture manifest path."""
        return RepositoryManifestListing(
            supported=["requirements.txt"], unreadable=[], truncated=False
        )

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Return the fixture manifest body."""
        return self._manifest


class _RealScorerProfiler(DependencyProfiler):
    """Enriches the named packages, then scores everything for real.

    The enrichment list is the fixture's only opinion. Whether a dependency
    ends up scorable is decided by ``RiskScorer``, so the exclusion under test
    is not one this double performed on the scanner's behalf — the failure mode
    AGENTS.md rule 6 records twice.
    """

    def __init__(self, resolvable: List[str]) -> None:
        """Record which packages the registry is pretending to know about.

        Args:
            resolvable: Names to enrich before scoring.
        """
        self._resolvable = set(resolvable)

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Score every dependency through the production scorer.

        Args:
            dependencies: The parsed inventory, keyed by identity.

        Returns:
            One score per dependency.
        """
        scorer = RiskScorer()
        return {
            key: scorer.score_dependency(
                _resolvable(key.name)
                if key.name in self._resolvable
                else _unresolvable(key.name)
            )
            for key in dependencies
        }


def _repository_entry(resolvable: List[str], names: List[str]) -> Dict[str, object]:
    """Run an offline org scan and return its one repository summary.

    Args:
        resolvable: Package names the fixture registry answers about.
        names: Every package name in the fixture manifest.

    Returns:
        The serialized repository summary.
    """
    report = OrgScanRunner(
        _OneRepositoryClient(names), _RealScorerProfiler(resolvable)
    ).run(OrgScanOptions(org="acme"))
    document = report_to_dict(report)
    repositories = cast(List[Dict[str, object]], document["riskiest_repositories"])
    return repositories[0]


def test_a_repository_average_excludes_dependencies_it_could_not_score() -> None:
    """REGRESSION #276: ``scan-org``'s repository average had the same defect.

    Worst in exactly the repositories the scan understood least, and it is the
    fourth sort key of ``riskiest_repositories``.
    """
    measured = _repository_entry(["alpha"], ["alpha"])
    diluted = _repository_entry(["alpha"], ["alpha", "gone-a", "gone-b", "gone-c"])

    assert diluted["average_risk_score"] == measured["average_risk_score"]
    assert diluted["dependency_count"] == 4
    assert diluted["scored_dependency_count"] == 1


def test_a_repository_nothing_could_be_scored_in_has_no_average() -> None:
    """REGRESSION #276: it reported ``average_risk_score: 0.0``."""
    entry = _repository_entry([], ["gone-a", "gone-b"])

    assert entry["average_risk_score"] is None
    assert entry["scored_dependency_count"] == 0
    assert entry["dependency_count"] == 2
