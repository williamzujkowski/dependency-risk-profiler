"""Community metrics analyzer for dependencies."""

import logging
import subprocess  # nosec B404
from datetime import datetime, timedelta
from typing import Dict, Optional

from ..forges import CanonicalRepo, ForgeCapability, ForgeRegistry
from ..models import CommunityMetrics, DependencyMetadata
from ..signals import FieldSource, ProvenancedField
from ..utils import is_shallow_clone
from ..versioning import match_release_date

logger = logging.getLogger(__name__)


def calculate_commit_frequency(repo_dir: str, months: int = 6) -> Optional[float]:
    """Calculate commit frequency over the last N months.

    Args:
        repo_dir: Path to the git repository.
        months: Number of months to look back.

    Returns:
        Average number of commits per month, or None if the repository cannot
        answer — including when it is a shallow clone, whose single reachable
        commit would read as a confidently dead project for every repository
        on earth. The real number then comes from the GitHub API (see
        ``utils.github_commit_frequency``), the same split ``count_contributors``
        already makes.
    """
    if is_shallow_clone(repo_dir):
        logger.debug(
            "Skipping commit frequency in %s: shallow clone has no history",
            repo_dir,
        )
        return None

    try:
        # Get the date N months ago
        date_threshold = (datetime.now() - timedelta(days=30 * months)).strftime(
            "%Y-%m-%d"
        )

        # Count commits since that date
        result = subprocess.run(
            [
                "git",
                "rev-list",
                "--count",
                f"--since={date_threshold}",
                "HEAD",
            ],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )

        commit_count = int(result.stdout.strip())

        # Calculate average commits per month
        return commit_count / months
    except (subprocess.SubprocessError, ValueError) as e:
        logger.error(f"Error calculating commit frequency: {e}")
        return None


def analyze_forge_community_metrics(
    dependency: DependencyMetadata,
    github_token: Optional[str] = None,
) -> DependencyMetadata:
    """Ask whichever forge hosts this dependency for the facts a clone lacks.

    Three facts, routed by repository host through
    :class:`~dependency_risk_profiler.forges.ForgeRegistry`. A host no adapter
    claims yields three ``UNMEASURED`` answers naming that, rather than three
    signals that quietly never appear — which is the visible-coverage half of
    #292. The repository is still cloned and still answers every clone-derived
    signal either way.

    Args:
        dependency: Dependency metadata, updated in place.
        github_token: A GitHub token, when the caller resolved one. The two
            REST-backed facts need it; without one they stay unknown rather
            than being guessed from a shallow clone, whose answer is one
            contributor and one commit for every repository on earth.

    Returns:
        The same dependency, carrying whatever the forge supplied.
    """
    repo = CanonicalRepo.from_url(dependency.repository_url)
    if repo is None:
        return dependency

    dependency.forge = ForgeRegistry.match_forge_by_host(repo.host)
    logger.info(
        "Asking %s for community metrics for %s/%s",
        dependency.forge.value if dependency.forge else f"no adapter ({repo.host})",
        repo.owner,
        repo.name,
    )

    # Reuse whatever the repository clone already measured. Assigning a fresh
    # CommunityMetrics here would discard the clone-derived commit frequency,
    # because the analyze pipeline runs the clone first (#166).
    community_metrics = dependency.community_metrics or CommunityMetrics()

    contributors = ForgeRegistry.ask(
        repo, ForgeCapability.CONTRIBUTOR_COUNT, github_token
    )
    dependency.forge_answers[ForgeCapability.CONTRIBUTOR_COUNT] = contributors
    if contributors.is_measured:
        count = int(contributors.value or 0)
        dependency.maintainer_count = count
        community_metrics.contributor_count = count
        source = contributors.field_source
        if source is not None:
            dependency.record_field_source(ProvenancedField.MAINTAINER_COUNT, source)
            dependency.record_field_source(ProvenancedField.CONTRIBUTOR_COUNT, source)
    elif dependency.maintainer_count is not None:
        community_metrics.contributor_count = dependency.maintainer_count
        # A copy, so it inherits the copied field's provenance rather than
        # claiming one of its own. If nothing recorded a source for
        # ``maintainer_count`` — an ecosystem whose registry does not publish
        # maintainers — the copy stays unattributed, which is the honest answer.
        copied = dependency.field_sources.get(ProvenancedField.MAINTAINER_COUNT)
        if copied is not None:
            dependency.record_field_source(ProvenancedField.CONTRIBUTOR_COUNT, copied)

    cadence = ForgeRegistry.ask(repo, ForgeCapability.COMMIT_FREQUENCY, github_token)
    dependency.forge_answers[ForgeCapability.COMMIT_FREQUENCY] = cadence
    if cadence.is_measured and cadence.field_source is not None:
        community_metrics.commit_frequency = cadence.value
        dependency.record_field_source(
            ProvenancedField.COMMIT_FREQUENCY, cadence.field_source
        )

    stars = ForgeRegistry.ask(repo, ForgeCapability.STAR_COUNT, github_token)
    dependency.forge_answers[ForgeCapability.STAR_COUNT] = stars
    if stars.is_measured and stars.field_source is not None:
        community_metrics.star_count = int(stars.value or 0)
        dependency.record_field_source(
            ProvenancedField.STAR_COUNT, stars.field_source
        )

    dependency.community_metrics = community_metrics

    return dependency


def analyze_npm_community_metrics(
    dependency: DependencyMetadata, npm_data: Dict
) -> DependencyMetadata:
    """Analyze npm community metrics for a dependency.

    Args:
        dependency: Dependency metadata.
        npm_data: npm package data.

    Returns:
        Updated dependency metadata with community metrics.
    """
    if not dependency.community_metrics:
        dependency.community_metrics = CommunityMetrics()

    # Extract maintainer count if not already set
    if dependency.maintainer_count is None and "maintainers" in npm_data:
        if isinstance(npm_data["maintainers"], list):
            dependency.maintainer_count = len(npm_data["maintainers"])
            dependency.community_metrics.contributor_count = dependency.maintainer_count
            dependency.record_field_source(
                ProvenancedField.MAINTAINER_COUNT, FieldSource.REGISTRY_METADATA
            )
            dependency.record_field_source(
                ProvenancedField.CONTRIBUTOR_COUNT, FieldSource.REGISTRY_METADATA
            )

    # Extract last release date
    if "time" in npm_data:
        if isinstance(npm_data["time"], dict):
            # Exclude metadata fields
            release_dates = {
                k: v
                for k, v in npm_data["time"].items()
                if k not in ["created", "modified", "updated"]
            }

            if release_dates:
                latest_release = max(release_dates.items(), key=lambda x: x[1])
                try:
                    dependency.community_metrics.last_release_date = (
                        datetime.fromisoformat(latest_release[1].replace("Z", "+00:00"))
                    )
                except ValueError:
                    pass

                # Same payload, one more read: the installed version's
                # publication date drives elapsed-time drift for CalVer (#126).
                parsed_release_dates: Dict[str, datetime] = {}
                for release_version, published in release_dates.items():
                    try:
                        parsed_release_dates[release_version] = datetime.fromisoformat(
                            published.replace("Z", "+00:00")
                        )
                    except (AttributeError, ValueError):
                        continue

                installed_release_date = match_release_date(
                    parsed_release_dates, dependency.installed_version
                )
                if installed_release_date:
                    dependency.community_metrics.installed_release_date = (
                        installed_release_date
                    )

    return dependency


def analyze_pypi_community_metrics(
    dependency: DependencyMetadata, pypi_data: Dict
) -> DependencyMetadata:
    """Analyze PyPI community metrics for a dependency.

    Args:
        dependency: Dependency metadata.
        pypi_data: PyPI package data.

    Returns:
        Updated dependency metadata with community metrics.
    """
    if not dependency.community_metrics:
        dependency.community_metrics = CommunityMetrics()

    # Extract last release date
    if "releases" in pypi_data:
        latest_release_date = None
        # Publication date per version, taken from the payload already fetched
        # above. The installed version's date is what makes elapsed-time drift
        # measurable for calendar-versioned packages (#126).
        release_dates: Dict[str, datetime] = {}
        for release_version, releases in pypi_data["releases"].items():
            if releases:
                for release in releases:
                    if "upload_time" in release:
                        try:
                            release_date = datetime.fromisoformat(
                                release["upload_time"].replace("Z", "+00:00")
                            )
                        except ValueError:
                            continue
                        if (
                            latest_release_date is None
                            or release_date > latest_release_date
                        ):
                            latest_release_date = release_date
                        existing = release_dates.get(release_version)
                        if existing is None or release_date < existing:
                            release_dates[release_version] = release_date

        if latest_release_date:
            dependency.community_metrics.last_release_date = latest_release_date

        installed_release_date = match_release_date(
            release_dates, dependency.installed_version
        )
        if installed_release_date:
            dependency.community_metrics.installed_release_date = installed_release_date

    return dependency


def analyze_community_metrics(
    dependency: DependencyMetadata,
    metadata: Optional[Dict] = None,
    github_token: Optional[str] = None,
) -> DependencyMetadata:
    """Analyze community metrics for a dependency.

    Args:
        dependency: Dependency metadata.
        metadata: Package metadata.
        github_token: Optional GitHub token for reading the true contributor
            count from the API.

    Returns:
        Updated dependency metadata with community metrics.
    """
    logger.info(f"Analyzing community metrics for {dependency.name}")

    try:
        # Initialize community metrics if not already present
        if not dependency.community_metrics:
            dependency.community_metrics = CommunityMetrics()

        # Ask the forge for what a clone cannot supply, if there is a repository
        # to ask about.
        if dependency.repository_url:
            dependency = analyze_forge_community_metrics(dependency, github_token)

        # Analyze package registry specific metrics
        if metadata:
            if "name" in metadata and dependency.name.startswith("@"):
                # npm package
                dependency = analyze_npm_community_metrics(dependency, metadata)
            elif "info" in metadata and "name" in metadata["info"]:
                # PyPI package
                dependency = analyze_pypi_community_metrics(dependency, metadata)

    except Exception as e:
        logger.error(f"Error analyzing community metrics for {dependency.name}: {e}")

    return dependency
