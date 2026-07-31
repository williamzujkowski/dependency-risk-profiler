"""Popularity helpers shared by scoring and report formatting."""

from __future__ import annotations

from .models import DependencyMetadata

POPULARITY_HIGH_STARS_DEFAULT = 2000
POPULARITY_HIGH_CONTRIBUTORS_DEFAULT = 25
STALENESS_POPULARITY_DAMPENING_DEFAULT = 0.5
GITHUB_REPOSITORY_ARCHIVED_KEY = "github_repository_archived"


def has_high_adoption(
    dependency: DependencyMetadata,
    popularity_high_stars: int = POPULARITY_HIGH_STARS_DEFAULT,
    popularity_high_contributors: int = POPULARITY_HIGH_CONTRIBUTORS_DEFAULT,
) -> bool:
    """Return whether measured community signals show broad adoption."""
    metrics = dependency.community_metrics
    if metrics is None:
        return False

    if metrics.star_count is not None and metrics.star_count >= popularity_high_stars:
        return True

    return (
        metrics.contributor_count is not None
        and metrics.contributor_count >= popularity_high_contributors
    )


def has_hard_abandonment_indicator(dependency: DependencyMetadata) -> bool:
    """Return whether explicit metadata indicates abandonment."""
    return (
        dependency.is_deprecated
        or dependency.additional_info.get(GITHUB_REPOSITORY_ARCHIVED_KEY) == "true"
    )


def should_soften_low_release_cadence(
    dependency: DependencyMetadata,
    popularity_high_stars: int = POPULARITY_HIGH_STARS_DEFAULT,
    popularity_high_contributors: int = POPULARITY_HIGH_CONTRIBUTORS_DEFAULT,
) -> bool:
    """Return whether staleness should read as mature cadence instead of abandonment."""
    return has_high_adoption(
        dependency,
        popularity_high_stars=popularity_high_stars,
        popularity_high_contributors=popularity_high_contributors,
    ) and not has_hard_abandonment_indicator(dependency)
