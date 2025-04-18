"""Supply chain risk analyzer for dependencies."""

import logging
from typing import Dict, List, Set, Tuple

from ..models import DependencyMetadata

logger = logging.getLogger(__name__)


def calculate_path_criticality(
    dependency: str, transitive_deps: Dict[str, Set[str]], visited: Set[str] = None
) -> int:
    """Calculate the criticality of a dependency based on its position in the dependency graph.

    Args:
        dependency: Name of the dependency to analyze.
        transitive_deps: Dictionary mapping dependency names to their dependencies.
        visited: Set of already visited dependencies to prevent cycles.

    Returns:
        Criticality score based on number of dependencies that rely on this one.
    """
    if visited is None:
        visited = set()

    if dependency in visited:
        return 0  # Prevent cycles

    visited.add(dependency)

    # Direct dependents count
    dependent_count = 0

    # Check which other packages depend on this one
    for dep_name, deps in transitive_deps.items():
        if dependency in deps and dep_name != dependency:
            # Add 1 for this direct dependent
            dependent_count += 1
            # Add indirect dependents (recursively)
            dependent_count += calculate_path_criticality(
                dep_name, transitive_deps, visited.copy()
            )

    return dependent_count


def identify_high_risk_dependencies(
    dependencies: Dict[str, DependencyMetadata],
) -> List[Tuple[str, float]]:
    """Identify dependencies with high supply chain risk.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.

    Returns:
        List of (dependency_name, risk_score) tuples, sorted by descending risk.
    """
    risk_scores = []

    # Build transitive dependency map for criticality analysis
    transitive_deps = {}
    for name, dep in dependencies.items():
        transitive_deps[name] = dep.transitive_dependencies

    # Calculate supply chain risk for each dependency
    for name, dep in dependencies.items():
        # Start with a base risk of 0
        risk_score = 0.0

        # Factor 1: Criticality in the dependency graph
        criticality = calculate_path_criticality(name, transitive_deps)
        criticality_factor = min(1.0, criticality / 10.0)  # Normalize to 0-1 range
        risk_score += criticality_factor * 0.4  # 40% weight

        # Factor 2: Security issues
        security_issues = 0

        if dep.security_metrics:
            # Count missing security features
            if dep.security_metrics.has_security_policy is False:
                security_issues += 1
            if dep.security_metrics.has_dependency_update_tools is False:
                security_issues += 1
            if dep.security_metrics.has_signed_commits is False:
                security_issues += 1
            if dep.security_metrics.has_branch_protection is False:
                security_issues += 1

            # Include vulnerability count if available
            if dep.security_metrics.vulnerability_count:
                security_issues += min(5, dep.security_metrics.vulnerability_count)

        security_factor = min(1.0, security_issues / 5.0)  # Normalize to 0-1 range
        risk_score += security_factor * 0.3  # 30% weight

        # Factor 3: Maintenance risk
        maintenance_risk = 0.0

        if dep.is_deprecated:
            maintenance_risk += 1.0

        if dep.maintainer_count is not None:
            if dep.maintainer_count < 2:
                maintenance_risk += 0.5

        maintenance_factor = min(1.0, maintenance_risk)
        risk_score += maintenance_factor * 0.3  # 30% weight

        # Add to the list of risk scores
        risk_scores.append((name, risk_score))

    # Sort by descending risk
    risk_scores.sort(key=lambda x: x[1], reverse=True)

    return risk_scores


def analyze_supply_chain_risk(
    dependencies: Dict[str, DependencyMetadata],
) -> Dict[str, object]:
    """Analyze supply chain risks in the project's dependencies.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.

    Returns:
        Dictionary with supply chain risk analysis results.
    """
    results = {
        "high_risk_dependencies": [],
        "dependency_count": len(dependencies),
        "transitive_dependency_count": 0,
        "critical_path_dependencies": [],
        "maintainer_count_histogram": {},
        "unknown_source_dependencies": [],
    }

    # Calculate transitive dependency count
    for name, dep in dependencies.items():
        results["transitive_dependency_count"] += len(dep.transitive_dependencies)

    # Build maintainer count histogram
    maintainer_counts = {}
    for name, dep in dependencies.items():
        if dep.maintainer_count is not None:
            count = min(10, dep.maintainer_count)  # Cap at 10+ for better visualization
            maintainer_counts[count] = maintainer_counts.get(count, 0) + 1

    results["maintainer_count_histogram"] = maintainer_counts

    # Identify high risk dependencies
    high_risk_deps = identify_high_risk_dependencies(dependencies)

    # Include the top 10 highest risk dependencies
    results["high_risk_dependencies"] = high_risk_deps[:10]

    # Identify dependencies without a source repository
    for name, dep in dependencies.items():
        if not dep.repository_url:
            results["unknown_source_dependencies"].append(name)

    # Calculate critical path dependencies (those with most dependents)
    transitive_deps = {}
    for name, dep in dependencies.items():
        transitive_deps[name] = dep.transitive_dependencies

    criticality_scores = []
    for name in dependencies:
        criticality = calculate_path_criticality(name, transitive_deps)
        criticality_scores.append((name, criticality))

    criticality_scores.sort(key=lambda x: x[1], reverse=True)
    results["critical_path_dependencies"] = criticality_scores[:10]

    return results
