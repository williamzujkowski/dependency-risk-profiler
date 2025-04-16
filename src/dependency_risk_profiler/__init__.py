"""Dependency Risk Profiler - Tool for analyzing the health of project dependencies."""

__version__ = "0.2.0"

# Convenience imports for key functionality
from .models import (
    DependencyMetadata,
    DependencyRiskScore,
    ProjectRiskProfile,
    RiskLevel
)

from .supply_chain import (
    analyze_supply_chain_risk,
    generate_dependency_graph,
    save_historical_profile,
    analyze_historical_trends,
    generate_trend_visualization
)

# Imports for vulnerability aggregation
from .vulnerabilities import (
    aggregate_vulnerability_data,
    normalize_cvss_score
)

# Imports for secure release functionality
from .secure_release import (
    sign_artifact,
    verify_signature,
    create_release
)
