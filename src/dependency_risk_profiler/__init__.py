"""Dependency Risk Profiler - Tool for analyzing the health of project dependencies."""

__version__ = "0.3.0"

# Convenience imports for key functionality
from .models import (
    DependencyMetadata,
    DependencyRiskScore,
    ProjectRiskProfile,
    RiskLevel,
)

# Imports for secure release functionality
from .secure_release import create_release, sign_artifact, verify_signature
from .supply_chain import (
    analyze_historical_trends,
    analyze_supply_chain_risk,
    generate_dependency_graph,
    generate_trend_visualization,
    save_historical_profile,
)

# Imports for vulnerability aggregation
from .vulnerabilities import aggregate_vulnerability_data, normalize_cvss_score

# Explicitly define __all__ to indicate what should be imported with "from dependency_risk_profiler import *"
__all__ = [
    "DependencyMetadata",
    "DependencyRiskScore",
    "ProjectRiskProfile",
    "RiskLevel",
    "analyze_supply_chain_risk",
    "generate_dependency_graph",
    "save_historical_profile",
    "analyze_historical_trends",
    "generate_trend_visualization",
    "aggregate_vulnerability_data",
    "normalize_cvss_score",
    "sign_artifact",
    "verify_signature",
    "create_release",
]
