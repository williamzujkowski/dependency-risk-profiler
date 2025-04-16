"""Supply chain risk assessment module for dependency analysis."""

from .analyzer import analyze_supply_chain_risk
from .graph import generate_dependency_graph
from .trends import (
    save_historical_profile,
    analyze_historical_trends,
    generate_trend_visualization
)

__all__ = [
    "analyze_supply_chain_risk",
    "generate_dependency_graph",
    "save_historical_profile",
    "analyze_historical_trends",
    "generate_trend_visualization"
]