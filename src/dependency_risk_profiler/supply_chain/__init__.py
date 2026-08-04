"""Supply chain risk assessment module for dependency analysis."""

from .graph import generate_dependency_graph
from .trends import (
    analyze_historical_trends,
    generate_trend_visualization,
    save_historical_profile,
)

__all__ = [
    "generate_dependency_graph",
    "save_historical_profile",
    "analyze_historical_trends",
    "generate_trend_visualization",
]
