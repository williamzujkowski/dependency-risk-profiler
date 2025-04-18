"""Historical trends analysis for dependency risk profiles."""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import ProjectRiskProfile

logger = logging.getLogger(__name__)

# Default location for storing historical data
DEFAULT_HISTORY_DIR = os.path.expanduser("~/.dependency-risk-profiler/history")


class HistoricalTrendAnalyzer:
    """Analyzer for historical trends in dependency risk profiles."""

    def __init__(self, history_dir: Optional[str] = None):
        """Initialize the historical trend analyzer.

        Args:
            history_dir: Directory to store historical data. Defaults to ~/.dependency-risk-profiler/history
        """
        self.history_dir = history_dir or DEFAULT_HISTORY_DIR

        # Ensure the history directory exists
        Path(self.history_dir).mkdir(parents=True, exist_ok=True)

    def get_project_history_path(self, project_id: str) -> str:
        """Get the file path for project history.

        Args:
            project_id: Project identifier (usually manifest path)

        Returns:
            Path to the project history file
        """
        # Create a sanitized project ID for the filename
        safe_id = project_id.replace("/", "_").replace("\\", "_").replace(":", "_")
        return os.path.join(self.history_dir, f"{safe_id}.json")

    def save_profile(self, profile: ProjectRiskProfile) -> str:
        """Save a project risk profile to history.

        Args:
            profile: Project risk profile to save

        Returns:
            Path to the saved history file
        """
        history_path = self.get_project_history_path(profile.manifest_path)

        # Load existing history if available
        history = self._load_history(history_path)

        # Add new profile data
        timestamp = profile.scan_time.isoformat()

        if "scans" not in history:
            history["scans"] = {}

        # Store profile data with timestamp as key
        history["scans"][timestamp] = {
            "overall_risk_score": profile.overall_risk_score,
            "high_risk_dependencies": profile.high_risk_dependencies,
            "medium_risk_dependencies": profile.medium_risk_dependencies,
            "low_risk_dependencies": profile.low_risk_dependencies,
            "dependencies": {
                dep.dependency.name: {
                    "total_score": dep.total_score,
                    "risk_level": dep.risk_level.value,
                    "installed_version": dep.dependency.installed_version,
                    "scores": {
                        # Using getattr with default values to handle missing attributes
                        "staleness_score": getattr(dep, "staleness_score", 0),
                        "maintainer_score": getattr(dep, "maintainer_score", 0),
                        "security_policy_score": getattr(
                            dep, "security_policy_score", 0
                        ),
                        "dependency_update_score": getattr(
                            dep, "dependency_update_score", 0
                        ),
                        "signed_commits_score": getattr(dep, "signed_commits_score", 0),
                        "branch_protection_score": getattr(
                            dep, "branch_protection_score", 0
                        ),
                        "license_score": getattr(dep, "license_score", 0),
                        "community_score": getattr(dep, "community_score", 0),
                        "transitive_score": getattr(dep, "transitive_score", 0),
                    },
                }
                for dep in profile.dependencies
            },
        }

        # Save back to file
        with open(history_path, "w") as f:
            json.dump(history, f, indent=2)

        logger.info(f"Saved historical profile data to {history_path}")
        return history_path

    def analyze_trends(self, project_id: str, limit: int = 10) -> Dict[str, Any]:
        """Analyze historical trends for a project.

        Args:
            project_id: Project identifier (usually manifest path)
            limit: Maximum number of historical data points to analyze

        Returns:
            Dictionary with trend analysis results
        """
        history_path = self.get_project_history_path(project_id)
        history = self._load_history(history_path)

        if not history or "scans" not in history:
            logger.warning(f"No historical data found for {project_id}")
            return {"error": "No historical data available"}

        # Sort scans by timestamp (newest first)
        timestamps = sorted(history["scans"].keys(), reverse=True)

        # Limit to the specified number of scans
        timestamps = timestamps[:limit]

        # Extract trend data
        overall_scores = []
        risk_distribution = []
        dependency_trends = {}

        for ts in reversed(timestamps):  # Reverse to show oldest to newest
            scan = history["scans"][ts]

            # Format the timestamp for display
            display_time = self._format_timestamp(ts)

            # Overall score trend
            overall_scores.append(
                {"timestamp": display_time, "score": scan["overall_risk_score"]}
            )

            # Risk distribution trend
            risk_distribution.append(
                {
                    "timestamp": display_time,
                    "high": scan["high_risk_dependencies"],
                    "medium": scan["medium_risk_dependencies"],
                    "low": scan["low_risk_dependencies"],
                }
            )

            # Individual dependency trends
            for dep_name, dep_data in scan["dependencies"].items():
                if dep_name not in dependency_trends:
                    dependency_trends[dep_name] = []

                dependency_trends[dep_name].append(
                    {
                        "timestamp": display_time,
                        "score": dep_data["total_score"],
                        "risk_level": dep_data["risk_level"],
                        "version": dep_data["installed_version"],
                    }
                )

        # Identify improving and deteriorating dependencies
        improving_deps, deteriorating_deps = self._identify_changing_dependencies(
            dependency_trends
        )

        # Calculate average risk score over time
        avg_risk_over_time = self._calculate_average_risk(overall_scores)

        # Calculate security metrics improvements
        security_improvements = self._analyze_security_improvements(history, timestamps)

        # Calculate velocity metrics
        velocity_metrics = self._calculate_velocity_metrics(history, timestamps)

        return {
            "overall_score_trend": overall_scores,
            "risk_distribution_trend": risk_distribution,
            "dependency_trends": dependency_trends,
            "improving_dependencies": improving_deps,
            "deteriorating_dependencies": deteriorating_deps,
            "average_risk_over_time": avg_risk_over_time,
            "security_improvements": security_improvements,
            "velocity_metrics": velocity_metrics,
            "analyzed_period": {
                "start": self._format_timestamp(timestamps[-1]) if timestamps else "",
                "end": self._format_timestamp(timestamps[0]) if timestamps else "",
                "scans_analyzed": len(timestamps),
            },
        }

    def generate_trend_visualization_data(
        self, project_id: str, visualization_type: str = "overall", limit: int = 10
    ) -> Dict[str, Any]:
        """Generate data for visualizing dependency risk trends.

        Args:
            project_id: Project identifier (usually manifest path)
            visualization_type: Type of visualization data to generate
                                (overall, distribution, dependencies, security)
            limit: Maximum number of historical data points to include

        Returns:
            Visualization data structure suitable for charting libraries
        """
        trend_data = self.analyze_trends(project_id, limit)

        if "error" in trend_data:
            return trend_data

        if visualization_type == "overall":
            # Format data for overall score line chart
            return {
                "type": "line_chart",
                "title": "Overall Risk Score Trend",
                "data": {
                    "labels": [
                        point["timestamp"]
                        for point in trend_data["overall_score_trend"]
                    ],
                    "datasets": [
                        {
                            "label": "Risk Score",
                            "data": [
                                point["score"]
                                for point in trend_data["overall_score_trend"]
                            ],
                            "borderColor": "#ff6384",
                            "backgroundColor": "rgba(255, 99, 132, 0.2)",
                        }
                    ],
                },
                "options": {
                    "scales": {
                        "y": {
                            "title": {"display": True, "text": "Risk Score (0-5)"},
                            "min": 0,
                            "max": 5,
                        }
                    }
                },
            }

        elif visualization_type == "distribution":
            # Format data for risk distribution stacked bar chart
            return {
                "type": "stacked_bar_chart",
                "title": "Risk Distribution Trend",
                "data": {
                    "labels": [
                        point["timestamp"]
                        for point in trend_data["risk_distribution_trend"]
                    ],
                    "datasets": [
                        {
                            "label": "High Risk",
                            "data": [
                                point["high"]
                                for point in trend_data["risk_distribution_trend"]
                            ],
                            "backgroundColor": "rgba(255, 99, 132, 0.7)",
                        },
                        {
                            "label": "Medium Risk",
                            "data": [
                                point["medium"]
                                for point in trend_data["risk_distribution_trend"]
                            ],
                            "backgroundColor": "rgba(255, 159, 64, 0.7)",
                        },
                        {
                            "label": "Low Risk",
                            "data": [
                                point["low"]
                                for point in trend_data["risk_distribution_trend"]
                            ],
                            "backgroundColor": "rgba(75, 192, 192, 0.7)",
                        },
                    ],
                },
                "options": {
                    "scales": {
                        "y": {
                            "stacked": True,
                            "title": {
                                "display": True,
                                "text": "Number of Dependencies",
                            },
                        },
                        "x": {"stacked": True},
                    }
                },
            }

        elif visualization_type == "dependencies":
            # Select top dependencies by risk (most recent scan)
            top_deps = self._get_top_dependencies(trend_data["dependency_trends"], 5)

            datasets = []
            for dep_name in top_deps:
                dep_data = trend_data["dependency_trends"][dep_name]

                datasets.append(
                    {
                        "label": dep_name,
                        "data": [point["score"] for point in dep_data],
                        "borderColor": self._get_random_color(dep_name),
                        "fill": False,
                    }
                )

            return {
                "type": "line_chart",
                "title": "Top Dependencies Risk Trends",
                "data": {
                    "labels": [
                        point["timestamp"]
                        for point in next(
                            iter(trend_data["dependency_trends"].values()), []
                        )
                    ],
                    "datasets": datasets,
                },
                "options": {
                    "scales": {
                        "y": {
                            "title": {"display": True, "text": "Risk Score (0-5)"},
                            "min": 0,
                            "max": 5,
                        }
                    }
                },
            }

        elif visualization_type == "security":
            # Format data for security metrics radar chart
            if not trend_data["security_improvements"]:
                return {"error": "No security metrics data available"}

            latest = trend_data["security_improvements"][-1]
            earliest = trend_data["security_improvements"][0]

            return {
                "type": "radar_chart",
                "title": "Security Metrics Improvement",
                "data": {
                    "labels": [
                        "Security Policy",
                        "Dependency Updates",
                        "Signed Commits",
                        "Branch Protection",
                    ],
                    "datasets": [
                        {
                            "label": earliest["timestamp"],
                            "data": [
                                earliest["metrics"]["security_policy"],
                                earliest["metrics"]["dependency_update"],
                                earliest["metrics"]["signed_commits"],
                                earliest["metrics"]["branch_protection"],
                            ],
                            "backgroundColor": "rgba(54, 162, 235, 0.2)",
                            "borderColor": "rgb(54, 162, 235)",
                        },
                        {
                            "label": latest["timestamp"],
                            "data": [
                                latest["metrics"]["security_policy"],
                                latest["metrics"]["dependency_update"],
                                latest["metrics"]["signed_commits"],
                                latest["metrics"]["branch_protection"],
                            ],
                            "backgroundColor": "rgba(255, 99, 132, 0.2)",
                            "borderColor": "rgb(255, 99, 132)",
                        },
                    ],
                },
                "options": {
                    "scales": {
                        "r": {"angleLines": {"display": True}, "min": 0, "max": 100}
                    }
                },
            }

        else:
            return {"error": f"Unsupported visualization type: {visualization_type}"}

    def _load_history(self, history_path: str) -> Dict[str, Any]:
        """Load historical data from file.

        Args:
            history_path: Path to history file

        Returns:
            Historical data as a dictionary
        """
        if not os.path.exists(history_path):
            return {}

        try:
            with open(history_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading history file {history_path}: {e}")
            return {}

    def _format_timestamp(self, timestamp: str) -> str:
        """Format an ISO timestamp for display.

        Args:
            timestamp: ISO formatted timestamp

        Returns:
            Formatted date string
        """
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            return timestamp

    def _identify_changing_dependencies(
        self, dependency_trends: Dict[str, List[Dict[str, Any]]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Identify dependencies that are improving or deteriorating.

        Args:
            dependency_trends: Dictionary of dependency trends

        Returns:
            Tuple of (improving_dependencies, deteriorating_dependencies)
        """
        improving = []
        deteriorating = []

        for dep_name, trend in dependency_trends.items():
            if len(trend) < 2:
                continue

            first_score = trend[0]["score"]
            last_score = trend[-1]["score"]

            # Calculate the change in score
            score_change = last_score - first_score

            # If score decreased by at least 0.5, it's improving (lower risk)
            if score_change <= -0.5:
                improving.append(
                    {
                        "name": dep_name,
                        "initial_score": first_score,
                        "current_score": last_score,
                        "improvement": -score_change,
                    }
                )
            # If score increased by at least 0.5, it's deteriorating (higher risk)
            elif score_change >= 0.5:
                deteriorating.append(
                    {
                        "name": dep_name,
                        "initial_score": first_score,
                        "current_score": last_score,
                        "deterioration": score_change,
                    }
                )

        # Sort by magnitude of change
        improving.sort(key=lambda x: x["improvement"], reverse=True)
        deteriorating.sort(key=lambda x: x["deterioration"], reverse=True)

        return improving, deteriorating

    def _calculate_average_risk(
        self, overall_scores: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate average risk scores over time.

        Args:
            overall_scores: List of overall risk scores

        Returns:
            Dictionary with average risk metrics
        """
        if not overall_scores:
            return {"average": 0, "trend": "stable"}

        # Calculate average
        total = sum(point["score"] for point in overall_scores)
        average = total / len(overall_scores)

        # Determine trend
        if len(overall_scores) < 2:
            trend = "stable"
        else:
            first = overall_scores[0]["score"]
            last = overall_scores[-1]["score"]

            if last < first - 0.3:
                trend = "improving"
            elif last > first + 0.3:
                trend = "deteriorating"
            else:
                trend = "stable"

        return {
            "average": average,
            "trend": trend,
            "first": overall_scores[0]["score"] if overall_scores else 0,
            "last": overall_scores[-1]["score"] if overall_scores else 0,
        }

    def _analyze_security_improvements(
        self, history: Dict[str, Any], timestamps: List[str]
    ) -> List[Dict[str, Any]]:
        """Analyze improvements in security metrics over time.

        Args:
            history: Historical data
            timestamps: List of timestamps to analyze

        Returns:
            List of security metrics improvements
        """
        security_improvements = []

        for ts in reversed(timestamps):
            scan = history["scans"][ts]

            # Initialize counters for security metrics
            security_policy_count = 0
            dependency_update_count = 0
            signed_commits_count = 0
            branch_protection_count = 0
            total_deps = len(scan["dependencies"])

            if total_deps == 0:
                continue

            # Calculate the percentage of dependencies with each security feature
            for dep_name, dep_data in scan["dependencies"].items():
                if "scores" in dep_data:
                    scores = dep_data["scores"]

                    # Using positive scores as indicators of security features
                    # Default to 0 if score not present to handle missing metrics
                    if scores.get("security_policy_score", 0) > 0:
                        security_policy_count += 1

                    if scores.get("dependency_update_score", 0) > 0:
                        dependency_update_count += 1

                    if scores.get("signed_commits_score", 0) > 0:
                        signed_commits_count += 1

                    if scores.get("branch_protection_score", 0) > 0:
                        branch_protection_count += 1

            # Calculate percentages
            security_improvements.append(
                {
                    "timestamp": self._format_timestamp(ts),
                    "metrics": {
                        "security_policy": round(
                            security_policy_count / total_deps * 100, 1
                        ),
                        "dependency_update": round(
                            dependency_update_count / total_deps * 100, 1
                        ),
                        "signed_commits": round(
                            signed_commits_count / total_deps * 100, 1
                        ),
                        "branch_protection": round(
                            branch_protection_count / total_deps * 100, 1
                        ),
                    },
                }
            )

        return security_improvements

    def _calculate_velocity_metrics(
        self, history: Dict[str, Any], timestamps: List[str]
    ) -> Dict[str, Any]:
        """Calculate velocity metrics for dependencies over time.

        Args:
            history: Historical data
            timestamps: List of timestamps to analyze

        Returns:
            Dictionary with velocity metrics
        """
        if len(timestamps) < 2:
            return {}

        # Get first and last scans for comparison
        first_scan = history["scans"][timestamps[-1]]
        last_scan = history["scans"][timestamps[0]]

        # Calculate timespan between first and last scan
        try:
            first_date = datetime.fromisoformat(timestamps[-1])
            last_date = datetime.fromisoformat(timestamps[0])
            days_difference = (last_date - first_date).days
        except ValueError:
            days_difference = 30  # Default to 30 days if date parsing fails

        # Identify all dependencies across all scans
        all_deps = set()
        for ts in timestamps:
            all_deps.update(history["scans"][ts]["dependencies"].keys())

        # Identify new, removed, and updated dependencies
        first_deps = set(first_scan["dependencies"].keys())
        last_deps = set(last_scan["dependencies"].keys())

        new_deps = last_deps - first_deps
        removed_deps = first_deps - last_deps

        # Identify updated dependencies
        updated_deps = set()
        for dep in first_deps.intersection(last_deps):
            first_version = first_scan["dependencies"][dep]["installed_version"]
            last_version = last_scan["dependencies"][dep]["installed_version"]

            if first_version != last_version:
                updated_deps.add(dep)

        # Calculate metrics for velocity
        velocity_metrics = {
            "new_dependencies": len(new_deps),
            "removed_dependencies": len(removed_deps),
            "updated_dependencies": len(updated_deps),
            "total_dependencies": len(all_deps),
            "days_in_period": days_difference,
            "dependency_churn_rate": (
                round((len(new_deps) + len(removed_deps)) / days_difference, 2)
                if days_difference > 0
                else 0
            ),
            "update_frequency": (
                round(len(updated_deps) / days_difference, 2)
                if days_difference > 0
                else 0
            ),
        }

        return velocity_metrics

    def _get_top_dependencies(
        self, dependency_trends: Dict[str, List[Dict[str, Any]]], count: int = 5
    ) -> List[str]:
        """Get the top dependencies by risk score in the most recent scan.

        Args:
            dependency_trends: Dictionary of dependency trends
            count: Number of top dependencies to return

        Returns:
            List of top dependency names
        """
        # Sort dependencies by their most recent risk score
        deps_by_risk = [
            (name, trend[-1]["score"] if trend else 0)
            for name, trend in dependency_trends.items()
            if trend
        ]

        deps_by_risk.sort(key=lambda x: x[1], reverse=True)

        # Return the top 'count' dependencies
        return [name for name, _ in deps_by_risk[:count]]

    def _get_random_color(self, seed: str) -> str:
        """Generate a random color based on a seed string.

        Args:
            seed: Seed string for color generation

        Returns:
            Hex color code
        """
        # Use the hash of the seed string to generate a deterministic color
        hash_val = hash(seed)
        r = (hash_val & 0xFF0000) >> 16
        g = (hash_val & 0x00FF00) >> 8
        b = hash_val & 0x0000FF

        # Ensure colors are bright enough to see
        r = max(r, 50)
        g = max(g, 50)
        b = max(b, 50)

        return f"rgb({r},{g},{b})"


def save_historical_profile(profile: ProjectRiskProfile) -> str:
    """Save a project risk profile to history.

    Args:
        profile: Project risk profile to save

    Returns:
        Path to the saved history file
    """
    analyzer = HistoricalTrendAnalyzer()
    return analyzer.save_profile(profile)


def analyze_historical_trends(project_id: str, limit: int = 10) -> Dict[str, Any]:
    """Analyze historical trends for a project.

    Args:
        project_id: Project identifier (usually manifest path)
        limit: Maximum number of historical data points to analyze

    Returns:
        Dictionary with trend analysis results
    """
    analyzer = HistoricalTrendAnalyzer()
    return analyzer.analyze_trends(project_id, limit)


def generate_trend_visualization(
    project_id: str, visualization_type: str = "overall", limit: int = 10
) -> Dict[str, Any]:
    """Generate data for visualizing dependency risk trends.

    Args:
        project_id: Project identifier (usually manifest path)
        visualization_type: Type of visualization data to generate
        limit: Maximum number of historical data points to include

    Returns:
        Visualization data structure suitable for charting libraries
    """
    analyzer = HistoricalTrendAnalyzer()
    return analyzer.generate_trend_visualization_data(
        project_id, visualization_type, limit
    )
