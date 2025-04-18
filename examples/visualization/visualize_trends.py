#!/usr/bin/env python
"""
Simple visualization example for dependency-risk-profiler trend data.

This script generates sample trend visualization data that can be loaded
into the trend_visualizer.html file.
"""
import json
from datetime import datetime, timedelta


# Generate sample data
def generate_sample_data():
    """Generate sample trend data for visualization."""
    # Sample dates
    today = datetime.now()
    dates = [(today - timedelta(days=30 * i)).strftime("%Y-%m-%d") for i in range(6)]
    dates.reverse()  # Oldest to newest

    # Sample overall risk scores (gradually improving)
    overall_scores = [4.2, 3.8, 3.5, 3.0, 2.5, 2.1]

    # Sample risk distribution
    high_risk = [8, 7, 6, 4, 3, 2]
    medium_risk = [12, 13, 14, 15, 14, 12]
    low_risk = [10, 12, 15, 18, 22, 26]

    # Sample dependency data
    dependencies = {
        "express": [3.8, 3.5, 3.2, 2.8, 2.3, 2.0],
        "lodash": [4.5, 4.2, 3.9, 3.5, 3.0, 2.6],
        "axios": [2.8, 2.5, 2.2, 1.9, 1.7, 1.5],
        "moment": [3.2, 3.0, 2.8, 2.5, 2.3, 2.0],
        "react": [2.0, 1.8, 1.5, 1.2, 1.0, 0.8],
    }

    # Sample security metrics - initial and final
    security_metrics_initial = {
        "security_policy": 25,
        "dependency_update": 40,
        "signed_commits": 15,
        "branch_protection": 30,
    }

    security_metrics_final = {
        "security_policy": 60,
        "dependency_update": 75,
        "signed_commits": 45,
        "branch_protection": 70,
    }

    # Generate visualization data
    visualizations = {}

    # Overall risk score trend
    visualizations["overall"] = {
        "type": "line_chart",
        "title": "Overall Risk Score Trend",
        "data": {
            "labels": dates,
            "datasets": [
                {
                    "label": "Risk Score",
                    "data": overall_scores,
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

    # Risk distribution trend
    visualizations["distribution"] = {
        "type": "stacked_bar_chart",
        "title": "Risk Distribution Trend",
        "data": {
            "labels": dates,
            "datasets": [
                {
                    "label": "High Risk",
                    "data": high_risk,
                    "backgroundColor": "rgba(255, 99, 132, 0.7)",
                },
                {
                    "label": "Medium Risk",
                    "data": medium_risk,
                    "backgroundColor": "rgba(255, 159, 64, 0.7)",
                },
                {
                    "label": "Low Risk",
                    "data": low_risk,
                    "backgroundColor": "rgba(75, 192, 192, 0.7)",
                },
            ],
        },
        "options": {
            "scales": {
                "y": {
                    "stacked": True,
                    "title": {"display": True, "text": "Number of Dependencies"},
                },
                "x": {"stacked": True},
            }
        },
    }

    # Top dependencies risk trends
    datasets = []
    colors = ["#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF"]

    for i, (name, scores) in enumerate(dependencies.items()):
        datasets.append(
            {
                "label": name,
                "data": scores,
                "borderColor": colors[i % len(colors)],
                "fill": False,
            }
        )

    visualizations["dependencies"] = {
        "type": "line_chart",
        "title": "Top Dependencies Risk Trends",
        "data": {"labels": dates, "datasets": datasets},
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

    # Security metrics radar chart
    visualizations["security"] = {
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
                    "label": dates[0],
                    "data": list(security_metrics_initial.values()),
                    "backgroundColor": "rgba(54, 162, 235, 0.2)",
                    "borderColor": "rgb(54, 162, 235)",
                },
                {
                    "label": dates[-1],
                    "data": list(security_metrics_final.values()),
                    "backgroundColor": "rgba(255, 99, 132, 0.2)",
                    "borderColor": "rgb(255, 99, 132)",
                },
            ],
        },
        "options": {
            "scales": {"r": {"angleLines": {"display": True}, "min": 0, "max": 100}}
        },
    }

    return visualizations


def main():
    """Generate and save visualization data."""
    visualizations = generate_sample_data()

    # Save each visualization type to a separate file
    for viz_type, data in visualizations.items():
        filename = f"{viz_type}_sample.json"
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Sample visualization data saved to: {filename}")

    print("\nTo view the visualizations:")
    print("1. Open trend_visualizer.html in a web browser")
    print("2. Click 'Choose File' and select one of the generated JSON files")
    print("3. The visualization will be displayed in the chart area")


if __name__ == "__main__":
    main()
