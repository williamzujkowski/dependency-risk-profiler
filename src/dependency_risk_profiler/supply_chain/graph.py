"""Dependency graph generation for visualization."""

import logging
from typing import Dict, Optional

from ..models import DependencyMetadata

logger = logging.getLogger(__name__)


def generate_dependency_graph(
    dependencies: Dict[str, DependencyMetadata],
    output_format: str = "d3",
    risk_scores: Optional[Dict[str, float]] = None,
    depth_limit: int = 3,
) -> Dict:
    """Generate a dependency graph for visualization.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.
        output_format: Format of the output (d3, graphviz, cytoscape).
        risk_scores: Optional dictionary mapping dependency names to risk scores.
        depth_limit: Maximum depth of transitive dependencies to include.

    Returns:
        Graph data structure suitable for visualization.
    """
    if output_format == "d3":
        return _generate_d3_graph(dependencies, risk_scores, depth_limit)
    elif output_format == "graphviz":
        return _generate_graphviz_graph(dependencies, risk_scores, depth_limit)
    elif output_format == "cytoscape":
        return _generate_cytoscape_graph(dependencies, risk_scores, depth_limit)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def _generate_d3_graph(
    dependencies: Dict[str, DependencyMetadata],
    risk_scores: Optional[Dict[str, float]] = None,
    depth_limit: int = 3,
) -> Dict:
    """Generate a graph in D3.js force-directed graph format.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.
        risk_scores: Optional dictionary mapping dependency names to risk scores.
        depth_limit: Maximum depth of transitive dependencies to include.

    Returns:
        Dictionary with nodes and links for D3.js force-directed graph.
    """
    nodes = []
    links = []
    node_ids = {}  # Map dependency names to node IDs

    # Process direct dependencies first
    for idx, (name, dep) in enumerate(dependencies.items()):
        # Determine node color based on risk level
        color = "#5aa8db"  # Default color (medium risk)
        if risk_scores and name in risk_scores:
            risk_score = risk_scores[name]
            if risk_score < 0.25:
                color = "#4caf50"  # Green (low risk)
            elif risk_score < 0.5:
                color = "#5aa8db"  # Blue (medium risk)
            elif risk_score < 0.75:
                color = "#ff9800"  # Orange (high risk)
            else:
                color = "#f44336"  # Red (critical risk)

        # Create the node
        nodes.append(
            {
                "id": idx,
                "name": name,
                "version": dep.installed_version,
                "color": color,
                "radius": 10,  # Direct dependencies are larger
                "level": 0,  # Direct dependency level
            }
        )

        node_ids[name] = idx

    # Process transitive dependencies up to the depth limit
    processed_deps = set(dependencies.keys())
    current_level_deps = list(dependencies.keys())
    next_level_deps = []

    for level in range(1, depth_limit + 1):
        for parent_dep in current_level_deps:
            parent_id = node_ids[parent_dep]

            if parent_dep in dependencies:
                parent_metadata = dependencies[parent_dep]

                # Process transitive dependencies for this parent
                for trans_dep in parent_metadata.transitive_dependencies:
                    # Skip if already processed to avoid cycles
                    if trans_dep in processed_deps:
                        # But still add the link
                        links.append(
                            {
                                "source": parent_id,
                                "target": node_ids[trans_dep],
                                "value": 1,  # Link strength
                            }
                        )
                        continue

                    # Add this transitive dependency as a node
                    trans_id = len(nodes)
                    nodes.append(
                        {
                            "id": trans_id,
                            "name": trans_dep,
                            "version": "?",  # May not have version info for transitive deps
                            "color": "#aaaaaa",  # Gray for transitive deps
                            "radius": 5,  # Smaller radius for transitive deps
                            "level": level,  # Transitive dependency level
                        }
                    )

                    node_ids[trans_dep] = trans_id
                    processed_deps.add(trans_dep)
                    next_level_deps.append(trans_dep)

                    # Add link to parent
                    links.append(
                        {
                            "source": parent_id,
                            "target": trans_id,
                            "value": 1,  # Link strength
                        }
                    )

        # Move to next level
        current_level_deps = next_level_deps
        next_level_deps = []

        # Stop if no more dependencies to process
        if not current_level_deps:
            break

    return {"nodes": nodes, "links": links}


def _generate_graphviz_graph(
    dependencies: Dict[str, DependencyMetadata],
    risk_scores: Optional[Dict[str, float]] = None,
    depth_limit: int = 3,
) -> Dict:
    """Generate a graph in Graphviz DOT format.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.
        risk_scores: Optional dictionary mapping dependency names to risk scores.
        depth_limit: Maximum depth of transitive dependencies to include.

    Returns:
        Dictionary with dot_source for Graphviz rendering.
    """
    dot_lines = ["digraph DependencyGraph {", "  rankdir=LR;", "  node [shape=box];"]
    processed_deps = set()

    def add_dependency_to_graph(dep_name, level=0):
        if dep_name in processed_deps or level > depth_limit:
            return
        processed_deps.add(dep_name)

        # Determine node color based on risk level
        color = "lightblue"  # Default color (medium risk)
        if risk_scores and dep_name in risk_scores:
            risk_score = risk_scores[dep_name]
            if risk_score < 0.25:
                color = "lightgreen"  # Green (low risk)
            elif risk_score < 0.5:
                color = "lightblue"  # Blue (medium risk)
            elif risk_score < 0.75:
                color = "orange"  # Orange (high risk)
            else:
                color = "red"  # Red (critical risk)

        # Add the node
        dot_lines.append(f'  "{dep_name}" [style=filled, fillcolor={color}];')

        # Add edges for transitive dependencies
        if dep_name in dependencies:
            dep = dependencies[dep_name]
            for trans_dep in dep.transitive_dependencies:
                dot_lines.append(f'  "{dep_name}" -> "{trans_dep}";')
                add_dependency_to_graph(trans_dep, level + 1)

    # Process all direct dependencies
    for dep_name in dependencies:
        add_dependency_to_graph(dep_name)

    dot_lines.append("}")

    return {"dot_source": "\n".join(dot_lines)}


def _generate_cytoscape_graph(
    dependencies: Dict[str, DependencyMetadata],
    risk_scores: Optional[Dict[str, float]] = None,
    depth_limit: int = 3,
) -> Dict:
    """Generate a graph in Cytoscape.js format.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.
        risk_scores: Optional dictionary mapping dependency names to risk scores.
        depth_limit: Maximum depth of transitive dependencies to include.

    Returns:
        Dictionary with elements for Cytoscape.js.
    """
    elements = {"nodes": [], "edges": []}
    processed_deps = set()

    def add_dependency_to_graph(dep_name, level=0):
        if dep_name in processed_deps or level > depth_limit:
            return
        processed_deps.add(dep_name)

        # Determine node color based on risk level
        color = "#5aa8db"  # Default color (medium risk)
        if risk_scores and dep_name in risk_scores:
            risk_score = risk_scores[dep_name]
            if risk_score < 0.25:
                color = "#4caf50"  # Green (low risk)
            elif risk_score < 0.5:
                color = "#5aa8db"  # Blue (medium risk)
            elif risk_score < 0.75:
                color = "#ff9800"  # Orange (high risk)
            else:
                color = "#f44336"  # Red (critical risk)

        # Create the node
        node_data = {"id": dep_name, "label": dep_name}

        # Add version if available
        if dep_name in dependencies:
            node_data["version"] = dependencies[dep_name].installed_version

        elements["nodes"].append(
            {
                "data": node_data,
                "style": {
                    "background-color": color,
                    "shape": "rectangle" if level == 0 else "ellipse",
                    "width": 20 if level == 0 else 15,
                    "height": 20 if level == 0 else 15,
                },
            }
        )

        # Add edges for transitive dependencies
        if dep_name in dependencies:
            dep = dependencies[dep_name]
            for trans_dep in dep.transitive_dependencies:
                edge_id = f"{dep_name}-{trans_dep}"
                elements["edges"].append(
                    {"data": {"id": edge_id, "source": dep_name, "target": trans_dep}}
                )
                add_dependency_to_graph(trans_dep, level + 1)

    # Process all direct dependencies
    for dep_name in dependencies:
        add_dependency_to_graph(dep_name)

    return elements
