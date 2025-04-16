"""Command-line interface for the dependency risk profiler."""
import argparse
import logging
import os
import sys
from typing import Dict, List, Optional

from ..analyzers.base import BaseAnalyzer
from ..models import DependencyMetadata
from ..parsers.base import BaseParser
from ..scoring.risk_scorer import RiskScorer
from .formatter import JsonFormatter, TerminalFormatter


def setup_logging(debug: bool = False) -> None:
    """Set up logging.
    
    Args:
        debug: Whether to enable debug logging.
    """
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.
    
    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Dependency Risk Profiler - A tool to evaluate the health and risk "
        "of a project's dependencies beyond vulnerability scanning."
    )
    
    parser.add_argument(
        "--manifest",
        "-m",
        required=True,
        help="Path to the dependency manifest file (e.g., package-lock.json, "
        "requirements.txt, go.mod).",
    )
    
    parser.add_argument(
        "--output",
        "-o",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format. Defaults to terminal.",
    )
    
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable color output in terminal mode.",
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    
    # Historical trends analysis options
    trends_group = parser.add_argument_group("Historical Trends Analysis")
    
    trends_group.add_argument(
        "--save-history",
        action="store_true",
        help="Save current scan results to historical data.",
    )
    
    trends_group.add_argument(
        "--analyze-trends",
        action="store_true",
        help="Analyze historical trends for the project.",
    )
    
    trends_group.add_argument(
        "--trend-limit",
        type=int,
        default=10,
        help="Maximum number of historical scans to include in trend analysis. Defaults to 10.",
    )
    
    trends_group.add_argument(
        "--trend-visualization",
        choices=["overall", "distribution", "dependencies", "security"],
        help="Generate visualization data for the specified trend type.",
    )
    
    # Supply chain visualization options
    visualization_group = parser.add_argument_group("Supply Chain Visualization")
    
    visualization_group.add_argument(
        "--generate-graph",
        action="store_true",
        help="Generate a dependency graph for visualization.",
    )
    
    visualization_group.add_argument(
        "--graph-format",
        choices=["d3", "graphviz", "cytoscape"],
        default="d3",
        help="Format for the dependency graph. Defaults to d3.",
    )
    
    visualization_group.add_argument(
        "--graph-depth",
        type=int,
        default=3,
        help="Maximum depth of transitive dependencies to include in the graph. Defaults to 3.",
    )
    
    # Base risk factors
    risk_group = parser.add_argument_group("Basic Risk Factors")
    
    risk_group.add_argument(
        "--staleness-weight",
        type=float,
        default=0.25,
        help="Weight for staleness score. Defaults to 0.25.",
    )
    
    risk_group.add_argument(
        "--maintainer-weight",
        type=float,
        default=0.2,
        help="Weight for maintainer count score. Defaults to 0.2.",
    )
    
    risk_group.add_argument(
        "--deprecation-weight",
        type=float,
        default=0.3,
        help="Weight for deprecation score. Defaults to 0.3.",
    )
    
    risk_group.add_argument(
        "--exploit-weight",
        type=float,
        default=0.5,
        help="Weight for known exploits score. Defaults to 0.5.",
    )
    
    risk_group.add_argument(
        "--version-weight",
        type=float,
        default=0.15,
        help="Weight for version difference score. Defaults to 0.15.",
    )
    
    risk_group.add_argument(
        "--health-weight",
        type=float,
        default=0.1,
        help="Weight for health indicators score. Defaults to 0.1.",
    )
    
    # Enhanced risk factors
    enhanced_group = parser.add_argument_group("Enhanced Risk Factors")
    
    enhanced_group.add_argument(
        "--license-weight",
        type=float,
        default=0.3,
        help="Weight for license risk score. Defaults to 0.3.",
    )
    
    enhanced_group.add_argument(
        "--community-weight",
        type=float,
        default=0.2,
        help="Weight for community health score. Defaults to 0.2.",
    )
    
    enhanced_group.add_argument(
        "--transitive-weight",
        type=float,
        default=0.15,
        help="Weight for transitive dependency score. Defaults to 0.15.",
    )
    
    # Vulnerability sources
    vuln_group = parser.add_argument_group("Vulnerability Sources")
    
    vuln_group.add_argument(
        "--enable-osv",
        action="store_true",
        default=True,
        help="Enable OSV vulnerability source. Enabled by default.",
    )
    
    vuln_group.add_argument(
        "--enable-nvd",
        action="store_true",
        help="Enable NVD vulnerability source.",
    )
    
    vuln_group.add_argument(
        "--enable-github-advisory",
        action="store_true",
        help="Enable GitHub Advisory vulnerability source.",
    )
    
    vuln_group.add_argument(
        "--github-token",
        help="GitHub API token for GitHub Advisory vulnerability source.",
    )
    
    vuln_group.add_argument(
        "--nvd-api-key",
        help="NVD API key for NVD vulnerability source.",
    )
    
    return parser.parse_args()


def get_ecosystem_from_manifest(manifest_path: str) -> str:
    """Determine the ecosystem from the manifest file path.
    
    Args:
        manifest_path: Path to the manifest file.
        
    Returns:
        Ecosystem name.
    """
    file_name = os.path.basename(manifest_path).lower()
    
    if file_name == "package-lock.json":
        return "nodejs"
    elif file_name in ["requirements.txt", "pipfile.lock"]:
        return "python"
    elif file_name == "go.mod":
        return "golang"
    else:
        return "unknown"


def main() -> int:
    """Main entry point for the command-line interface.
    
    Returns:
        Exit code.
    """
    args = parse_args()
    setup_logging(args.debug)
    
    logger = logging.getLogger(__name__)
    
    try:
        # Parse manifest file
        manifest_path = os.path.abspath(args.manifest)
        logger.info(f"Parsing manifest file: {manifest_path}")
        
        parser = BaseParser.get_parser_for_file(manifest_path)
        if not parser:
            logger.error(f"Unsupported manifest file: {manifest_path}")
            return 1
        
        dependencies = parser.parse()
        if not dependencies:
            logger.warning(f"No dependencies found in {manifest_path}")
            return 0
        
        logger.info(f"Found {len(dependencies)} dependencies")
        
        # Analyze dependencies
        ecosystem = get_ecosystem_from_manifest(manifest_path)
        analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(ecosystem)
        if not analyzer:
            logger.error(f"Unsupported ecosystem: {ecosystem}")
            return 1
        
        logger.info(f"Analyzing dependencies for {ecosystem}")
        dependencies = analyzer.analyze(dependencies)
        
        # Apply enhanced analyzers
        try:
            # Import enhanced analyzers
            from ..license.analyzer import analyze_license
            from ..community.analyzer import analyze_community_metrics
            from ..transitive.analyzer import analyze_transitive_dependencies
            
            logger.info("Analyzing license information")
            # Apply license analysis to each dependency
            for name, dep in dependencies.items():
                if hasattr(analyzer, 'metadata_cache') and name in analyzer.metadata_cache:
                    dependencies[name] = analyze_license(dep, analyzer.metadata_cache[name])
            
            logger.info("Analyzing community metrics")
            # Apply community metrics analysis to each dependency
            for name, dep in dependencies.items():
                if hasattr(analyzer, 'metadata_cache') and name in analyzer.metadata_cache:
                    dependencies[name] = analyze_community_metrics(dep, analyzer.metadata_cache[name])
                else:
                    dependencies[name] = analyze_community_metrics(dep)
            
            logger.info("Analyzing transitive dependencies")
            dependencies = analyze_transitive_dependencies(dependencies, manifest_path)
            
            # Aggregate vulnerability data from multiple sources
            if args.enable_osv or args.enable_nvd or args.enable_github_advisory:
                try:
                    from ..vulnerabilities.aggregator import aggregate_vulnerability_data
                    
                    logger.info("Aggregating vulnerability data from multiple sources")
                    
                    # Configure API keys
                    api_keys = {}
                    if args.github_token and args.enable_github_advisory:
                        api_keys["github"] = args.github_token
                    
                    if args.nvd_api_key and args.enable_nvd:
                        api_keys["nvd"] = args.nvd_api_key
                    
                    # Process each dependency
                    for name, dep in dependencies.items():
                        try:
                            logger.debug(f"Checking vulnerability data for {name}")
                            dependencies[name], vulns = aggregate_vulnerability_data(dep, api_keys)
                            logger.debug(f"Found {len(vulns)} vulnerabilities for {name}")
                        except Exception as e:
                            logger.warning(f"Error aggregating vulnerability data for {name}: {e}")
                
                except ImportError as e:
                    logger.warning(f"Vulnerability aggregation not available: {e}")
            
        except ImportError as e:
            logger.warning(f"Enhanced analyzers not available: {e}")
        except Exception as e:
            logger.error(f"Error during enhanced analysis: {e}")
        
        # Score dependencies
        logger.info("Scoring dependencies")
        scorer = RiskScorer(
            staleness_weight=args.staleness_weight,
            maintainer_weight=args.maintainer_weight,
            deprecation_weight=args.deprecation_weight,
            exploit_weight=args.exploit_weight,
            version_difference_weight=args.version_weight,
            health_indicators_weight=args.health_weight,
            # Enhanced risk factors - default weights
            license_weight=0.3,
            community_weight=0.2,
            transitive_weight=0.15,
        )
        
        profile = scorer.create_project_profile(manifest_path, ecosystem, dependencies)
        
        # Format output
        if args.output == "terminal":
            formatter = TerminalFormatter(color=not args.no_color)
        else:
            formatter = JsonFormatter()
        
        output = formatter.format_profile(profile)
        print(output)
        
        # Process supply chain visualization if requested
        if args.generate_graph:
            try:
                from ..supply_chain import generate_dependency_graph
                
                logger.info(f"Generating dependency graph in {args.graph_format} format")
                
                # Extract risk scores for graph coloring
                risk_scores = {}
                for dep in profile.dependencies:
                    risk_scores[dep.dependency.name] = dep.total_score / 5.0  # Normalize to 0-1
                
                # Generate the graph
                graph_data = generate_dependency_graph(
                    dependencies={dep.dependency.name: dep.dependency for dep in profile.dependencies},
                    output_format=args.graph_format,
                    risk_scores=risk_scores,
                    depth_limit=args.graph_depth
                )
                
                # Determine output file name
                base_name = os.path.splitext(os.path.basename(manifest_path))[0]
                graph_file = f"{base_name}_dependency_graph.json"
                
                # Save the graph data
                with open(graph_file, "w") as f:
                    json.dump(graph_data, f, indent=2)
                
                logger.info(f"Dependency graph saved to {graph_file}")
                print(f"\nDependency graph saved to {graph_file}")
                
            except ImportError as e:
                logger.warning(f"Supply chain visualization not available: {e}")
            except Exception as e:
                logger.error(f"Error generating dependency graph: {e}", exc_info=args.debug)
        
        # Handle historical trends functionality
        try:
            if args.save_history:
                from ..supply_chain import save_historical_profile
                
                logger.info("Saving scan results to historical data")
                history_path = save_historical_profile(profile)
                print(f"\nScan results saved to historical data at {history_path}")
            
            if args.analyze_trends:
                from ..supply_chain import analyze_historical_trends
                
                logger.info("Analyzing historical trends")
                trends = analyze_historical_trends(profile.manifest_path, args.trend_limit)
                
                if "error" in trends:
                    print(f"\nTrend analysis error: {trends['error']}")
                else:
                    # Output trend summary
                    print("\nHistorical Trend Analysis:")
                    
                    # Overall risk summary
                    avg_risk = trends["average_risk_over_time"]
                    print(f"  Average Risk Score: {avg_risk['average']:.2f}/5.0 ({avg_risk['trend']})")
                    
                    # Improving and deteriorating dependencies
                    print(f"  Improving Dependencies: {len(trends['improving_dependencies'])}")
                    print(f"  Deteriorating Dependencies: {len(trends['deteriorating_dependencies'])}")
                    
                    # Period analyzed
                    print(f"  Analysis Period: {trends['analyzed_period']['start']} to {trends['analyzed_period']['end']}")
                    print(f"  Scans Analyzed: {trends['analyzed_period']['scans_analyzed']}")
                    
                    # Velocity metrics
                    if "velocity_metrics" in trends and trends["velocity_metrics"]:
                        vm = trends["velocity_metrics"]
                        print("\n  Dependency Velocity Metrics:")
                        print(f"    New Dependencies: {vm.get('new_dependencies', 0)}")
                        print(f"    Updated Dependencies: {vm.get('updated_dependencies', 0)}")
                        print(f"    Removed Dependencies: {vm.get('removed_dependencies', 0)}")
                        print(f"    Dependency Churn Rate: {vm.get('dependency_churn_rate', 0)} deps/day")
            
            if args.trend_visualization:
                from ..supply_chain import generate_trend_visualization
                
                logger.info(f"Generating trend visualization for {args.trend_visualization}")
                viz_data = generate_trend_visualization(
                    profile.manifest_path,
                    args.trend_visualization,
                    args.trend_limit
                )
                
                if "error" in viz_data:
                    print(f"\nVisualization error: {viz_data['error']}")
                else:
                    # Determine output file name
                    base_name = os.path.splitext(os.path.basename(manifest_path))[0]
                    viz_file = f"{base_name}_{args.trend_visualization}_trend.json"
                    
                    # Save the visualization data
                    with open(viz_file, "w") as f:
                        json.dump(viz_data, f, indent=2)
                    
                    logger.info(f"Trend visualization data saved to {viz_file}")
                    print(f"\nTrend visualization data saved to {viz_file}")
                
        except ImportError as e:
            logger.warning(f"Historical trends analysis not available: {e}")
        except Exception as e:
            logger.error(f"Error in historical trends analysis: {e}", exc_info=args.debug)
        
        return 0
    
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.debug)
        return 1


if __name__ == "__main__":
    sys.exit(main())