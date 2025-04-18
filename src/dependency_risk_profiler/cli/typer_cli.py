"""Command-line interface using Typer for the dependency risk profiler."""

import json
import logging
import os
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..analyzers.base import BaseAnalyzer
from ..config import Config
from ..models import ProjectRiskProfile
from ..parsers.base import BaseParser
from ..parsers.registry import EcosystemRegistry
from ..scoring.risk_scorer import RiskScorer
from .formatter import JsonFormatter, TerminalFormatter

# Create Typer app
app = typer.Typer(
    name="dependency-risk-profiler",
    help=(
        "A tool to evaluate the health and risk of a project's dependencies "
        "beyond vulnerability scanning."
    ),
    add_completion=False,
)

# Create console for rich output
console = Console()


# Define enums for choices
class OutputFormat(str, Enum):
    """Output format enum."""

    TERMINAL = "terminal"
    JSON = "json"


class GraphFormat(str, Enum):
    """Graph format enum."""

    D3 = "d3"
    GRAPHVIZ = "graphviz"
    CYTOSCAPE = "cytoscape"


class TrendVisualization(str, Enum):
    """Trend visualization enum."""

    OVERALL = "overall"
    DISTRIBUTION = "distribution"
    DEPENDENCIES = "dependencies"
    SECURITY = "security"


def setup_logging(debug: bool = False) -> None:
    """Set up logging with rich handler.

    Args:
        debug: Whether to enable debug logging
    """
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )


def display_ecosystem_list() -> None:
    """Display a list of supported ecosystems and file types."""
    try:
        # If the registry is empty, initialize it with built-in parsers
        if not EcosystemRegistry.get_available_ecosystems():
            BaseParser._initialize_registry()

        # Get ecosystem details
        ecosystem_details = EcosystemRegistry.get_ecosystem_details()

        if ecosystem_details:
            console.print("\n[bold]Supported ecosystems and file types:[/bold]")
            for ecosystem, details in ecosystem_details.items():
                console.print(f"\n- [bold cyan]{ecosystem.capitalize()}:[/bold cyan]")
                for pattern in details.get("file_patterns", []):
                    console.print(f"  • [green]{pattern}[/green]")
        else:
            console.print("\n[bold red]No ecosystems are registered.[/bold red]")

    except ImportError as e:
        console.print(
            f"\n[bold red]Error: Registry module not available: {e}[/bold red]"
        )
    except Exception as e:
        console.print(
            f"\n[bold red]Error displaying available ecosystems: {e}[/bold red]"
        )


def get_ecosystem_from_manifest(manifest_path: str) -> str:
    """Determine the ecosystem from the manifest file path.

    Args:
        manifest_path: Path to the manifest file

    Returns:
        Ecosystem name
    """
    try:
        # If the registry is empty, initialize it with built-in parsers
        if not EcosystemRegistry.get_available_ecosystems():
            BaseParser._initialize_registry()

        # Detect the ecosystem using the registry
        ecosystem = EcosystemRegistry.detect_ecosystem(Path(manifest_path))
        if ecosystem:
            return ecosystem
    except ImportError:
        pass  # Fall back to the default implementation

    # Fallback implementation if registry is not available or doesn't match
    file_name = os.path.basename(manifest_path).lower()

    if file_name == "package-lock.json":
        return "nodejs"
    elif file_name in ["requirements.txt", "pipfile.lock"]:
        return "python"
    elif file_name == "go.mod":
        return "golang"
    elif file_name in ["pyproject.toml", "cargo.toml"] or file_name.endswith(".toml"):
        return "toml"
    else:
        return "unknown"


@app.callback()
def callback(
    ctx: typer.Context,
    config_path: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
        exists=True,
        dir_okay=False,
        file_okay=True,
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug logging",
    ),
) -> None:
    """
    Dependency Risk Profiler - A tool to evaluate the health and risk of a project's dependencies.
    """
    # Initialize configuration
    ctx.obj = Config(config_path)

    # Update debug setting from config
    debug_from_config = ctx.obj.get("general", "debug", False)
    debug = debug or debug_from_config

    # Set up logging
    setup_logging(debug)


@app.command()
def analyze(
    # Basic options
    manifest: Optional[Path] = typer.Argument(
        None,
        help=(
            "Path to the dependency manifest file or directory "
            "(e.g., package-lock.json, requirements.txt, or a project directory)"
        ),
        exists=True,
        dir_okay=True,
        file_okay=True,
    ),
    recursive: bool = typer.Option(
        False,
        "--recursive",
        "-r",
        help="Recursively search for manifest files in the provided directory",
    ),
    timeout: int = typer.Option(
        120,
        "--timeout",
        "-t",
        help="Timeout in seconds for the analysis of each manifest file",
    ),
    output: OutputFormat = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable color output in terminal mode",
    ),
    # Risk factor weights
    staleness_weight: Optional[float] = typer.Option(
        None,
        "--staleness-weight",
        help="Weight for staleness score (default: 0.25)",
        min=0.0,
        max=1.0,
    ),
    maintainer_weight: Optional[float] = typer.Option(
        None,
        "--maintainer-weight",
        help="Weight for maintainer count score (default: 0.2)",
        min=0.0,
        max=1.0,
    ),
    deprecation_weight: Optional[float] = typer.Option(
        None,
        "--deprecation-weight",
        help="Weight for deprecation score (default: 0.3)",
        min=0.0,
        max=1.0,
    ),
    exploit_weight: Optional[float] = typer.Option(
        None,
        "--exploit-weight",
        help="Weight for known exploits score (default: 0.5)",
        min=0.0,
        max=1.0,
    ),
    version_weight: Optional[float] = typer.Option(
        None,
        "--version-weight",
        help="Weight for version difference score (default: 0.15)",
        min=0.0,
        max=1.0,
    ),
    health_weight: Optional[float] = typer.Option(
        None,
        "--health-weight",
        help="Weight for health indicators score (default: 0.1)",
        min=0.0,
        max=1.0,
    ),
    license_weight: Optional[float] = typer.Option(
        None,
        "--license-weight",
        help="Weight for license risk score (default: 0.3)",
        min=0.0,
        max=1.0,
    ),
    community_weight: Optional[float] = typer.Option(
        None,
        "--community-weight",
        help="Weight for community health score (default: 0.2)",
        min=0.0,
        max=1.0,
    ),
    transitive_weight: Optional[float] = typer.Option(
        None,
        "--transitive-weight",
        help="Weight for transitive dependency score (default: 0.15)",
        min=0.0,
        max=1.0,
    ),
    # Vulnerability options
    enable_osv: bool = typer.Option(
        True,
        "--enable-osv/--disable-osv",
        help="Enable/disable OSV vulnerability source",
    ),
    enable_nvd: bool = typer.Option(
        False,
        "--enable-nvd",
        help="Enable NVD vulnerability source",
    ),
    enable_github_advisory: bool = typer.Option(
        False,
        "--enable-github-advisory",
        help="Enable GitHub Advisory vulnerability source",
    ),
    github_token: Optional[str] = typer.Option(
        None,
        "--github-token",
        help="GitHub API token for GitHub Advisory vulnerability source",
        envvar="GITHUB_TOKEN",
    ),
    nvd_api_key: Optional[str] = typer.Option(
        None,
        "--nvd-api-key",
        help="NVD API key for NVD vulnerability source",
        envvar="NVD_API_KEY",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable caching of vulnerability data",
    ),
    clear_cache: bool = typer.Option(
        False,
        "--clear-cache",
        help="Clear the vulnerability cache before running",
    ),
    # Supply chain visualization options
    generate_graph: bool = typer.Option(
        False,
        "--generate-graph",
        help="Generate a dependency graph for visualization",
    ),
    graph_format: GraphFormat = typer.Option(
        "d3",
        "--graph-format",
        help="Format for the dependency graph",
    ),
    graph_depth: int = typer.Option(
        3,
        "--graph-depth",
        help="Maximum depth of transitive dependencies to include in the graph",
        min=1,
    ),
    # Historical trends options
    save_history: bool = typer.Option(
        False,
        "--save-history",
        help="Save current scan results to historical data",
    ),
    analyze_trends: bool = typer.Option(
        False,
        "--analyze-trends",
        help="Analyze historical trends for the project",
    ),
    trend_limit: int = typer.Option(
        10,
        "--trend-limit",
        help="Maximum number of historical scans to include in trend analysis",
        min=1,
    ),
    trend_visualization: Optional[TrendVisualization] = typer.Option(
        None,
        "--trend-visualization",
        help="Generate visualization data for the specified trend type",
    ),
    # Context and config
    ctx: typer.Context = typer.Context,
) -> None:
    """Analyze dependencies and generate risk profile."""
    # Get configuration
    config = ctx.obj

    # Update configuration with command-line arguments
    args = {
        "output": output.value if output else None,
        "no_color": no_color,
        "debug": ctx.parent.params.get("debug", False) if ctx.parent else False,
        "timeout": timeout,
        "staleness_weight": staleness_weight,
        "maintainer_weight": maintainer_weight,
        "deprecation_weight": deprecation_weight,
        "exploit_weight": exploit_weight,
        "version_weight": version_weight,
        "health_weight": health_weight,
        "license_weight": license_weight,
        "community_weight": community_weight,
        "transitive_weight": transitive_weight,
        "enable_osv": enable_osv,
        "enable_nvd": enable_nvd,
        "enable_github_advisory": enable_github_advisory,
        "github_token": github_token,
        "nvd_api_key": nvd_api_key,
        "no_cache": no_cache,
        "clear_cache": clear_cache,
        "generate_graph": generate_graph,
        "graph_format": graph_format.value if graph_format else None,
        "graph_depth": graph_depth,
        "save_history": save_history,
        "analyze_trends": analyze_trends,
        "trend_limit": trend_limit,
        "trend_visualization": (
            trend_visualization.value if trend_visualization else None
        ),
    }
    config.update_from_args(args)

    # Get logger
    logger = logging.getLogger(__name__)

    try:
        # Check if manifest argument is provided
        if not manifest:
            console.print(
                "[bold red]Error: the MANIFEST argument is required.[/bold red]"
            )
            console.print(
                (
                    "Run [bold]dependency-risk-profiler list-ecosystems[/bold] to see "
                    "all supported ecosystems and file types."
                )
            )
            raise typer.Exit(code=1)

        # Handle directory scanning
        manifest_path = os.path.abspath(manifest)
        manifest_files = []

        if os.path.isdir(manifest_path):
            logger.info(f"Scanning directory: {manifest_path}")
            # Import the registry to check file matchers
            from ..parsers.registry import EcosystemRegistry

            # Initialize registry if needed
            if not EcosystemRegistry.get_available_ecosystems():
                BaseParser._initialize_registry()

            console.print(
                f"[bold]Scanning {'recursively' if recursive else 'directory'} for manifest files...[/bold]"
            )

            for root, _, files in os.walk(manifest_path):
                # Skip if we're not in recursive mode and this isn't the top-level directory
                if not recursive and root != manifest_path:
                    continue

                for filename in files:
                    file_path = os.path.join(root, filename)

                    # Check if this file matches any ecosystem parser
                    if EcosystemRegistry.detect_ecosystem(Path(file_path)):
                        manifest_files.append(file_path)
                        logger.debug(f"Found manifest file: {file_path}")

                # If not recursive, break after the first directory
                if not recursive:
                    break

            if not manifest_files:
                console.print(
                    "[bold yellow]No supported manifest files found.[/bold yellow]"
                )
                display_ecosystem_list()
                raise typer.Exit(code=0)

            console.print(
                f"[bold green]Found {len(manifest_files)} manifest files to analyze[/bold green]"
            )
        else:
            # Single file mode
            manifest_files = [manifest_path]

        # Track overall results and failures
        overall_results: List[ProjectRiskProfile] = []
        failed_files: List[Dict[str, Any]] = []

        # Process each manifest file
        for manifest_path in manifest_files:
            try:
                # Parse manifest file
                logger.info(f"Parsing manifest file: {manifest_path}")

                # Get timeout value from config
                timeout_seconds = config.get("general", "timeout", 120)

                try:
                    # Create a progress spinner
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[bold green]Processing..."),
                        transient=True,
                    ) as progress:
                        progress.add_task("Parsing", total=None)

                        # Create an asyncio task with timeout
                        async def parse_with_timeout():
                            parser = BaseParser.get_parser_for_file(manifest_path)
                            if not parser:
                                logger.error(
                                    f"Unsupported manifest file: {manifest_path}"
                                )
                                return None, "unsupported"

                            dependencies = parser.parse()
                            if not dependencies:
                                logger.warning(
                                    f"No dependencies found in {manifest_path}"
                                )
                                return None, "empty"

                            return dependencies, None

                        # Run the parsing task with timeout
                        import asyncio

                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)

                        try:
                            dependencies, error = loop.run_until_complete(
                                asyncio.wait_for(
                                    parse_with_timeout(), timeout=timeout_seconds
                                )
                            )

                            if error == "unsupported":
                                console.print(
                                    f"[bold yellow]Skipping unsupported file: {manifest_path}[/bold yellow]"
                                )
                                continue
                            elif error == "empty":
                                console.print(
                                    f"[bold yellow]No dependencies found in {manifest_path}[/bold yellow]"
                                )
                                continue

                        except asyncio.TimeoutError:
                            logger.error(
                                f"Analysis timed out after {timeout_seconds} seconds for {manifest_path}"
                            )
                            console.print(
                                f"[bold red]Analysis timed out after {timeout_seconds} seconds for {manifest_path}. "
                                f"Try increasing the timeout with --timeout option or reducing the scope of analysis.[/bold red]"
                            )
                            # Add a record of the failed file to the summary
                            failed_file = {
                                "manifest_path": manifest_path,
                                "reason": "timeout",
                                "timeout": timeout_seconds,
                            }
                            failed_files.append(failed_file)

                            # Log the error for debug
                            logger.debug(
                                f"Added file to failed_files due to timeout: {manifest_path}"
                            )
                            logger.debug(
                                f"Current failed_files count: {len(failed_files)}"
                            )
                            continue
                except Exception as e:
                    # Fall back to non-async if there's an issue with the async implementation
                    logger.warning(f"Falling back to non-async parsing due to: {e}")

                    parser = BaseParser.get_parser_for_file(manifest_path)
                    if not parser:
                        logger.error(f"Unsupported manifest file: {manifest_path}")
                        console.print(
                            f"[bold yellow]Skipping unsupported file: {manifest_path}[/bold yellow]"
                        )
                        # Add unsupported file to failed list
                        failed_file = {
                            "manifest_path": manifest_path,
                            "reason": "unsupported",
                        }
                        failed_files.append(failed_file)
                        continue

                    dependencies = parser.parse()
                    if not dependencies:
                        logger.warning(f"No dependencies found in {manifest_path}")
                        console.print(
                            f"[bold yellow]No dependencies found in {manifest_path}[/bold yellow]"
                        )
                        # Add empty file to failed list
                        failed_file = {
                            "manifest_path": manifest_path,
                            "reason": "empty",
                        }
                        failed_files.append(failed_file)
                        continue

                    logger.info(f"Found {len(dependencies)} dependencies")

                    # Analyze dependencies
                    ecosystem = get_ecosystem_from_manifest(manifest_path)
                    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(ecosystem)
                    if not analyzer:
                        logger.error(f"Unsupported ecosystem: {ecosystem}")
                        console.print(
                            f"[bold red]The ecosystem '{ecosystem}' was detected for {manifest_path}, but no analyzer is available for it.[/bold red]"
                        )
                        console.print(
                            "Please check if you have all required analyzers installed."
                        )
                        continue

                    logger.info(f"Analyzing dependencies for {ecosystem}")
                    dependencies = analyzer.analyze(dependencies)

                    # Apply enhanced analyzers
                    try:
                        # Import enhanced analyzers
                        from ..community.analyzer import analyze_community_metrics
                        from ..license.analyzer import analyze_license
                        from ..transitive.analyzer_enhanced import (
                            analyze_transitive_dependencies_enhanced,
                        )

                        logger.info("Analyzing license information")
                        # Apply license analysis to each dependency
                        for name, dep in dependencies.items():
                            if (
                                hasattr(analyzer, "metadata_cache")
                                and name in analyzer.metadata_cache
                            ):
                                dependencies[name] = analyze_license(
                                    dep, analyzer.metadata_cache[name]
                                )

                        logger.info("Analyzing community metrics")
                        # Apply community metrics analysis to each dependency
                        for name, dep in dependencies.items():
                            if (
                                hasattr(analyzer, "metadata_cache")
                                and name in analyzer.metadata_cache
                            ):
                                dependencies[name] = analyze_community_metrics(
                                    dep, analyzer.metadata_cache[name]
                                )
                            else:
                                dependencies[name] = analyze_community_metrics(dep)

                        logger.info("Analyzing transitive dependencies")
                        dependencies = analyze_transitive_dependencies_enhanced(
                            dependencies, manifest_path
                        )

                        # Aggregate vulnerability data from multiple sources
                        vuln_config = config.get_vulnerability_config()
                        if (
                            vuln_config.get("enable_osv")
                            or vuln_config.get("enable_nvd")
                            or vuln_config.get("enable_github_advisory")
                        ):
                            try:
                                from ..vulnerabilities.aggregator_async import (
                                    aggregate_vulnerability_data_async,
                                )

                                logger.info(
                                    "Aggregating vulnerability data from multiple sources"
                                )

                                # Handle cache settings
                                if vuln_config.get("disable_cache"):
                                    # Set environment variable to disable cache
                                    os.environ["DEPENDENCY_RISK_DISABLE_CACHE"] = "1"
                                    logger.info(
                                        "Vulnerability data caching is disabled"
                                    )

                                if vuln_config.get("clear_cache"):
                                    try:
                                        from ..vulnerabilities.cache import (
                                            default_cache,
                                        )

                                        cleared = default_cache.clear()
                                        logger.info(
                                            f"Cleared {cleared} entries from vulnerability cache"
                                        )
                                    except ImportError:
                                        logger.warning(
                                            "Vulnerability cache module not available"
                                        )

                                # Configure API keys
                                api_keys = config.get_api_keys()

                                # Process dependencies
                                updated_dependencies, vuln_counts = (
                                    aggregate_vulnerability_data_async(
                                        dependencies,
                                        api_keys=api_keys,
                                        enable_osv=vuln_config.get("enable_osv", True),
                                        enable_nvd=vuln_config.get("enable_nvd", False),
                                        enable_github=vuln_config.get(
                                            "enable_github_advisory", False
                                        ),
                                    )
                                )

                                dependencies = updated_dependencies
                                logger.info(
                                    f"Found vulnerabilities in {len(vuln_counts)} dependencies"
                                )

                            except ImportError as e:
                                logger.warning(
                                    f"Async vulnerability aggregation not available: {e}"
                                )
                                # Fall back to synchronous implementation
                                try:
                                    from ..vulnerabilities.aggregator import (
                                        aggregate_vulnerability_data,
                                    )

                                    # Process each dependency
                                    for name, dep in dependencies.items():
                                        try:
                                            logger.debug(
                                                f"Checking vulnerability data for {name}"
                                            )
                                            dependencies[name], vulns = (
                                                aggregate_vulnerability_data(
                                                    dep, api_keys
                                                )
                                            )
                                            logger.debug(
                                                f"Found {len(vulns)} vulnerabilities for {name}"
                                            )
                                        except Exception as e:
                                            logger.warning(
                                                f"Error aggregating vulnerability data for {name}: {e}"
                                            )
                                except ImportError as e:
                                    logger.warning(
                                        f"Vulnerability aggregation not available: {e}"
                                    )

                    except ImportError as e:
                        logger.warning(f"Enhanced analyzers not available: {e}")
                    except Exception as e:
                        logger.error(f"Error during enhanced analysis: {e}")

                    # Score dependencies
                    logger.info("Scoring dependencies")
                    scorer = RiskScorer(**config.get_scoring_weights())

                    profile = scorer.create_project_profile(
                        manifest_path, ecosystem, dependencies
                    )

                    # Format output
                    use_color = config.get("general", "use_color", True)
                    if config.get("general", "output_format") == "json":
                        formatter = JsonFormatter()
                    else:
                        formatter = TerminalFormatter(color=use_color)

                    output = formatter.format_profile(profile)

                    # In multi-file mode, prefix with the manifest path
                    if len(manifest_files) > 1:
                        console.print(
                            f"\n[bold blue]===== Results for {manifest_path} =====[/bold blue]"
                        )

                    console.print(output)

                    # Save the profile to our results
                    overall_results.append(profile)

                    # Process supply chain visualization if requested
                    if config.get("general", "generate_graph", False):
                        try:
                            from ..supply_chain import generate_dependency_graph

                            logger.info(
                                f"Generating dependency graph in {config.get('graph', 'format')} format"
                            )

                            # Extract risk scores for graph coloring
                            risk_scores = {}
                            for dep in profile.dependencies:
                                risk_scores[dep.dependency.name] = (
                                    dep.total_score / 5.0
                                )  # Normalize to 0-1

                            # Generate the graph
                            graph_data = generate_dependency_graph(
                                dependencies={
                                    dep.dependency.name: dep.dependency
                                    for dep in profile.dependencies
                                },
                                output_format=config.get("graph", "format"),
                                risk_scores=risk_scores,
                                depth_limit=config.get("graph", "depth"),
                            )

                            # Determine output file name
                            base_name = os.path.splitext(
                                os.path.basename(manifest_path)
                            )[0]
                            graph_file = f"{base_name}_dependency_graph.json"

                            # Save the graph data
                            with open(graph_file, "w") as f:
                                json.dump(graph_data, f, indent=2)

                            logger.info(f"Dependency graph saved to {graph_file}")
                            console.print(
                                f"\n[bold green]Dependency graph saved to {graph_file}[/bold green]"
                            )

                        except ImportError as e:
                            logger.warning(
                                f"Supply chain visualization not available: {e}"
                            )
                        except Exception as e:
                            logger.error(f"Error generating dependency graph: {e}")

                    # Handle historical trends functionality
                    try:
                        if config.get("general", "save_history", False):
                            from ..supply_chain import save_historical_profile

                            logger.info("Saving scan results to historical data")
                            history_path = save_historical_profile(profile)
                            console.print(
                                (
                                    f"\n[bold green]Scan results saved to historical data at "
                                    f"{history_path}[/bold green]"
                                )
                            )

                        if config.get("general", "analyze_trends", False):
                            from ..supply_chain import analyze_historical_trends

                            logger.info("Analyzing historical trends")
                            trends = analyze_historical_trends(
                                profile.manifest_path, config.get("trends", "limit")
                            )

                            if "error" in trends:
                                console.print(
                                    f"\n[bold red]Trend analysis error: {trends['error']}[/bold red]"
                                )
                            else:
                                # Output trend summary
                                console.print(
                                    "\n[bold]Historical Trend Analysis:[/bold]"
                                )

                                # Overall risk summary
                                avg_risk = trends["average_risk_over_time"]
                                console.print(
                                    f"  Average Risk Score: {avg_risk['average']:.2f}/5.0 ({avg_risk['trend']})"
                                )

                                # Improving and deteriorating dependencies
                                console.print(
                                    f"  Improving Dependencies: {len(trends['improving_dependencies'])}"
                                )
                                console.print(
                                    f"  Deteriorating Dependencies: {len(trends['deteriorating_dependencies'])}"
                                )

                                # Period analyzed
                                console.print(
                                    f"  Analysis Period: {trends['analyzed_period']['start']} to {trends['analyzed_period']['end']}"
                                )
                                console.print(
                                    f"  Scans Analyzed: {trends['analyzed_period']['scans_analyzed']}"
                                )

                                # Velocity metrics
                                if (
                                    "velocity_metrics" in trends
                                    and trends["velocity_metrics"]
                                ):
                                    vm = trends["velocity_metrics"]
                                    console.print(
                                        "\n  [bold]Dependency Velocity Metrics:[/bold]"
                                    )
                                    console.print(
                                        f"    New Dependencies: {vm.get('new_dependencies', 0)}"
                                    )
                                    console.print(
                                        f"    Updated Dependencies: {vm.get('updated_dependencies', 0)}"
                                    )
                                    console.print(
                                        f"    Removed Dependencies: {vm.get('removed_dependencies', 0)}"
                                    )
                                    console.print(
                                        f"    Dependency Churn Rate: {vm.get('dependency_churn_rate', 0)} deps/day"
                                    )

                        if config.get("general", "trend_visualization"):
                            from ..supply_chain import generate_trend_visualization

                            viz_type = config.get("general", "trend_visualization")
                            logger.info(
                                f"Generating trend visualization for {viz_type}"
                            )
                            viz_data = generate_trend_visualization(
                                profile.manifest_path,
                                viz_type,
                                config.get("trends", "limit"),
                            )

                            if "error" in viz_data:
                                console.print(
                                    f"\n[bold red]Visualization error: {viz_data['error']}[/bold red]"
                                )
                            else:
                                # Determine output file name
                                base_name = os.path.splitext(
                                    os.path.basename(manifest_path)
                                )[0]
                                viz_file = f"{base_name}_{viz_type}_trend.json"

                                # Save the visualization data
                                with open(viz_file, "w") as f:
                                    json.dump(viz_data, f, indent=2)

                                logger.info(
                                    f"Trend visualization data saved to {viz_file}"
                                )
                                console.print(
                                    f"\n[bold green]Trend visualization data saved to {viz_file}[/bold green]"
                                )

                    except ImportError as e:
                        logger.warning(f"Historical trends analysis not available: {e}")
                    except Exception as e:
                        logger.error(f"Error in historical trends analysis: {e}")

            except Exception as e:
                logger.error(f"Error processing {manifest_path}: {e}", exc_info=True)
                console.print(
                    f"[bold red]Error processing {manifest_path}: {e}[/bold red]"
                )
                # Add error file to failed list
                failed_file = {
                    "manifest_path": manifest_path,
                    "reason": "error",
                    "error": str(e),
                }
                failed_files.append(failed_file)

        # Display summary if manifest files were scanned
        if len(manifest_files) > 0:
            console.print("\n[bold]======== Overall Summary ========[/bold]")

            # Calculate total dependencies and risk levels
            total_deps = sum(len(profile.dependencies) for profile in overall_results)
            high_risk = sum(
                profile.high_risk_dependencies for profile in overall_results
            )
            medium_risk = sum(
                profile.medium_risk_dependencies for profile in overall_results
            )
            low_risk = sum(profile.low_risk_dependencies for profile in overall_results)

            # Calculate average risk score
            if total_deps > 0:
                total_score = sum(
                    profile.overall_risk_score * len(profile.dependencies)
                    for profile in overall_results
                )
                avg_score = total_score / total_deps
            else:
                avg_score = 0.0

            # Display the summary
            console.print(
                f"Total manifest files found: [bold]{len(manifest_files)}[/bold]"
            )
            console.print(f"Successfully analyzed: [bold]{len(overall_results)}[/bold]")
            if failed_files:
                console.print(
                    f"Failed analysis: [bold red]{len(failed_files)}[/bold red]"
                )

            if total_deps > 0:
                console.print(f"Total dependencies analyzed: [bold]{total_deps}[/bold]")
                console.print(
                    f"Overall average risk score: [bold]{avg_score:.2f}/5.0[/bold]"
                )
                console.print(
                    f"High risk dependencies: [bold red]{high_risk}[/bold red]"
                )
                console.print(
                    f"Medium risk dependencies: [bold yellow]{medium_risk}[/bold yellow]"
                )
                console.print(
                    f"Low risk dependencies: [bold green]{low_risk}[/bold green]"
                )

            # Show list of manifest files with highest risk scores
            if overall_results:
                # Sort by risk score (highest first)
                sorted_results = sorted(
                    overall_results, key=lambda x: x.overall_risk_score, reverse=True
                )

                console.print(
                    "\n[bold]Manifest files by risk score (highest first):[/bold]"
                )
                for i, profile in enumerate(sorted_results[:5], 1):  # Show top 5
                    risk_color = (
                        "red"
                        if profile.overall_risk_score > 3.5
                        else "yellow" if profile.overall_risk_score > 2.0 else "green"
                    )
                    console.print(
                        f"{i}. [bold]{profile.manifest_path}[/bold]: [{risk_color}]{profile.overall_risk_score:.2f}/5.0[/{risk_color}] ({len(profile.dependencies)} dependencies)"
                    )

                if len(sorted_results) > 5:
                    console.print(f"... and {len(sorted_results) - 5} more")

            # Show failed files if any
            if failed_files:
                console.print("\n[bold red]Files that failed analysis:[/bold red]")
                logger.debug(f"Failed files: {len(failed_files)}")

                # Print failed files directly to console when debugging to diagnose issues
                for f in failed_files:
                    logger.debug(f"Failed file: {f}")

                # Track failure reasons
                failure_reasons = {}

                # Group by failure reason
                for failed in failed_files:
                    reason = failed.get("reason", "unknown")
                    if reason not in failure_reasons:
                        failure_reasons[reason] = []
                    failure_reasons[reason].append(failed)

                # Show counts by reason
                for reason, files in failure_reasons.items():
                    if reason == "timeout":
                        console.print(
                            f"  [bold yellow]Timed out[/bold yellow]: {len(files)} file(s)"
                        )
                        for f in files[:3]:  # Show first 3
                            timeout = f.get("timeout", "unknown")
                            console.print(
                                f"    - {f['manifest_path']} (timeout: {timeout}s)"
                            )
                    elif reason == "empty":
                        console.print(
                            f"  [bold blue]No dependencies[/bold blue]: {len(files)} file(s)"
                        )
                        for f in files[:3]:  # Show first 3
                            console.print(f"    - {f['manifest_path']}")
                    elif reason == "unsupported":
                        console.print(
                            f"  [bold magenta]Unsupported format[/bold magenta]: {len(files)} file(s)"
                        )
                        for f in files[:3]:  # Show first 3
                            console.print(f"    - {f['manifest_path']}")
                    elif reason == "error":
                        console.print(
                            f"  [bold red]Errors[/bold red]: {len(files)} file(s)"
                        )
                        for f in files[:3]:  # Show first 3
                            error = f.get("error", "unknown error")
                            console.print(f"    - {f['manifest_path']}: {error}")

                    # Show ellipsis if more than 3 files of this reason
                    if len(files) > 3:
                        console.print(f"    ... and {len(files) - 3} more")

                # Show tip for timeouts
                if "timeout" in failure_reasons:
                    console.print(
                        "\n[italic]Tip: Use --timeout option to increase timeout for slow-to-analyze files.[/italic]"
                    )

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command("list-ecosystems")
def list_ecosystems() -> None:
    """List all supported ecosystems and file types."""
    display_ecosystem_list()


@app.command("generate-config")
def generate_config(
    output_path: Path = typer.Argument(
        ...,
        help="Path to save the configuration file",
        dir_okay=False,
    ),
    format: str = typer.Option(
        "toml",
        "--format",
        "-f",
        help="Configuration file format (toml or yaml)",
    ),
) -> None:
    """Generate a sample configuration file."""
    from ..config import get_config

    config = get_config()
    if config.generate_sample_config(output_path, format):
        console.print(
            f"[bold green]Sample configuration file generated at {output_path}[/bold green]"
        )
    else:
        console.print(
            "[bold red]Failed to generate sample configuration file.[/bold red]"
        )
        raise typer.Exit(code=1)


def main() -> None:
    """Command-line entry point."""
    app()


if __name__ == "__main__":
    main()

    # For debugging failures:
    # import asyncio
    # manifest_path = "/tmp/requirements.txt"
    # timeout_seconds = 1
    # async def parse_test():
    #     return await asyncio.sleep(2)
    # try:
    #     loop = asyncio.get_event_loop()
    #     loop.run_until_complete(asyncio.wait_for(parse_test(), timeout=timeout_seconds))
    # except asyncio.TimeoutError:
    #     print(f"Timeout detected after {timeout_seconds} seconds")
    #     # This works, so our async code should be working!
