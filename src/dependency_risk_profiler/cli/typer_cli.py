"""Command-line interface using Typer for the dependency risk profiler."""

import json
import logging
import os
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..analyzers.base import BaseAnalyzer
from ..config import Config
from ..contract import schema_deprecation_notice
from ..manifest_guidance import unsupported_manifest_guidance
from ..models import DependencyMetadata, ProjectRiskProfile, RiskLevel
from ..org_scan import (
    ExistingDependencyProfiler,
    GitHubOrgClient,
    OrgScanOptions,
    OrgScanRunner,
    render_html_report,
    render_terminal_summary,
    write_csv_report,
    write_json_report,
)
from ..org_scan.models import AccountType, OrgScanReport, RepositoryRef
from ..org_scan.pipeline import VulnerabilityOptions
from ..parsers.base import BaseParser
from ..parsers.registry import EcosystemRegistry
from ..scoring.risk_scorer import RiskScorer
from ..utils import resolve_github_token
from .formatter import JsonFormatter, TerminalFormatter
from .json_v1 import JsonFormatterV1

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


class SchemaVersion(str, Enum):
    """Which output schema a command emits.

    ``v2`` is the unified ``ScoredDependency`` contract both ``analyze`` and
    ``scan-org`` serialize. ``v1`` is the pre-unification pair of incompatible
    shapes, kept for one release cycle and removed in
    ``contract.SCHEMA_V1_REMOVAL_VERSION``.
    """

    V1 = "v1"
    V2 = "v2"


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


class VulnerabilitySeverity(str, Enum):
    """Minimum vulnerability severity for scoring."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FailOn(str, Enum):
    """Threshold that makes a scan exit non-zero (for CI / agent gating)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    KNOWN_VULNERABLE = "known-vulnerable"


# Severity ranking used only by --fail-on; UNKNOWN never triggers a failure.
_FAIL_ON_SEVERITY = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 1,
    RiskLevel.UNKNOWN: 0,
}
_FAIL_ON_THRESHOLD = {
    FailOn.CRITICAL: RiskLevel.CRITICAL,
    FailOn.HIGH: RiskLevel.HIGH,
    FailOn.MEDIUM: RiskLevel.MEDIUM,
    FailOn.LOW: RiskLevel.LOW,
}


def _apply_fail_on(report: "OrgScanReport", fail_on: Optional[FailOn]) -> None:
    """Exit non-zero (code 2) when the scan matches the --fail-on threshold."""
    if fail_on is None:
        return
    if fail_on is FailOn.KNOWN_VULNERABLE:
        triggered = any(dep.is_known_vulnerable for dep in report.inventory)
        detail = "known-vulnerable dependencies"
    else:
        minimum = _FAIL_ON_SEVERITY[_FAIL_ON_THRESHOLD[fail_on]]
        triggered = any(
            _FAIL_ON_SEVERITY.get(dep.risk_level, 0) >= minimum
            for dep in report.inventory
        )
        detail = f"dependencies at risk level {fail_on.value} or above"
    if triggered:
        console.print(
            f"[bold red]--fail-on {fail_on.value}: found {detail}.[/bold red]"
        )
        raise typer.Exit(code=2)


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
        # Route diagnostic logs to stderr so stdout carries only the report
        # (or, in --output json mode, only valid JSON). See issue #20.
        handlers=[RichHandler(rich_tracebacks=True, console=Console(stderr=True))],
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
    elif file_name == "pyproject.toml":
        return "pyproject"
    elif file_name == "cargo.toml":
        return "cargo"
    elif file_name == "gemfile.lock":
        return "rubygems"
    elif file_name == "composer.lock":
        return "composer"
    elif file_name == "packages.lock.json" or file_name.endswith(".csproj"):
        return "nuget"
    elif file_name == "pom.xml":
        return "maven"
    elif file_name in ["build.gradle", "build.gradle.kts"]:
        return "gradle"
    else:
        return "unknown"


def _default_graph_output_path(manifest_path: str, graph_format: str) -> str:
    """Build the default graph output path for an analyzed manifest."""
    base_name = os.path.splitext(os.path.basename(manifest_path))[0]
    extension = "dot" if graph_format == "graphviz" else "json"
    return f"{base_name}_graph.{extension}"


def _write_graph_file(
    graph_data: Dict[str, object], graph_format: str, graph_file: str
) -> None:
    """Write graph data as JSON or DOT based on the selected output path."""
    graph_path = Path(graph_file)
    graph_path.parent.mkdir(parents=True, exist_ok=True)

    if graph_format == "graphviz" and graph_path.suffix == ".dot":
        dot_source = graph_data.get("dot_source")
        if isinstance(dot_source, str):
            graph_path.write_text(dot_source, encoding="utf-8")
            return

    graph_path.write_text(json.dumps(graph_data, indent=2), encoding="utf-8")


def _auxiliary_console(json_output: bool) -> Console:
    """Use stderr for side-effect status messages when stdout is JSON."""
    return Console(stderr=True) if json_output else console


def _note(status_console: Console, message: str, style: str) -> None:
    """Print a diagnostic without letting a file path be read as rich markup."""
    status_console.print(message, style=style, markup=False, highlight=False)


def _skip_reason(manifest_path: str, reason: str) -> str:
    """Build the human-readable note for a manifest that produced no profile.

    For an unsupported file this is where #125 is answered: instead of a bare
    "Unsupported manifest file", say which resolved-version companion to point
    at, or which parser would have accepted the same bytes under a supported
    name. Files outside that table keep the original message.
    """
    if reason == "unsupported":
        message = f"Unsupported manifest file: {manifest_path}"
        guidance = unsupported_manifest_guidance(manifest_path)
        return message if guidance is None else f"{message}. {guidance}"
    if reason == "empty":
        return f"No dependencies found in {manifest_path}"
    return f"Could not analyze {manifest_path} ({reason})"


def _warn_legacy_schema(schema: SchemaVersion) -> None:
    """Announce the v1 deprecation on stderr, never on stdout.

    stdout is the JSON document. A notice printed there would be the one thing
    a schema guarantee cannot survive, so this follows the existing convention
    and writes to stderr regardless of output format.

    Args:
        schema: The schema the caller asked for.
    """
    if schema is SchemaVersion.V1:
        Console(stderr=True).print(
            schema_deprecation_notice(), style="yellow", markup=False, highlight=False
        )


def _emit_json_report(
    profiles: List[ProjectRiskProfile],
    manifest_path: str,
    warnings: List[str],
    schema: SchemaVersion = SchemaVersion.V2,
) -> None:
    """Write the one JSON document a JSON-mode run always owes its caller.

    Args:
        profiles: Successfully analyzed manifest profiles, possibly empty.
        manifest_path: The path the user pointed the tool at.
        warnings: Human-readable notes about skipped or refused inputs.
        schema: Which output schema to emit.
    """
    # Branched rather than a ternary: the two formatters share no base class,
    # so the conditional expression collapsed to `object` and the call below
    # went unchecked.
    if schema is SchemaVersion.V1:
        report = JsonFormatterV1().format_report(profiles, manifest_path, warnings)
    else:
        report = JsonFormatter().format_report(profiles, manifest_path, warnings)
    print(report)


# A manifest that parsed but declared nothing is "nothing to do", not a refusal.
_REFUSAL_REASONS = frozenset({"unsupported", "no-analyzer", "timeout", "error"})


def _refused_manifests(failed_files: List[Dict[str, object]]) -> bool:
    """Whether any manifest was actively refused rather than merely empty."""
    return any(failed.get("reason") in _REFUSAL_REASONS for failed in failed_files)


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
    """Initialize Dependency Risk Profiler command configuration."""
    # Initialize configuration
    ctx.obj = Config(config_path)

    # Update debug setting from config
    # `Config.get` hands back whatever the config file held, so coerce here:
    # `debug` is declared bool and is about to select a logging level.
    debug_from_config = ctx.obj.get("general", "debug", False)
    debug = debug or bool(debug_from_config)

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
    graph_output: Optional[str] = typer.Argument(
        None,
        help="Optional dependency graph output path used with --generate-graph",
        hidden=True,
    ),
    recursive: bool = typer.Option(
        False,
        "--recursive",
        "-r",
        help="Recursively search for manifest files in the provided directory",
    ),
    install_transitive: bool = typer.Option(
        False,
        "--install-transitive",
        help=(
            "Resolve Python transitive dependencies by installing the manifest "
            "in a temp venv. This runs `pip install` on the manifest, executing "
            "arbitrary package code (setup.py / build backends) — only enable "
            "for manifests you trust. Off by default."
        ),
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
    schema: SchemaVersion = typer.Option(
        "v2",
        "--schema",
        help=(
            "JSON output schema. v2 is the unified contract shared with "
            "scan-org; v1 is the deprecated pre-unification shape."
        ),
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
    minimum_vulnerability_severity: VulnerabilitySeverity = typer.Option(
        "LOW",
        "--minimum-vulnerability-severity",
        help="Minimum vulnerability severity that counts toward scoring",
    ),
    # Supply chain visualization options
    generate_graph: bool = typer.Option(
        False,
        "--generate-graph",
        help=(
            "Generate dependency graph data. Add an output path after the option "
            "or use the default path."
        ),
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
    # Keyword-only, and with no default: Typer fills this in from the click
    # context by annotation and ignores whatever default is written here, so
    # `= typer.Context` was a class masquerading as an instance of itself.
    *,
    ctx: typer.Context,
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
        "minimum_vulnerability_severity": minimum_vulnerability_severity.value,
        "generate_graph": generate_graph,
        "graph_output": graph_output,
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

    # When stdout carries JSON, status messages must go to stderr so the output
    # stays machine-clean (see docs/agents.md).
    json_output = config.get("general", "output_format") == "json"
    status_console = _auxiliary_console(json_output)
    _warn_legacy_schema(schema)

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

        if graph_output and not config.get("graph", "generate", False):
            console.print(
                "[bold red]Error: graph output path requires "
                "--generate-graph.[/bold red]"
            )
            raise typer.Exit(code=1)

        # Handle directory scanning
        manifest_path = os.path.abspath(manifest)
        # `manifest_path` is rebound per file in the loop below; the path the
        # user actually named is what the JSON report reports on.
        input_path = manifest_path
        warnings: List[str] = []
        manifest_files = []

        if os.path.isdir(manifest_path):
            logger.info(f"Scanning directory: {manifest_path}")
            # Import the registry to check file matchers
            from ..parsers.registry import EcosystemRegistry

            # Initialize registry if needed
            if not EcosystemRegistry.get_available_ecosystems():
                BaseParser._initialize_registry()

            scan_mode = "recursively" if recursive else "directory"
            status_console.print(
                f"[bold]Scanning {scan_mode} for manifest files...[/bold]"
            )

            for root, _, files in os.walk(manifest_path):
                # Skip nested directories unless recursive mode is enabled.
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
                status_console.print(
                    "[bold yellow]No supported manifest files found.[/bold yellow]"
                )
                # An empty directory is a legitimate, successful outcome (#20,
                # #68) — but a successful JSON run still owes stdout a document
                # (#147).
                if json_output:
                    _emit_json_report(
                        [], input_path, ["No supported manifest files found"], schema
                    )
                else:
                    display_ecosystem_list()
                raise typer.Exit(code=0)

            status_console.print(
                "[bold green]Found "
                f"{len(manifest_files)} manifest files to analyze[/bold green]"
            )
        else:
            # Single file mode
            manifest_files = [manifest_path]

        # Track overall results and failures
        overall_results: List[ProjectRiskProfile] = []
        failed_files: List[Dict[str, object]] = []

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
                        async def parse_with_timeout(
                            manifest_path: str = manifest_path,
                        ) -> Tuple[
                            Optional[Dict[str, DependencyMetadata]], Optional[str]
                        ]:
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
                            if loop.is_closed():
                                raise RuntimeError("Event loop is closed")
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)

                        try:
                            dependencies, error = loop.run_until_complete(
                                asyncio.wait_for(
                                    parse_with_timeout(), timeout=timeout_seconds
                                )
                            )

                            # Keyed on `dependencies`, not on `error`: those are
                            # the same condition (the parser returns None with a
                            # reason or a dict with none), but only this spelling
                            # tells the type checker the dict below is real.
                            if dependencies is None:
                                reason = error or "unsupported"
                                note = _skip_reason(manifest_path, reason)
                                warnings.append(note)
                                # stderr in JSON mode: stdout is the report.
                                _note(status_console, note, "bold yellow")
                                failed_files.append(
                                    {
                                        "manifest_path": manifest_path,
                                        "reason": reason,
                                    }
                                )
                                continue

                        except asyncio.TimeoutError:
                            logger.error(
                                "Analysis timed out after "
                                f"{timeout_seconds} seconds for {manifest_path}"
                            )
                            console.print(
                                "[bold red]Analysis timed out after "
                                f"{timeout_seconds} seconds for {manifest_path}. "
                                "Try increasing the timeout with --timeout "
                                "option or reducing the scope of analysis.[/bold red]"
                            )
                            # Add a record of the failed file to the summary
                            failed_file = {
                                "manifest_path": manifest_path,
                                "reason": "timeout",
                                "timeout": timeout_seconds,
                            }
                            failed_files.append(failed_file)
                            warnings.append(
                                f"Analysis timed out after {timeout_seconds}s "
                                f"for {manifest_path}"
                            )

                            # Log the error for debug
                            logger.debug(
                                "Added file to failed_files due to timeout: "
                                f"{manifest_path}"
                            )
                            logger.debug(
                                f"Current failed_files count: {len(failed_files)}"
                            )
                            continue
                except Exception as e:
                    # Fall back if there's an issue with the async implementation.
                    logger.warning(f"Falling back to non-async parsing due to: {e}")

                    parser = BaseParser.get_parser_for_file(manifest_path)
                    if not parser:
                        note = _skip_reason(manifest_path, "unsupported")
                        logger.error(note)
                        warnings.append(note)
                        _note(status_console, note, "bold yellow")
                        # Add unsupported file to failed list
                        failed_file = {
                            "manifest_path": manifest_path,
                            "reason": "unsupported",
                        }
                        failed_files.append(failed_file)
                        continue

                    dependencies = parser.parse()
                    if not dependencies:
                        note = _skip_reason(manifest_path, "empty")
                        logger.warning(note)
                        warnings.append(note)
                        _note(status_console, note, "bold yellow")
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
                    note = (
                        f"The ecosystem '{ecosystem}' was detected for "
                        f"{manifest_path}, but no analyzer is available for it."
                    )
                    logger.error(f"Unsupported ecosystem: {ecosystem}")
                    warnings.append(note)
                    _note(status_console, note, "bold red")
                    _note(
                        status_console,
                        "Please check if you have all required analyzers installed.",
                        "",
                    )
                    failed_files.append(
                        {
                            "manifest_path": manifest_path,
                            "reason": "no-analyzer",
                        }
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
                    # Resolve a token once (flag / env / gh CLI) so the real
                    # contributor count can be read from the GitHub API.
                    community_token = resolve_github_token(github_token)
                    # Apply community metrics analysis to each dependency
                    for name, dep in dependencies.items():
                        if (
                            hasattr(analyzer, "metadata_cache")
                            and name in analyzer.metadata_cache
                        ):
                            dependencies[name] = analyze_community_metrics(
                                dep,
                                analyzer.metadata_cache[name],
                                github_token=community_token,
                            )
                        else:
                            dependencies[name] = analyze_community_metrics(
                                dep, github_token=community_token
                            )

                    logger.info("Analyzing transitive dependencies")
                    dependencies = analyze_transitive_dependencies_enhanced(
                        dependencies, manifest_path, allow_install=install_transitive
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
                                "Aggregating vulnerability data from multiple "
                                "sources"
                            )

                            # Handle cache settings
                            if vuln_config.get("disable_cache"):
                                # Set environment variable to disable cache
                                os.environ["DEPENDENCY_RISK_DISABLE_CACHE"] = "1"
                                logger.info("Vulnerability data caching is disabled")

                            if vuln_config.get("clear_cache"):
                                try:
                                    from ..vulnerabilities.cache import default_cache

                                    cleared = default_cache.clear()
                                    logger.info(
                                        "Cleared "
                                        f"{cleared} entries from vulnerability "
                                        "cache"
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
                                    minimum_severity=vuln_config.get(
                                        "minimum_severity_for_scoring", "LOW"
                                    ),
                                )
                            )

                            dependencies = updated_dependencies
                            logger.info(
                                "Found vulnerabilities in "
                                f"{len(vuln_counts)} dependencies"
                            )

                        except ImportError as e:
                            logger.warning(
                                "Async vulnerability aggregation not " f"available: {e}"
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
                                            "Checking vulnerability data for " f"{name}"
                                        )
                                        dependencies[name], vulns = (
                                            aggregate_vulnerability_data(
                                                dep,
                                                api_keys,
                                                vuln_config.get(
                                                    "minimum_severity_for_scoring",
                                                    "LOW",
                                                ),
                                            )
                                        )
                                        logger.debug(
                                            "Found "
                                            f"{len(vulns)} vulnerabilities for "
                                            f"{name}"
                                        )
                                    except Exception as e:
                                        logger.warning(
                                            "Error aggregating vulnerability "
                                            f"data for {name}: {e}"
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

                # Format output. JSON is emitted once, after every manifest has
                # been processed: printing one document per manifest produced a
                # concatenation that json.load() rejects (#147).
                use_color = config.get("general", "use_color", True)
                if not json_output:
                    if len(manifest_files) > 1:
                        console.print(
                            "\n[bold blue]===== Results for "
                            f"{manifest_path} =====[/bold blue]"
                        )
                    console.print(
                        TerminalFormatter(color=use_color).format_profile(profile),
                        soft_wrap=True,
                    )

                # Save the profile to our results
                overall_results.append(profile)

                # Process supply chain visualization if requested
                if config.get("graph", "generate", False):
                    try:
                        from ..supply_chain import generate_dependency_graph

                        graph_format_config = config.get("graph", "format")
                        graph_depth_config = config.get("graph", "depth")
                        logger.info(
                            "Generating dependency graph in "
                            f"{graph_format_config} format"
                        )

                        # Extract risk scores for graph coloring
                        risk_scores: Dict[str, float] = {}
                        # `scored`, not `dep`: the loops above bind `dep` to a
                        # DependencyMetadata, and reusing the name here made
                        # every attribute read on a DependencyRiskScore
                        # unresolvable.
                        for scored in profile.dependencies:
                            risk_scores[scored.dependency.name] = (
                                scored.total_score / 5.0
                            )  # Normalize to 0-1

                        # Generate the graph
                        graph_data = generate_dependency_graph(
                            dependencies={
                                scored.dependency.name: scored.dependency
                                for scored in profile.dependencies
                            },
                            output_format=graph_format_config,
                            risk_scores=risk_scores,
                            depth_limit=graph_depth_config,
                        )

                        # Determine output file name
                        graph_file = config.get("graph", "output") or (
                            _default_graph_output_path(
                                manifest_path, graph_format_config
                            )
                        )

                        # Save the graph data
                        _write_graph_file(graph_data, graph_format_config, graph_file)

                        logger.info(f"Dependency graph saved to {graph_file}")
                        _auxiliary_console(json_output).print(
                            "\n[bold green]Dependency graph saved to "
                            f"{graph_file}[/bold green]"
                        )

                    except ImportError as e:
                        logger.warning(f"Supply chain visualization not available: {e}")
                    except Exception as e:
                        logger.error(f"Error generating dependency graph: {e}")

                # Handle historical trends functionality
                try:
                    if config.get("trends", "save_history", False):
                        from ..supply_chain import save_historical_profile

                        logger.info("Saving scan results to historical data")
                        history_path = save_historical_profile(profile)
                        _auxiliary_console(json_output).print(
                            (
                                "\n[bold green]Scan results saved to "
                                "historical data at "
                                f"{history_path}[/bold green]"
                            )
                        )

                    if config.get("trends", "analyze", False):
                        from ..supply_chain import analyze_historical_trends

                        logger.info("Analyzing historical trends")
                        trends = analyze_historical_trends(
                            profile.manifest_path, config.get("trends", "limit")
                        )

                        if "error" in trends:
                            _auxiliary_console(json_output).print(
                                "\n[bold red]Trend analysis error: "
                                f"{trends['error']}[/bold red]"
                            )
                        else:
                            trend_console = _auxiliary_console(json_output)
                            # Output trend summary
                            trend_console.print(
                                "\n[bold]Historical Trend Analysis:[/bold]"
                            )

                            # Overall risk summary
                            avg_risk = trends["average_risk_over_time"]
                            trend_console.print(
                                "  Average Risk Score: "
                                f"{avg_risk['average']:.2f}/5.0 "
                                f"({avg_risk['trend']})"
                            )

                            # Improving and deteriorating dependencies
                            trend_console.print(
                                "  Improving Dependencies: "
                                f"{len(trends['improving_dependencies'])}"
                            )
                            trend_console.print(
                                "  Deteriorating Dependencies: "
                                f"{len(trends['deteriorating_dependencies'])}"
                            )

                            # Period analyzed
                            trend_console.print(
                                "  Analysis Period: "
                                f"{trends['analyzed_period']['start']} to "
                                f"{trends['analyzed_period']['end']}"
                            )
                            trend_console.print(
                                "  Scans Analyzed: "
                                f"{trends['analyzed_period']['scans_analyzed']}"
                            )

                            # Velocity metrics
                            if (
                                "velocity_metrics" in trends
                                and trends["velocity_metrics"]
                            ):
                                vm = trends["velocity_metrics"]
                                trend_console.print(
                                    "\n  [bold]Dependency Velocity Metrics:[/bold]"
                                )
                                trend_console.print(
                                    "    New Dependencies: "
                                    f"{vm.get('new_dependencies', 0)}"
                                )
                                trend_console.print(
                                    "    Updated Dependencies: "
                                    f"{vm.get('updated_dependencies', 0)}"
                                )
                                trend_console.print(
                                    "    Removed Dependencies: "
                                    f"{vm.get('removed_dependencies', 0)}"
                                )
                                trend_console.print(
                                    "    Dependency Churn Rate: "
                                    f"{vm.get('dependency_churn_rate', 0)} "
                                    "deps/day"
                                )

                    if config.get("trends", "visualization"):
                        from ..supply_chain import generate_trend_visualization

                        viz_type = config.get("trends", "visualization")
                        logger.info(f"Generating trend visualization for {viz_type}")
                        viz_data = generate_trend_visualization(
                            profile.manifest_path,
                            viz_type,
                            config.get("trends", "limit"),
                        )

                        if "error" in viz_data:
                            _auxiliary_console(json_output).print(
                                "\n[bold red]Visualization error: "
                                f"{viz_data['error']}[/bold red]"
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

                            logger.info(f"Trend visualization data saved to {viz_file}")
                            _auxiliary_console(json_output).print(
                                "\n[bold green]Trend visualization data saved "
                                f"to {viz_file}[/bold green]"
                            )

                except ImportError as e:
                    logger.warning(f"Historical trends analysis not available: {e}")
                except Exception as e:
                    logger.error(f"Error in historical trends analysis: {e}")

            except Exception as e:
                logger.error(f"Error processing {manifest_path}: {e}", exc_info=True)
                note = f"Error processing {manifest_path}: {e}"
                warnings.append(note)
                _note(status_console, note, "bold red")
                # Add error file to failed list
                failed_file = {
                    "manifest_path": manifest_path,
                    "reason": "error",
                    "error": str(e),
                }
                failed_files.append(failed_file)

        if json_output:
            _emit_json_report(overall_results, input_path, warnings, schema)

        # Display summary if manifest files were scanned
        if len(manifest_files) > 0 and not json_output:
            console.print("\n[bold]Overall Summary[/bold]")

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
                    "Medium risk dependencies: "
                    f"[bold yellow]{medium_risk}[/bold yellow]"
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
                        f"{i}. [bold]{profile.manifest_path}[/bold]: "
                        f"[{risk_color}]{profile.overall_risk_score:.2f}/5.0"
                        f"[/{risk_color}] "
                        f"({len(profile.dependencies)} dependencies)"
                    )

                if len(sorted_results) > 5:
                    console.print(f"... and {len(sorted_results) - 5} more")

            # Show failed files if any
            if failed_files:
                console.print("\n[bold red]Files that failed analysis:[/bold red]")
                logger.debug(f"Failed files: {len(failed_files)}")

                # Print failed files directly when debugging to diagnose issues.
                # `failed_entry`, not `f`: `f` is the file handle opened for the
                # visualization dump above, and rebinding it here made every
                # dict operation below type-check against a TextIOWrapper.
                for failed_entry in failed_files:
                    logger.debug(f"Failed file: {failed_entry}")

                # Track failure reasons
                failure_reasons: Dict[str, List[Dict[str, object]]] = {}

                # Group by failure reason
                for failed in failed_files:
                    reason_value = failed.get("reason", "unknown")
                    reason = (
                        reason_value if isinstance(reason_value, str) else "unknown"
                    )
                    if reason not in failure_reasons:
                        failure_reasons[reason] = []
                    failure_reasons[reason].append(failed)

                # Show counts by reason. `reason_files`, not `files`: `files` is
                # the os.walk filename list from the directory scan above.
                for reason, reason_files in failure_reasons.items():
                    if reason == "timeout":
                        console.print(
                            "  [bold yellow]Timed out[/bold yellow]: "
                            f"{len(reason_files)} file(s)"
                        )
                        for failed_entry in reason_files[:3]:  # Show first 3
                            elapsed = failed_entry.get("timeout", "unknown")
                            console.print(
                                f"    - {failed_entry['manifest_path']} "
                                f"(timeout: {elapsed}s)"
                            )
                    elif reason == "empty":
                        console.print(
                            "  [bold blue]No dependencies[/bold blue]: "
                            f"{len(reason_files)} file(s)"
                        )
                        for failed_entry in reason_files[:3]:  # Show first 3
                            console.print(f"    - {failed_entry['manifest_path']}")
                    elif reason == "unsupported":
                        console.print(
                            "  [bold magenta]Unsupported format[/bold magenta]: "
                            f"{len(reason_files)} file(s)"
                        )
                        for failed_entry in reason_files[:3]:  # Show first 3
                            console.print(f"    - {failed_entry['manifest_path']}")
                    elif reason == "error":
                        console.print(
                            "  [bold red]Errors[/bold red]: "
                            f"{len(reason_files)} file(s)"
                        )
                        for failed_entry in reason_files[:3]:  # Show first 3
                            detail = failed_entry.get("error", "unknown error")
                            console.print(
                                f"    - {failed_entry['manifest_path']}: {detail}"
                            )

                    # Show ellipsis if more than 3 files of this reason
                    if len(reason_files) > 3:
                        console.print(f"    ... and {len(reason_files) - 3} more")

                # Show tip for timeouts
                if "timeout" in failure_reasons:
                    console.print(
                        "\n[italic]Tip: Use --timeout option to increase timeout "
                        "for slow-to-analyze files.[/italic]"
                    )

        # "I refused every file you gave me" is not success (#125). Two cases
        # stay at exit 0 because they are genuinely "nothing to do", not a
        # refusal (#20, #68): a directory with no manifests (handled above),
        # and a manifest that parsed fine and simply declares no dependencies.
        if not overall_results and _refused_manifests(failed_files):
            _note(
                status_console,
                f"Analyzed 0 of {len(manifest_files)} manifest file(s); "
                "nothing was scored.",
                "bold red",
            )
            raise typer.Exit(code=1)

    except typer.Exit:
        # Intentional control-flow exits (e.g. "no manifests found" → code 0)
        # must keep their own exit code, not be rewritten to 1 below.
        raise
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise typer.Exit(code=1) from e


@app.command("list-ecosystems")
def list_ecosystems() -> None:
    """List all supported ecosystems and file types."""
    display_ecosystem_list()


@app.command("scan-org")
def scan_org(
    org: str = typer.Argument(..., help="GitHub organization to scan"),
    github_token: Optional[str] = typer.Option(
        None,
        "--github-token",
        help="GitHub token with organization repository read access",
    ),
    output_html: Path = typer.Option(
        Path("dependency-risk-org-report.html"),
        "--output-html",
        help="Path for the self-contained HTML report",
        dir_okay=False,
    ),
    output_json: Path = typer.Option(
        Path("dependency-risk-org-report.json"),
        "--output-json",
        help="Path for the aggregate JSON report",
        dir_okay=False,
    ),
    output_csv: Optional[Path] = typer.Option(
        None,
        "--output-csv",
        help="Optional path for a flat CSV of the dependency inventory",
        dir_okay=False,
    ),
    schema: SchemaVersion = typer.Option(
        "v2",
        "--schema",
        help=(
            "JSON output schema. v2 is the unified contract shared with "
            "analyze; v1 is the deprecated pre-unification shape."
        ),
    ),
    fail_on: Optional[FailOn] = typer.Option(
        None,
        "--fail-on",
        help=(
            "Exit non-zero (code 2) if any dependency meets this risk level or "
            "is known-vulnerable. For CI gates and agent workflows."
        ),
    ),
    max_repos: Optional[int] = typer.Option(
        None,
        "--max-repos",
        help="Maximum number of repositories to scan",
        min=1,
    ),
    include_archived: bool = typer.Option(
        False,
        "--include-archived",
        help="Include archived repositories. Forks are still skipped.",
    ),
    manifest_glob: Optional[List[str]] = typer.Option(
        None,
        "--manifest-glob",
        help="Manifest glob to include. May be provided multiple times.",
    ),
    concurrency: int = typer.Option(
        8,
        "--concurrency",
        help="Bounded repository discovery concurrency",
        min=1,
        max=32,
    ),
    # Keyword-only, and with no default: Typer fills this in from the click
    # context by annotation and ignores whatever default is written here, so
    # `= typer.Context` was a class masquerading as an instance of itself.
    *,
    ctx: typer.Context,
) -> None:
    """Scan a GitHub organization and write org-wide dependency risk reports."""
    _scan_github_account(
        account=org,
        account_type="organization",
        github_token=github_token,
        output_html=output_html,
        output_json=output_json,
        output_csv=output_csv,
        schema=schema,
        fail_on=fail_on,
        max_repos=max_repos,
        include_archived=include_archived,
        manifest_glob=manifest_glob,
        concurrency=concurrency,
        ctx=ctx,
    )


@app.command("scan-user")
def scan_user(
    username: str = typer.Argument(..., help="GitHub user to scan"),
    github_token: Optional[str] = typer.Option(
        None,
        "--github-token",
        help="GitHub token with user repository read access",
    ),
    output_html: Path = typer.Option(
        Path("dependency-risk-user-report.html"),
        "--output-html",
        help="Path for the self-contained HTML report",
        dir_okay=False,
    ),
    output_json: Path = typer.Option(
        Path("dependency-risk-user-report.json"),
        "--output-json",
        help="Path for the aggregate JSON report",
        dir_okay=False,
    ),
    output_csv: Optional[Path] = typer.Option(
        None,
        "--output-csv",
        help="Optional path for a flat CSV of the dependency inventory",
        dir_okay=False,
    ),
    schema: SchemaVersion = typer.Option(
        "v2",
        "--schema",
        help=(
            "JSON output schema. v2 is the unified contract shared with "
            "analyze; v1 is the deprecated pre-unification shape."
        ),
    ),
    fail_on: Optional[FailOn] = typer.Option(
        None,
        "--fail-on",
        help=(
            "Exit non-zero (code 2) if any dependency meets this risk level or "
            "is known-vulnerable. For CI gates and agent workflows."
        ),
    ),
    max_repos: Optional[int] = typer.Option(
        None,
        "--max-repos",
        help="Maximum number of repositories to scan",
        min=1,
    ),
    include_archived: bool = typer.Option(
        False,
        "--include-archived",
        help="Include archived repositories. Forks are still skipped.",
    ),
    include_collaborations: bool = typer.Option(
        False,
        "--include-collaborations",
        help=(
            "Also scan repositories the user only collaborates on in other "
            "orgs (GitHub type=all). By default only repositories the user "
            "owns are scanned."
        ),
    ),
    manifest_glob: Optional[List[str]] = typer.Option(
        None,
        "--manifest-glob",
        help="Manifest glob to include. May be provided multiple times.",
    ),
    concurrency: int = typer.Option(
        8,
        "--concurrency",
        help="Bounded repository discovery concurrency",
        min=1,
        max=32,
    ),
    # Keyword-only, and with no default: Typer fills this in from the click
    # context by annotation and ignores whatever default is written here, so
    # `= typer.Context` was a class masquerading as an instance of itself.
    *,
    ctx: typer.Context,
) -> None:
    """Scan a GitHub user and write account-wide dependency risk reports."""
    _scan_github_account(
        account=username,
        account_type="user",
        github_token=github_token,
        output_html=output_html,
        output_json=output_json,
        output_csv=output_csv,
        schema=schema,
        fail_on=fail_on,
        max_repos=max_repos,
        include_archived=include_archived,
        manifest_glob=manifest_glob,
        concurrency=concurrency,
        ctx=ctx,
        include_collaborations=include_collaborations,
    )


def _scan_github_account(
    account: str,
    account_type: AccountType,
    github_token: Optional[str],
    output_html: Path,
    output_json: Path,
    output_csv: Optional[Path],
    schema: SchemaVersion,
    fail_on: Optional[FailOn],
    max_repos: Optional[int],
    include_archived: bool,
    manifest_glob: Optional[List[str]],
    concurrency: int,
    ctx: typer.Context,
    include_collaborations: bool = False,
) -> None:
    """Run the shared GitHub account scan implementation."""
    _warn_legacy_schema(schema)
    token = resolve_github_token(github_token)
    if not token:
        console.print(
            "[bold red]Error: GitHub token required via --github-token, "
            "the GITHUB_TOKEN / GH_TOKEN / DRP_GITHUB_TOKEN environment "
            "variables, or an authenticated gh CLI (gh auth login).[/bold red]"
        )
        raise typer.Exit(code=1)

    config = ctx.obj
    vulnerability_options = _vulnerability_options(config, token)
    manifest_globs = _manifest_globs(manifest_glob)

    client = GitHubOrgClient(token=token)
    profiler = ExistingDependencyProfiler(
        scoring_weights=config.get_scoring_weights(),
        vulnerability_options=vulnerability_options,
        timeout=int(config.get("general", "timeout", 120)),
        repository_signals_client=client,
    )
    runner = OrgScanRunner(
        github_client=client,
        dependency_profiler=profiler,
        progress=lambda message: console.print(f"[dim]{message}[/dim]"),
    )
    repository_lister = _repository_lister(client, account_type, include_collaborations)

    try:
        report = runner.run(
            OrgScanOptions(
                org=account,
                account_type=account_type,
                repository_lister=repository_lister,
                include_archived=include_archived,
                max_repos=max_repos,
                manifest_globs=manifest_globs,
                concurrency=concurrency,
            )
        )
    except Exception as exc:
        console.print(f"[bold red]GitHub account scan failed: {exc}[/bold red]")
        raise typer.Exit(code=1) from exc

    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(render_html_report(report), encoding="utf-8")
    write_json_report(report, output_json, legacy_schema=schema is SchemaVersion.V1)
    console.print(render_terminal_summary(report), soft_wrap=True)
    console.print(f"\n[bold green]HTML report written to {output_html}[/bold green]")
    console.print(f"[bold green]JSON report written to {output_json}[/bold green]")
    if output_csv is not None:
        write_csv_report(report, output_csv)
        console.print(f"[bold green]CSV report written to {output_csv}[/bold green]")
    _apply_fail_on(report, fail_on)


def _vulnerability_options(config: Config, token: str) -> VulnerabilityOptions:
    """Build vulnerability options for account scans from CLI config."""
    vulnerability_config = config.get_vulnerability_config()
    return VulnerabilityOptions(
        enable_osv=bool(vulnerability_config.get("enable_osv", True)),
        enable_nvd=bool(vulnerability_config.get("enable_nvd", False)),
        enable_github_advisory=bool(
            vulnerability_config.get("enable_github_advisory", False)
        ),
        github_token=str(vulnerability_config.get("github_token") or token),
        nvd_api_key=str(vulnerability_config.get("nvd_api_key") or ""),
        disable_cache=bool(vulnerability_config.get("disable_cache", False)),
        clear_cache=bool(vulnerability_config.get("clear_cache", False)),
        minimum_severity_for_scoring=str(
            vulnerability_config.get("minimum_severity_for_scoring", "LOW")
        ),
    )


def _manifest_globs(manifest_glob: Optional[List[str]]) -> Tuple[str, ...]:
    """Resolve user-provided manifest globs or the built-in defaults."""
    if manifest_glob:
        return tuple(manifest_glob)

    from ..org_scan.scanner import SUPPORTED_MANIFEST_NAMES

    return SUPPORTED_MANIFEST_NAMES


def _repository_lister(
    client: GitHubOrgClient,
    account_type: AccountType,
    include_collaborations: bool = False,
) -> Callable[[str, bool, Optional[int]], List[RepositoryRef]]:
    """Return the GitHub repository lister for an account source.

    For a user, the ``include_collaborations`` choice is bound here so the
    lister keeps the shared three-argument signature the runner expects.
    """
    if account_type == "user":

        def _list_user(
            user: str,
            include_archived: bool,
            max_repos: Optional[int],
        ) -> List[RepositoryRef]:
            return client.list_user_repositories(
                user,
                include_archived,
                max_repos,
                include_collaborations=include_collaborations,
            )

        return _list_user
    return client.list_org_repositories


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
            "[bold green]Sample configuration file generated at "
            f"{output_path}[/bold green]"
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
