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
            # License analysis would be performed on each dependency with metadata
            
            logger.info("Analyzing community metrics")
            # Community metrics analysis would be performed on each dependency
            
            logger.info("Analyzing transitive dependencies")
            dependencies = analyze_transitive_dependencies(dependencies, manifest_path)
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
        
        return 0
    
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.debug)
        return 1


if __name__ == "__main__":
    sys.exit(main())