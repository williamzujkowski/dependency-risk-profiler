"""Command-line entry point for the dependency risk profiler."""

import sys


# Declare the main function with a consistent return type
def cli_main() -> int:
    """Main CLI entry point that returns an exit code."""
    # Use the Typer CLI as the default entry point
    try:
        from .cli.typer_cli import main

        main()  # Typer CLI doesn't return an exit code
        return 0
    except ImportError:
        # Fall back to the old argparse CLI if Typer is not available
        try:
            from .cli.main import main as argparse_main

            return argparse_main()  # Original CLI returns an exit code
        except ImportError:
            print("Error: CLI modules not found")
            return 1


if __name__ == "__main__":
    sys.exit(cli_main())
