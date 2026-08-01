"""Command-line entry point for the dependency risk profiler."""

import sys


def cli_main() -> int:
    """Run the Typer CLI and return an exit code."""
    from .cli.typer_cli import main

    main()
    return 0


if __name__ == "__main__":
    sys.exit(cli_main())
