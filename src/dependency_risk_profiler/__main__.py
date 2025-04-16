"""Command-line entry point for the dependency risk profiler."""
import sys

from .cli.main import main

if __name__ == "__main__":
    sys.exit(main())