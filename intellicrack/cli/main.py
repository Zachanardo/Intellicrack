"""Main entry point for the CLI.

This module serves as the entry point for the command-line interface,
delegating to the click-based CLI implementation.
"""

import sys

from intellicrack.cli.cli import cli


def main() -> None:
    """Execute the CLI."""
    cli()


if __name__ == "__main__":
    main()
    sys.exit(0)
