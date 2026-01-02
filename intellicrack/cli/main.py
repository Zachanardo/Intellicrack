"""Main entry point for the CLI.

This module serves as the entry point for the command-line interface,
delegating to the click-based CLI implementation.
"""

import sys

from intellicrack.cli.cli import cli


def main() -> None:
    """Execute the CLI entry point.

    Delegates to the click-based CLI implementation which handles all
    command-line argument parsing and command execution.
    """
    cli()


if __name__ == "__main__":
    main()
    sys.exit(0)
