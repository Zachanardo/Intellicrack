"""Package entry point for running Intellicrack as a module.

This enables execution via: python -m intellicrack

Example:
    python -m intellicrack
    python -m intellicrack --version
    python -m intellicrack --help
"""

from __future__ import annotations

import sys


def run() -> None:
    """Execute the Intellicrack application.

    This function serves as the main entry point when the package
    is invoked as a module. It imports and calls the main function
    from the main module, handling any import errors gracefully.
    """
    try:
        from intellicrack.main import main  # noqa: PLC0415
    except ImportError as e:
        print(f"Failed to import Intellicrack: {e}", file=sys.stderr)
        print("Ensure all dependencies are installed.", file=sys.stderr)
        sys.exit(1)

    sys.exit(main())


if __name__ == "__main__":
    run()
