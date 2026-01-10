"""Main application entry point for Intellicrack.

This module bootstraps the application, initializing configuration,
logging, providers, tool bridges, and the GUI.
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    """Run the Intellicrack application.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    from intellicrack.core.config import Config
    from intellicrack.core.logging import setup_logging

    config_path = Path("config.toml")
    if config_path.exists():
        config = Config.load(config_path)
    else:
        config = Config.default()

    setup_logging(config.log)

    try:
        from intellicrack.ui.app import run_app
        return run_app(config)
    except ImportError:
        print("GUI dependencies not available. Install PyQt6 to use the GUI.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
