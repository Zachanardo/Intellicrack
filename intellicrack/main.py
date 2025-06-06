"""
Main Entry Point for Intellicrack

This module provides the main application entry point for the refactored
Intellicrack binary analysis framework.
"""

import os
import sys

# Set Qt to offscreen mode for WSL/headless environments if no display
if 'DISPLAY' not in os.environ and 'QT_QPA_PLATFORM' not in os.environ:
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# Comprehensive logging disabled for Qt compatibility
# The comprehensive logging system interferes with Qt's window display mechanisms


def main() -> int:
    """
    Main entry point for the Intellicrack application.

    Returns:
        Application exit code
    """
    try:
        # Import and launch the GUI
        from .ui.main_app import launch
        return launch()

    except ImportError as e:
        print(f"Error: Failed to import Intellicrack components: {e}")
        print("\nPlease ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        return 1

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error launching Intellicrack: {e}")
        import traceback
        traceback.print_exc()
        return 1


# Command line entry point
if __name__ == "__main__":
    sys.exit(main())
