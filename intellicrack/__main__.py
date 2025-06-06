"""
Entry point for running Intellicrack as a module.

This allows the package to be run with:
    python -m intellicrack
"""

import os
import sys

# Set Qt to offscreen mode for WSL/headless environments if no display
if 'DISPLAY' not in os.environ and 'QT_QPA_PLATFORM' not in os.environ:
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'

from .main import main

if __name__ == "__main__":
    sys.exit(main())
