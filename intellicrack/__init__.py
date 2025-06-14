"""
Intellicrack: A fully featured, AI-assisted software analysis and security research suite.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

This package provides comprehensive tools for binary analysis, vulnerability detection,
automated patching, and advanced security research capabilities.

Key Features:
- Static and dynamic binary analysis
- Multi-format binary parsing (PE, ELF, Mach-O)
- AI-assisted vulnerability detection
- Automated patching and exploit generation
- Network protocol analysis
- Hardware protection bypass
- Advanced GUI with integrated tools

Usage:
    from intellicrack import IntellicrackApp
    from intellicrack.config import CONFIG

    # Initialize and run the application
    app = IntellicrackApp()
    app.run()
"""

__version__ = "1.0.0"
__author__ = "Intellicrack Team"
__license__ = "GPL-3.0"

# Standard library imports first
import logging

# Local imports
from .config import CONFIG

# Setup logging after imports
logger = logging.getLogger(__name__)

# Main application
try:
    from .main import main
    from .ui.main_app import IntellicrackApp
except ImportError:
    # Handle case where dependencies aren't available
    main = None
    IntellicrackApp = None

# Core analysis modules
try:
    from . import ai, core, utils
except ImportError as e:
    logger.warning("Core modules not available: %s", e)
    ai = core = utils = None

# UI modules (optional - requires PyQt5)
try:
    from . import ui
except ImportError as e:
    logger.warning("UI module not available: %s", e)
    ui = None

# Plugin system
try:
    from . import plugins
except ImportError as e:
    logger.warning("Plugins module not available: %s", e)
    plugins = None

# Hex viewer integration (optional - requires PyQt5)
try:
    from . import hexview
except ImportError as e:
    logger.warning("Hexview module not available: %s", e)
    hexview = None

# Version info
def get_version():
    """Return the current version of Intellicrack."""
    return __version__

# Package-level convenience functions
def create_app():
    """Create and return a new Intellicrack application instance."""
    if IntellicrackApp is None:
        raise ImportError("IntellicrackApp not available. Check dependencies.")
    return IntellicrackApp()

def run_app():
    """Run the Intellicrack application."""
    if main is None:
        raise ImportError("Main function not available. Check dependencies.")
    return main()

__all__ = [
    'CONFIG',
    'IntellicrackApp',
    'main',
    'core',
    'ai',
    'utils',
    'ui',
    'plugins',
    'hexview',
    'get_version',
    'create_app',
    'run_app',
    '__version__',
    '__author__',
    '__license__'
]
