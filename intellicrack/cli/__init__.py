"""CLI Scripts Module for Intellicrack.

This module provides command-line interface components for the application.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging


logger = logging.getLogger(__name__)

# Import CLI modules with error handling
try:
    from . import main
except ImportError as e:
    logger.warning("Failed to import main: %s", e)
    main = None

try:
    from . import interactive_mode
except ImportError as e:
    logger.warning("Failed to import interactive_mode: %s", e)
    interactive_mode = None

try:
    from . import config_manager
except ImportError as e:
    logger.warning("Failed to import config_manager: %s", e)
    config_manager = None

try:
    from . import project_manager
except ImportError as e:
    logger.warning("Failed to import project_manager: %s", e)
    project_manager = None

try:
    from . import terminal_dashboard
except ImportError as e:
    logger.warning("Failed to import terminal_dashboard: %s", e)
    terminal_dashboard = None

try:
    from . import pipeline
except ImportError as e:
    logger.warning("Failed to import pipeline: %s", e)
    pipeline = None

try:
    from . import advanced_export
except ImportError as e:
    logger.warning("Failed to import advanced_export: %s", e)
    advanced_export = None

try:
    from . import ai_chat_interface
except ImportError as e:
    logger.warning("Failed to import ai_chat_interface: %s", e)
    ai_chat_interface = None

try:
    from . import ai_integration
except ImportError as e:
    logger.warning("Failed to import ai_integration: %s", e)
    ai_integration = None

try:
    from . import ascii_charts
except ImportError as e:
    logger.warning("Failed to import ascii_charts: %s", e)
    ascii_charts = None

try:
    from . import hex_viewer_cli
except ImportError as e:
    logger.warning("Failed to import hex_viewer_cli: %s", e)
    hex_viewer_cli = None

try:
    from . import tutorial_system
except ImportError as e:
    logger.warning("Failed to import tutorial_system: %s", e)
    tutorial_system = None

try:
    from . import progress_manager
except ImportError as e:
    logger.warning("Failed to import progress_manager: %s", e)
    progress_manager = None

__all__ = [
    "advanced_export",
    "ai_chat_interface",
    "ai_integration",
    "ascii_charts",
    "config_manager",
    "hex_viewer_cli",
    "interactive_mode",
    "main",
    "pipeline",
    "progress_manager",
    "project_manager",
    "terminal_dashboard",
    "tutorial_system",
]

# Filter out None values from __all__
__all__ = [item for item in __all__ if locals().get(item) is not None]
