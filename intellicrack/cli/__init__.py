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

import importlib
import logging
from types import ModuleType
from typing import Optional


logger = logging.getLogger(__name__)


def _safe_import(name: str) -> Optional[ModuleType]:
    """Safely import a module from the current package.

    Args:
        name: The module name to import from the current package.

    Returns:
        Optional[ModuleType]: The imported module, or None if import fails.
    """
    try:
        return importlib.import_module(f".{name}", __package__)
    except ImportError as e:
        logger.warning("Failed to import %s: %s", name, e)
        return None


# Import CLI modules with error handling
main = _safe_import("main")
interactive_mode = _safe_import("interactive_mode")
config_manager = _safe_import("config_manager")
project_manager = _safe_import("project_manager")
terminal_dashboard = _safe_import("terminal_dashboard")
pipeline = _safe_import("pipeline")
advanced_export = _safe_import("advanced_export")
ai_chat_interface = _safe_import("ai_chat_interface")
ai_integration = _safe_import("ai_integration")
ascii_charts = _safe_import("ascii_charts")
hex_viewer_cli = _safe_import("hex_viewer_cli")
tutorial_system = _safe_import("tutorial_system")
progress_manager = _safe_import("progress_manager")

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
