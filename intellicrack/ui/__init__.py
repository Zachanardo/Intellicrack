"""
Intellicrack User Interface Package 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import main UI components with error handling
try:
    from .main_window import IntellicrackMainWindow
except ImportError as e:
    logger.warning("Failed to import main_window: %s", e)

try:
    from .dashboard_manager import DashboardManager
except ImportError as e:
    logger.warning("Failed to import dashboard_manager: %s", e)

# Import subpackages
try:
    from . import dialogs, widgets
except ImportError as e:
    logger.warning("Failed to import UI subpackages: %s", e)

# Define package exports
__all__ = [
    # From main_window
    'IntellicrackMainWindow',

    # From dashboard_manager
    'DashboardManager',

    # Subpackages
    'dialogs',
    'widgets',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
