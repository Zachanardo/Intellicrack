"""
Intellicrack User Interface Package

This package provides the graphical user interface components for the Intellicrack framework.
It includes the main application window, dialogs, widgets, and a dashboard manager for
creating a comprehensive and user-friendly interface for binary analysis tasks.

Modules:
    - main_window: Main application window and interface
    - dashboard_manager: Dashboard management and layout system
    - dialogs: Collection of specialized dialog windows
    - widgets: Custom UI widgets and components

Key Features:
    - Modern Qt-based interface
    - Customizable layouts and themes
    - Interactive visualizations
    - Real-time analysis feedback
    - Plugin integration support
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
