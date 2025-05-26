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
    from .main_window import *
except ImportError as e:
    logger.warning(f"Failed to import main_window: {e}")

try:
    from .dashboard_manager import *
except ImportError as e:
    logger.warning(f"Failed to import dashboard_manager: {e}")

# Import subpackages
try:
    from . import dialogs
    from . import widgets
except ImportError as e:
    logger.warning(f"Failed to import UI subpackages: {e}")

# Define package exports
__all__ = [
    # From main_window
    'MainWindow',
    'ApplicationInterface',
    'create_main_window',
    'setup_ui',
    
    # From dashboard_manager
    'DashboardManager',
    'DashboardWidget',
    'create_dashboard',
    'load_dashboard_layout',
    
    # Subpackages
    'dialogs',
    'widgets',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
