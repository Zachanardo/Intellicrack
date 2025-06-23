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

# Import comprehensive radare2 UI integration
try:
    from .comprehensive_integration import (
        ComprehensiveR2Integration,
        cleanup_integration,
        get_comprehensive_integration,
        get_integration_status,
        integrate_radare2_comprehensive,
    )
    logger.info("Radare2 comprehensive UI integration loaded successfully")
except ImportError as e:
    logger.warning("Failed to import radare2 UI integration: %s", e)
    # Provide fallback functions
    def integrate_radare2_comprehensive(main_app):
        """Fallback for radare2 comprehensive integration."""
        logger.error("Radare2 integration not available")

        # Use main_app to show error message if possible
        if main_app:
            # Update status bar if available
            if hasattr(main_app, 'status_bar'):
                main_app.status_bar.showMessage("Radare2 integration module not available", 5000)

            # Log to output if available
            if hasattr(main_app, 'update_output'):
                main_app.update_output.emit("[Error] Radare2 comprehensive integration module not found")

            # Show message box if Qt is available
            try:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.warning(
                    main_app,
                    "Integration Not Available",
                    "The Radare2 comprehensive integration module is not available.\n"
                    "Please check that all dependencies are installed."
                )
            except ImportError:
                pass

            # Try to disable radare2-related UI elements
            if hasattr(main_app, 'radare2_action'):
                main_app.radare2_action.setEnabled(False)
                main_app.radare2_action.setText("Radare2 (Not Available)")

            # Track failed integration attempt
            if hasattr(main_app, 'integration_attempts'):
                main_app.integration_attempts.append({
                    'module': 'radare2_comprehensive',
                    'status': 'failed',
                    'reason': 'Module not available'
                })

        return False

    def get_comprehensive_integration():
        """Fallback for getting comprehensive integration instance."""
        logger.error("Radare2 integration not available")
        return None

    def get_integration_status():
        """Fallback for getting integration status."""
        return {"error": "Integration not available"}

    def cleanup_integration():
        """Fallback for cleanup integration."""
        pass

    ComprehensiveR2Integration = None

# Import radare2 UI components
try:
    from .radare2_integration_ui import (
        R2ConfigurationDialog,
        R2IntegrationWidget,
        R2ResultsViewer,
        create_radare2_tab,
    )
    logger.info("Radare2 UI components loaded successfully")
except ImportError as e:
    logger.warning("Failed to import radare2 UI components: %s", e)
    R2IntegrationWidget = None
    R2ConfigurationDialog = None
    R2ResultsViewer = None
    create_radare2_tab = None

# Import enhanced UI features
try:
    from .enhanced_ui_integration import (
        EnhancedAnalysisDashboard,
        EnhancedMainWindow,
        create_enhanced_application,
    )
    logger.info("Enhanced UI features loaded successfully")
except ImportError as e:
    logger.warning("Failed to import enhanced UI features: %s", e)
    EnhancedAnalysisDashboard = None
    EnhancedMainWindow = None
    create_enhanced_application = None

# Import UI manager
try:
    from .radare2_ui_manager import R2UIManager, create_r2_ui_manager
    logger.info("Radare2 UI manager loaded successfully")
except ImportError as e:
    logger.warning("Failed to import radare2 UI manager: %s", e)
    R2UIManager = None
    create_r2_ui_manager = None

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

    # Radare2 comprehensive integration
    'integrate_radare2_comprehensive',
    'get_comprehensive_integration',
    'get_integration_status',
    'cleanup_integration',
    'ComprehensiveR2Integration',

    # Radare2 UI components
    'R2IntegrationWidget',
    'R2ConfigurationDialog',
    'R2ResultsViewer',
    'create_radare2_tab',

    # Enhanced UI features
    'EnhancedAnalysisDashboard',
    'EnhancedMainWindow',
    'create_enhanced_application',

    # UI manager
    'R2UIManager',
    'create_r2_ui_manager',

    # Subpackages
    'dialogs',
    'widgets',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
