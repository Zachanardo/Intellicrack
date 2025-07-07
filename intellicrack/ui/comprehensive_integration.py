"""
Comprehensive Integration Module for All Radare2 UI Features

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

from typing import Dict, Optional

from PyQt6.QtWidgets import QMainWindow, QTabWidget, QWidget

from ..utils.logger import get_logger
from .enhanced_ui_integration import EnhancedAnalysisDashboard
from .radare2_integration_ui import R2IntegrationWidget
from .radare2_ui_manager import R2UIManager, integrate_radare2_ui_comprehensive

logger = get_logger(__name__)


class ComprehensiveR2Integration:
    """
    Comprehensive integration class that handles all radare2 UI features.

    This class provides the main entry point for integrating all radare2
    functionality into any Intellicrack application variant.
    """

    def __init__(self):
        self.logger = logger
        self.ui_manager = None
        self.integrated_apps = []
        self.integration_status = {
            'ui_manager': False,
            'main_app': False,
            'menu_integration': False,
            'signal_connections': False,
            'error_handling': False
        }

    def integrate_with_application(self, main_app) -> bool:
        """
        Main integration method that handles all types of applications.

        Args:
            main_app: The main application instance (any type)

        Returns:
            bool: True if integration successful, False otherwise
        """
        try:
            self.logger.info(f"Starting comprehensive radare2 integration with {type(main_app).__name__}")

            # Detect application type and use appropriate integration method
            integration_method = self._detect_integration_method(main_app)
            self.logger.info(f"Using integration method: {integration_method}")

            if integration_method == "intellicrack_app":
                success = self._integrate_with_intellicrack_app(main_app)
            elif integration_method == "main_window":
                success = self._integrate_with_main_window(main_app)
            elif integration_method == "tab_widget":
                success = self._integrate_with_tab_widget(main_app)
            elif integration_method == "generic_widget":
                success = self._integrate_with_generic_widget(main_app)
            else:
                success = self._integrate_fallback_method(main_app)

            if success:
                self.integrated_apps.append(main_app)
                self.logger.info("Comprehensive radare2 integration completed successfully")
            else:
                self.logger.error("Comprehensive radare2 integration failed")

            return success

        except Exception as e:
            self.logger.error(f"Integration failed with exception: {e}")
            return False

    def _detect_integration_method(self, main_app) -> str:
        """Detect the best integration method based on application type"""
        try:
            # Check for IntellicrackApp class
            if hasattr(main_app, '__class__') and 'IntellicrackApp' in str(type(main_app)):
                return "intellicrack_app"

            # Check for QMainWindow
            if isinstance(main_app, QMainWindow):
                return "main_window"

            # Check for tab widget
            if hasattr(main_app, 'tab_widget') and main_app.tab_widget:
                return "tab_widget"

            # Check for generic widget
            if isinstance(main_app, QWidget):
                return "generic_widget"

            # Fallback
            return "fallback"

        except Exception as e:
            self.logger.error(f"Failed to detect integration method: {e}")
            return "fallback"

    def _integrate_with_intellicrack_app(self, main_app) -> bool:
        """Integration specific to IntellicrackApp"""
        try:
            self.logger.info("Integrating with IntellicrackApp")

            # Use the comprehensive UI manager
            self.ui_manager = integrate_radare2_ui_comprehensive(main_app)
            if not self.ui_manager:
                return False

            self.integration_status['ui_manager'] = True

            # Add specific IntellicrackApp integrations
            self._integrate_intellicrack_specific_features(main_app)

            # Setup binary path synchronization
            self._setup_intellicrack_binary_sync(main_app)

            # Setup signal connections
            self._setup_intellicrack_signals(main_app)

            self.integration_status['main_app'] = True
            return True

        except Exception as e:
            self.logger.error(f"IntellicrackApp integration failed: {e}")
            return False

    def _integrate_with_main_window(self, main_app) -> bool:
        """Integration with QMainWindow applications"""
        try:
            self.logger.info("Integrating with QMainWindow")

            # Create UI manager
            self.ui_manager = R2UIManager(main_app)
            if not self.ui_manager.integrate_with_application(main_app):
                return False

            self.integration_status['ui_manager'] = True

            # Setup main window specific features
            self._setup_main_window_features(main_app)

            self.integration_status['main_app'] = True
            return True

        except Exception as e:
            self.logger.error(f"QMainWindow integration failed: {e}")
            return False

    def _integrate_with_tab_widget(self, main_app) -> bool:
        """Integration with applications that have tab widgets"""
        try:
            self.logger.info("Integrating with tab widget application")

            # Create and add radare2 widgets
            r2_widget = R2IntegrationWidget(main_app)
            enhanced_dashboard = EnhancedAnalysisDashboard(main_app)

            # Add tabs
            main_app.tab_widget.addTab(r2_widget, "Radare2 Analysis")
            main_app.tab_widget.addTab(enhanced_dashboard, "Enhanced Analysis")

            # Store references
            main_app.r2_widget = r2_widget
            main_app.enhanced_dashboard = enhanced_dashboard

            # Create UI manager
            self.ui_manager = R2UIManager(main_app)
            main_app.r2_ui_manager = self.ui_manager

            self.integration_status['ui_manager'] = True
            self.integration_status['main_app'] = True
            return True

        except Exception as e:
            self.logger.error(f"Tab widget integration failed: {e}")
            return False

    def _integrate_with_generic_widget(self, main_app) -> bool:
        """Integration with generic QWidget applications"""
        try:
            self.logger.info("Integrating with generic widget application")

            # Create a tab widget if it doesn't exist
            if not hasattr(main_app, 'tab_widget'):
                main_app.tab_widget = QTabWidget()

                # Try to add to layout if it exists
                if hasattr(main_app, 'layout') and main_app.layout():
                    main_app.layout().addWidget(main_app.tab_widget)

            # Use tab widget integration method
            return self._integrate_with_tab_widget(main_app)

        except Exception as e:
            self.logger.error(f"Generic widget integration failed: {e}")
            return False

    def _integrate_fallback_method(self, main_app) -> bool:
        """Fallback integration method"""
        try:
            self.logger.info("Using fallback integration method")

            # Try to create minimal integration
            self.ui_manager = R2UIManager(main_app)

            # Store reference in main app if possible
            if hasattr(main_app, '__dict__'):
                main_app.r2_ui_manager = self.ui_manager

            self.integration_status['ui_manager'] = True

            # Try to add some basic functionality
            self._add_fallback_functionality(main_app)

            return True

        except Exception as e:
            self.logger.error(f"Fallback integration failed: {e}")
            return False

    def _integrate_intellicrack_specific_features(self, main_app):
        """Add IntellicrackApp specific integrations"""
        try:
            # Connect to existing signals if they exist
            if hasattr(main_app, 'update_output'):
                self.ui_manager.status_updated.connect(
                    lambda msg: main_app.update_output.emit(f"[R2] {msg}")
                )

            # Add menu items to existing menu
            if hasattr(main_app, 'menuBar') and main_app.menuBar():
                self._add_radare2_menu_items(main_app)
                self.integration_status['menu_integration'] = True

            # Connect binary path updates
            if hasattr(main_app, 'binary_path'):
                if main_app.binary_path:
                    self.ui_manager.set_binary_path(main_app.binary_path)

            self.logger.info("IntellicrackApp specific features integrated")

        except Exception as e:
            self.logger.error(f"IntellicrackApp specific integration failed: {e}")

    def _setup_intellicrack_binary_sync(self, main_app):
        """Setup binary path synchronization for IntellicrackApp"""
        try:
            # Create a method to update binary path
            def update_binary_path():
                if hasattr(main_app, 'binary_path') and main_app.binary_path:
                    self.ui_manager.set_binary_path(main_app.binary_path)

            # Connect to binary path changes if possible
            if hasattr(main_app, 'binary_path_changed'):
                main_app.binary_path_changed.connect(update_binary_path)

            # Initial sync
            update_binary_path()

            self.logger.info("Binary path synchronization setup completed")

        except Exception as e:
            self.logger.error(f"Binary path sync setup failed: {e}")

    def _setup_intellicrack_signals(self, main_app):
        """Setup signal connections for IntellicrackApp"""
        try:
            # Connect analysis completion to main app
            if hasattr(main_app, 'update_analysis_results'):
                self.ui_manager.analysis_completed.connect(
                    lambda results: main_app.update_analysis_results.emit(str(results))
                )

            # Connect progress updates
            if hasattr(main_app, 'update_progress'):
                self.ui_manager.analysis_progress.connect(main_app.update_progress.emit)

            self.integration_status['signal_connections'] = True
            self.logger.info("Signal connections established")

        except Exception as e:
            self.logger.error(f"Signal setup failed: {e}")

    def _setup_main_window_features(self, main_app):
        """Setup features specific to QMainWindow"""
        try:
            # Add toolbar items if toolbar exists
            if hasattr(main_app, 'addToolBar'):
                self._add_radare2_toolbar(main_app)

            # Add status bar integration
            if hasattr(main_app, 'statusBar'):
                self._integrate_status_bar(main_app)

            self.logger.info("Main window features setup completed")

        except Exception as e:
            self.logger.error(f"Main window features setup failed: {e}")

    def _add_radare2_menu_items(self, main_app):
        """Add radare2 menu items to application"""
        try:
            from .menu_utils import find_or_create_menu

            menu_bar = main_app.menuBar()

            # Create or find Radare2 menu
            r2_menu = find_or_create_menu(menu_bar, "Radare2")

            # Clear existing items
            r2_menu.clear()

            # Add analysis actions
            analysis_actions = [
                ("Comprehensive Analysis", "comprehensive"),
                ("Vulnerability Scan", "vulnerability"),
                ("License Analysis", "decompilation"),
                ("String Analysis", "strings"),
                ("Import Analysis", "imports"),
                ("CFG Analysis", "cfg"),
                ("AI Analysis", "ai"),
                ("Bypass Generation", "bypass")
            ]

            for action_name, analysis_type in analysis_actions:
                action = r2_menu.addAction(action_name)
                action.triggered.connect(
                    lambda checked, t=analysis_type: self.ui_manager.start_analysis(t)
                )

            # Add separator and utilities
            r2_menu.addSeparator()

            config_action = r2_menu.addAction("Configuration")
            config_action.triggered.connect(self.ui_manager.show_configuration)

            export_action = r2_menu.addAction("Export Results")
            export_action.triggered.connect(self.ui_manager.export_results)

            self.logger.info("Radare2 menu items added")

        except Exception as e:
            self.logger.error(f"Failed to add menu items: {e}")

    def _add_radare2_toolbar(self, main_app):
        """Add radare2 toolbar to main window"""
        try:
            toolbar = main_app.addToolBar("Radare2")

            # Add quick analysis buttons
            quick_actions = [
                ("Analyze", "comprehensive"),
                ("Vulnerabilities", "vulnerability"),
                ("License", "decompilation")
            ]

            for action_name, analysis_type in quick_actions:
                action = toolbar.addAction(action_name)
                action.triggered.connect(
                    lambda checked, t=analysis_type: self.ui_manager.start_analysis(t)
                )

            toolbar.addSeparator()

            # Add configuration action
            config_action = toolbar.addAction("Config")
            config_action.triggered.connect(self.ui_manager.show_configuration)

            self.logger.info("Radare2 toolbar added")

        except Exception as e:
            self.logger.error(f"Failed to add toolbar: {e}")

    def _integrate_status_bar(self, main_app):
        """Integrate with application status bar"""
        try:
            if hasattr(main_app, 'statusBar'):
                status_bar = main_app.statusBar()

                # Connect status updates
                self.ui_manager.status_updated.connect(
                    lambda msg: status_bar.showMessage(f"R2: {msg}", 5000)
                )

                self.logger.info("Status bar integration completed")

        except Exception as e:
            self.logger.error(f"Status bar integration failed: {e}")

    def _add_fallback_functionality(self, main_app):
        """Add basic functionality for fallback integration"""
        try:
            # Try to add at least a way to start analysis
            if hasattr(main_app, '__dict__'):
                # Add start_radare2_analysis method
                def start_r2_analysis(analysis_type="comprehensive"):
                    if self.ui_manager:
                        return self.ui_manager.start_analysis(analysis_type)
                    return False

                main_app.start_radare2_analysis = start_r2_analysis

                # Add configuration method
                def show_r2_config():
                    if self.ui_manager:
                        self.ui_manager.show_configuration()

                main_app.show_radare2_configuration = show_r2_config

                self.logger.info("Fallback functionality added")

        except Exception as e:
            self.logger.error(f"Failed to add fallback functionality: {e}")

    def get_integration_status(self) -> Dict[str, bool]:
        """Get current integration status"""
        return self.integration_status.copy()

    def get_ui_manager(self) -> Optional[R2UIManager]:
        """Get the UI manager instance"""
        return self.ui_manager

    def cleanup(self):
        """Cleanup all integrations"""
        try:
            if self.ui_manager:
                self.ui_manager.cleanup()

            self.integrated_apps.clear()
            self.integration_status = {key: False for key in self.integration_status}

            self.logger.info("Comprehensive integration cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")


# Global integration instance
_GLOBAL_INTEGRATION = None


def get_comprehensive_integration() -> ComprehensiveR2Integration:
    """Get or create global comprehensive integration instance"""
    global _GLOBAL_INTEGRATION
    if _GLOBAL_INTEGRATION is None:
        _GLOBAL_INTEGRATION = ComprehensiveR2Integration()
    return _GLOBAL_INTEGRATION


def integrate_radare2_comprehensive(main_app) -> bool:
    """
    Main entry point for comprehensive radare2 integration.

    This function provides the simplest way to integrate all radare2
    functionality into any Intellicrack application.

    Args:
        main_app: The main application instance

    Returns:
        bool: True if integration successful, False otherwise
    """
    try:
        integration = get_comprehensive_integration()
        return integration.integrate_with_application(main_app)
    except Exception as e:
        logger.error(f"Comprehensive radare2 integration failed: {e}")
        return False


def get_integration_status() -> Dict[str, bool]:
    """Get current integration status"""
    integration = get_comprehensive_integration()
    return integration.get_integration_status()


def cleanup_integration():
    """Cleanup all radare2 integrations"""
    global _GLOBAL_INTEGRATION
    if _GLOBAL_INTEGRATION:
        _GLOBAL_INTEGRATION.cleanup()
        _GLOBAL_INTEGRATION = None


__all__ = [
    'ComprehensiveR2Integration',
    'integrate_radare2_comprehensive',
    'get_comprehensive_integration',
    'get_integration_status',
    'cleanup_integration'
]
