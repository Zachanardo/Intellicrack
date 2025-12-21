"""Comprehensive Integration Module for All Radare2 UI Features.

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

from typing import TYPE_CHECKING

from intellicrack.handlers.pyqt6_handler import QMainWindow, QTabWidget, QWidget

from ..utils.logger import get_logger
from .enhanced_ui_integration import EnhancedAnalysisDashboard
from .radare2_integration_ui import R2IntegrationWidget
from .radare2_ui_manager import R2UIManager, integrate_radare2_ui_comprehensive


logger = get_logger(__name__)


class ComprehensiveR2Integration:
    """Comprehensive integration class that handles all radare2 UI features.

    This class provides the main entry point for integrating all radare2
    functionality into any Intellicrack application variant.
    """

    def __init__(self) -> None:
        """Initialize the ComprehensiveR2Integration with default values."""
        self.logger = logger
        self.ui_manager: R2UIManager | None = None
        self.integrated_apps: list[object] = []
        self.integration_status: dict[str, bool] = {
            "ui_manager": False,
            "main_app": False,
            "menu_integration": False,
            "signal_connections": False,
            "error_handling": False,
        }

    def integrate_with_application(self, main_app: object) -> bool:
        """Integrate radare2 functionality with application.

        Args:
            main_app: The main application instance (any type)

        Returns:
            bool: True if integration successful, False otherwise

        """
        try:
            self.logger.info("Starting comprehensive radare2 integration with %s", type(main_app).__name__)

            # Detect application type and use appropriate integration method
            integration_method = self._detect_integration_method(main_app)
            self.logger.info("Using integration method: %s", integration_method)

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
                self.logger.exception("Comprehensive radare2 integration failed")

            return success

        except Exception as e:
            self.logger.exception("Integration failed with exception: %s", e)
            return False

    def _detect_integration_method(self, main_app: object) -> str:
        """Detect the best integration method based on application type.

        Args:
            main_app: The main application instance to analyze

        Returns:
            str: Integration method name (intellicrack_app, main_window, tab_widget, generic_widget, or fallback)

        """
        try:
            # Check for IntellicrackApp class
            if hasattr(main_app, "__class__") and "IntellicrackApp" in str(type(main_app)):
                return "intellicrack_app"

            # Check for QMainWindow
            if isinstance(main_app, QMainWindow):
                return "main_window"

            # Check for tab widget
            if hasattr(main_app, "tab_widget") and main_app.tab_widget:
                return "tab_widget"

            # Check for generic widget
            return "generic_widget" if isinstance(main_app, QWidget) else "fallback"
        except Exception as e:
            self.logger.exception("Failed to detect integration method: %s", e)
            return "fallback"

    def _integrate_with_intellicrack_app(self, main_app: object) -> bool:
        """Integration specific to IntellicrackApp.

        Args:
            main_app: The IntellicrackApp instance

        Returns:
            bool: True if integration successful, False otherwise

        """
        try:
            self.logger.info("Integrating with IntellicrackApp")

            # Use the comprehensive UI manager
            self.ui_manager = integrate_radare2_ui_comprehensive(main_app)
            if not self.ui_manager:
                return False

            self.integration_status["ui_manager"] = True

            # Add specific IntellicrackApp integrations
            self._integrate_intellicrack_specific_features(main_app)

            # Setup binary path synchronization
            self._setup_intellicrack_binary_sync(main_app)

            # Setup signal connections
            self._setup_intellicrack_signals(main_app)

            self.integration_status["main_app"] = True
            return True

        except Exception as e:
            self.logger.exception("IntellicrackApp integration failed: %s", e)
            return False

    def _integrate_with_main_window(self, main_app: object) -> bool:
        """Integration with QMainWindow applications.

        Args:
            main_app: The QMainWindow application instance

        Returns:
            bool: True if integration successful, False otherwise

        """
        try:
            self.logger.info("Integrating with QMainWindow")

            # Create UI manager
            self.ui_manager = R2UIManager(main_app)
            if not self.ui_manager.integrate_with_application(main_app):
                return False

            self.integration_status["ui_manager"] = True

            # Setup main window specific features
            self._setup_main_window_features(main_app)

            self.integration_status["main_app"] = True
            return True

        except Exception as e:
            self.logger.exception("QMainWindow integration failed: %s", e)
            return False

    def _integrate_with_tab_widget(self, main_app: object) -> bool:
        """Integration with applications that have tab widgets.

        Args:
            main_app: The application instance with tab_widget attribute

        Returns:
            bool: True if integration successful, False otherwise

        """
        try:
            self.logger.info("Integrating with tab widget application")

            # Create and add radare2 widgets
            r2_widget = R2IntegrationWidget(None)
            enhanced_dashboard = EnhancedAnalysisDashboard(None)

            # Add tabs
            if hasattr(main_app, "tab_widget") and main_app.tab_widget:
                main_app.tab_widget.addTab(r2_widget, "Radare2 Analysis")
                main_app.tab_widget.addTab(enhanced_dashboard, "Enhanced Analysis")

            # Store references
            if hasattr(main_app, "__dict__"):
                main_app.r2_widget = r2_widget
                main_app.enhanced_dashboard = enhanced_dashboard

            # Create UI manager
            self.ui_manager = R2UIManager(main_app)
            if hasattr(main_app, "__dict__"):
                main_app.r2_ui_manager = self.ui_manager

            self.integration_status["ui_manager"] = True
            self.integration_status["main_app"] = True
            return True

        except Exception as e:
            self.logger.exception("Tab widget integration failed: %s", e)
            return False

    def _integrate_with_generic_widget(self, main_app: object) -> bool:
        """Integration with generic QWidget applications.

        Args:
            main_app: The QWidget application instance

        Returns:
            bool: True if integration successful, False otherwise

        """
        try:
            self.logger.info("Integrating with generic widget application")

            # Create a tab widget if it doesn't exist
            if not hasattr(main_app, "tab_widget") and hasattr(main_app, "__dict__"):
                tab_widget_obj = QTabWidget()
                main_app.tab_widget = tab_widget_obj

                # Try to add to layout if it exists
                if hasattr(main_app, "layout"):
                    layout = getattr(main_app, "layout", None)
                    if layout and callable(layout):
                        if layout_obj := layout():
                            layout_obj.addWidget(tab_widget_obj)

            # Use tab widget integration method
            return self._integrate_with_tab_widget(main_app)

        except Exception as e:
            self.logger.exception("Generic widget integration failed: %s", e)
            return False

    def _integrate_fallback_method(self, main_app: object) -> bool:
        """Fallback integration method.

        Args:
            main_app: The application instance to integrate

        Returns:
            bool: True if integration successful, False otherwise

        """
        try:
            self.logger.info("Using fallback integration method")

            # Try to create minimal integration
            self.ui_manager = R2UIManager(main_app)

            # Store reference in main app if possible
            if hasattr(main_app, "__dict__"):
                main_app.r2_ui_manager = self.ui_manager

            self.integration_status["ui_manager"] = True

            # Try to add some basic functionality
            self._add_fallback_functionality(main_app)

            return True

        except Exception as e:
            self.logger.exception("Fallback integration failed: %s", e)
            return False

    def _integrate_intellicrack_specific_features(self, main_app: object) -> None:
        """Add IntellicrackApp specific integrations.

        Args:
            main_app: The IntellicrackApp instance

        """
        try:
            # Connect to existing signals if they exist
            if self.ui_manager and hasattr(main_app, "update_output"):
                self.ui_manager.status_updated.connect(
                    lambda msg: main_app.update_output.emit(f"[R2] {msg}"),
                )

            # Add menu items to existing menu
            if hasattr(main_app, "menuBar"):
                menuBar = getattr(main_app, "menuBar", None)
                if menuBar and callable(menuBar):
                    if menu_bar_obj := menuBar():
                        self._add_radare2_menu_items(main_app)
                        self.integration_status["menu_integration"] = True

            # Connect binary path updates
            if self.ui_manager and hasattr(main_app, "binary_path"):
                if binary_path := getattr(main_app, "binary_path", None):
                    self.ui_manager.set_binary_path(binary_path)

            self.logger.info("IntellicrackApp specific features integrated")

        except Exception as e:
            self.logger.exception("IntellicrackApp specific integration failed: %s", e)

    def _setup_intellicrack_binary_sync(self, main_app: object) -> None:
        """Set up binary path synchronization for IntellicrackApp.

        Args:
            main_app: The IntellicrackApp instance

        """
        try:
            # Create a method to update binary path
            def update_binary_path() -> None:
                if self.ui_manager and hasattr(main_app, "binary_path"):
                    binary_path = getattr(main_app, "binary_path", None)
                    if binary_path:
                        self.ui_manager.set_binary_path(binary_path)

            # Connect to binary path changes if possible
            if hasattr(main_app, "binary_path_changed"):
                binary_path_changed = getattr(main_app, "binary_path_changed", None)
                if binary_path_changed:
                    binary_path_changed.connect(update_binary_path)

            # Initial sync
            update_binary_path()

            self.logger.info("Binary path synchronization setup completed")

        except Exception as e:
            self.logger.exception("Binary path sync setup failed: %s", e)

    def _setup_intellicrack_signals(self, main_app: object) -> None:
        """Set up signal connections for IntellicrackApp.

        Args:
            main_app: The IntellicrackApp instance

        """
        try:
            # Connect analysis completion to main app
            if self.ui_manager and hasattr(main_app, "update_analysis_results"):
                if update_analysis_results := getattr(main_app, "update_analysis_results", None):
                    self.ui_manager.analysis_completed.connect(
                        lambda results: update_analysis_results.emit(str(results)),
                    )

            # Connect progress updates
            if self.ui_manager and hasattr(main_app, "update_progress"):
                if update_progress := getattr(main_app, "update_progress", None):
                    self.ui_manager.analysis_progress.connect(update_progress.emit)

            self.integration_status["signal_connections"] = True
            self.logger.info("Signal connections established")

        except Exception as e:
            self.logger.exception("Signal setup failed: %s", e)

    def _setup_main_window_features(self, main_app: object) -> None:
        """Set up features specific to QMainWindow.

        Args:
            main_app: The QMainWindow application instance

        """
        try:
            # Add toolbar items if toolbar exists
            if hasattr(main_app, "addToolBar"):
                self._add_radare2_toolbar(main_app)

            # Add status bar integration
            if hasattr(main_app, "statusBar"):
                self._integrate_status_bar(main_app)

            self.logger.info("Main window features setup completed")

        except Exception as e:
            self.logger.exception("Main window features setup failed: %s", e)

    def _add_radare2_menu_items(self, main_app: object) -> None:
        """Add radare2 menu items to application.

        Args:
            main_app: The application instance with menuBar method

        """
        try:
            from .menu_utils import find_or_create_menu

            menuBar = getattr(main_app, "menuBar", None)
            if not menuBar or not callable(menuBar):
                return

            menu_bar = menuBar()
            if not menu_bar:
                return

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
                ("Bypass Generation", "bypass"),
            ]

            for action_name, analysis_type in analysis_actions:
                action = r2_menu.addAction(action_name)
                if action and self.ui_manager:
                    action.triggered.connect(
                        lambda checked, t=analysis_type: self.ui_manager.start_analysis(t) if self.ui_manager else None,
                    )

            # Add separator and utilities
            r2_menu.addSeparator()

            config_action = r2_menu.addAction("Configuration")
            if config_action and self.ui_manager:
                config_action.triggered.connect(self.ui_manager.show_configuration)

            export_action = r2_menu.addAction("Export Results")
            if export_action and self.ui_manager:
                export_action.triggered.connect(self.ui_manager.export_results)

            self.logger.info("Radare2 menu items added")

        except Exception as e:
            self.logger.exception("Failed to add menu items: %s", e)

    def _add_radare2_toolbar(self, main_app: object) -> None:
        """Add radare2 toolbar to main window.

        Args:
            main_app: The QMainWindow application instance

        """
        try:
            addToolBar = getattr(main_app, "addToolBar", None)
            if not addToolBar or not callable(addToolBar):
                return

            toolbar = addToolBar("Radare2")
            if not toolbar:
                return

            # Add quick analysis buttons
            quick_actions = [
                ("Analyze", "comprehensive"),
                ("Vulnerabilities", "vulnerability"),
                ("License", "decompilation"),
            ]

            for action_name, analysis_type in quick_actions:
                action = toolbar.addAction(action_name)
                if self.ui_manager:
                    action.triggered.connect(
                        lambda checked, t=analysis_type: self.ui_manager.start_analysis(t) if self.ui_manager else None,
                    )

            toolbar.addSeparator()

            # Add configuration action
            config_action = toolbar.addAction("Config")
            if config_action and self.ui_manager:
                config_action.triggered.connect(self.ui_manager.show_configuration)

            self.logger.info("Radare2 toolbar added")

        except Exception as e:
            self.logger.exception("Failed to add toolbar: %s", e)

    def _integrate_status_bar(self, main_app: object) -> None:
        """Integrate with application status bar.

        Args:
            main_app: The application instance with statusBar method

        """
        try:
            if hasattr(main_app, "statusBar"):
                statusBar = getattr(main_app, "statusBar", None)
                if statusBar and callable(statusBar):
                    status_bar = statusBar()

                    # Connect status updates
                    if self.ui_manager and status_bar:
                        self.ui_manager.status_updated.connect(
                            lambda msg: status_bar.showMessage(f"R2: {msg}", 5000),
                        )

                    self.logger.info("Status bar integration completed")

        except Exception as e:
            self.logger.exception("Status bar integration failed: %s", e)

    def _add_fallback_functionality(self, main_app: object) -> None:
        """Add basic functionality for fallback integration.

        Args:
            main_app: The application instance to enhance with fallback functionality

        """
        try:
            # Try to add at least a way to start analysis
            if hasattr(main_app, "__dict__"):
                # Add start_radare2_analysis method
                def start_r2_analysis(analysis_type: str = "comprehensive") -> bool | None:
                    if self.ui_manager:
                        return self.ui_manager.start_analysis(analysis_type)
                    return False

                main_app.start_radare2_analysis = start_r2_analysis

                # Add configuration method
                def show_r2_config() -> None:
                    if self.ui_manager:
                        self.ui_manager.show_configuration()

                main_app.show_radare2_configuration = show_r2_config

                self.logger.info("Fallback functionality added")

        except Exception as e:
            self.logger.exception("Failed to add fallback functionality: %s", e)

    def get_integration_status(self) -> dict[str, bool]:
        """Get current integration status.

        Returns:
            dict[str, bool]: Copy of the integration status dictionary

        """
        return self.integration_status.copy()

    def get_ui_manager(self) -> R2UIManager | None:
        """Get the UI manager instance.

        Returns:
            R2UIManager | None: The UI manager instance if available, None otherwise

        """
        return self.ui_manager

    def cleanup(self) -> None:
        """Cleanup all integrations.

        Performs cleanup of all integrated applications and resets internal state.

        """
        try:
            if self.ui_manager:
                self.ui_manager.cleanup()

            self.integrated_apps.clear()
            self.integration_status = dict.fromkeys(self.integration_status, False)

            self.logger.info("Comprehensive integration cleanup completed")

        except Exception as e:
            self.logger.exception("Cleanup failed: %s", e)


# Global integration instance managed by this module
_GLOBAL_INTEGRATION: ComprehensiveR2Integration | None = None


def get_comprehensive_integration() -> ComprehensiveR2Integration:
    """Get or create global comprehensive integration instance.

    Returns:
        ComprehensiveR2Integration: The singleton integration instance

    """
    global _GLOBAL_INTEGRATION
    if _GLOBAL_INTEGRATION is None:
        _GLOBAL_INTEGRATION = ComprehensiveR2Integration()
    return _GLOBAL_INTEGRATION


def integrate_radare2_comprehensive(main_app: object) -> bool:
    """Integrate radare2 comprehensively into application.

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
        logger.exception("Comprehensive radare2 integration failed: %s", e)
        return False


def get_integration_status() -> dict[str, bool]:
    """Get current integration status.

    Returns:
        dict[str, bool]: Integration status for each component

    """
    integration = get_comprehensive_integration()
    return integration.get_integration_status()


def cleanup_integration() -> None:
    """Cleanup all radare2 integrations.

    Performs cleanup of the global integration instance and resets it to None.

    """
    global _GLOBAL_INTEGRATION
    if _GLOBAL_INTEGRATION:
        _GLOBAL_INTEGRATION.cleanup()
        _GLOBAL_INTEGRATION = None


__all__ = [
    "ComprehensiveR2Integration",
    "cleanup_integration",
    "get_comprehensive_integration",
    "get_integration_status",
    "integrate_radare2_comprehensive",
]
