"""Comprehensive Radare2 UI Manager for Intellicrack.

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

import os
from typing import Any

from intellicrack.handlers.pyqt6_handler import QMessageBox, QObject, QTabWidget, pyqtSignal

from ..utils.logger import get_logger
from .enhanced_ui_integration import EnhancedAnalysisDashboard, integrate_enhanced_ui_with_existing_app
from .radare2_integration_ui import R2ConfigurationDialog, R2IntegrationWidget, R2ResultsViewer, integrate_with_main_app


logger = get_logger(__name__)


class R2UIManager(QObject):
    """Comprehensive manager for all radare2 UI integrations.

    This class handles the integration of all radare2 features into the main
    Intellicrack application, providing a unified interface for:
    - Analysis execution and monitoring
    - Results visualization and management
    - Configuration and settings
    - Export and reporting capabilities
    """

    # Signals for UI updates
    #: Signal emitted when analysis starts (str: analysis_type)
    analysis_started = pyqtSignal(str)
    #: Signal emitted during analysis progress (int: progress percentage)
    analysis_progress = pyqtSignal(int)
    #: Signal emitted when analysis completes (dict: results)
    analysis_completed = pyqtSignal(dict)
    #: Signal emitted when analysis fails (str: error message)
    analysis_failed = pyqtSignal(str)
    #: Signal emitted when status updates (str: status message)
    status_updated = pyqtSignal(str)
    #: Signal emitted when binary is loaded (str: binary path)
    binary_loaded = pyqtSignal(str)

    def __init__(self, main_app: object | None = None) -> None:
        """Initialize the radare2 UI manager with main application integration."""
        super().__init__()
        self.logger = logger
        self.main_app = main_app
        self.binary_path = None
        self.current_results = {}
        self.ui_components = {}
        self.analysis_history = []

        # Initialize UI components
        self._initialize_ui_components()

        # Setup signal connections
        self._setup_signal_connections()

        self.logger.info("R2UIManager initialized successfully")

    def _initialize_ui_components(self) -> None:
        """Initialize all UI components."""
        try:
            # Core radare2 integration widget
            self.ui_components["r2_widget"] = R2IntegrationWidget(self.main_app)

            # Enhanced dashboard
            self.ui_components["enhanced_dashboard"] = EnhancedAnalysisDashboard(self.main_app)

            # Results viewer
            self.ui_components["results_viewer"] = R2ResultsViewer(self.main_app)

            # Configuration dialog
            self.ui_components["config_dialog"] = R2ConfigurationDialog(self.main_app)

            self.logger.info("UI components initialized successfully")

        except Exception as e:
            self.logger.error("Failed to initialize UI components: %s", e)

    def _setup_signal_connections(self) -> None:
        """Set up signal connections between components."""
        try:
            # Connect main UI manager signals to UI components
            self.binary_loaded.connect(self._on_binary_loaded)
            self.analysis_started.connect(self._on_analysis_started)
            self.analysis_completed.connect(self._on_analysis_completed)
            self.analysis_failed.connect(self._on_analysis_failed)

            # Connect UI component signals if they exist
            if "r2_widget" in self.ui_components:
                self.ui_components["r2_widget"]
            self.logger.info("Signal connections established")

        except Exception as e:
            self.logger.error("Failed to setup signal connections: %s", e)

    def integrate_with_application(self, main_app: object) -> bool:
        """Integrate all radare2 UI components with the main application.

        Args:
            main_app: The main Intellicrack application instance

        Returns:
            bool: True if integration successful, False otherwise

        """
        try:
            self.main_app = main_app
            integration_success = True

            # Method 1: Try direct tab widget integration
            if hasattr(main_app, "tab_widget") and main_app.tab_widget:
                self.logger.info("Integrating with existing tab widget")

                # Add radare2 analysis tab
                main_app.tab_widget.addTab(
                    self.ui_components["r2_widget"],
                    "Radare2 Analysis",
                )

                # Add enhanced dashboard tab
                main_app.tab_widget.addTab(
                    self.ui_components["enhanced_dashboard"],
                    "Enhanced Analysis",
                )

                # Store references in main app
                main_app.r2_ui_manager = self
                main_app.r2_widget = self.ui_components["r2_widget"]
                main_app.enhanced_dashboard = self.ui_components["enhanced_dashboard"]

                self.logger.info("Successfully integrated with tab widget")

            # Method 2: Try central widget integration
            elif hasattr(main_app, "setCentralWidget"):
                self.logger.info("Integrating with central widget")

                # Create tab widget if it doesn't exist
                if not hasattr(main_app, "tab_widget"):
                    main_app.tab_widget = QTabWidget()
                    main_app.setCentralWidget(main_app.tab_widget)

                # Add our components
                main_app.tab_widget.addTab(
                    self.ui_components["r2_widget"],
                    "Radare2 Analysis",
                )
                main_app.tab_widget.addTab(
                    self.ui_components["enhanced_dashboard"],
                    "Enhanced Analysis",
                )

                # Store references
                main_app.r2_ui_manager = self

                self.logger.info("Successfully integrated with central widget")

            # Method 3: Try integration with existing IntellicrackApp structure
            else:
                self.logger.info("Attempting integration with existing app structure")

                # Use the existing integration functions
                if integrate_with_main_app(main_app):
                    self.logger.info("Used existing integration method")
                else:
                    self.logger.warning("Existing integration method failed")
                    integration_success = False

                # Try enhanced integration
                if integrate_enhanced_ui_with_existing_app(main_app):
                    self.logger.info("Enhanced integration successful")
                else:
                    self.logger.warning("Enhanced integration failed")

            # Setup menu integration if possible
            self._integrate_menu_items(main_app)

            # Setup binary path synchronization
            self._setup_binary_path_sync(main_app)

            # Setup status bar integration
            self._integrate_status_bar(main_app)

            if integration_success:
                self.logger.info("R2UIManager integration completed successfully")
                return True
            self.logger.error("R2UIManager integration failed")
            return False

        except Exception as e:
            self.logger.error("Failed to integrate with application: %s", e)
            return False

    def _integrate_menu_items(self, main_app: object) -> None:
        """Integrate radare2 menu items with main application."""
        try:
            if hasattr(main_app, "menuBar") and main_app.menuBar():
                from .menu_utils import find_or_create_menu

                menu_bar = main_app.menuBar()

                # Create Radare2 menu if it doesn't exist
                r2_menu = find_or_create_menu(menu_bar, "Radare2")

                # Add analysis actions
                analysis_actions = [
                    ("Comprehensive Analysis", lambda: self.start_analysis("comprehensive")),
                    ("Vulnerability Scan", lambda: self.start_analysis("vulnerability")),
                    ("License Analysis", lambda: self.start_analysis("decompilation")),
                    ("String Analysis", lambda: self.start_analysis("strings")),
                    ("AI Analysis", lambda: self.start_analysis("ai")),
                    ("CFG Analysis", lambda: self.start_analysis("cfg")),
                ]

                for action_name, callback in analysis_actions:
                    action = r2_menu.addAction(action_name)
                    action.triggered.connect(callback)

                # Add separator and configuration
                r2_menu.addSeparator()
                config_action = r2_menu.addAction("Configuration")
                config_action.triggered.connect(self.show_configuration)

                self.logger.info("Menu integration completed")

        except Exception as e:
            self.logger.error("Menu integration failed: %s", e)

    def _setup_binary_path_sync(self, main_app: object) -> None:
        """Set up binary path synchronization."""
        try:
            # Connect to main app's binary path changes
            if hasattr(main_app, "binary_path") and main_app.binary_path:
                self.set_binary_path(main_app.binary_path)

            # Setup signal connection if main app emits binary path changes
            if hasattr(main_app, "binary_path_changed"):
                main_app.binary_path_changed.connect(self.set_binary_path)

            self.logger.info("Binary path synchronization setup completed")

        except Exception as e:
            self.logger.error("Binary path sync setup failed: %s", e)

    def _integrate_status_bar(self, main_app: object) -> None:
        """Integrate with main application status bar."""
        try:
            if hasattr(main_app, "statusBar") and main_app.statusBar():
                # Connect our status updates to main app status bar
                self.status_updated.connect(
                    lambda msg: main_app.statusBar().showMessage(f"R2: {msg}"),
                )

                self.logger.info("Status bar integration completed")

        except Exception as e:
            self.logger.error("Status bar integration failed: %s", e)

    def set_binary_path(self, path: str) -> None:
        """Set binary path for all components."""
        try:
            self.binary_path = path

            # Update all UI components
            if "r2_widget" in self.ui_components:
                self.ui_components["r2_widget"].set_binary_path(path)

            if "enhanced_dashboard" in self.ui_components and hasattr(self.ui_components["enhanced_dashboard"], "r2_widget"):
                self.ui_components["enhanced_dashboard"].r2_widget.set_binary_path(path)

            # Emit signal
            self.binary_loaded.emit(path)

            self.logger.info("Binary path set: %s", path)

        except Exception as e:
            self.logger.error("Failed to set binary path: %s", e)

    def start_analysis(self, analysis_type: str, options: dict[str, Any] = None) -> bool | None:
        """Start radare2 analysis of specified type."""
        try:
            if not self.binary_path:
                QMessageBox.warning(
                    self.main_app,
                    "No Binary",
                    "Please select a binary file first",
                )
                return False

            # Use r2_widget to start analysis
            if "r2_widget" in self.ui_components:
                self.ui_components["r2_widget"]._start_analysis(analysis_type)

                # Add to analysis history
                self.analysis_history.append(
                    {
                        "type": analysis_type,
                        "binary": self.binary_path,
                        "timestamp": self._get_r2_timestamp(),
                        "options": options or {},
                    },
                )

                # Emit signal
                self.analysis_started.emit(analysis_type)

                self.logger.info("Started %s analysis", analysis_type)
                return True
            self.logger.error("R2 widget not available")
            return False

        except Exception as e:
            self.logger.error("Failed to start analysis: %s", e)
            self.analysis_failed.emit(str(e))
            return False

    def show_configuration(self) -> None:
        """Show radare2 configuration dialog."""
        try:
            if "config_dialog" in self.ui_components:
                dialog = self.ui_components["config_dialog"]
                if dialog.exec() == dialog.Accepted:
                    config = dialog.get_configuration()
                    self._apply_configuration(config)
                    self.logger.info("Configuration updated")

        except Exception as e:
            self.logger.error("Failed to show configuration: %s", e)

    def _apply_configuration(self, config: dict[str, Any]) -> None:
        """Apply configuration to all components."""
        try:
            # Store configuration
            self.analysis_config = config

            # Apply to r2_widget if available
            if "r2_widget" in self.ui_components:
                self.ui_components["r2_widget"].analysis_config = config

            self.logger.info("Configuration applied to all components")

        except Exception as e:
            self.logger.error("Failed to apply configuration: %s", e)

    def export_results(self, file_path: str = None) -> bool:
        """Export current analysis results."""
        try:
            if not self.current_results:
                QMessageBox.information(
                    self.main_app,
                    "No Results",
                    "No analysis results available to export",
                )
                return False

            # Use provided file_path or generate default
            if file_path:
                self.logger.info("Exporting results to specified path: %s", file_path)
                export_path = file_path
            else:
                # Generate default path based on binary name
                if self.binary_path:
                    base_name = os.path.splitext(os.path.basename(self.binary_path))[0]
                    export_path = f"{base_name}_radare2_analysis.json"
                else:
                    export_path = "radare2_analysis.json"
                self.logger.info("Using default export path: %s", export_path)

            # Use results viewer to export with specified path
            if "results_viewer" in self.ui_components:
                self.ui_components["results_viewer"].results_data = self.current_results

                # Check if the results_viewer has a method to export to specific path
                if hasattr(self.ui_components["results_viewer"], "export_to_file"):
                    self.ui_components["results_viewer"].export_to_file(export_path)
                else:
                    # Fallback: Set default path and use standard export
                    self.ui_components["results_viewer"].default_export_path = export_path
                    self.ui_components["results_viewer"]._export_results()

                # Log export details
                self.logger.info("Results exported to: %s", export_path)

                # Update status
                self.status_updated.emit(f"Results exported to {export_path}")

                # Track in history
                self.analysis_history.append(
                    {
                        "timestamp": self._get_r2_timestamp(),
                        "action": "export",
                        "file_path": export_path,
                        "binary": self.binary_path,
                        "results_count": len(self.current_results),
                    },
                )

                return True
            # Direct export if no viewer available
            import json

            with open(export_path, "w") as f:
                json.dump(self.current_results, f, indent=2)

            self.logger.info("Results exported directly to: %s", export_path)
            return True

        except Exception as e:
            self.logger.error("Failed to export results to %s: %s", file_path, e)
            self.status_updated.emit(f"Export failed: {e!s}")
            return False

    def get_analysis_history(self) -> list[dict[str, Any]]:
        """Get analysis history."""
        return self.analysis_history.copy()

    def get_current_results(self) -> dict[str, Any]:
        """Get current analysis results."""
        return self.current_results.copy()

    def clear_results(self) -> None:
        """Clear current analysis results."""
        self.current_results = {}

        # Clear results viewer
        if "results_viewer" in self.ui_components:
            self.ui_components["results_viewer"].results_data = {}

    def _get_r2_timestamp(self) -> str:
        """Get current timestamp for radare2 operations."""
        from datetime import datetime

        return datetime.now().isoformat()

    # Signal handlers
    def _on_binary_loaded(self, path: str) -> None:
        """Handle binary loaded signal."""
        self.status_updated.emit(f"Binary loaded: {os.path.basename(path)}")

    def _on_analysis_started(self, analysis_type: str) -> None:
        """Handle analysis started signal."""
        self.status_updated.emit(f"Starting {analysis_type} analysis...")

    def _on_analysis_completed(self, results: dict[str, Any]) -> None:
        """Handle analysis completed signal."""
        self.current_results = results
        self.status_updated.emit("Analysis completed successfully")

        # Update results viewer
        if "results_viewer" in self.ui_components:
            self.ui_components["results_viewer"].display_results(results)

    def _on_analysis_failed(self, error: str) -> None:
        """Handle analysis failed signal."""
        self.status_updated.emit(f"Analysis failed: {error}")
        QMessageBox.critical(
            self.main_app,
            "Analysis Error",
            f"Analysis failed:\n{error}",
        )

    def cleanup(self) -> None:
        """Cleanup resources."""
        try:
            # Stop any running analysis
            if "r2_widget" in self.ui_components:
                r2_widget = self.ui_components["r2_widget"]
                if hasattr(r2_widget, "current_worker") and r2_widget.current_worker and r2_widget.current_worker.isRunning():
                    r2_widget.current_worker.terminate()
                    r2_widget.current_worker.wait()

            # Clear references
            self.ui_components.clear()
            self.current_results.clear()
            self.analysis_history.clear()

            self.logger.info("R2UIManager cleanup completed")

        except Exception as e:
            self.logger.error("Cleanup failed: %s", e)


def create_r2_ui_manager(main_app: object | None = None) -> R2UIManager:
    """Create and return configured R2UIManager instance."""
    return R2UIManager(main_app)


def integrate_radare2_ui_comprehensive(main_app: object) -> R2UIManager | None:
    """Comprehensive integration of all radare2 UI features with main application.

    This is the main entry point for integrating all radare2 functionality
    into an existing Intellicrack application.

    Args:
        main_app: The main Intellicrack application instance

    Returns:
        R2UIManager: Configured UI manager instance, or None if integration fails

    """
    try:
        # Create UI manager
        ui_manager = create_r2_ui_manager(main_app)

        # Integrate with application
        if ui_manager.integrate_with_application(main_app):
            logger.info("Comprehensive radare2 UI integration completed successfully")
            return ui_manager
        logger.error("Comprehensive radare2 UI integration failed")
        return None

    except Exception as e:
        logger.error("Failed to integrate radare2 UI comprehensively: %s", e)
        return None


__all__ = [
    "R2UIManager",
    "create_r2_ui_manager",
    "integrate_radare2_ui_comprehensive",
]
