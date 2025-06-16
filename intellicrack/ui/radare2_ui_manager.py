"""
Comprehensive Radare2 UI Manager for Intellicrack

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

import os
from typing import Any, Dict, List

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QMessageBox, QTabWidget

from ..utils.logger import get_logger
from .enhanced_ui_integration import (
    EnhancedAnalysisDashboard,
    integrate_enhanced_ui_with_existing_app,
)
from .radare2_integration_ui import (
    R2ConfigurationDialog,
    R2IntegrationWidget,
    R2ResultsViewer,
    integrate_with_main_app,
)

logger = get_logger(__name__)


class R2UIManager(QObject):
    """
    Comprehensive manager for all radare2 UI integrations.
    
    This class handles the integration of all radare2 features into the main
    Intellicrack application, providing a unified interface for:
    - Analysis execution and monitoring
    - Results visualization and management
    - Configuration and settings
    - Export and reporting capabilities
    """

    # Signals for UI updates
    analysis_started = pyqtSignal(str)  # analysis_type
    analysis_progress = pyqtSignal(int)  # progress percentage
    analysis_completed = pyqtSignal(dict)  # results
    analysis_failed = pyqtSignal(str)  # error message
    status_updated = pyqtSignal(str)  # status message
    binary_loaded = pyqtSignal(str)  # binary path

    def __init__(self, main_app=None):
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

    def _initialize_ui_components(self):
        """Initialize all UI components"""
        try:
            # Core radare2 integration widget
            self.ui_components['r2_widget'] = R2IntegrationWidget(self.main_app)

            # Enhanced dashboard
            self.ui_components['enhanced_dashboard'] = EnhancedAnalysisDashboard(self.main_app)

            # Results viewer
            self.ui_components['results_viewer'] = R2ResultsViewer(self.main_app)

            # Configuration dialog
            self.ui_components['config_dialog'] = R2ConfigurationDialog(self.main_app)

            self.logger.info("UI components initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize UI components: {e}")

    def _setup_signal_connections(self):
        """Setup signal connections between components"""
        try:
            # Connect main UI manager signals to UI components
            self.binary_loaded.connect(self._on_binary_loaded)
            self.analysis_started.connect(self._on_analysis_started)
            self.analysis_completed.connect(self._on_analysis_completed)
            self.analysis_failed.connect(self._on_analysis_failed)

            # Connect UI component signals if they exist
            if 'r2_widget' in self.ui_components:
                r2_widget = self.ui_components['r2_widget']
                # Connect internal signals if available
                if hasattr(r2_widget, 'current_worker'):
                    # These will be connected when worker is created
                    pass

            self.logger.info("Signal connections established")

        except Exception as e:
            self.logger.error(f"Failed to setup signal connections: {e}")

    def integrate_with_application(self, main_app) -> bool:
        """
        Integrate all radare2 UI components with the main application.
        
        Args:
            main_app: The main Intellicrack application instance
            
        Returns:
            bool: True if integration successful, False otherwise
        """
        try:
            self.main_app = main_app
            integration_success = True

            # Method 1: Try direct tab widget integration
            if hasattr(main_app, 'tab_widget') and main_app.tab_widget:
                self.logger.info("Integrating with existing tab widget")

                # Add radare2 analysis tab
                main_app.tab_widget.addTab(
                    self.ui_components['r2_widget'],
                    "Radare2 Analysis"
                )

                # Add enhanced dashboard tab
                main_app.tab_widget.addTab(
                    self.ui_components['enhanced_dashboard'],
                    "Enhanced Analysis"
                )

                # Store references in main app
                main_app.r2_ui_manager = self
                main_app.r2_widget = self.ui_components['r2_widget']
                main_app.enhanced_dashboard = self.ui_components['enhanced_dashboard']

                self.logger.info("Successfully integrated with tab widget")

            # Method 2: Try central widget integration
            elif hasattr(main_app, 'setCentralWidget'):
                self.logger.info("Integrating with central widget")

                # Create tab widget if it doesn't exist
                if not hasattr(main_app, 'tab_widget'):
                    main_app.tab_widget = QTabWidget()
                    main_app.setCentralWidget(main_app.tab_widget)

                # Add our components
                main_app.tab_widget.addTab(
                    self.ui_components['r2_widget'],
                    "Radare2 Analysis"
                )
                main_app.tab_widget.addTab(
                    self.ui_components['enhanced_dashboard'],
                    "Enhanced Analysis"
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
            else:
                self.logger.error("R2UIManager integration failed")
                return False

        except Exception as e:
            self.logger.error(f"Failed to integrate with application: {e}")
            return False

    def _integrate_menu_items(self, main_app):
        """Integrate radare2 menu items with main application"""
        try:
            if hasattr(main_app, 'menuBar') and main_app.menuBar():
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
                    ("CFG Analysis", lambda: self.start_analysis("cfg"))
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
            self.logger.error(f"Menu integration failed: {e}")

    def _setup_binary_path_sync(self, main_app):
        """Setup binary path synchronization"""
        try:
            # Connect to main app's binary path changes
            if hasattr(main_app, 'binary_path'):
                if main_app.binary_path:
                    self.set_binary_path(main_app.binary_path)

            # Setup signal connection if main app emits binary path changes
            if hasattr(main_app, 'binary_path_changed'):
                main_app.binary_path_changed.connect(self.set_binary_path)

            self.logger.info("Binary path synchronization setup completed")

        except Exception as e:
            self.logger.error(f"Binary path sync setup failed: {e}")

    def _integrate_status_bar(self, main_app):
        """Integrate with main application status bar"""
        try:
            if hasattr(main_app, 'statusBar') and main_app.statusBar():
                # Connect our status updates to main app status bar
                self.status_updated.connect(
                    lambda msg: main_app.statusBar().showMessage(f"R2: {msg}")
                )

                self.logger.info("Status bar integration completed")

        except Exception as e:
            self.logger.error(f"Status bar integration failed: {e}")

    def set_binary_path(self, path: str):
        """Set binary path for all components"""
        try:
            self.binary_path = path

            # Update all UI components
            if 'r2_widget' in self.ui_components:
                self.ui_components['r2_widget'].set_binary_path(path)

            if 'enhanced_dashboard' in self.ui_components:
                if hasattr(self.ui_components['enhanced_dashboard'], 'r2_widget'):
                    self.ui_components['enhanced_dashboard'].r2_widget.set_binary_path(path)

            # Emit signal
            self.binary_loaded.emit(path)

            self.logger.info(f"Binary path set: {path}")

        except Exception as e:
            self.logger.error(f"Failed to set binary path: {e}")

    def start_analysis(self, analysis_type: str, options: Dict[str, Any] = None):
        """Start radare2 analysis of specified type"""
        try:
            if not self.binary_path:
                QMessageBox.warning(
                    self.main_app,
                    "No Binary",
                    "Please select a binary file first"
                )
                return False

            # Use r2_widget to start analysis
            if 'r2_widget' in self.ui_components:
                self.ui_components['r2_widget']._start_analysis(analysis_type)

                # Add to analysis history
                self.analysis_history.append({
                    'type': analysis_type,
                    'binary': self.binary_path,
                    'timestamp': self._get_timestamp(),
                    'options': options or {}
                })

                # Emit signal
                self.analysis_started.emit(analysis_type)

                self.logger.info(f"Started {analysis_type} analysis")
                return True
            else:
                self.logger.error("R2 widget not available")
                return False

        except Exception as e:
            self.logger.error(f"Failed to start analysis: {e}")
            self.analysis_failed.emit(str(e))
            return False

    def show_configuration(self):
        """Show radare2 configuration dialog"""
        try:
            if 'config_dialog' in self.ui_components:
                dialog = self.ui_components['config_dialog']
                if dialog.exec_() == dialog.Accepted:
                    config = dialog.get_configuration()
                    self._apply_configuration(config)
                    self.logger.info("Configuration updated")

        except Exception as e:
            self.logger.error(f"Failed to show configuration: {e}")

    def _apply_configuration(self, config: Dict[str, Any]):
        """Apply configuration to all components"""
        try:
            # Store configuration
            self.analysis_config = config

            # Apply to r2_widget if available
            if 'r2_widget' in self.ui_components:
                self.ui_components['r2_widget'].analysis_config = config

            self.logger.info("Configuration applied to all components")

        except Exception as e:
            self.logger.error(f"Failed to apply configuration: {e}")

    def export_results(self, file_path: str = None) -> bool:
        """Export current analysis results"""
        try:
            if not self.current_results:
                QMessageBox.information(
                    self.main_app,
                    "No Results",
                    "No analysis results available to export"
                )
                return False

            # Use results viewer to export
            if 'results_viewer' in self.ui_components:
                self.ui_components['results_viewer'].results_data = self.current_results
                self.ui_components['results_viewer']._export_results()
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            return False

    def get_analysis_history(self) -> List[Dict[str, Any]]:
        """Get analysis history"""
        return self.analysis_history.copy()

    def get_current_results(self) -> Dict[str, Any]:
        """Get current analysis results"""
        return self.current_results.copy()

    def clear_results(self):
        """Clear current analysis results"""
        self.current_results = {}

        # Clear results viewer
        if 'results_viewer' in self.ui_components:
            self.ui_components['results_viewer'].results_data = {}

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

    # Signal handlers
    def _on_binary_loaded(self, path: str):
        """Handle binary loaded signal"""
        self.status_updated.emit(f"Binary loaded: {os.path.basename(path)}")

    def _on_analysis_started(self, analysis_type: str):
        """Handle analysis started signal"""
        self.status_updated.emit(f"Starting {analysis_type} analysis...")

    def _on_analysis_completed(self, results: Dict[str, Any]):
        """Handle analysis completed signal"""
        self.current_results = results
        self.status_updated.emit("Analysis completed successfully")

        # Update results viewer
        if 'results_viewer' in self.ui_components:
            self.ui_components['results_viewer'].display_results(results)

    def _on_analysis_failed(self, error: str):
        """Handle analysis failed signal"""
        self.status_updated.emit(f"Analysis failed: {error}")
        QMessageBox.critical(
            self.main_app,
            "Analysis Error",
            f"Analysis failed:\n{error}"
        )

    def cleanup(self):
        """Cleanup resources"""
        try:
            # Stop any running analysis
            if 'r2_widget' in self.ui_components:
                r2_widget = self.ui_components['r2_widget']
                if hasattr(r2_widget, 'current_worker') and r2_widget.current_worker:
                    if r2_widget.current_worker.isRunning():
                        r2_widget.current_worker.terminate()
                        r2_widget.current_worker.wait()

            # Clear references
            self.ui_components.clear()
            self.current_results.clear()
            self.analysis_history.clear()

            self.logger.info("R2UIManager cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")


def create_r2_ui_manager(main_app=None) -> R2UIManager:
    """Create and return configured R2UIManager instance"""
    return R2UIManager(main_app)


def integrate_radare2_ui_comprehensive(main_app) -> R2UIManager:
    """
    Comprehensive integration of all radare2 UI features with main application.
    
    This is the main entry point for integrating all radare2 functionality
    into an existing Intellicrack application.
    
    Args:
        main_app: The main Intellicrack application instance
        
    Returns:
        R2UIManager: Configured UI manager instance
    """
    try:
        # Create UI manager
        ui_manager = create_r2_ui_manager(main_app)

        # Integrate with application
        if ui_manager.integrate_with_application(main_app):
            logger.info("Comprehensive radare2 UI integration completed successfully")
            return ui_manager
        else:
            logger.error("Comprehensive radare2 UI integration failed")
            return None

    except Exception as e:
        logger.error(f"Failed to integrate radare2 UI comprehensively: {e}")
        return None


__all__ = [
    'R2UIManager',
    'create_r2_ui_manager',
    'integrate_radare2_ui_comprehensive'
]
