"""
Behavioral Analysis Tab

This tab integrates the behavioral protection detection system into the
main Intellicrack user interface, providing access to all behavioral
analysis features.

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

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QTimer, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QFileDialog,
    QGroupBox, QMessageBox, QSplitter, QTabWidget
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

# Import behavioral analysis components
try:
    from ..widgets.behavioral_analysis_widget import BehavioralAnalysisWidget
    from ...core.analysis.behavioral_protection_system import (
        get_behavioral_protection_system,
        BehavioralProtectionSystem,
        AnalysisMode,
        SystemState
    )
    BEHAVIORAL_COMPONENTS_AVAILABLE = True
except ImportError as e:
    BEHAVIORAL_COMPONENTS_AVAILABLE = False
    print(f"Behavioral analysis components not available: {e}")

from ...utils.logger import get_logger


class BehavioralAnalysisTab(QWidget):
    """Main tab for behavioral analysis functionality."""
    
    analysis_started = pyqtSignal()
    analysis_stopped = pyqtSignal()
    detection_occurred = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self.behavioral_system = None
        self.system_initialized = False
        
        # Initialize behavioral protection system
        self._initialize_behavioral_system()
        
        self.init_ui()
        self.setup_connections()
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_system_status)
        self.status_timer.start(5000)  # Update every 5 seconds
    
    def _initialize_behavioral_system(self):
        """Initialize the behavioral protection system."""
        if not BEHAVIORAL_COMPONENTS_AVAILABLE:
            self.logger.warning("Behavioral analysis components not available")
            return
        
        try:
            # Get global behavioral protection system instance
            self.behavioral_system = get_behavioral_protection_system()
            
            # Register callbacks
            self.behavioral_system.register_detection_callback(self._on_detection_result)
            self.behavioral_system.register_state_change_callback(self._on_state_change)
            
            self.system_initialized = True
            self.logger.info("Behavioral protection system initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize behavioral system: {e}")
            self.system_initialized = False
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Header section
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Behavioral Protection Analysis")
        title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # System status indicator
        self.system_status_label = QLabel("System: Initializing...")
        self.system_status_label.setStyleSheet("QLabel { padding: 4px; border: 1px solid gray; }")
        header_layout.addWidget(self.system_status_label)
        
        layout.addLayout(header_layout)
        
        # Main content area
        if BEHAVIORAL_COMPONENTS_AVAILABLE and self.system_initialized:
            # Create main behavioral analysis widget
            self.analysis_widget = BehavioralAnalysisWidget()
            layout.addWidget(self.analysis_widget)
            
            # Action buttons
            button_layout = QHBoxLayout()
            
            self.export_button = QPushButton("Export Results")
            self.export_button.clicked.connect(self.export_analysis_results)
            button_layout.addWidget(self.export_button)
            
            self.report_button = QPushButton("Generate Report")
            self.report_button.clicked.connect(self.generate_comprehensive_report)
            button_layout.addWidget(self.report_button)
            
            button_layout.addStretch()
            
            self.refresh_button = QPushButton("Refresh Status")
            self.refresh_button.clicked.connect(self.update_system_status)
            button_layout.addWidget(self.refresh_button)
            
            layout.addLayout(button_layout)
        else:
            # Show unavailable message
            self._create_unavailable_ui(layout)
    
    def _create_unavailable_ui(self, layout):
        """Create UI for when behavioral analysis is unavailable."""
        # Main message
        message_group = QGroupBox("Behavioral Analysis Unavailable")
        message_layout = QVBoxLayout(message_group)
        
        if not BEHAVIORAL_COMPONENTS_AVAILABLE:
            message = (
                "Behavioral analysis components are not available.\n\n"
                "This may be due to:\n"
                "• Missing dependencies (scikit-learn, scipy)\n"
                "• Component initialization errors\n"
                "• System configuration issues\n\n"
                "Please check the logs for more information."
            )
        else:
            message = (
                "Behavioral protection system failed to initialize.\n\n"
                "Please check the logs and try restarting the application."
            )
        
        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_layout.addWidget(message_label)
        
        # Retry button
        retry_button = QPushButton("Retry Initialization")
        retry_button.clicked.connect(self.retry_initialization)
        message_layout.addWidget(retry_button)
        
        layout.addWidget(message_group)
        layout.addStretch()
    
    def setup_connections(self):
        """Setup signal connections."""
        if hasattr(self, 'analysis_widget'):
            # Connect analysis widget signals to tab signals
            # This allows other components to listen to tab-level events
            pass
    
    def retry_initialization(self):
        """Retry behavioral system initialization."""
        try:
            self.logger.info("Retrying behavioral system initialization...")
            
            # Clear existing widgets
            for i in reversed(range(self.layout().count())):
                child = self.layout().itemAt(i).widget()
                if child:
                    child.setParent(None)
            
            # Reinitialize
            self._initialize_behavioral_system()
            self.init_ui()
            self.setup_connections()
            
            if self.system_initialized:
                QMessageBox.information(
                    self,
                    "Initialization Successful",
                    "Behavioral analysis system has been successfully initialized."
                )
            else:
                QMessageBox.warning(
                    self,
                    "Initialization Failed",
                    "Failed to initialize behavioral analysis system. Check logs for details."
                )
                
        except Exception as e:
            self.logger.error(f"Retry initialization failed: {e}")
            QMessageBox.critical(
                self,
                "Initialization Error",
                f"An error occurred during initialization:\n{str(e)}"
            )
    
    def update_system_status(self):
        """Update system status display."""
        try:
            if not self.behavioral_system:
                self.system_status_label.setText("System: Not Available")
                self.system_status_label.setStyleSheet(
                    "QLabel { padding: 4px; border: 1px solid gray; background-color: lightgray; }"
                )
                return
            
            # Get system status
            status = self.behavioral_system.get_system_status()
            system_state = status.get('system_state', 'unknown')
            
            # Update status label
            self.system_status_label.setText(f"System: {system_state.title()}")
            
            # Color code based on state
            if system_state == 'ready':
                color = "lightgreen"
            elif system_state == 'analyzing':
                color = "lightblue"
            elif system_state == 'error':
                color = "lightcoral"
            elif system_state == 'initializing':
                color = "yellow"
            else:
                color = "lightgray"
            
            self.system_status_label.setStyleSheet(
                f"QLabel {{ padding: 4px; border: 1px solid gray; background-color: {color}; }}"
            )
            
        except Exception as e:
            self.logger.error(f"Error updating system status: {e}")
            self.system_status_label.setText("System: Error")
            self.system_status_label.setStyleSheet(
                "QLabel { padding: 4px; border: 1px solid gray; background-color: lightcoral; }"
            )
    
    def export_analysis_results(self):
        """Export analysis results to file."""
        try:
            if not self.behavioral_system:
                QMessageBox.warning(self, "Export Error", "Behavioral system not available")
                return
            
            # Get export file path
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Analysis Results",
                f"behavioral_analysis_{int(time.time())}.json",
                "JSON Files (*.json);;All Files (*)"
            )
            
            if not file_path:
                return
            
            # Export results
            if hasattr(self, 'analysis_widget'):
                success = self.analysis_widget.export_results(Path(file_path))
            else:
                # Fallback: export system status
                status = self.behavioral_system.get_system_status()
                with open(file_path, 'w') as f:
                    json.dump(status, f, indent=2, default=str)
                success = True
            
            if success:
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Analysis results exported to:\n{file_path}"
                )
            else:
                QMessageBox.warning(
                    self,
                    "Export Failed",
                    "Failed to export analysis results. Check logs for details."
                )
                
        except Exception as e:
            self.logger.error(f"Export error: {e}")
            QMessageBox.critical(
                self,
                "Export Error",
                f"An error occurred during export:\n{str(e)}"
            )
    
    def generate_comprehensive_report(self):
        """Generate and display comprehensive analysis report."""
        try:
            if not self.behavioral_system:
                QMessageBox.warning(self, "Report Error", "Behavioral system not available")
                return
            
            # Get comprehensive report
            if hasattr(self, 'analysis_widget'):
                report = self.analysis_widget.get_analysis_report()
            else:
                report = self.behavioral_system.get_system_status()
            
            if not report:
                QMessageBox.information(self, "No Data", "No analysis data available for report")
                return
            
            # Create report dialog
            report_dialog = QMessageBox(self)
            report_dialog.setWindowTitle("Behavioral Analysis Report")
            report_dialog.setIcon(QMessageBox.Icon.Information)
            
            # Format report summary
            summary_lines = []
            
            if 'behavioral_analysis' in report:
                behavioral = report['behavioral_analysis']
                if 'summary' in behavioral:
                    summary = behavioral['summary']
                    summary_lines.extend([
                        f"Detected Family: {summary.get('detected_family', 'unknown')}",
                        f"Confidence: {summary.get('confidence', 0):.2f}",
                        f"Detection Count: {summary.get('detection_count', 0)}",
                        f"Patterns Analyzed: {summary.get('patterns_analyzed', 0)}"
                    ])
            
            if 'system_metrics' in report:
                metrics = report['system_metrics']
                summary_lines.extend([
                    "",
                    "System Metrics:",
                    f"Total Sessions: {metrics.get('total_sessions', 0)}",
                    f"Total Detections: {metrics.get('total_detections', 0)}",
                    f"Uptime: {metrics.get('uptime', 0):.1f} seconds"
                ])
            
            report_text = '\n'.join(summary_lines) if summary_lines else "No analysis data available"
            
            report_dialog.setText("Behavioral Analysis Report Summary")
            report_dialog.setDetailedText(json.dumps(report, indent=2, default=str))
            report_dialog.setInformativeText(report_text)
            
            # Add export button
            export_button = report_dialog.addButton("Export Full Report", QMessageBox.ButtonRole.ActionRole)
            report_dialog.addButton(QMessageBox.StandardButton.Ok)
            
            result = report_dialog.exec()
            
            # Handle export if requested
            if report_dialog.clickedButton() == export_button:
                file_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Export Full Report",
                    f"behavioral_analysis_report_{int(time.time())}.json",
                    "JSON Files (*.json);;All Files (*)"
                )
                
                if file_path:
                    with open(file_path, 'w') as f:
                        json.dump(report, f, indent=2, default=str)
                    
                    QMessageBox.information(
                        self,
                        "Export Successful",
                        f"Full report exported to:\n{file_path}"
                    )
            
        except Exception as e:
            self.logger.error(f"Report generation error: {e}")
            QMessageBox.critical(
                self,
                "Report Error",
                f"An error occurred while generating the report:\n{str(e)}"
            )
    
    @pyqtSlot(object)
    def _on_detection_result(self, result):
        """Handle detection results from behavioral system."""
        try:
            self.detection_occurred.emit(result)
            self.logger.info(f"Detection result received: {result.family.value}")
            
        except Exception as e:
            self.logger.error(f"Error handling detection result: {e}")
    
    @pyqtSlot(object)
    def _on_state_change(self, new_state):
        """Handle system state changes."""
        try:
            if new_state == SystemState.ANALYZING:
                self.analysis_started.emit()
            elif new_state == SystemState.READY:
                self.analysis_stopped.emit()
            
            # Update status display
            self.update_system_status()
            
        except Exception as e:
            self.logger.error(f"Error handling state change: {e}")
    
    def start_behavioral_analysis(self, target_binary: Optional[Path] = None,
                                target_process: Optional[int] = None):
        """Start behavioral analysis programmatically."""
        try:
            if not self.behavioral_system:
                raise RuntimeError("Behavioral system not available")
            
            session_id = self.behavioral_system.start_analysis(
                target_binary=target_binary,
                target_process=target_process,
                mode=AnalysisMode.ACTIVE_ANALYSIS
            )
            
            self.logger.info(f"Started behavioral analysis session: {session_id}")
            return session_id
            
        except Exception as e:
            self.logger.error(f"Failed to start behavioral analysis: {e}")
            raise
    
    def stop_behavioral_analysis(self):
        """Stop behavioral analysis programmatically."""
        try:
            if not self.behavioral_system:
                return False
            
            success = self.behavioral_system.stop_analysis()
            
            if success:
                self.logger.info("Stopped behavioral analysis")
            else:
                self.logger.warning("Failed to stop behavioral analysis")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error stopping behavioral analysis: {e}")
            return False
    
    def get_current_analysis_status(self) -> Dict[str, Any]:
        """Get current analysis status."""
        try:
            if not self.behavioral_system:
                return {'available': False, 'error': 'System not available'}
            
            return self.behavioral_system.get_system_status()
            
        except Exception as e:
            self.logger.error(f"Error getting analysis status: {e}")
            return {'available': False, 'error': str(e)}
    
    def closeEvent(self, event):
        """Handle tab close event."""
        try:
            # Stop any running analysis
            if self.behavioral_system and hasattr(self.behavioral_system, 'current_session'):
                if self.behavioral_system.current_session:
                    self.stop_behavioral_analysis()
            
            # Stop status timer
            if hasattr(self, 'status_timer'):
                self.status_timer.stop()
            
            event.accept()
            
        except Exception as e:
            self.logger.error(f"Error during tab close: {e}")
            event.accept()
    
    def is_analysis_available(self) -> bool:
        """Check if behavioral analysis is available."""
        return BEHAVIORAL_COMPONENTS_AVAILABLE and self.system_initialized
    
    def get_analysis_capabilities(self) -> Dict[str, bool]:
        """Get analysis capabilities."""
        if not self.is_analysis_available():
            return {
                'behavioral_analysis': False,
                'real_time_detection': False,
                'ml_classification': False,
                'signature_matching': False,
                'temporal_analysis': False,
                'multi_source_integration': False
            }
        
        try:
            status = self.behavioral_system.get_system_status()
            return status.get('capabilities', {})
            
        except Exception as e:
            self.logger.error(f"Error getting capabilities: {e}")
            return {'error': str(e)}