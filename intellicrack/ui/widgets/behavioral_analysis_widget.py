"""
Behavioral Analysis Widget

This widget provides a comprehensive interface for behavior-based protection
detection, including real-time monitoring, pattern visualization, and
detection results display.

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

from PyQt6.QtCore import QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QTextEdit, QTableWidget, QTableWidgetItem,
    QGroupBox, QProgressBar, QComboBox, QSpinBox, QCheckBox,
    QTabWidget, QSplitter, QScrollArea, QFrame
)
from PyQt6.QtGui import QFont, QColor, QPalette
from PyQt6.QtCore import Qt

# Import analysis components
try:
    from ...core.analysis.behavior_based_protection_detector import (
        BehaviorBasedProtectionDetector,
        DetectionResult,
        ProtectionFamily,
        DetectionConfidence
    )
    from ...core.analysis.behavioral_integration_manager import (
        BehavioralIntegrationManager,
        IntegrationStatus,
        ComponentStatus
    )
    ANALYSIS_COMPONENTS_AVAILABLE = True
except ImportError:
    ANALYSIS_COMPONENTS_AVAILABLE = False

from ...utils.logger import get_logger


class BehavioralAnalysisWorker(QThread):
    """Worker thread for behavioral analysis operations."""
    
    detection_result = pyqtSignal(object)  # DetectionResult
    status_update = pyqtSignal(dict)  # Status dictionary
    error_occurred = pyqtSignal(str)  # Error message
    
    def __init__(self, integration_manager: Optional[Any] = None):
        super().__init__()
        self.integration_manager = integration_manager
        self.is_running = False
        self.logger = get_logger(__name__)
    
    def start_analysis(self, target_binary: Optional[Path] = None,
                      target_process: Optional[int] = None):
        """Start behavioral analysis."""
        self.target_binary = target_binary
        self.target_process = target_process
        self.is_running = True
        self.start()
    
    def stop_analysis(self):
        """Stop behavioral analysis."""
        self.is_running = False
        if self.integration_manager:
            self.integration_manager.stop_behavioral_analysis()
    
    def run(self):
        """Main worker thread execution."""
        try:
            if not self.integration_manager:
                self.error_occurred.emit("Integration manager not available")
                return
            
            # Start behavioral analysis
            success = self.integration_manager.start_behavioral_analysis(
                self.target_binary, self.target_process
            )
            
            if not success:
                self.error_occurred.emit("Failed to start behavioral analysis")
                return
            
            # Register callbacks
            self.integration_manager.register_detection_callback(
                self._on_detection_result
            )
            
            # Monitor status and emit updates
            while self.is_running:
                try:
                    status = self.integration_manager.get_integration_status()
                    self.status_update.emit(status)
                    
                    self.msleep(1000)  # Update every second
                    
                except Exception as e:
                    self.logger.error(f"Status monitoring error: {e}")
                    self.msleep(5000)  # Wait longer on error
        
        except Exception as e:
            self.error_occurred.emit(f"Analysis worker error: {str(e)}")
    
    def _on_detection_result(self, result):
        """Handle detection results from integration manager."""
        self.detection_result.emit(result)


class DetectionResultsWidget(QWidget):
    """Widget for displaying detection results."""
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self.detection_history = []
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        self.results_label = QLabel("Protection Detection Results")
        self.results_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header_layout.addWidget(self.results_label)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        header_layout.addWidget(self.clear_button)
        
        layout.addLayout(header_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Timestamp", "Protection Family", "Confidence", "Evidence Count", "Source"
        ])
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.itemSelectionChanged.connect(self.on_selection_changed)
        
        layout.addWidget(self.results_table)
        
        # Details panel
        details_group = QGroupBox("Detection Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setMaximumHeight(150)
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        layout.addWidget(details_group)
    
    def add_detection_result(self, result):
        """Add a new detection result to the display."""
        try:
            # Add to history
            detection_data = {
                'timestamp': time.time(),
                'result': result,
                'formatted_time': time.strftime('%H:%M:%S')
            }
            self.detection_history.append(detection_data)
            
            # Add to table
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            # Timestamp
            time_item = QTableWidgetItem(detection_data['formatted_time'])
            self.results_table.setItem(row, 0, time_item)
            
            # Protection family
            family_item = QTableWidgetItem(result.family.value)
            self.results_table.setItem(row, 1, family_item)
            
            # Confidence
            confidence_item = QTableWidgetItem(f"{result.confidence:.2f}")
            # Color code confidence
            if result.confidence >= 0.8:
                confidence_item.setBackground(QColor(144, 238, 144))  # Light green
            elif result.confidence >= 0.5:
                confidence_item.setBackground(QColor(255, 255, 144))  # Light yellow
            else:
                confidence_item.setBackground(QColor(255, 182, 193))  # Light red
            
            self.results_table.setItem(row, 2, confidence_item)
            
            # Evidence count
            evidence_item = QTableWidgetItem(str(len(result.evidence)))
            self.results_table.setItem(row, 3, evidence_item)
            
            # Source
            source = "ML" if result.analysis_metadata.get('ml_classification') else "Signature"
            source_item = QTableWidgetItem(source)
            self.results_table.setItem(row, 4, source_item)
            
            # Auto-scroll to latest result
            self.results_table.scrollToBottom()
            
            # Update results count
            self.results_label.setText(f"Protection Detection Results ({len(self.detection_history)})")
            
        except Exception as e:
            self.logger.error(f"Error adding detection result: {e}")
    
    def on_selection_changed(self):
        """Handle selection change in results table."""
        try:
            current_row = self.results_table.currentRow()
            if current_row >= 0 and current_row < len(self.detection_history):
                detection_data = self.detection_history[current_row]
                result = detection_data['result']
                
                # Format details
                details = []
                details.append(f"Protection Family: {result.family.value}")
                details.append(f"Confidence: {result.confidence:.2f}")
                details.append(f"Evidence Patterns: {len(result.evidence)}")
                
                if result.signature_matches:
                    details.append(f"Signature Matches: {', '.join(result.signature_matches)}")
                
                if result.classification_features:
                    details.append("\nClassification Features:")
                    for key, value in result.classification_features.items():
                        details.append(f"  {key}: {value}")
                
                if result.analysis_metadata:
                    details.append("\nAnalysis Metadata:")
                    for key, value in result.analysis_metadata.items():
                        details.append(f"  {key}: {value}")
                
                self.details_text.setPlainText('\n'.join(details))
            else:
                self.details_text.clear()
                
        except Exception as e:
            self.logger.error(f"Error handling selection change: {e}")
    
    def clear_results(self):
        """Clear all detection results."""
        self.detection_history.clear()
        self.results_table.setRowCount(0)
        self.details_text.clear()
        self.results_label.setText("Protection Detection Results")


class ComponentStatusWidget(QWidget):
    """Widget for displaying component integration status."""
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Header
        self.status_label = QLabel("Component Integration Status")
        self.status_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(self.status_label)
        
        # Status table
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(4)
        self.status_table.setHorizontalHeaderLabels([
            "Component", "Status", "Last Update", "Data Count"
        ])
        self.status_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.status_table)
        
        # Overall health indicator
        health_layout = QHBoxLayout()
        
        self.health_label = QLabel("Overall Health:")
        health_layout.addWidget(self.health_label)
        
        self.health_indicator = QLabel("Unknown")
        self.health_indicator.setStyleSheet("QLabel { padding: 4px; border: 1px solid gray; }")
        health_layout.addWidget(self.health_indicator)
        
        health_layout.addStretch()
        layout.addLayout(health_layout)
    
    def update_status(self, status_data: Dict[str, Any]):
        """Update component status display."""
        try:
            # Update overall health
            overall_health = status_data.get('overall_health', 'unknown')
            self.health_indicator.setText(overall_health.title())
            
            # Color code health indicator
            if overall_health == 'healthy':
                self.health_indicator.setStyleSheet(
                    "QLabel { padding: 4px; border: 1px solid gray; background-color: lightgreen; }"
                )
            elif overall_health == 'degraded':
                self.health_indicator.setStyleSheet(
                    "QLabel { padding: 4px; border: 1px solid gray; background-color: yellow; }"
                )
            elif overall_health == 'critical':
                self.health_indicator.setStyleSheet(
                    "QLabel { padding: 4px; border: 1px solid gray; background-color: lightcoral; }"
                )
            else:
                self.health_indicator.setStyleSheet(
                    "QLabel { padding: 4px; border: 1px solid gray; background-color: lightgray; }"
                )
            
            # Update component table
            components = status_data.get('components', {})
            self.status_table.setRowCount(len(components))
            
            for row, (component_name, component_status) in enumerate(components.items()):
                # Component name
                name_item = QTableWidgetItem(component_name)
                self.status_table.setItem(row, 0, name_item)
                
                # Status
                status_item = QTableWidgetItem(component_status.title())
                
                # Color code status
                if component_status == 'running':
                    status_item.setBackground(QColor(144, 238, 144))  # Light green
                elif component_status == 'ready':
                    status_item.setBackground(QColor(173, 216, 230))  # Light blue
                elif component_status == 'error':
                    status_item.setBackground(QColor(255, 182, 193))  # Light red
                else:
                    status_item.setBackground(QColor(211, 211, 211))  # Light gray
                
                self.status_table.setItem(row, 1, status_item)
                
                # Last update (placeholder)
                update_item = QTableWidgetItem("Just now")
                self.status_table.setItem(row, 2, update_item)
                
                # Data count (placeholder)
                count_item = QTableWidgetItem("0")
                self.status_table.setItem(row, 3, count_item)
            
        except Exception as e:
            self.logger.error(f"Error updating status: {e}")


class AnalysisControlWidget(QWidget):
    """Widget for controlling behavioral analysis."""
    
    analysis_started = pyqtSignal(object, object)  # target_binary, target_process
    analysis_stopped = pyqtSignal()
    settings_changed = pyqtSignal(dict)  # Configuration changes
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self.is_analyzing = False
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Analysis")
        self.start_button.setStyleSheet("QPushButton { background-color: lightgreen; }")
        self.start_button.clicked.connect(self.start_analysis)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Analysis")
        self.stop_button.setStyleSheet("QPushButton { background-color: lightcoral; }")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_analysis)
        button_layout.addWidget(self.stop_button)
        
        layout.addLayout(button_layout)
        
        # Settings group
        settings_group = QGroupBox("Analysis Settings")
        settings_layout = QGridLayout(settings_group)
        
        # Analysis window
        settings_layout.addWidget(QLabel("Analysis Window (seconds):"), 0, 0)
        self.window_spinbox = QSpinBox()
        self.window_spinbox.setRange(10, 300)
        self.window_spinbox.setValue(30)
        self.window_spinbox.valueChanged.connect(self.on_settings_changed)
        settings_layout.addWidget(self.window_spinbox, 0, 1)
        
        # Minimum confidence
        settings_layout.addWidget(QLabel("Minimum Confidence:"), 1, 0)
        self.confidence_spinbox = QSpinBox()
        self.confidence_spinbox.setRange(10, 99)
        self.confidence_spinbox.setValue(30)
        self.confidence_spinbox.setSuffix("%")
        self.confidence_spinbox.valueChanged.connect(self.on_settings_changed)
        settings_layout.addWidget(self.confidence_spinbox, 1, 1)
        
        # Real-time analysis
        self.realtime_checkbox = QCheckBox("Enable Real-time Analysis")
        self.realtime_checkbox.setChecked(True)
        self.realtime_checkbox.toggled.connect(self.on_settings_changed)
        settings_layout.addWidget(self.realtime_checkbox, 2, 0, 1, 2)
        
        # ML classification
        self.ml_checkbox = QCheckBox("Enable ML Classification")
        self.ml_checkbox.setChecked(True)
        self.ml_checkbox.toggled.connect(self.on_settings_changed)
        settings_layout.addWidget(self.ml_checkbox, 3, 0, 1, 2)
        
        layout.addWidget(settings_group)
        
        # Status indicator
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)
        
        layout.addLayout(status_layout)
        
        layout.addStretch()
    
    def start_analysis(self):
        """Start behavioral analysis."""
        try:
            if self.is_analyzing:
                return
            
            self.is_analyzing = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText("Status: Starting Analysis...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            
            # Emit signal with current settings
            target_binary = None  # Could be configured in settings
            target_process = None  # Could be configured in settings
            
            self.analysis_started.emit(target_binary, target_process)
            
        except Exception as e:
            self.logger.error(f"Error starting analysis: {e}")
            self.reset_ui_state()
    
    def stop_analysis(self):
        """Stop behavioral analysis."""
        try:
            if not self.is_analyzing:
                return
            
            self.analysis_stopped.emit()
            self.reset_ui_state()
            
        except Exception as e:
            self.logger.error(f"Error stopping analysis: {e}")
    
    def reset_ui_state(self):
        """Reset UI to initial state."""
        self.is_analyzing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Status: Ready")
        self.progress_bar.setVisible(False)
    
    def update_status(self, status: str):
        """Update status display."""
        self.status_label.setText(f"Status: {status}")
    
    def on_settings_changed(self):
        """Handle settings changes."""
        settings = {
            'analysis_window': self.window_spinbox.value(),
            'min_confidence': self.confidence_spinbox.value() / 100.0,
            'enable_realtime': self.realtime_checkbox.isChecked(),
            'enable_ml': self.ml_checkbox.isChecked()
        }
        
        self.settings_changed.emit(settings)


class BehavioralAnalysisWidget(QWidget):
    """Main widget for behavioral analysis interface."""
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self.integration_manager = None
        self.analysis_worker = None
        
        # Initialize integration manager if components are available
        if ANALYSIS_COMPONENTS_AVAILABLE:
            try:
                self.integration_manager = BehavioralIntegrationManager()
                self.logger.info("Behavioral analysis components initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize analysis components: {e}")
        else:
            self.logger.warning("Analysis components not available")
        
        self.init_ui()
        self.setup_connections()
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status_display)
        self.status_timer.start(2000)  # Update every 2 seconds
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Controls and status
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Analysis controls
        self.control_widget = AnalysisControlWidget()
        left_layout.addWidget(self.control_widget)
        
        # Component status
        self.status_widget = ComponentStatusWidget()
        left_layout.addWidget(self.status_widget)
        
        main_splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Detection results
        self.results_widget = DetectionResultsWidget()
        right_layout.addWidget(self.results_widget)
        
        main_splitter.addWidget(right_panel)
        
        # Set splitter proportions
        main_splitter.setSizes([300, 700])
        
        layout.addWidget(main_splitter)
        
        # Status bar
        status_layout = QHBoxLayout()
        
        self.overall_status_label = QLabel("System Status: Initializing...")
        status_layout.addWidget(self.overall_status_label)
        
        status_layout.addStretch()
        
        self.component_availability_label = QLabel(
            "Components Available" if ANALYSIS_COMPONENTS_AVAILABLE else "Components Not Available"
        )
        self.component_availability_label.setStyleSheet(
            "QLabel { color: green; }" if ANALYSIS_COMPONENTS_AVAILABLE else "QLabel { color: red; }"
        )
        status_layout.addWidget(self.component_availability_label)
        
        layout.addLayout(status_layout)
    
    def setup_connections(self):
        """Setup signal connections."""
        # Control widget connections
        self.control_widget.analysis_started.connect(self.on_analysis_started)
        self.control_widget.analysis_stopped.connect(self.on_analysis_stopped)
        self.control_widget.settings_changed.connect(self.on_settings_changed)
    
    @pyqtSlot(object, object)
    def on_analysis_started(self, target_binary, target_process):
        """Handle analysis start request."""
        try:
            if not self.integration_manager:
                self.control_widget.update_status("Error: Components not available")
                self.control_widget.reset_ui_state()
                return
            
            # Create and start analysis worker
            self.analysis_worker = BehavioralAnalysisWorker(self.integration_manager)
            self.analysis_worker.detection_result.connect(self.on_detection_result)
            self.analysis_worker.status_update.connect(self.on_status_update)
            self.analysis_worker.error_occurred.connect(self.on_analysis_error)
            
            self.analysis_worker.start_analysis(target_binary, target_process)
            
            self.control_widget.update_status("Running")
            self.overall_status_label.setText("System Status: Analyzing...")
            
        except Exception as e:
            self.logger.error(f"Error starting analysis: {e}")
            self.control_widget.update_status(f"Error: {str(e)}")
            self.control_widget.reset_ui_state()
    
    @pyqtSlot()
    def on_analysis_stopped(self):
        """Handle analysis stop request."""
        try:
            if self.analysis_worker:
                self.analysis_worker.stop_analysis()
                self.analysis_worker.wait(5000)  # Wait up to 5 seconds
                self.analysis_worker = None
            
            self.control_widget.update_status("Stopped")
            self.overall_status_label.setText("System Status: Ready")
            
        except Exception as e:
            self.logger.error(f"Error stopping analysis: {e}")
    
    @pyqtSlot(dict)
    def on_settings_changed(self, settings):
        """Handle settings changes."""
        try:
            if self.integration_manager:
                # Update behavior detector configuration
                behavior_config = {
                    'analysis_window': settings.get('analysis_window', 30),
                    'min_confidence': settings.get('min_confidence', 0.3),
                    'enable_realtime': settings.get('enable_realtime', True),
                    'enable_ml': settings.get('enable_ml', True)
                }
                
                # Apply configuration to integration manager
                # This would need to be implemented in the integration manager
                self.logger.info(f"Settings updated: {behavior_config}")
            
        except Exception as e:
            self.logger.error(f"Error updating settings: {e}")
    
    @pyqtSlot(object)
    def on_detection_result(self, result):
        """Handle detection results from analysis worker."""
        try:
            self.results_widget.add_detection_result(result)
            
            # Update overall status with latest detection
            confidence_text = f"{result.confidence:.0%}"
            self.overall_status_label.setText(
                f"System Status: Detected {result.family.value} ({confidence_text})"
            )
            
        except Exception as e:
            self.logger.error(f"Error handling detection result: {e}")
    
    @pyqtSlot(dict)
    def on_status_update(self, status_data):
        """Handle status updates from analysis worker."""
        try:
            self.status_widget.update_status(status_data)
            
        except Exception as e:
            self.logger.error(f"Error handling status update: {e}")
    
    @pyqtSlot(str)
    def on_analysis_error(self, error_message):
        """Handle analysis errors."""
        self.logger.error(f"Analysis error: {error_message}")
        self.control_widget.update_status(f"Error: {error_message}")
        self.control_widget.reset_ui_state()
        self.overall_status_label.setText("System Status: Error")
    
    def update_status_display(self):
        """Update status display periodically."""
        try:
            if self.integration_manager and not self.analysis_worker:
                # Update status when not actively analyzing
                status = self.integration_manager.get_integration_status()
                self.status_widget.update_status(status)
                
                if status.get('overall_health') == 'healthy':
                    self.overall_status_label.setText("System Status: Ready")
                else:
                    health = status.get('overall_health', 'unknown')
                    self.overall_status_label.setText(f"System Status: {health.title()}")
            
        except Exception as e:
            self.logger.debug(f"Status update error: {e}")
    
    def get_analysis_report(self) -> Optional[Dict[str, Any]]:
        """Get comprehensive analysis report."""
        try:
            if self.integration_manager:
                return self.integration_manager.get_comprehensive_report()
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting analysis report: {e}")
            return None
    
    def export_results(self, export_path: Path) -> bool:
        """Export analysis results and reports."""
        try:
            if self.integration_manager:
                return self.integration_manager.export_integration_data(export_path)
            return False
            
        except Exception as e:
            self.logger.error(f"Error exporting results: {e}")
            return False