"""
Analysis Progress Dashboard Widget

Real-time visualization of analysis progress across multiple engines with
live backend integration and detailed progress tracking.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import time
from datetime import datetime
from typing import Dict, List, Optional, Any

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QMutex
from PyQt6.QtGui import QFont, QPainter, QPen, QBrush, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QGroupBox, QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame
)

from ...core.analysis.analysis_orchestrator import AnalysisOrchestrator
from ...utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisProgressDashboard(QWidget):
    """
    Real-time analysis progress dashboard with live backend integration.
    
    Displays progress from AnalysisOrchestrator and various analysis engines
    with detailed metrics, timing information, and visual progress indicators.
    """
    
    progress_updated = pyqtSignal(str, float)
    analysis_completed = pyqtSignal(str, dict)
    engine_status_changed = pyqtSignal(str, str)
    
    def __init__(self, shared_context=None, parent=None):
        """Initialize the analysis progress dashboard."""
        super().__init__(parent)
        self.shared_context = shared_context
        self.analysis_orchestrator = None
        self.update_timer = QTimer()
        self.mutex = QMutex()
        
        # Progress tracking
        self.analysis_engines = {}
        self.current_analysis = None
        self.start_time = None
        self.progress_history = []
        
        self.setup_ui()
        self.setup_connections()
        self.initialize_orchestrator()
        
    def setup_ui(self):
        """Setup the user interface components."""
        layout = QVBoxLayout(self)
        
        # Header with overall progress
        header_group = self.create_header_section()
        layout.addWidget(header_group)
        
        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Engine status
        left_panel = self.create_engine_status_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Details and logs
        right_panel = self.create_details_panel()
        splitter.addWidget(right_panel)
        
        splitter.setStretchFactor(0, 40)
        splitter.setStretchFactor(1, 60)
        
        layout.addWidget(splitter)
        
        # Footer with controls
        footer = self.create_control_footer()
        layout.addWidget(footer)
        
    def create_header_section(self):
        """Create the header section with overall progress."""
        group = QGroupBox("Analysis Progress Overview")
        layout = QVBoxLayout(group)
        
        # Overall progress bar
        self.overall_progress = QProgressBar()
        self.overall_progress.setRange(0, 100)
        self.overall_progress.setValue(0)
        self.overall_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
                font-weight: bold;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
        """)
        
        # Status labels
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("Status: Ready")
        self.status_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        
        self.elapsed_label = QLabel("Elapsed: 00:00:00")
        self.elapsed_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.eta_label = QLabel("ETA: --:--:--")
        self.eta_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.elapsed_label)
        status_layout.addWidget(self.eta_label)
        
        layout.addWidget(self.overall_progress)
        layout.addLayout(status_layout)
        
        return group
        
    def create_engine_status_panel(self):
        """Create the engine status panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Engine status tree
        engine_group = QGroupBox("Analysis Engines")
        engine_layout = QVBoxLayout(engine_group)
        
        self.engine_tree = QTreeWidget()
        self.engine_tree.setHeaderLabels(["Engine", "Status", "Progress", "Time"])
        self.engine_tree.setAlternatingRowColors(True)
        
        # Resize columns
        header = self.engine_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        engine_layout.addWidget(self.engine_tree)
        
        # Engine statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(150)
        self.stats_text.setReadOnly(True)
        self.stats_text.setFont(QFont("Consolas", 9))
        self.stats_text.setStyleSheet("background-color: #f5f5f5;")
        
        stats_layout.addWidget(self.stats_text)
        
        layout.addWidget(engine_group)
        layout.addWidget(stats_group)
        
        return panel
        
    def create_details_panel(self):
        """Create the details and logging panel."""
        panel = QTabWidget()
        
        # Progress details tab
        details_tab = QWidget()
        details_layout = QVBoxLayout(details_tab)
        
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(4)
        self.details_table.setHorizontalHeaderLabels(["Timestamp", "Engine", "Event", "Details"])
        
        header = self.details_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        details_layout.addWidget(self.details_table)
        
        # Live log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #666666;
            }
        """)
        
        log_layout.addWidget(self.log_text)
        
        # Performance metrics tab
        metrics_tab = QWidget()
        metrics_layout = QVBoxLayout(metrics_tab)
        
        self.metrics_table = QTableWidget()
        self.metrics_table.setColumnCount(3)
        self.metrics_table.setHorizontalHeaderLabels(["Metric", "Current", "Average"])
        
        metrics_layout.addWidget(self.metrics_table)
        
        panel.addTab(details_tab, "Progress Details")
        panel.addTab(log_tab, "Live Log")
        panel.addTab(metrics_tab, "Performance")
        
        return panel
        
    def create_control_footer(self):
        """Create the control footer with action buttons."""
        footer = QFrame()
        footer.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(footer)
        
        # Control buttons
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.clicked.connect(self.pause_analysis)
        self.pause_btn.setEnabled(False)
        
        self.resume_btn = QPushButton("Resume")
        self.resume_btn.clicked.connect(self.resume_analysis)
        self.resume_btn.setEnabled(False)
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_analysis)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("color: red; font-weight: bold;")
        
        self.clear_btn = QPushButton("Clear Log")
        self.clear_btn.clicked.connect(self.clear_log)
        
        self.export_btn = QPushButton("Export Progress")
        self.export_btn.clicked.connect(self.export_progress)
        
        layout.addWidget(self.pause_btn)
        layout.addWidget(self.resume_btn)
        layout.addWidget(self.stop_btn)
        layout.addStretch()
        layout.addWidget(self.clear_btn)
        layout.addWidget(self.export_btn)
        
        return footer
        
    def setup_connections(self):
        """Setup signal connections and timers."""
        # Update timer for real-time progress
        self.update_timer.timeout.connect(self.update_progress_display)
        self.update_timer.start(500)  # Update every 500ms
        
        # Connect to shared context signals if available
        if self.shared_context:
            context = self.shared_context
            if hasattr(context, 'analysis_progress_updated'):
                context.analysis_progress_updated.connect(self.on_progress_updated)
            if hasattr(context, 'analysis_engine_status_changed'):
                context.analysis_engine_status_changed.connect(self.on_engine_status_changed)
                
    def initialize_orchestrator(self):
        """Initialize the analysis orchestrator."""
        try:
            if self.shared_context and hasattr(self.shared_context, 'analysis_orchestrator'):
                self.analysis_orchestrator = self.shared_context.analysis_orchestrator
            else:
                # Create new orchestrator if not available
                self.analysis_orchestrator = AnalysisOrchestrator()
                
            # Initialize engine tracking
            self.initialize_engine_tracking()
            
            self.log_message("Analysis orchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize analysis orchestrator: {e}")
            self.log_message(f"Error: Failed to initialize orchestrator - {e}")
            
    def initialize_engine_tracking(self):
        """Initialize tracking for various analysis engines."""
        engines = [
            ("Binary Analyzer", "static"),
            ("Dynamic Analyzer", "dynamic"),
            ("Entropy Analyzer", "entropy"),
            ("Ghidra Decompiler", "decompiler"),
            ("Radare2 Integration", "disassembler"),
            ("Protection Detector", "protection"),
            ("Vulnerability Scanner", "vulnerability"),
            ("YARA Pattern Engine", "patterns"),
            ("Obfuscation Analyzer", "obfuscation"),
            ("Multi-Format Analyzer", "format")
        ]
        
        # Clear existing items
        self.engine_tree.clear()
        
        for engine_name, engine_type in engines:
            item = QTreeWidgetItem(self.engine_tree)
            item.setText(0, engine_name)
            item.setText(1, "Ready")
            item.setText(2, "0%")
            item.setText(3, "00:00:00")
            
            # Store engine info
            self.analysis_engines[engine_name] = {
                "type": engine_type,
                "status": "ready",
                "progress": 0.0,
                "start_time": None,
                "item": item
            }
            
    def start_analysis(self, binary_path: str, analysis_config: Dict[str, Any] = None):
        """Start a new analysis with progress tracking."""
        try:
            if not binary_path:
                self.log_message("Error: No binary path provided")
                return
                
            self.current_analysis = binary_path
            self.start_time = time.time()
            
            # Reset progress
            self.overall_progress.setValue(0)
            self.status_label.setText("Status: Starting Analysis...")
            
            # Enable controls
            self.pause_btn.setEnabled(True)
            self.stop_btn.setEnabled(True)
            
            # Reset engines
            for engine_name, engine_info in self.analysis_engines.items():
                engine_info["status"] = "waiting"
                engine_info["progress"] = 0.0
                engine_info["start_time"] = None
                engine_info["item"].setText(1, "Waiting")
                engine_info["item"].setText(2, "0%")
                
            # Start orchestrator if available
            if self.analysis_orchestrator:
                config = analysis_config or {}
                self.analysis_orchestrator.start_analysis(binary_path, config)
            else:
                # No analysis orchestrator available
                self.log_message("Analysis orchestrator not available")
                
            self.log_message(f"Started analysis of: {binary_path}")
            
        except Exception as e:
            logger.error(f"Failed to start analysis: {e}")
            self.log_message(f"Error starting analysis: {e}")
            

            
    def update_progress_display(self):
        """Update the progress display with current information."""
        try:
            if not self.current_analysis:
                return
                
            # Calculate overall progress
            total_progress = sum(info["progress"] for info in self.analysis_engines.values())
            overall_progress = total_progress / len(self.analysis_engines)
            self.overall_progress.setValue(int(overall_progress))
            
            # Update elapsed time
            if self.start_time:
                elapsed = time.time() - self.start_time
                self.elapsed_label.setText(f"Elapsed: {self.format_time(elapsed)}")
                
                # Calculate ETA
                if overall_progress > 5:  # Only show ETA after 5% progress
                    eta_seconds = (elapsed / overall_progress) * (100 - overall_progress)
                    self.eta_label.setText(f"ETA: {self.format_time(eta_seconds)}")
                    
            # Update statistics
            self.update_statistics()
            
            # Simulate progress for demo engines
            self.update_simulation_progress()
            
        except Exception as e:
            logger.error(f"Error updating progress display: {e}")
            
    def update_simulation_progress(self):
        """Update simulated progress for demonstration."""
        for engine_name, engine_info in self.analysis_engines.items():
            if engine_info["status"] == "running" and engine_info["progress"] < 100:
                # Simulate progress increase
                progress_increment = 0.5 + (hash(engine_name) % 10) / 10.0
                engine_info["progress"] = min(100, engine_info["progress"] + progress_increment)
                
                # Update display
                engine_info["item"].setText(2, f"{engine_info['progress']:.1f}%")
                
                # Mark as completed if at 100%
                if engine_info["progress"] >= 100:
                    engine_info["status"] = "completed"
                    engine_info["item"].setText(1, "Completed")
                    self.log_message(f"Completed {engine_name}")
                    
    def update_statistics(self):
        """Update the statistics display."""
        stats = []
        
        # Engine counts
        total_engines = len(self.analysis_engines)
        running_engines = sum(1 for info in self.analysis_engines.values() 
                            if info["status"] == "running")
        completed_engines = sum(1 for info in self.analysis_engines.values() 
                              if info["status"] == "completed")
        
        stats.append(f"Total Engines: {total_engines}")
        stats.append(f"Running: {running_engines}")
        stats.append(f"Completed: {completed_engines}")
        
        # Performance metrics
        if self.start_time:
            elapsed = time.time() - self.start_time
            overall_progress = sum(info["progress"] for info in self.analysis_engines.values()) / total_engines
            
            if overall_progress > 0:
                rate = overall_progress / elapsed
                stats.append(f"Progress Rate: {rate:.2f}%/sec")
                
        self.stats_text.setText("\n".join(stats))
        
    def on_progress_updated(self, engine_name: str, progress: float):
        """Handle progress updates from the orchestrator."""
        if engine_name in self.analysis_engines:
            engine_info = self.analysis_engines[engine_name]
            engine_info["progress"] = progress
            engine_info["item"].setText(2, f"{progress:.1f}%")
            
            # Add to details table
            self.add_progress_detail(engine_name, "Progress Update", f"{progress:.1f}%")
            
    def on_engine_status_changed(self, engine_name: str, status: str):
        """Handle engine status changes."""
        if engine_name in self.analysis_engines:
            engine_info = self.analysis_engines[engine_name]
            engine_info["status"] = status
            engine_info["item"].setText(1, status.capitalize())
            
            if status == "running" and not engine_info["start_time"]:
                engine_info["start_time"] = time.time()
                
            self.log_message(f"{engine_name}: {status}")
            self.add_progress_detail(engine_name, "Status Change", status)
            
    def add_progress_detail(self, engine: str, event: str, details: str):
        """Add a detail entry to the progress table."""
        row = self.details_table.rowCount()
        self.details_table.insertRow(row)
        
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        self.details_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.details_table.setItem(row, 1, QTableWidgetItem(engine))
        self.details_table.setItem(row, 2, QTableWidgetItem(event))
        self.details_table.setItem(row, 3, QTableWidgetItem(details))
        
        # Auto-scroll to bottom
        self.details_table.scrollToBottom()
        
    def log_message(self, message: str):
        """Add a message to the log display."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        self.log_text.append(formatted_message)
        
        # Limit log size
        if self.log_text.document().blockCount() > 1000:
            cursor = self.log_text.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.select(cursor.SelectionType.BlockUnderCursor)
            cursor.deleteChar()
            
    def pause_analysis(self):
        """Pause the current analysis."""
        if self.analysis_orchestrator:
            self.analysis_orchestrator.pause_analysis()
            
        self.status_label.setText("Status: Paused")
        self.pause_btn.setEnabled(False)
        self.resume_btn.setEnabled(True)
        self.log_message("Analysis paused")
        
    def resume_analysis(self):
        """Resume the paused analysis."""
        if self.analysis_orchestrator:
            self.analysis_orchestrator.resume_analysis()
            
        self.status_label.setText("Status: Running")
        self.pause_btn.setEnabled(True)
        self.resume_btn.setEnabled(False)
        self.log_message("Analysis resumed")
        
    def stop_analysis(self):
        """Stop the current analysis."""
        if self.analysis_orchestrator:
            self.analysis_orchestrator.stop_analysis()
            
        self.status_label.setText("Status: Stopped")
        self.pause_btn.setEnabled(False)
        self.resume_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        
        # Reset engine states
        for engine_info in self.analysis_engines.values():
            if engine_info["status"] != "completed":
                engine_info["status"] = "stopped"
                engine_info["item"].setText(1, "Stopped")
                
        self.log_message("Analysis stopped")
        
    def clear_log(self):
        """Clear the log display."""
        self.log_text.clear()
        self.details_table.setRowCount(0)
        
    def export_progress(self):
        """Export progress data to file."""
        try:
            progress_data = {
                "analysis_target": self.current_analysis,
                "start_time": self.start_time,
                "engines": {name: {
                    "type": info["type"],
                    "status": info["status"],
                    "progress": info["progress"],
                    "start_time": info["start_time"]
                } for name, info in self.analysis_engines.items()},
                "overall_progress": self.overall_progress.value(),
                "export_time": time.time()
            }
            
            # Save to file (simplified for demo)
            import json
            filename = f"analysis_progress_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(progress_data, f, indent=2, default=str)
                
            self.log_message(f"Progress exported to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export progress: {e}")
            self.log_message(f"Error exporting progress: {e}")
            
    def format_time(self, seconds: float) -> str:
        """Format seconds into HH:MM:SS format."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        
    def get_analysis_status(self) -> Dict[str, Any]:
        """Get current analysis status for external access."""
        return {
            "current_analysis": self.current_analysis,
            "overall_progress": self.overall_progress.value(),
            "engines": {name: {
                "status": info["status"],
                "progress": info["progress"]
            } for name, info in self.analysis_engines.items()},
            "elapsed_time": time.time() - self.start_time if self.start_time else 0
        }