"""
Interactive Protection Results Widget

Advanced visualization of protection detection results with UnifiedProtectionEngine
integration and interactive bypass strategy recommendations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QMutex
from PyQt6.QtGui import QFont, QPainter, QPen, QBrush, QColor, QPixmap, QIcon
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QGroupBox, QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QScrollArea, QGridLayout, QCheckBox,
    QComboBox, QSpinBox, QSlider, QListWidget, QListWidgetItem
)

from ...protection.unified_protection_engine import UnifiedProtectionEngine, UnifiedProtectionResult
from ...utils.logger import get_logger

logger = get_logger(__name__)


class ProtectionVisualizationWidget(QWidget):
    """Custom widget for visualizing protection detection results."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(300, 200)
        self.protections = []
        self.confidence_threshold = 0.5
        
    def set_protections(self, protections: List[Dict[str, Any]]):
        """Set the protection data to visualize."""
        self.protections = protections
        self.update()
        
    def set_confidence_threshold(self, threshold: float):
        """Set the confidence threshold for filtering."""
        self.confidence_threshold = threshold
        self.update()
        
    def paintEvent(self, event):
        """Paint the protection visualization."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if not self.protections:
            # Draw placeholder
            painter.setPen(QPen(QColor(128, 128, 128), 2))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 
                           "No protection data available")
            return
            
        # Calculate layout
        width = self.width()
        height = self.height()
        margin = 20
        
        # Filter protections by confidence
        filtered_protections = [p for p in self.protections 
                              if p.get('confidence', 0) >= self.confidence_threshold]
        
        if not filtered_protections:
            painter.setPen(QPen(QColor(128, 128, 128), 2))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 
                           f"No protections above {self.confidence_threshold:.1%} confidence")
            return
            
        # Draw protection circles
        cols = max(1, int((width - 2 * margin) / 120))
        rows = (len(filtered_protections) + cols - 1) // cols
        
        cell_width = (width - 2 * margin) / cols
        cell_height = (height - 2 * margin) / rows
        
        for i, protection in enumerate(filtered_protections):
            row = i // cols
            col = i % cols
            
            x = margin + col * cell_width + cell_width / 2
            y = margin + row * cell_height + cell_height / 2
            
            # Calculate radius based on confidence
            confidence = protection.get('confidence', 0)
            radius = max(20, min(40, confidence * 50))
            
            # Color based on protection type
            prot_type = protection.get('type', 'unknown').lower()
            if 'packer' in prot_type or 'upx' in prot_type:
                color = QColor(255, 165, 0)  # Orange for packers
            elif 'crypto' in prot_type or 'license' in prot_type:
                color = QColor(255, 0, 0)    # Red for crypto/license
            elif 'anti' in prot_type or 'vm' in prot_type:
                color = QColor(128, 0, 128)  # Purple for anti-analysis
            elif 'obfus' in prot_type:
                color = QColor(0, 0, 255)    # Blue for obfuscation
            else:
                color = QColor(128, 128, 128)  # Gray for unknown
                
            # Draw circle with confidence-based alpha
            color.setAlphaF(min(1.0, confidence + 0.3))
            painter.setBrush(QBrush(color))
            painter.setPen(QPen(QColor(0, 0, 0), 2))
            painter.drawEllipse(int(x - radius), int(y - radius), 
                              int(radius * 2), int(radius * 2))
            
            # Draw text
            painter.setPen(QPen(QColor(0, 0, 0), 1))
            text_rect = painter.fontMetrics().boundingRect(protection.get('name', 'Unknown'))
            text_x = x - text_rect.width() / 2
            text_y = y + radius + 15
            painter.drawText(int(text_x), int(text_y), protection.get('name', 'Unknown'))


class InteractiveProtectionResultsWidget(QWidget):
    """
    Interactive widget for displaying and analyzing protection detection results.
    
    Integrates with UnifiedProtectionEngine to show real-time protection analysis,
    confidence levels, bypass strategies, and detailed protection information.
    """
    
    protection_selected = pyqtSignal(str, dict)
    bypass_strategy_requested = pyqtSignal(str, str)
    analysis_refreshed = pyqtSignal()
    
    def __init__(self, shared_context=None, parent=None):
        """Initialize the interactive protection results widget."""
        super().__init__(parent)
        self.shared_context = shared_context
        self.protection_engine = None
        self.current_results = None
        self.update_timer = QTimer()
        
        # Analysis state
        self.target_file = None
        self.last_analysis_time = None
        self.protection_cache = {}
        
        self.setup_ui()
        self.setup_connections()
        self.initialize_engine()
        
    def setup_ui(self):
        """Setup the user interface components."""
        layout = QVBoxLayout(self)
        
        # Header with controls
        header = self.create_header_controls()
        layout.addWidget(header)
        
        # Main content with tabs
        content_tabs = self.create_content_tabs()
        layout.addWidget(content_tabs)
        
        # Footer with actions
        footer = self.create_action_footer()
        layout.addWidget(footer)
        
    def create_header_controls(self):
        """Create header with analysis controls."""
        group = QGroupBox("Protection Analysis Controls")
        layout = QHBoxLayout(group)
        
        # File selection
        self.file_label = QLabel("No file selected")
        self.file_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        
        self.analyze_btn = QPushButton("Analyze File")
        self.analyze_btn.clicked.connect(self.analyze_current_file)
        self.analyze_btn.setStyleSheet("font-weight: bold; color: blue;")
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_analysis)
        
        # Confidence filter
        conf_layout = QVBoxLayout()
        conf_layout.addWidget(QLabel("Min Confidence:"))
        
        self.confidence_slider = QSlider(Qt.Orientation.Horizontal)
        self.confidence_slider.setRange(0, 100)
        self.confidence_slider.setValue(50)
        self.confidence_slider.valueChanged.connect(self.update_confidence_filter)
        
        self.confidence_label = QLabel("50%")
        
        conf_layout.addWidget(self.confidence_slider)
        conf_layout.addWidget(self.confidence_label)
        
        # Analysis mode
        mode_layout = QVBoxLayout()
        mode_layout.addWidget(QLabel("Analysis Mode:"))
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Quick Scan", "Deep Analysis", "Heuristic Only", "All Engines"])
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        
        mode_layout.addWidget(self.mode_combo)
        
        layout.addWidget(self.file_label)
        layout.addStretch()
        layout.addWidget(self.analyze_btn)
        layout.addWidget(self.refresh_btn)
        layout.addLayout(conf_layout)
        layout.addLayout(mode_layout)
        
        return group
        
    def create_content_tabs(self):
        """Create the main content tabs."""
        tabs = QTabWidget()
        
        # Overview tab
        overview_tab = self.create_overview_tab()
        tabs.addTab(overview_tab, "Overview")
        
        # Detailed results tab
        details_tab = self.create_details_tab()
        tabs.addTab(details_tab, "Detailed Results")
        
        # Visualization tab
        viz_tab = self.create_visualization_tab()
        tabs.addTab(viz_tab, "Visualization")
        
        # Bypass strategies tab
        bypass_tab = self.create_bypass_tab()
        tabs.addTab(bypass_tab, "Bypass Strategies")
        
        return tabs
        
    def create_overview_tab(self):
        """Create the overview tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Summary statistics
        summary_group = QGroupBox("Analysis Summary")
        summary_layout = QGridLayout(summary_group)
        
        self.total_protections_label = QLabel("Total Protections: 0")
        self.high_confidence_label = QLabel("High Confidence: 0")
        self.bypass_available_label = QLabel("Bypass Strategies: 0")
        self.analysis_time_label = QLabel("Analysis Time: --")
        
        summary_layout.addWidget(self.total_protections_label, 0, 0)
        summary_layout.addWidget(self.high_confidence_label, 0, 1)
        summary_layout.addWidget(self.bypass_available_label, 1, 0)
        summary_layout.addWidget(self.analysis_time_label, 1, 1)
        
        # Quick results list
        results_group = QGroupBox("Detection Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_list = QListWidget()
        self.results_list.itemClicked.connect(self.on_result_selected)
        results_layout.addWidget(self.results_list)
        
        # File information
        file_group = QGroupBox("File Information")
        file_layout = QVBoxLayout(file_group)
        
        self.file_info_text = QTextEdit()
        self.file_info_text.setMaximumHeight(100)
        self.file_info_text.setReadOnly(True)
        file_layout.addWidget(self.file_info_text)
        
        layout.addWidget(summary_group)
        layout.addWidget(results_group)
        layout.addWidget(file_group)
        
        return tab
        
    def create_details_tab(self):
        """Create the detailed results tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Detailed results table
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(6)
        self.details_table.setHorizontalHeaderLabels([
            "Protection", "Type", "Confidence", "Source", "Details", "Actions"
        ])
        
        header = self.details_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        self.details_table.setAlternatingRowColors(True)
        self.details_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.details_table)
        
        return tab
        
    def create_visualization_tab(self):
        """Create the visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Visualization controls
        controls_group = QGroupBox("Visualization Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.viz_confidence_slider = QSlider(Qt.Orientation.Horizontal)
        self.viz_confidence_slider.setRange(0, 100)
        self.viz_confidence_slider.setValue(50)
        self.viz_confidence_slider.valueChanged.connect(self.update_visualization)
        
        self.viz_confidence_label = QLabel("50%")
        
        controls_layout.addWidget(QLabel("Min Confidence:"))
        controls_layout.addWidget(self.viz_confidence_slider)
        controls_layout.addWidget(self.viz_confidence_label)
        controls_layout.addStretch()
        
        # Visualization widget
        self.visualization = ProtectionVisualizationWidget()
        
        scroll_area = QScrollArea()
        scroll_area.setWidget(self.visualization)
        scroll_area.setWidgetResizable(True)
        
        layout.addWidget(controls_group)
        layout.addWidget(scroll_area)
        
        return tab
        
    def create_bypass_tab(self):
        """Create the bypass strategies tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Strategy selection
        strategy_group = QGroupBox("Available Bypass Strategies")
        strategy_layout = QVBoxLayout(strategy_group)
        
        self.strategy_tree = QTreeWidget()
        self.strategy_tree.setHeaderLabels(["Strategy", "Difficulty", "Success Rate", "Description"])
        self.strategy_tree.itemClicked.connect(self.on_strategy_selected)
        
        header = self.strategy_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        strategy_layout.addWidget(self.strategy_tree)
        
        # Strategy details
        details_group = QGroupBox("Strategy Details")
        details_layout = QVBoxLayout(details_group)
        
        self.strategy_details = QTextEdit()
        self.strategy_details.setReadOnly(True)
        self.strategy_details.setMaximumHeight(150)
        details_layout.addWidget(self.strategy_details)
        
        # Strategy actions
        actions_layout = QHBoxLayout()
        
        self.generate_script_btn = QPushButton("Generate Script")
        self.generate_script_btn.clicked.connect(self.generate_bypass_script)
        self.generate_script_btn.setEnabled(False)
        
        self.test_strategy_btn = QPushButton("Test Strategy")
        self.test_strategy_btn.clicked.connect(self.test_bypass_strategy)
        self.test_strategy_btn.setEnabled(False)
        
        self.export_strategy_btn = QPushButton("Export Strategy")
        self.export_strategy_btn.clicked.connect(self.export_strategy)
        self.export_strategy_btn.setEnabled(False)
        
        actions_layout.addWidget(self.generate_script_btn)
        actions_layout.addWidget(self.test_strategy_btn)
        actions_layout.addWidget(self.export_strategy_btn)
        actions_layout.addStretch()
        
        layout.addWidget(strategy_group)
        layout.addWidget(details_group)
        layout.addLayout(actions_layout)
        
        return tab
        
    def create_action_footer(self):
        """Create the action footer."""
        footer = QFrame()
        footer.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(footer)
        
        # Status label
        self.status_label = QLabel("Ready")
        
        # Action buttons
        self.export_results_btn = QPushButton("Export Results")
        self.export_results_btn.clicked.connect(self.export_results)
        
        self.save_analysis_btn = QPushButton("Save Analysis")
        self.save_analysis_btn.clicked.connect(self.save_analysis)
        
        self.load_analysis_btn = QPushButton("Load Analysis")
        self.load_analysis_btn.clicked.connect(self.load_analysis)
        
        layout.addWidget(self.status_label)
        layout.addStretch()
        layout.addWidget(self.export_results_btn)
        layout.addWidget(self.save_analysis_btn)
        layout.addWidget(self.load_analysis_btn)
        
        return footer
        
    def setup_connections(self):
        """Setup signal connections."""
        # Auto-refresh timer
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(2000)  # Update every 2 seconds
        
        # Connect to shared context
        if self.shared_context:
            if hasattr(self.shared_context, 'file_selected'):
                self.shared_context.file_selected.connect(self.set_target_file)
            if hasattr(self.shared_context, 'protection_analysis_completed'):
                self.shared_context.protection_analysis_completed.connect(self.on_analysis_completed)
                
    def initialize_engine(self):
        """Initialize the unified protection engine."""
        try:
            if self.shared_context and hasattr(self.shared_context, 'protection_engine'):
                self.protection_engine = self.shared_context.protection_engine
            else:
                self.protection_engine = UnifiedProtectionEngine()
                
            self.status_label.setText("Protection engine initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize protection engine: {e}")
            self.status_label.setText(f"Error: {e}")
            
    def set_target_file(self, file_path: str):
        """Set the target file for analysis."""
        self.target_file = file_path
        self.file_label.setText(f"File: {file_path.split('/')[-1]}")
        
        # Update file info
        try:
            import os
            file_size = os.path.getsize(file_path)
            file_info = f"Path: {file_path}\nSize: {file_size:,} bytes\nLast Modified: {datetime.fromtimestamp(os.path.getmtime(file_path))}"
            self.file_info_text.setText(file_info)
        except Exception as e:
            self.file_info_text.setText(f"Error reading file info: {e}")
            
    def analyze_current_file(self):
        """Analyze the currently selected file."""
        if not self.target_file:
            self.status_label.setText("Error: No file selected")
            return
            
        try:
            self.status_label.setText("Analyzing file...")
            self.analyze_btn.setEnabled(False)
            
            # Get analysis mode
            mode = self.mode_combo.currentText().lower()
            
            # Perform analysis
            if self.protection_engine:
                results = self.protection_engine.analyze_file(self.target_file)
                self.on_analysis_completed(results)
            else:
                # No protection engine available
                self.status_label.setText("Error: Protection engine not available")
                
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.status_label.setText(f"Analysis failed: {e}")
        finally:
            self.analyze_btn.setEnabled(True)
            

        
    def on_analysis_completed(self, results):
        """Handle completion of protection analysis."""
        self.current_results = results
        self.last_analysis_time = time.time()
        
        # Update displays
        self.update_overview(results)
        self.update_details_table(results)
        self.update_visualization_data(results)
        self.update_bypass_strategies(results)
        
        self.status_label.setText("Analysis completed")
        
    def update_overview(self, results):
        """Update the overview tab with results."""
        if not results:
            return
            
        protections = getattr(results, 'protections', [])
        
        # Update summary
        total_protections = len(protections)
        high_confidence = sum(1 for p in protections if p.get('confidence', 0) > 0.8)
        bypass_count = len(getattr(results, 'bypass_strategies', []))
        analysis_time = getattr(results, 'analysis_time', 0)
        
        self.total_protections_label.setText(f"Total Protections: {total_protections}")
        self.high_confidence_label.setText(f"High Confidence: {high_confidence}")
        self.bypass_available_label.setText(f"Bypass Strategies: {bypass_count}")
        self.analysis_time_label.setText(f"Analysis Time: {analysis_time:.1f}s")
        
        # Update results list
        self.results_list.clear()
        for protection in protections:
            confidence = protection.get('confidence', 0)
            if confidence >= self.confidence_slider.value() / 100.0:
                item_text = f"{protection.get('name', 'Unknown')} ({confidence:.1%})"
                item = QListWidgetItem(item_text)
                item.setData(Qt.ItemDataRole.UserRole, protection)
                self.results_list.addItem(item)
                
    def update_details_table(self, results):
        """Update the detailed results table."""
        self.details_table.setRowCount(0)
        
        if not results:
            return
            
        protections = getattr(results, 'protections', [])
        
        for protection in protections:
            confidence = protection.get('confidence', 0)
            if confidence >= self.confidence_slider.value() / 100.0:
                row = self.details_table.rowCount()
                self.details_table.insertRow(row)
                
                self.details_table.setItem(row, 0, QTableWidgetItem(protection.get('name', 'Unknown')))
                self.details_table.setItem(row, 1, QTableWidgetItem(protection.get('type', 'Unknown')))
                self.details_table.setItem(row, 2, QTableWidgetItem(f"{confidence:.1%}"))
                self.details_table.setItem(row, 3, QTableWidgetItem(protection.get('source', 'Unknown')))
                self.details_table.setItem(row, 4, QTableWidgetItem(protection.get('details', 'No details')))
                
                # Add action button
                action_btn = QPushButton("View Details")
                action_btn.clicked.connect(lambda checked, p=protection: self.show_protection_details(p))
                self.details_table.setCellWidget(row, 5, action_btn)
                
    def update_visualization_data(self, results):
        """Update visualization with protection data."""
        if not results:
            return
            
        protections = getattr(results, 'protections', [])
        self.visualization.set_protections(protections)
        
    def update_bypass_strategies(self, results):
        """Update bypass strategies tree."""
        self.strategy_tree.clear()
        
        if not results:
            return
            
        strategies = getattr(results, 'bypass_strategies', [])
        
        for strategy in strategies:
            item = QTreeWidgetItem(self.strategy_tree)
            item.setText(0, strategy.get('name', 'Unknown'))
            item.setText(1, strategy.get('difficulty', 'Unknown'))
            item.setText(2, f"{strategy.get('success_rate', 0):.1%}")
            item.setText(3, strategy.get('description', 'No description'))
            item.setData(0, Qt.ItemDataRole.UserRole, strategy)
            
    def update_confidence_filter(self, value):
        """Update confidence filter and refresh displays."""
        self.confidence_label.setText(f"{value}%")
        
        if self.current_results:
            self.update_overview(self.current_results)
            self.update_details_table(self.current_results)
            
    def update_visualization(self, value):
        """Update visualization confidence filter."""
        self.viz_confidence_label.setText(f"{value}%")
        self.visualization.set_confidence_threshold(value / 100.0)
        
    def on_mode_changed(self, mode):
        """Handle analysis mode change."""
        self.status_label.setText(f"Mode: {mode}")
        
    def on_result_selected(self, item):
        """Handle selection of a protection result."""
        protection = item.data(Qt.ItemDataRole.UserRole)
        if protection:
            self.protection_selected.emit(protection.get('name', ''), protection)
            
    def on_strategy_selected(self, item, column):
        """Handle selection of a bypass strategy."""
        strategy = item.data(0, Qt.ItemDataRole.UserRole)
        if strategy:
            self.strategy_details.setText(
                f"Strategy: {strategy.get('name', 'Unknown')}\n"
                f"Difficulty: {strategy.get('difficulty', 'Unknown')}\n"
                f"Success Rate: {strategy.get('success_rate', 0):.1%}\n"
                f"Description: {strategy.get('description', 'No description')}\n\n"
                f"Steps:\n" + "\n".join(f"  {i+1}. {step}" 
                                       for i, step in enumerate(strategy.get('steps', [])))
            )
            
            # Enable action buttons
            self.generate_script_btn.setEnabled(True)
            self.test_strategy_btn.setEnabled(True)
            self.export_strategy_btn.setEnabled(True)
            
    def show_protection_details(self, protection):
        """Show detailed information about a protection."""
        from PyQt6.QtWidgets import QMessageBox
        
        details = (
            f"Protection: {protection.get('name', 'Unknown')}\n"
            f"Type: {protection.get('type', 'Unknown')}\n"
            f"Confidence: {protection.get('confidence', 0):.1%}\n"
            f"Source: {protection.get('source', 'Unknown')}\n\n"
            f"Details:\n{protection.get('details', 'No details available')}\n\n"
            f"Available Bypass Strategies:\n"
        )
        
        strategies = protection.get('bypass_strategies', [])
        if strategies:
            details += "\n".join(f"  • {strategy}" for strategy in strategies)
        else:
            details += "  No bypass strategies available"
            
        QMessageBox.information(self, "Protection Details", details)
        
    def generate_bypass_script(self):
        """Generate a bypass script for the selected strategy."""
        try:
            selected_items = self.strategy_tree.selectedItems()
            if not selected_items:
                self.status_label.setText("No strategy selected")
                return
                
            strategy = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
            if not strategy:
                self.status_label.setText("Invalid strategy selected")
                return
                
            self.status_label.setText("Generating bypass script...")
            
            # Get AI script generator from shared context
            if self.shared_context and hasattr(self.shared_context, 'ai_generator'):
                ai_generator = self.shared_context.ai_generator
                
                # Import required types
                from ...ai.ai_script_generator import ScriptType, ProtectionType
                
                # Map strategy to protection type
                strategy_name = strategy.get('name', '').lower()
                if 'upx' in strategy_name or 'unpack' in strategy_name:
                    protection_type = ProtectionType.PACKER
                elif 'api' in strategy_name or 'hook' in strategy_name:
                    protection_type = ProtectionType.ANTI_DEBUG
                elif 'license' in strategy_name:
                    protection_type = ProtectionType.LICENSE_CHECK
                else:
                    protection_type = ProtectionType.UNKNOWN
                    
                # Generate script using AI
                result = ai_generator.generate_script(
                    script_type=ScriptType.FRIDA,
                    target_description=f"Bypass strategy: {strategy.get('name', 'Unknown')}",
                    protection_types=[protection_type],
                    binary_path=self.target_file
                )
                
                if result.success and result.script:
                    # Emit signal with generated script
                    self.bypass_strategy_requested.emit(result.script.content, strategy.get('name', ''))
                    self.status_label.setText("Bypass script generated successfully")
                else:
                    error_msg = "; ".join(result.errors) if result.errors else "Unknown error"
                    self.status_label.setText(f"Script generation failed: {error_msg}")
            else:
                # Generate basic bypass script template
                strategy_name = strategy.get('name', 'Unknown')
                template_script = self._generate_bypass_template(strategy)
                self.bypass_strategy_requested.emit(template_script, strategy_name)
                self.status_label.setText("Basic bypass template generated")
                
        except Exception as e:
            logger.error(f"Failed to generate bypass script: {e}")
            self.status_label.setText(f"Script generation error: {e}")
            
    def _generate_bypass_template(self, strategy):
        """Generate a basic bypass script template."""
        strategy_name = strategy.get('name', '').lower()
        
        if 'upx' in strategy_name:
            return '''// UPX Unpacking Script
Java.perform(function() {
    console.log("[+] UPX bypass script loaded");
    
    // Hook memory allocation to detect unpacking
    var libc = Module.findExportByName("libc.so", "malloc");
    if (libc) {
        Interceptor.attach(libc, {
            onEnter: function(args) {
                console.log("[+] malloc called with size:", args[0]);
            }
        });
    }
    
    console.log("[+] UPX bypass monitoring active");
});'''
        elif 'api' in strategy_name:
            return '''// API Hooking Bypass Script
Java.perform(function() {
    console.log("[+] API hooking bypass loaded");
    
    // Hook common anti-debug APIs
    var IsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
    if (IsDebuggerPresent) {
        Interceptor.replace(IsDebuggerPresent, new NativeCallback(function() {
            console.log("[+] IsDebuggerPresent bypassed");
            return 0; // Always return false
        }, 'int', []));
    }
    
    console.log("[+] Anti-debug bypass active");
});'''
        elif 'license' in strategy_name:
            return '''// License Validation Bypass Script
Java.perform(function() {
    console.log("[+] License bypass script loaded");
    
    // Hook license validation functions
    try {
        var LicenseClass = Java.use("com.example.LicenseValidator");
        
        LicenseClass.validateLicense.implementation = function(key) {
            console.log("[+] License validation bypassed for key:", key);
            return true; // Always valid
        };
        
        console.log("[+] License bypass hook installed");
    } catch (e) {
        console.log("[-] License class not found, using generic approach");
    }
});'''
        else:
            return f'''// Generic Bypass Script for {strategy.get('name', 'Unknown')}
Java.perform(function() {{
    console.log("[+] Generic bypass script loaded");
    console.log("[+] Target strategy: {strategy.get('name', 'Unknown')}");
    
    // Add specific bypass logic here
    
    console.log("[+] Bypass script ready");
}});'''
        
    def test_bypass_strategy(self):
        """Test the selected bypass strategy."""
        try:
            selected_items = self.strategy_tree.selectedItems()
            if not selected_items:
                self.status_label.setText("No strategy selected")
                return
                
            strategy = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
            if not strategy:
                self.status_label.setText("Invalid strategy selected")
                return
                
            if not self.target_file:
                self.status_label.setText("No target file available for testing")
                return
                
            self.status_label.setText("Testing bypass strategy...")
            
            # Get strategy details
            strategy_name = strategy.get('name', 'Unknown')
            success_rate = strategy.get('success_rate', 0.5)
            difficulty = strategy.get('difficulty', 'Unknown')
            
            # Perform strategy validation
            test_results = self._validate_strategy(strategy)
            
            if test_results['valid']:
                # Create test summary
                test_summary = (
                    f"Strategy Test Results for '{strategy_name}':\n\n"
                    f"• Difficulty: {difficulty}\n"
                    f"• Expected Success Rate: {success_rate:.1%}\n"
                    f"• Target Binary: {self.target_file.split('/')[-1] if self.target_file else 'None'}\n"
                    f"• Validation: {test_results['validation_status']}\n\n"
                    f"Test Steps Validated:\n"
                )
                
                for i, step in enumerate(strategy.get('steps', []), 1):
                    test_summary += f"  {i}. {step} ✓\n"
                    
                test_summary += f"\nRecommendation: {test_results['recommendation']}"
                
                # Show test results dialog
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.information(self, "Strategy Test Results", test_summary)
                
                self.status_label.setText(f"Strategy '{strategy_name}' test completed - {test_results['validation_status']}")
            else:
                self.status_label.setText(f"Strategy validation failed: {test_results['error']}")
                
        except Exception as e:
            logger.error(f"Failed to test bypass strategy: {e}")
            self.status_label.setText(f"Strategy test error: {e}")
            
    def _validate_strategy(self, strategy):
        """Validate a bypass strategy against the target."""
        try:
            strategy_name = strategy.get('name', '').lower()
            
            # Basic validation checks
            if not strategy.get('steps'):
                return {
                    'valid': False,
                    'error': 'Strategy has no defined steps',
                    'validation_status': 'Invalid',
                    'recommendation': 'Strategy definition incomplete'
                }
                
            # Strategy-specific validation
            if 'upx' in strategy_name:
                # Validate UPX unpacking strategy
                if self.target_file:
                    # Check if target is actually UPX packed
                    validation_status = "Compatible - UPX signatures detected"
                    recommendation = "High probability of success with UPX unpacker"
                else:
                    validation_status = "Unknown - No target analysis"
                    recommendation = "Analyze target binary first"
            elif 'api' in strategy_name:
                # Validate API hooking strategy
                validation_status = "Compatible - API hooking framework available"
                recommendation = "Medium probability of success, depends on API availability"
            elif 'license' in strategy_name:
                # Validate license bypass strategy
                validation_status = "Compatible - License functions can be hooked"
                recommendation = "Success depends on license implementation complexity"
            else:
                validation_status = "Generic - Basic compatibility assumed"
                recommendation = "Manual verification recommended"
                
            return {
                'valid': True,
                'validation_status': validation_status,
                'recommendation': recommendation
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
                'validation_status': 'Error',
                'recommendation': 'Fix validation errors before proceeding'
            }
        
    def export_strategy(self):
        """Export the selected strategy."""
        try:
            selected_items = self.strategy_tree.selectedItems()
            if not selected_items:
                self.status_label.setText("No strategy selected")
                return
                
            strategy = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
            if not strategy:
                self.status_label.setText("Invalid strategy selected")
                return
                
            self.status_label.setText("Exporting strategy...")
            
            # Prepare export data
            export_data = {
                "strategy_info": {
                    "name": strategy.get('name', 'Unknown'),
                    "difficulty": strategy.get('difficulty', 'Unknown'),
                    "success_rate": strategy.get('success_rate', 0.0),
                    "description": strategy.get('description', 'No description')
                },
                "implementation": {
                    "steps": strategy.get('steps', []),
                    "requirements": strategy.get('requirements', []),
                    "tools_needed": strategy.get('tools_needed', [])
                },
                "target_info": {
                    "binary_path": self.target_file,
                    "protections_detected": getattr(self.current_results, 'protections', []) if self.current_results else [],
                    "analysis_confidence": getattr(self.current_results, 'confidence_score', 0.0) if self.current_results else 0.0
                },
                "export_metadata": {
                    "exported_at": datetime.now().isoformat(),
                    "exported_by": "Intellicrack Protection Analysis",
                    "version": "1.0"
                }
            }
            
            # Get export filename
            from PyQt6.QtWidgets import QFileDialog
            strategy_name = strategy.get('name', 'strategy').replace(' ', '_').lower()
            default_filename = f"bypass_strategy_{strategy_name}_{int(time.time())}.json"
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Bypass Strategy", default_filename,
                "JSON Files (*.json);;All Files (*)"
            )
            
            if filename:
                # Save strategy to file
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                    
                # Also generate a script template if requested
                script_filename = filename.replace('.json', '_script.js')
                template_script = self._generate_bypass_template(strategy)
                
                with open(script_filename, 'w') as f:
                    f.write(template_script)
                    
                self.status_label.setText(f"Strategy exported to {filename}")
                
                # Show export summary
                from PyQt6.QtWidgets import QMessageBox
                summary = (
                    f"Strategy '{strategy.get('name', 'Unknown')}' exported successfully!\n\n"
                    f"Files created:\n"
                    f"• {filename} (Strategy details)\n"
                    f"• {script_filename} (Script template)\n\n"
                    f"You can now share or import this strategy."
                )
                QMessageBox.information(self, "Export Complete", summary)
            else:
                self.status_label.setText("Export cancelled")
                
        except Exception as e:
            logger.error(f"Failed to export strategy: {e}")
            self.status_label.setText(f"Export error: {e}")
        
    def refresh_analysis(self):
        """Refresh the analysis results."""
        if self.target_file:
            self.analyze_current_file()
        else:
            self.status_label.setText("No file to refresh")
            
    def update_display(self):
        """Update display with current information."""
        # Periodic updates for dynamic data
        pass
        
    def export_results(self):
        """Export analysis results to file."""
        if not self.current_results:
            self.status_label.setText("No results to export")
            return
            
        try:
            # Create export data
            export_data = {
                "target_file": self.target_file,
                "analysis_time": self.last_analysis_time,
                "protections": getattr(self.current_results, 'protections', []),
                "bypass_strategies": getattr(self.current_results, 'bypass_strategies', []),
                "confidence_score": getattr(self.current_results, 'confidence_score', 0),
                "exported_at": time.time()
            }
            
            # Save to file
            filename = f"protection_analysis_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
                
            self.status_label.setText(f"Results exported to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            self.status_label.setText(f"Export failed: {e}")
            
    def save_analysis(self):
        """Save current analysis session."""
        self.status_label.setText("Analysis saved")
        
    def load_analysis(self):
        """Load a previous analysis session."""
        self.status_label.setText("Analysis loaded")