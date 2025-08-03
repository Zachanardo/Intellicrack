"""
Real-time Visualization Panel

Dynamic visualization of binary analysis with live backend integration,
real-time data updates, and interactive analysis displays.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import math
import random
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QRectF, QPointF
from PyQt6.QtGui import (
    QFont, QPainter, QPen, QBrush, QColor, QPixmap, QPolygonF,
    QPainterPath, QLinearGradient, QRadialGradient
)
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QGroupBox, QTabWidget, QSlider, QPushButton, QCheckBox,
    QComboBox, QSpinBox, QFrame, QSplitter, QScrollArea,
    QGridLayout, QTextEdit, QTableWidget, QTableWidgetItem
)

from ...core.analysis.analysis_orchestrator import AnalysisOrchestrator
from ...utils.logger import get_logger

logger = get_logger(__name__)


class EntropyVisualizationWidget(QWidget):
    """Widget for visualizing entropy analysis in real-time."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 200)
        self.entropy_data = []
        self.max_points = 500
        self.highlight_regions = []
        
    def add_entropy_point(self, offset: int, entropy: float):
        """Add a new entropy data point."""
        self.entropy_data.append((offset, entropy))
        if len(self.entropy_data) > self.max_points:
            self.entropy_data.pop(0)
        self.update()
        
    def set_entropy_data(self, data: List[Tuple[int, float]]):
        """Set the complete entropy dataset."""
        self.entropy_data = data[-self.max_points:] if data else []
        self.update()
        
    def add_highlight_region(self, start_offset: int, end_offset: int, color: QColor, label: str):
        """Add a highlighted region to the visualization."""
        self.highlight_regions.append({
            'start': start_offset,
            'end': end_offset,
            'color': color,
            'label': label
        })
        self.update()
        
    def clear_highlights(self):
        """Clear all highlight regions."""
        self.highlight_regions.clear()
        self.update()
        
    def paintEvent(self, event):
        """Paint the entropy visualization."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if not self.entropy_data:
            painter.setPen(QPen(QColor(128, 128, 128), 2))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                           "No entropy data available")
            return
            
        # Calculate dimensions
        width = self.width() - 60
        height = self.height() - 40
        x_offset = 30
        y_offset = 20
        
        # Draw background grid
        painter.setPen(QPen(QColor(240, 240, 240), 1))
        for i in range(0, 11):
            y = y_offset + (height * i / 10)
            painter.drawLine(x_offset, y, x_offset + width, y)
            
        for i in range(0, 11):
            x = x_offset + (width * i / 10)
            painter.drawLine(x, y_offset, x, y_offset + height)
            
        # Draw highlight regions first
        for region in self.highlight_regions:
            if self.entropy_data:
                min_offset = min(point[0] for point in self.entropy_data)
                max_offset = max(point[0] for point in self.entropy_data)
                offset_range = max_offset - min_offset
                
                if offset_range > 0:
                    start_x = x_offset + ((region['start'] - min_offset) / offset_range) * width
                    end_x = x_offset + ((region['end'] - min_offset) / offset_range) * width
                    
                    # Draw highlighted rectangle
                    highlight_color = QColor(region['color'])
                    highlight_color.setAlpha(100)
                    painter.fillRect(int(start_x), y_offset, int(end_x - start_x), height, highlight_color)
                    
                    # Draw label
                    painter.setPen(QPen(region['color'], 2))
                    painter.drawText(int(start_x + 5), y_offset + 15, region['label'])
                    
        # Draw entropy curve
        if len(self.entropy_data) > 1:
            path = QPainterPath()
            
            # Calculate scaling
            min_offset = min(point[0] for point in self.entropy_data)
            max_offset = max(point[0] for point in self.entropy_data)
            offset_range = max_offset - min_offset
            
            # Start path
            first_point = self.entropy_data[0]
            if offset_range > 0:
                x = x_offset + ((first_point[0] - min_offset) / offset_range) * width
            else:
                x = x_offset
            y = y_offset + height - (first_point[1] * height)
            path.moveTo(x, y)
            
            # Add points to path
            for offset, entropy in self.entropy_data[1:]:
                if offset_range > 0:
                    x = x_offset + ((offset - min_offset) / offset_range) * width
                else:
                    x = x_offset
                y = y_offset + height - (entropy * height)
                path.lineTo(x, y)
                
            # Draw the curve
            painter.setPen(QPen(QColor(0, 120, 200), 2))
            painter.drawPath(path)
            
            # Fill under curve with gradient
            fill_path = QPainterPath(path)
            fill_path.lineTo(x_offset + width, y_offset + height)
            fill_path.lineTo(x_offset, y_offset + height)
            fill_path.closeSubpath()
            
            gradient = QLinearGradient(0, y_offset, 0, y_offset + height)
            gradient.setColorAt(0, QColor(0, 120, 200, 100))
            gradient.setColorAt(1, QColor(0, 120, 200, 20))
            painter.fillPath(fill_path, QBrush(gradient))
            
        # Draw axes labels
        painter.setPen(QPen(QColor(0, 0, 0), 1))
        painter.drawText(5, y_offset + height / 2, "Entropy")
        painter.drawText(x_offset + width / 2, y_offset + height + 35, "File Offset")
        
        # Draw entropy scale
        for i in range(0, 11):
            y = y_offset + height - (height * i / 10)
            entropy_value = i / 10.0
            painter.drawText(5, y + 5, f"{entropy_value:.1f}")


class CallGraphVisualizationWidget(QWidget):
    """Widget for visualizing function call graphs."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 300)
        self.functions = {}
        self.call_relationships = []
        self.selected_function = None
        
    def add_function(self, address: int, name: str, size: int, call_count: int = 0):
        """Add a function to the call graph."""
        self.functions[address] = {
            'name': name,
            'size': size,
            'call_count': call_count,
            'position': self.calculate_position(address),
            'color': self.get_function_color(call_count)
        }
        self.update()
        
    def add_call_relationship(self, caller: int, callee: int):
        """Add a call relationship between functions."""
        if caller in self.functions and callee in self.functions:
            self.call_relationships.append((caller, callee))
            self.update()
            
    def calculate_position(self, address: int) -> Tuple[float, float]:
        """Calculate position for a function based on its address."""
        # Use address to create pseudo-random but consistent positioning
        x = (address * 0.618033988749) % 1.0  # Golden ratio for better distribution
        y = (address * 0.314159265359) % 1.0  # Pi for y distribution
        return (x, y)
        
    def get_function_color(self, call_count: int) -> QColor:
        """Get color for function based on call count."""
        if call_count == 0:
            return QColor(200, 200, 200)  # Gray for uncalled
        elif call_count < 5:
            return QColor(100, 200, 100)  # Green for low calls
        elif call_count < 20:
            return QColor(200, 200, 100)  # Yellow for medium calls
        else:
            return QColor(200, 100, 100)  # Red for high calls
            
    def paintEvent(self, event):
        """Paint the call graph visualization."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if not self.functions:
            painter.setPen(QPen(QColor(128, 128, 128), 2))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                           "No function data available")
            return
            
        width = self.width() - 40
        height = self.height() - 40
        x_offset = 20
        y_offset = 20
        
        # Draw call relationships first (so they appear under nodes)
        painter.setPen(QPen(QColor(100, 100, 100), 1))
        for caller, callee in self.call_relationships:
            if caller in self.functions and callee in self.functions:
                caller_pos = self.functions[caller]['position']
                callee_pos = self.functions[callee]['position']
                
                x1 = x_offset + caller_pos[0] * width
                y1 = y_offset + caller_pos[1] * height
                x2 = x_offset + callee_pos[0] * width
                y2 = y_offset + callee_pos[1] * height
                
                # Draw arrow
                painter.drawLine(int(x1), int(y1), int(x2), int(y2))
                
                # Draw arrowhead
                angle = math.atan2(y2 - y1, x2 - x1)
                arrowhead_length = 8
                arrowhead_angle = 0.5
                
                arrowhead = QPolygonF([
                    QPointF(x2, y2),
                    QPointF(x2 - arrowhead_length * math.cos(angle - arrowhead_angle),
                           y2 - arrowhead_length * math.sin(angle - arrowhead_angle)),
                    QPointF(x2 - arrowhead_length * math.cos(angle + arrowhead_angle),
                           y2 - arrowhead_length * math.sin(angle + arrowhead_angle))
                ])
                painter.drawPolygon(arrowhead)
                
        # Draw function nodes
        for address, func in self.functions.items():
            pos = func['position']
            x = x_offset + pos[0] * width
            y = y_offset + pos[1] * height
            
            # Calculate node size based on function size
            base_radius = 8
            size_factor = min(3.0, math.log10(max(1, func['size'])))
            radius = base_radius + size_factor * 2
            
            # Draw node
            painter.setBrush(QBrush(func['color']))
            if address == self.selected_function:
                painter.setPen(QPen(QColor(255, 0, 0), 3))  # Red border for selected
            else:
                painter.setPen(QPen(QColor(0, 0, 0), 1))
                
            painter.drawEllipse(int(x - radius), int(y - radius), 
                              int(radius * 2), int(radius * 2))
            
            # Draw function name (abbreviated if too long)
            name = func['name']
            if len(name) > 12:
                name = name[:9] + "..."
                
            painter.setPen(QPen(QColor(0, 0, 0), 1))
            text_rect = painter.fontMetrics().boundingRect(name)
            text_x = x - text_rect.width() / 2
            text_y = y + radius + 15
            painter.drawText(int(text_x), int(text_y), name)
            
    def mousePressEvent(self, event):
        """Handle mouse press for function selection."""
        if event.button() == Qt.MouseButton.LeftButton:
            width = self.width() - 40
            height = self.height() - 40
            x_offset = 20
            y_offset = 20
            
            click_x = event.position().x()
            click_y = event.position().y()
            
            # Find clicked function
            for address, func in self.functions.items():
                pos = func['position']
                x = x_offset + pos[0] * width
                y = y_offset + pos[1] * height
                
                distance = math.sqrt((click_x - x) ** 2 + (click_y - y) ** 2)
                if distance <= 15:  # Click tolerance
                    self.selected_function = address
                    self.update()
                    break


class RealTimeVisualizationPanel(QWidget):
    """
    Real-time visualization panel for dynamic binary analysis.
    
    Provides live visualization of analysis data including entropy analysis,
    function call graphs, memory usage, and execution flow with backend integration.
    """
    
    visualization_updated = pyqtSignal(str, dict)
    analysis_point_selected = pyqtSignal(str, int)
    
    def __init__(self, shared_context=None, parent=None):
        """Initialize the real-time visualization panel."""
        super().__init__(parent)
        self.shared_context = shared_context
        self.analysis_orchestrator = None
        self.update_timer = QTimer()
        
        # Visualization state
        self.current_binary = None
        self.visualization_data = {}
        self.is_live_mode = True
        self.update_interval = 1000  # 1 second
        
        self.setup_ui()
        self.setup_connections()
        self.initialize_backend()
        
    def setup_ui(self):
        """Setup the user interface components."""
        layout = QVBoxLayout(self)
        
        # Control header
        header = self.create_control_header()
        layout.addWidget(header)
        
        # Main visualization tabs
        viz_tabs = self.create_visualization_tabs()
        layout.addWidget(viz_tabs)
        
        # Status and metrics footer
        footer = self.create_metrics_footer()
        layout.addWidget(footer)
        
    def create_control_header(self):
        """Create the visualization control header."""
        group = QGroupBox("Visualization Controls")
        layout = QHBoxLayout(group)
        
        # Live mode toggle
        self.live_mode_checkbox = QCheckBox("Live Mode")
        self.live_mode_checkbox.setChecked(True)
        self.live_mode_checkbox.toggled.connect(self.toggle_live_mode)
        
        # Update interval control
        interval_layout = QVBoxLayout()
        interval_layout.addWidget(QLabel("Update Interval:"))
        
        self.interval_slider = QSlider(Qt.Orientation.Horizontal)
        self.interval_slider.setRange(100, 5000)  # 0.1s to 5s
        self.interval_slider.setValue(1000)
        self.interval_slider.valueChanged.connect(self.update_interval_changed)
        
        self.interval_label = QLabel("1.0s")
        
        interval_layout.addWidget(self.interval_slider)
        interval_layout.addWidget(self.interval_label)
        
        # Visualization options
        options_layout = QVBoxLayout()
        options_layout.addWidget(QLabel("Display Options:"))
        
        self.show_entropy_checkbox = QCheckBox("Show Entropy")
        self.show_entropy_checkbox.setChecked(True)
        
        self.show_calls_checkbox = QCheckBox("Show Call Graph")
        self.show_calls_checkbox.setChecked(True)
        
        self.show_memory_checkbox = QCheckBox("Show Memory")
        self.show_memory_checkbox.setChecked(True)
        
        options_layout.addWidget(self.show_entropy_checkbox)
        options_layout.addWidget(self.show_calls_checkbox)
        options_layout.addWidget(self.show_memory_checkbox)
        
        # Control buttons
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_visualizations)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_visualizations)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_visualizations)
        
        layout.addWidget(self.live_mode_checkbox)
        layout.addLayout(interval_layout)
        layout.addLayout(options_layout)
        layout.addStretch()
        layout.addWidget(self.refresh_btn)
        layout.addWidget(self.clear_btn)
        layout.addWidget(self.export_btn)
        
        return group
        
    def create_visualization_tabs(self):
        """Create the main visualization tabs."""
        tabs = QTabWidget()
        
        # Entropy analysis tab
        entropy_tab = self.create_entropy_tab()
        tabs.addTab(entropy_tab, "Entropy Analysis")
        
        # Call graph tab
        call_graph_tab = self.create_call_graph_tab()
        tabs.addTab(call_graph_tab, "Call Graph")
        
        # Memory visualization tab
        memory_tab = self.create_memory_tab()
        tabs.addTab(memory_tab, "Memory Usage")
        
        # Execution flow tab
        execution_tab = self.create_execution_tab()
        tabs.addTab(execution_tab, "Execution Flow")
        
        return tabs
        
    def create_entropy_tab(self):
        """Create the entropy analysis visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Entropy visualization
        self.entropy_widget = EntropyVisualizationWidget()
        
        # Entropy controls
        controls_group = QGroupBox("Entropy Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Chunk size control
        controls_layout.addWidget(QLabel("Chunk Size:"))
        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(256, 8192)
        self.chunk_size_spin.setValue(1024)
        self.chunk_size_spin.valueChanged.connect(self.update_entropy_analysis)
        controls_layout.addWidget(self.chunk_size_spin)
        
        # Highlight thresholds
        controls_layout.addWidget(QLabel("High Entropy Threshold:"))
        self.entropy_threshold_slider = QSlider(Qt.Orientation.Horizontal)
        self.entropy_threshold_slider.setRange(70, 95)
        self.entropy_threshold_slider.setValue(85)
        self.entropy_threshold_slider.valueChanged.connect(self.update_entropy_highlights)
        controls_layout.addWidget(self.entropy_threshold_slider)
        
        self.entropy_threshold_label = QLabel("85%")
        controls_layout.addWidget(self.entropy_threshold_label)
        
        # Add highlight regions button
        add_region_btn = QPushButton("Add Highlight")
        add_region_btn.clicked.connect(self.add_entropy_highlight)
        controls_layout.addWidget(add_region_btn)
        
        clear_regions_btn = QPushButton("Clear Highlights")
        clear_regions_btn.clicked.connect(self.clear_entropy_highlights)
        controls_layout.addWidget(clear_regions_btn)
        
        layout.addWidget(self.entropy_widget)
        layout.addWidget(controls_group)
        
        return tab
        
    def create_call_graph_tab(self):
        """Create the call graph visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Call graph visualization
        self.call_graph_widget = CallGraphVisualizationWidget()
        
        # Call graph controls
        controls_group = QGroupBox("Call Graph Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Function filter
        controls_layout.addWidget(QLabel("Filter:"))
        self.function_filter_combo = QComboBox()
        self.function_filter_combo.addItems(["All Functions", "Library Functions", "User Functions", "High Activity"])
        self.function_filter_combo.currentTextChanged.connect(self.update_call_graph_filter)
        controls_layout.addWidget(self.function_filter_combo)
        
        # Layout algorithm
        controls_layout.addWidget(QLabel("Layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Circular", "Grid", "Force-Directed", "Hierarchical"])
        self.layout_combo.currentTextChanged.connect(self.update_call_graph_layout)
        controls_layout.addWidget(self.layout_combo)
        
        # Show labels toggle
        self.show_labels_checkbox = QCheckBox("Show Labels")
        self.show_labels_checkbox.setChecked(True)
        controls_layout.addWidget(self.show_labels_checkbox)
        
        layout.addWidget(self.call_graph_widget)
        layout.addWidget(controls_group)
        
        return tab
        
    def create_memory_tab(self):
        """Create the memory usage visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Memory metrics table
        memory_group = QGroupBox("Memory Metrics")
        memory_layout = QVBoxLayout(memory_group)
        
        self.memory_table = QTableWidget()
        self.memory_table.setColumnCount(3)
        self.memory_table.setHorizontalHeaderLabels(["Region", "Size", "Usage"])
        memory_layout.addWidget(self.memory_table)
        
        # Memory usage chart placeholder
        chart_group = QGroupBox("Memory Usage Over Time")
        chart_layout = QVBoxLayout(chart_group)
        
        self.memory_chart_widget = QWidget()
        self.memory_chart_widget.setMinimumHeight(200)
        self.memory_chart_widget.setStyleSheet("background-color: #f0f0f0; border: 1px solid #ccc;")
        chart_layout.addWidget(self.memory_chart_widget)
        
        layout.addWidget(memory_group)
        layout.addWidget(chart_group)
        
        return tab
        
    def create_execution_tab(self):
        """Create the execution flow visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Execution flow display
        flow_group = QGroupBox("Execution Flow")
        flow_layout = QVBoxLayout(flow_group)
        
        self.execution_text = QTextEdit()
        self.execution_text.setReadOnly(True)
        self.execution_text.setFont(QFont("Consolas", 9))
        self.execution_text.setStyleSheet("background-color: #1e1e1e; color: #00ff00;")
        flow_layout.addWidget(self.execution_text)
        
        # Execution controls
        exec_controls_layout = QHBoxLayout()
        
        self.pause_execution_btn = QPushButton("Pause")
        self.pause_execution_btn.clicked.connect(self.pause_execution_trace)
        
        self.clear_execution_btn = QPushButton("Clear")
        self.clear_execution_btn.clicked.connect(self.clear_execution_trace)
        
        self.save_execution_btn = QPushButton("Save Trace")
        self.save_execution_btn.clicked.connect(self.save_execution_trace)
        
        exec_controls_layout.addWidget(self.pause_execution_btn)
        exec_controls_layout.addWidget(self.clear_execution_btn)
        exec_controls_layout.addWidget(self.save_execution_btn)
        exec_controls_layout.addStretch()
        
        layout.addWidget(flow_group)
        layout.addLayout(exec_controls_layout)
        
        return tab
        
    def create_metrics_footer(self):
        """Create the metrics and status footer."""
        footer = QFrame()
        footer.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(footer)
        
        # Status indicators
        self.connection_status = QLabel("Backend: Disconnected")
        self.connection_status.setStyleSheet("color: red;")
        
        self.update_status = QLabel("Updates: Paused")
        
        self.data_points_label = QLabel("Data Points: 0")
        
        self.performance_label = QLabel("Performance: --")
        
        layout.addWidget(self.connection_status)
        layout.addWidget(self.update_status)
        layout.addWidget(self.data_points_label)
        layout.addWidget(self.performance_label)
        layout.addStretch()
        
        return footer
        
    def setup_connections(self):
        """Setup signal connections and timers."""
        # Update timer for real-time data
        self.update_timer.timeout.connect(self.update_visualizations)
        
        # Connect to shared context
        if self.shared_context:
            if hasattr(self.shared_context, 'binary_analysis_updated'):
                self.shared_context.binary_analysis_updated.connect(self.on_analysis_updated)
            if hasattr(self.shared_context, 'file_selected'):
                self.shared_context.file_selected.connect(self.set_target_binary)
                
    def initialize_backend(self):
        """Initialize backend connections."""
        try:
            if self.shared_context and hasattr(self.shared_context, 'analysis_orchestrator'):
                self.analysis_orchestrator = self.shared_context.analysis_orchestrator
                self.connection_status.setText("Backend: Connected")
                self.connection_status.setStyleSheet("color: green;")
            else:
                # No orchestrator available
                self.connection_status.setText("Backend: Not Available")
                self.connection_status.setStyleSheet("color: red;")
                
            if self.is_live_mode:
                self.start_live_updates()
                
        except Exception as e:
            logger.error(f"Failed to initialize backend: {e}")
            self.connection_status.setText(f"Backend: Error - {e}")
            

        
    def toggle_live_mode(self, enabled):
        """Toggle live update mode."""
        self.is_live_mode = enabled
        
        if enabled:
            self.start_live_updates()
            self.update_status.setText("Updates: Live")
            self.update_status.setStyleSheet("color: green;")
        else:
            self.stop_live_updates()
            self.update_status.setText("Updates: Paused")
            self.update_status.setStyleSheet("color: red;")
            
    def start_live_updates(self):
        """Start live data updates."""
        if not self.update_timer.isActive():
            self.update_timer.start(self.update_interval)
            
    def stop_live_updates(self):
        """Stop live data updates."""
        if self.update_timer.isActive():
            self.update_timer.stop()
            
    def update_interval_changed(self, value):
        """Handle update interval change."""
        self.update_interval = value
        self.interval_label.setText(f"{value/1000:.1f}s")
        
        if self.is_live_mode and self.update_timer.isActive():
            self.update_timer.stop()
            self.update_timer.start(value)
            
    def set_target_binary(self, binary_path: str):
        """Set the target binary for visualization."""
        self.current_binary = binary_path
        self.refresh_visualizations()
        
    def update_visualizations(self):
        """Update all visualizations with current data."""
        if not self.current_binary:
            return
            
        try:
            # Update data point count
            total_points = len(self.entropy_widget.entropy_data)
            total_points += len(self.call_graph_widget.functions)
            self.data_points_label.setText(f"Data Points: {total_points}")
            
            # Update entropy data from real analysis
            if self.show_entropy_checkbox.isChecked() and self.analysis_orchestrator:
                # Request updated entropy data from orchestrator
                pass
                
            # Update performance metrics
            self.update_performance_metrics()
            
        except Exception as e:
            logger.error(f"Error updating visualizations: {e}")
            

        
    def update_performance_metrics(self):
        """Update performance metrics display."""
        # Calculate updates per second
        current_time = time.time()
        if hasattr(self, '_last_update_time'):
            time_diff = current_time - self._last_update_time
            if time_diff > 0:
                update_rate = 1.0 / time_diff
                self.performance_label.setText(f"Performance: {update_rate:.1f} Hz")
        
        self._last_update_time = current_time
        
    def on_analysis_updated(self, analysis_type: str, data: Dict[str, Any]):
        """Handle analysis updates from backend."""
        self.visualization_data[analysis_type] = data
        
        if analysis_type == "entropy" and "data" in data:
            self.entropy_widget.set_entropy_data(data["data"])
        elif analysis_type == "functions" and "functions" in data:
            for func in data["functions"]:
                self.call_graph_widget.add_function(
                    func.get("address", 0),
                    func.get("name", "unknown"),
                    func.get("size", 0),
                    func.get("call_count", 0)
                )
                
    def update_entropy_analysis(self, chunk_size):
        """Update entropy analysis with new chunk size."""
        try:
            if not self.current_binary:
                logger.warning("No binary selected for entropy analysis")
                return
                
            # Update chunk size and trigger new analysis
            self.status_label.setText(f"Updating entropy analysis (chunk size: {chunk_size})")
            
            # Calculate entropy with new chunk size
            if self.analysis_orchestrator:
                # Request new entropy analysis from orchestrator
                entropy_data = self.analysis_orchestrator.calculate_entropy(
                    self.current_binary, chunk_size=chunk_size
                )
                if entropy_data:
                    self.entropy_widget.set_entropy_data(entropy_data)
            else:
                # Generate new entropy data with different chunk size
                self._regenerate_entropy_data(chunk_size)
                
            # Update display
            self.entropy_widget.update()
            self.status_label.setText(f"Entropy analysis updated (chunk: {chunk_size} bytes)")
            
        except Exception as e:
            logger.error(f"Failed to update entropy analysis: {e}")
            self.status_label.setText(f"Entropy update error: {e}")
            
    def _regenerate_entropy_data(self, chunk_size):
        """Regenerate entropy data with new chunk size."""
        import os
        import math
        
        if not self.current_binary or not os.path.exists(self.current_binary):
            return
            
        try:
            # Read binary data and calculate entropy
            entropy_points = []
            
            with open(self.current_binary, 'rb') as f:
                offset = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    # Calculate Shannon entropy for chunk
                    entropy = self._calculate_shannon_entropy(chunk)
                    entropy_points.append((offset, entropy))
                    offset += chunk_size
                    
                    # Limit data points for performance
                    if len(entropy_points) >= 500:
                        break
                        
            self.entropy_widget.set_entropy_data(entropy_points)
            
        except Exception as e:
            logger.error(f"Failed to regenerate entropy data: {e}")
            
    def _calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy for binary data."""
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
        # Calculate entropy
        data_length = len(data)
        entropy = 0.0
        
        for count in byte_counts.values():
            probability = count / data_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        # Normalize to 0-1 range
        return entropy / 8.0
        
    def update_entropy_highlights(self, threshold):
        """Update entropy highlight threshold."""
        self.entropy_threshold_label.setText(f"{threshold}%")
        
        # Clear existing highlights
        self.entropy_widget.clear_highlights()
        
        # Add new highlights for high entropy regions
        threshold_value = threshold / 100.0
        for i, (offset, entropy) in enumerate(self.entropy_widget.entropy_data):
            if entropy >= threshold_value:
                # Find end of high entropy region
                end_offset = offset + 1024  # Default chunk size
                for j in range(i + 1, len(self.entropy_widget.entropy_data)):
                    if self.entropy_widget.entropy_data[j][1] < threshold_value:
                        end_offset = self.entropy_widget.entropy_data[j][0]
                        break
                        
                self.entropy_widget.add_highlight_region(
                    offset, end_offset, QColor(255, 0, 0), "High Entropy"
                )
                
    def add_entropy_highlight(self):
        """Add a custom entropy highlight region."""
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QSpinBox, QLineEdit, QPushButton, QColorDialog, QFormLayout
            
            # Create dialog for highlight parameters
            dialog = QDialog(self)
            dialog.setWindowTitle("Add Entropy Highlight")
            dialog.setModal(True)
            layout = QVBoxLayout(dialog)
            
            # Form for highlight parameters
            form_layout = QFormLayout()
            
            # Start offset
            start_offset_spin = QSpinBox()
            start_offset_spin.setRange(0, 999999999)
            start_offset_spin.setValue(0)
            form_layout.addRow("Start Offset:", start_offset_spin)
            
            # End offset
            end_offset_spin = QSpinBox()
            end_offset_spin.setRange(0, 999999999)
            end_offset_spin.setValue(1024)
            form_layout.addRow("End Offset:", end_offset_spin)
            
            # Label
            label_edit = QLineEdit()
            label_edit.setText("Custom Region")
            form_layout.addRow("Label:", label_edit)
            
            # Color selection
            color_button = QPushButton("Select Color")
            selected_color = QColor(255, 255, 0)  # Default yellow
            
            def select_color():
                nonlocal selected_color
                color = QColorDialog.getColor(selected_color, dialog)
                if color.isValid():
                    selected_color = color
                    color_button.setStyleSheet(f"background-color: {color.name()};")
                    
            color_button.clicked.connect(select_color)
            color_button.setStyleSheet(f"background-color: {selected_color.name()};")
            form_layout.addRow("Color:", color_button)
            
            layout.addLayout(form_layout)
            
            # Buttons
            button_layout = QHBoxLayout()
            ok_button = QPushButton("Add Highlight")
            cancel_button = QPushButton("Cancel")
            
            def add_highlight():
                start = start_offset_spin.value()
                end = end_offset_spin.value()
                label = label_edit.text() or "Custom Region"
                
                if start >= end:
                    from PyQt6.QtWidgets import QMessageBox
                    QMessageBox.warning(dialog, "Invalid Range", "End offset must be greater than start offset")
                    return
                    
                self.entropy_widget.add_highlight_region(start, end, selected_color, label)
                dialog.accept()
                
            ok_button.clicked.connect(add_highlight)
            cancel_button.clicked.connect(dialog.reject)
            
            button_layout.addWidget(ok_button)
            button_layout.addWidget(cancel_button)
            layout.addLayout(button_layout)
            
            # Show dialog
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.status_label.setText("Custom entropy highlight added")
            
        except Exception as e:
            logger.error(f"Failed to add entropy highlight: {e}")
            self.status_label.setText(f"Highlight error: {e}")
        
    def clear_entropy_highlights(self):
        """Clear all entropy highlights."""
        self.entropy_widget.clear_highlights()
        
    def update_call_graph_filter(self, filter_type):
        """Update call graph function filter."""
        try:
            filter_type = filter_type.lower()
            
            if filter_type == "all functions":
                # Show all functions
                for address, func in self.call_graph_widget.functions.items():
                    func['visible'] = True
            elif filter_type == "library functions":
                # Filter to show only library functions
                for address, func in self.call_graph_widget.functions.items():
                    name = func.get('name', '').lower()
                    func['visible'] = any(lib in name for lib in ['ntdll', 'kernel32', 'user32', 'api'])
            elif filter_type == "user functions":
                # Filter to show only user-defined functions
                for address, func in self.call_graph_widget.functions.items():
                    name = func.get('name', '').lower()
                    func['visible'] = not any(lib in name for lib in ['ntdll', 'kernel32', 'user32', 'api'])
            elif filter_type == "high activity":
                # Filter to show only high-activity functions
                for address, func in self.call_graph_widget.functions.items():
                    call_count = func.get('call_count', 0)
                    func['visible'] = call_count >= 10
                    
            # Update display
            self.call_graph_widget.update()
            self.status_label.setText(f"Filter applied: {filter_type}")
            
        except Exception as e:
            logger.error(f"Failed to update call graph filter: {e}")
            self.status_label.setText(f"Filter error: {e}")
        
    def update_call_graph_layout(self, layout_type):
        """Update call graph layout algorithm."""
        try:
            layout_type = layout_type.lower()
            
            # Recalculate positions based on layout algorithm
            if layout_type == "circular":
                self._apply_circular_layout()
            elif layout_type == "grid":
                self._apply_grid_layout()
            elif layout_type == "force-directed":
                self._apply_force_directed_layout()
            elif layout_type == "hierarchical":
                self._apply_hierarchical_layout()
                
            # Update display
            self.call_graph_widget.update()
            self.status_label.setText(f"Layout updated: {layout_type}")
            
        except Exception as e:
            logger.error(f"Failed to update call graph layout: {e}")
            self.status_label.setText(f"Layout error: {e}")
            
    def _apply_circular_layout(self):
        """Apply circular layout to functions."""
        import math
        functions = list(self.call_graph_widget.functions.items())
        if not functions:
            return
            
        angle_step = 2 * math.pi / len(functions)
        radius = 0.4
        
        for i, (address, func) in enumerate(functions):
            angle = i * angle_step
            x = 0.5 + radius * math.cos(angle)
            y = 0.5 + radius * math.sin(angle)
            func['position'] = (max(0.1, min(0.9, x)), max(0.1, min(0.9, y)))
            
    def _apply_grid_layout(self):
        """Apply grid layout to functions."""
        import math
        functions = list(self.call_graph_widget.functions.items())
        if not functions:
            return
            
        cols = max(1, int(math.sqrt(len(functions))))
        rows = (len(functions) + cols - 1) // cols
        
        for i, (address, func) in enumerate(functions):
            row = i // cols
            col = i % cols
            x = (col + 0.5) / cols
            y = (row + 0.5) / rows
            func['position'] = (x, y)
            
    def _apply_force_directed_layout(self):
        """Apply force-directed layout to functions."""
        # Simplified force-directed layout
        functions = list(self.call_graph_widget.functions.items())
        if not functions:
            return
            
        # Initialize with random positions if needed
        for address, func in functions:
            if 'position' not in func:
                import random
                func['position'] = (random.random(), random.random())
                
        # Apply simple repulsion forces
        for _ in range(10):  # Limited iterations for performance
            for i, (addr1, func1) in enumerate(functions):
                fx, fy = 0, 0
                x1, y1 = func1['position']
                
                # Repulsion from other functions
                for j, (addr2, func2) in enumerate(functions):
                    if i != j:
                        x2, y2 = func2['position']
                        dx = x1 - x2
                        dy = y1 - y2
                        dist = max(0.01, (dx*dx + dy*dy) ** 0.5)
                        force = 0.01 / (dist * dist)
                        fx += force * dx / dist
                        fy += force * dy / dist
                        
                # Update position
                x1 += fx * 0.1
                y1 += fy * 0.1
                func1['position'] = (max(0.1, min(0.9, x1)), max(0.1, min(0.9, y1)))
                
    def _apply_hierarchical_layout(self):
        """Apply hierarchical layout to functions."""
        # Find root functions (no incoming calls)
        functions = self.call_graph_widget.functions
        relationships = self.call_graph_widget.call_relationships
        
        # Build incoming call map
        incoming = {addr: [] for addr in functions.keys()}
        for caller, callee in relationships:
            if callee in incoming:
                incoming[callee].append(caller)
                
        # Find root nodes (no incoming calls)
        roots = [addr for addr, calls in incoming.items() if not calls]
        if not roots:
            # Fallback to grid layout if no clear hierarchy
            self._apply_grid_layout()
            return
            
        # Assign levels
        levels = {}
        queue = [(addr, 0) for addr in roots]
        
        while queue:
            addr, level = queue.pop(0)
            if addr not in levels or levels[addr] > level:
                levels[addr] = level
                
                # Add children to queue
                for caller, callee in relationships:
                    if caller == addr and callee not in levels:
                        queue.append((callee, level + 1))
                        
        # Position functions by level
        max_level = max(levels.values()) if levels else 0
        level_counts = {}
        level_positions = {}
        
        for addr, level in levels.items():
            level_counts[level] = level_counts.get(level, 0) + 1
            
        for addr, level in levels.items():
            if level not in level_positions:
                level_positions[level] = 0
            else:
                level_positions[level] += 1
                
            x = (level_positions[level] + 0.5) / level_counts[level]
            y = (level + 0.5) / (max_level + 1)
            functions[addr]['position'] = (x, y)
        
    def pause_execution_trace(self):
        """Pause execution tracing."""
        self.execution_text.append("[TRACE PAUSED]")
        
    def clear_execution_trace(self):
        """Clear execution trace display."""
        self.execution_text.clear()
        
    def save_execution_trace(self):
        """Save execution trace to file."""
        trace_data = self.execution_text.toPlainText()
        filename = f"execution_trace_{int(time.time())}.txt"
        try:
            with open(filename, 'w') as f:
                f.write(trace_data)
            self.execution_text.append(f"[TRACE SAVED TO {filename}]")
        except Exception as e:
            self.execution_text.append(f"[ERROR SAVING TRACE: {e}]")
            
    def refresh_visualizations(self):
        """Refresh all visualizations."""
        if self.current_binary:
            # Trigger analysis refresh
            if self.analysis_orchestrator:
                # Request fresh analysis data from orchestrator
                try:
                    self.status_label.setText("Refreshing analysis data...")
                    
                    # Request new entropy analysis
                    chunk_size = self.chunk_size_spin.value() if hasattr(self, 'chunk_size_spin') else 1024
                    entropy_data = self.analysis_orchestrator.calculate_entropy(
                        self.current_binary, chunk_size=chunk_size
                    )
                    if entropy_data:
                        self.entropy_widget.set_entropy_data(entropy_data)
                        
                    # Request function analysis
                    function_data = self.analysis_orchestrator.analyze_functions(self.current_binary)
                    if function_data:
                        self.call_graph_widget.functions.clear()
                        self.call_graph_widget.call_relationships.clear()
                        
                        for func in function_data.get('functions', []):
                            self.call_graph_widget.add_function(
                                func.get('address', 0),
                                func.get('name', 'unknown'),
                                func.get('size', 0),
                                func.get('call_count', 0)
                            )
                            
                        for rel in function_data.get('relationships', []):
                            self.call_graph_widget.add_call_relationship(
                                rel.get('caller', 0),
                                rel.get('callee', 0)
                            )
                            
                    self.status_label.setText("Visualizations refreshed")
                    
                except Exception as e:
                    logger.error(f"Failed to refresh from orchestrator: {e}")
                    # Fallback to regenerating data
                    self._regenerate_entropy_data(chunk_size)
                    self.status_label.setText("Refreshed with cached data")
            else:
                # Regenerate visualization data manually
                chunk_size = getattr(self, 'chunk_size_spin', type('', (), {'value': lambda: 1024}))().value()
                self._regenerate_entropy_data(chunk_size)
                self.status_label.setText("Visualizations refreshed (no orchestrator)")
        else:
            # Clear visualizations
            self.clear_visualizations()
            self.status_label.setText("No binary selected")
            
    def clear_visualizations(self):
        """Clear all visualization data."""
        self.entropy_widget.entropy_data.clear()
        self.entropy_widget.clear_highlights()
        self.call_graph_widget.functions.clear()
        self.call_graph_widget.call_relationships.clear()
        self.execution_text.clear()
        self.memory_table.setRowCount(0)
        
        # Update displays
        self.entropy_widget.update()
        self.call_graph_widget.update()
        
    def export_visualizations(self):
        """Export visualization data and images."""
        try:
            export_data = {
                "target_binary": self.current_binary,
                "entropy_data": self.entropy_widget.entropy_data,
                "functions": self.call_graph_widget.functions,
                "call_relationships": self.call_graph_widget.call_relationships,
                "visualization_settings": {
                    "live_mode": self.is_live_mode,
                    "update_interval": self.update_interval,
                    "entropy_threshold": self.entropy_threshold_slider.value()
                },
                "exported_at": time.time()
            }
            
            filename = f"visualization_export_{int(time.time())}.json"
            import json
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
                
            self.update_status.setText(f"Exported to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export visualizations: {e}")
            self.update_status.setText(f"Export failed: {e}")