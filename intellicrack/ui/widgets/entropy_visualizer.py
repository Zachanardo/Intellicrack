"""
Entropy Visualization Widget

Provides interactive entropy visualization for binary analysis,
showing entropy distribution across file sections with visual graphs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import numpy as np
from typing import List, Dict, Any, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QComboBox, QSlider, QCheckBox, QPushButton,
    QSplitter, QTextEdit, QGroupBox
)
from PyQt6.QtCore import Qt, pyqtSignal

try:
    import pyqtgraph as pg
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False
    
try:
    import matplotlib
    matplotlib.use('Qt5Agg')
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = Falseclass EntropyVisualizerWidget(QWidget):
    """Interactive entropy visualization widget"""
    
    # Signals
    section_selected = pyqtSignal(str, float, float)  # section_name, start_offset, end_offset
    threshold_changed = pyqtSignal(float)  # new_threshold
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.entropy_data = None
        self.high_entropy_threshold = 7.0
        self.medium_entropy_threshold = 5.0
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI components"""
        layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        # Visualization type selector
        controls_layout.addWidget(QLabel("Visualization:"))
        self.viz_type_combo = QComboBox()
        self.viz_type_combo.addItems([
            "Line Plot",
            "Heatmap", 
            "3D Surface",
            "Histogram",
            "Section Bars"
        ])
        self.viz_type_combo.currentTextChanged.connect(self.update_visualization)
        controls_layout.addWidget(self.viz_type_combo)        
        # Threshold slider
        controls_layout.addWidget(QLabel("High Entropy Threshold:"))
        self.threshold_slider = QSlider(Qt.Orientation.Horizontal)
        self.threshold_slider.setRange(50, 80)  # 5.0 to 8.0
        self.threshold_slider.setValue(70)  # 7.0
        self.threshold_slider.valueChanged.connect(self._on_threshold_changed)
        controls_layout.addWidget(self.threshold_slider)
        
        self.threshold_label = QLabel("7.0")
        controls_layout.addWidget(self.threshold_label)
        
        # Options
        self.show_grid_cb = QCheckBox("Show Grid")
        self.show_grid_cb.setChecked(True)
        self.show_grid_cb.stateChanged.connect(self.update_visualization)
        controls_layout.addWidget(self.show_grid_cb)
        
        self.highlight_suspicious_cb = QCheckBox("Highlight Suspicious")
        self.highlight_suspicious_cb.setChecked(True)
        self.highlight_suspicious_cb.stateChanged.connect(self.update_visualization)
        controls_layout.addWidget(self.highlight_suspicious_cb)
        
        controls_layout.addStretch()
        
        # Export button
        self.export_btn = QPushButton("Export Graph")
        self.export_btn.clicked.connect(self.export_graph)
        controls_layout.addWidget(self.export_btn)
        
        layout.addLayout(controls_layout)        
        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Graph area
        self.graph_widget = self._create_graph_widget()
        splitter.addWidget(self.graph_widget)
        
        # Details panel
        details_group = QGroupBox("Entropy Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumWidth(300)
        details_layout.addWidget(self.details_text)
        
        splitter.addWidget(details_group)
        splitter.setSizes([600, 300])
        
        layout.addWidget(splitter)
        
    def _create_graph_widget(self):
        """Create the appropriate graph widget based on available libraries"""
        if PYQTGRAPH_AVAILABLE:
            # Use pyqtgraph for better performance
            self.plot_widget = pg.PlotWidget()
            self.plot_widget.setLabel('left', 'Entropy', units='bits')
            self.plot_widget.setLabel('bottom', 'File Offset', units='bytes')
            self.plot_widget.showGrid(x=True, y=True)
            return self.plot_widget            
        elif MATPLOTLIB_AVAILABLE:
            # Fallback to matplotlib
            self.figure = Figure(figsize=(8, 6))
            self.canvas = FigureCanvas(self.figure)
            return self.canvas
            
        else:
            # No graphing library available
            label = QLabel("No graphing library available.\nInstall pyqtgraph or matplotlib.")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            return label
            
    def set_entropy_data(self, data: Dict[str, Any]):
        """Set entropy data for visualization"""
        self.entropy_data = data
        self.update_visualization()
        self.update_details()
        
    def update_visualization(self):
        """Update the visualization based on current settings"""
        if not self.entropy_data:
            return
            
        viz_type = self.viz_type_combo.currentText()
        
        if PYQTGRAPH_AVAILABLE:
            self._update_pyqtgraph(viz_type)
        elif MATPLOTLIB_AVAILABLE:
            self._update_matplotlib(viz_type)            
    def _update_pyqtgraph(self, viz_type: str):
        """Update visualization using pyqtgraph"""
        self.plot_widget.clear()
        
        if viz_type == "Line Plot":
            self._draw_line_plot_pg()
        elif viz_type == "Heatmap":
            self._draw_heatmap_pg()
        elif viz_type == "Section Bars":
            self._draw_section_bars_pg()
        elif viz_type == "Histogram":
            self._draw_histogram_pg()
        else:
            # Default to line plot
            self._draw_line_plot_pg()
            
    def _draw_line_plot_pg(self):
        """Draw line plot using pyqtgraph"""
        chunks = self.entropy_data.get("chunks", [])
        if not chunks:
            return
            
        # Extract data
        offsets = [c["offset"] for c in chunks]
        entropies = [c["entropy"] for c in chunks]
        
        # Create line plot
        pen = pg.mkPen(color=(100, 200, 255), width=2)
        self.plot_widget.plot(offsets, entropies, pen=pen, name="Entropy")        
        # Add threshold lines
        if self.highlight_suspicious_cb.isChecked():
            # High threshold
            high_line = pg.InfiniteLine(
                pos=self.high_entropy_threshold,
                angle=0,
                pen=pg.mkPen(color=(255, 100, 100), width=2, style=Qt.PenStyle.DashLine),
                label="High Entropy",
                labelOpts={'position': 0.95}
            )
            self.plot_widget.addItem(high_line)
            
            # Medium threshold
            medium_line = pg.InfiniteLine(
                pos=self.medium_entropy_threshold,
                angle=0,
                pen=pg.mkPen(color=(255, 200, 100), width=2, style=Qt.PenStyle.DashLine),
                label="Medium Entropy",
                labelOpts={'position': 0.05}
            )
            self.plot_widget.addItem(medium_line)
            
        # Highlight suspicious regions
        if self.highlight_suspicious_cb.isChecked():
            for chunk in chunks:
                if chunk.get("suspicious", False):
                    # Add vertical span for suspicious region
                    region = pg.LinearRegionItem(
                        [chunk["offset"], chunk["offset"] + chunk["size"]],
                        orientation='vertical',                        brush=pg.mkBrush(255, 100, 100, 50)
                    )
                    region.setMovable(False)
                    self.plot_widget.addItem(region)
                    
    def _draw_heatmap_pg(self):
        """Draw heatmap using pyqtgraph"""
        chunks = self.entropy_data.get("chunks", [])
        if not chunks:
            return
            
        # Create 2D array for heatmap
        # Group chunks into rows for visualization
        row_size = max(1, int(np.sqrt(len(chunks))))
        
        # Pad to make rectangular
        total_cells = row_size * row_size
        entropies = [c["entropy"] for c in chunks]
        entropies.extend([0] * (total_cells - len(entropies)))
        
        # Reshape into 2D array
        heatmap_data = np.array(entropies).reshape(row_size, row_size)
        
        # Create image item
        img = pg.ImageItem(heatmap_data)
        self.plot_widget.addItem(img)
        
        # Set colormap
        colors = [
            (0, 0, 100),      # Dark blue (low entropy)            (0, 100, 200),    # Blue
            (100, 200, 100),  # Green
            (255, 200, 0),    # Yellow
            (255, 100, 0),    # Orange
            (255, 0, 0),      # Red (high entropy)
        ]
        cmap = pg.ColorMap(pos=np.linspace(0.0, 8.0, len(colors)), color=colors)
        img.setColorMap(cmap)
        
        # Add labels
        self.plot_widget.setLabel('left', 'Block Row')
        self.plot_widget.setLabel('bottom', 'Block Column')
        
    def _draw_section_bars_pg(self):
        """Draw section bars using pyqtgraph"""
        sections = self.entropy_data.get("sections", {})
        if not sections:
            # Fall back to overall entropy
            overall = self.entropy_data.get("overall_entropy", 0)
            sections = {"File": overall}
            
        # Create bar graph
        x = np.arange(len(sections))
        heights = list(sections.values())
        names = list(sections.keys())
        
        # Create bar graph item
        bg = pg.BarGraphItem(x=x, height=heights, width=0.8, brush='b')
        self.plot_widget.addItem(bg)        
        # Color bars based on entropy level
        brushes = []
        for h in heights:
            if h > self.high_entropy_threshold:
                brushes.append(pg.mkBrush(255, 100, 100))  # Red
            elif h > self.medium_entropy_threshold:
                brushes.append(pg.mkBrush(255, 200, 100))  # Orange
            else:
                brushes.append(pg.mkBrush(100, 200, 100))  # Green
        bg.setOpts(brushes=brushes)
        
        # Set labels
        self.plot_widget.getAxis('bottom').setTicks([list(zip(x, names))])
        self.plot_widget.setLabel('left', 'Entropy', units='bits')
        
    def _draw_histogram_pg(self):
        """Draw histogram using pyqtgraph"""
        chunks = self.entropy_data.get("chunks", [])
        if not chunks:
            return
            
        entropies = [c["entropy"] for c in chunks]
        
        # Create histogram
        y, x = np.histogram(entropies, bins=50)
        
        # Create bar graph for histogram
        bg = pg.BarGraphItem(x=x[:-1], height=y, width=(x[1]-x[0]), brush='b')
        self.plot_widget.addItem(bg)        
        # Add threshold lines
        if self.highlight_suspicious_cb.isChecked():
            high_line = pg.InfiniteLine(
                pos=self.high_entropy_threshold,
                angle=90,
                pen=pg.mkPen(color=(255, 100, 100), width=2, style=Qt.PenStyle.DashLine)
            )
            self.plot_widget.addItem(high_line)
            
        self.plot_widget.setLabel('left', 'Count')
        self.plot_widget.setLabel('bottom', 'Entropy', units='bits')
        
    def _update_matplotlib(self, viz_type: str):
        """Update visualization using matplotlib"""
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        if viz_type == "Line Plot":
            self._draw_line_plot_mpl(ax)
        elif viz_type == "Heatmap":
            self._draw_heatmap_mpl(ax)
        elif viz_type == "Section Bars":
            self._draw_section_bars_mpl(ax)
        elif viz_type == "Histogram":
            self._draw_histogram_mpl(ax)
        else:
            self._draw_line_plot_mpl(ax)
            
        self.canvas.draw()        
    def _draw_line_plot_mpl(self, ax):
        """Draw line plot using matplotlib"""
        chunks = self.entropy_data.get("chunks", [])
        if not chunks:
            return
            
        offsets = [c["offset"] for c in chunks]
        entropies = [c["entropy"] for c in chunks]
        
        ax.plot(offsets, entropies, 'b-', linewidth=2, label="Entropy")
        
        # Add threshold lines
        if self.highlight_suspicious_cb.isChecked():
            ax.axhline(y=self.high_entropy_threshold, color='r', linestyle='--', label="High Threshold")
            ax.axhline(y=self.medium_entropy_threshold, color='orange', linestyle='--', label="Medium Threshold")
            
        ax.set_xlabel("File Offset (bytes)")
        ax.set_ylabel("Entropy (bits)")
        ax.set_title("Binary Entropy Distribution")
        ax.legend()
        ax.grid(self.show_grid_cb.isChecked())
        
    def update_details(self):
        """Update the details panel"""
        if not self.entropy_data:
            return
            
        details = "=== Entropy Analysis ===\n\n"        
        # Overall entropy
        overall = self.entropy_data.get("overall_entropy", 0)
        details += f"Overall Entropy: {overall:.4f} bits\n"
        
        if overall > self.high_entropy_threshold:
            details += "⚠️ High entropy - possible packing/encryption\n"
        elif overall > self.medium_entropy_threshold:
            details += "⚡ Medium entropy - some compression\n"
        else:
            details += "✓ Normal entropy\n"
            
        details += "\n"
        
        # High entropy chunks
        chunks = self.entropy_data.get("chunks", [])
        high_chunks = [c for c in chunks if c.get("suspicious", False)]
        
        if high_chunks:
            details += f"High Entropy Regions: {len(high_chunks)}\n\n"
            for i, chunk in enumerate(high_chunks[:10]):  # Show first 10
                details += f"Region {i+1}:\n"
                details += f"  Offset: 0x{chunk['offset']:08X}\n"
                details += f"  Size: {chunk['size']} bytes\n"
                details += f"  Entropy: {chunk['entropy']:.4f} bits\n\n"                
        # Section entropy
        sections = self.entropy_data.get("sections", {})
        if sections:
            details += "Section Entropy:\n"
            for name, entropy in sections.items():
                details += f"  {name}: {entropy:.4f} bits\n"
                
        self.details_text.setText(details)
        
    def _on_threshold_changed(self, value):
        """Handle threshold slider change"""
        self.high_entropy_threshold = value / 10.0
        self.threshold_label.setText(f"{self.high_entropy_threshold:.1f}")
        self.threshold_changed.emit(self.high_entropy_threshold)
        self.update_visualization()
        self.update_details()
        
    def export_graph(self):
        """Export the current graph"""
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Entropy Graph",
            "entropy_analysis.png",
            "PNG Files (*.png);;All Files (*)"
        )
        
        if filename:
            if PYQTGRAPH_AVAILABLE:
                # Export pyqtgraph
                exporter = pg.exporters.ImageExporter(self.plot_widget.plotItem)
                exporter.export(filename)
            elif MATPLOTLIB_AVAILABLE:
                # Export matplotlib
                self.figure.savefig(filename, dpi=300, bbox_inches='tight')