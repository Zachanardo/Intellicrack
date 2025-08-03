"""Entropy Visualization Widget

Provides graphical entropy visualization for protection analysis using PyQtGraph.
Replaces text-only entropy display with interactive bar charts.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ...utils.logger import get_logger

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False



logger = get_logger(__name__)

# Initialize matplotlib components to None
Figure = None
FigureCanvasQTAgg = None
plt = None

try:
    import pyqtgraph as pg
    PYQTGRAPH_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in entropy_graph_widget: %s", e)
    PYQTGRAPH_AVAILABLE = False
    # Fallback to matplotlib if pyqtgraph not available
    try:
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
        from matplotlib.figure import Figure
        plt.style.use("dark_background")
    except ImportError as e:
        logger.error("Import error in entropy_graph_widget: %s", e)
        # Already initialized to None above


class EntropyGraphWidget(QWidget):
    """Interactive entropy visualization widget using PyQtGraph.

    Displays entropy values as a bar chart with color coding
    to indicate likelihood of packing/encryption.
    """

    # Signals
    section_clicked = pyqtSignal(str, float)  # section_name, entropy_value

    def __init__(self, parent=None):
        """Initialize entropy graph widget with data storage and UI setup."""
        super().__init__(parent)
        self.entropy_data = []
        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Header
        header_layout = QHBoxLayout()
        self.title_label = QLabel("Section Entropy Analysis")
        self.title_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        header_layout.addWidget(self.title_label)

        header_layout.addStretch()

        # Legend
        legend_layout = QHBoxLayout()

        # Low entropy
        low_color = QLabel("█")
        low_color.setStyleSheet("color: #4CAF50;")  # Green
        legend_layout.addWidget(low_color)
        legend_layout.addWidget(QLabel("Low (0-6)"))

        # Medium entropy
        med_color = QLabel("█")
        med_color.setStyleSheet("color: #FF9800;")  # Orange
        legend_layout.addWidget(med_color)
        legend_layout.addWidget(QLabel("Medium (6-7)"))

        # High entropy
        high_color = QLabel("█")
        high_color.setStyleSheet("color: #F44336;")  # Red
        legend_layout.addWidget(high_color)
        legend_layout.addWidget(QLabel("High (7-8)"))

        header_layout.addLayout(legend_layout)

        layout.addLayout(header_layout)

        if PYQTGRAPH_AVAILABLE:
            # Create PyQtGraph plot widget
            self.plot_widget = pg.PlotWidget()
            self.plot_widget.setLabel("left", "Entropy", units="bits")
            self.plot_widget.setLabel("bottom", "Section")
            self.plot_widget.setYRange(0, 8.1)

            # Enable grid
            self.plot_widget.showGrid(x=False, y=True, alpha=0.3)

            # Set background color
            self.plot_widget.setBackground("w")

            # Create bar graph item
            self.bar_graph = pg.BarGraphItem(x=[], height=[], width=0.8, brush="b")
            self.plot_widget.addItem(self.bar_graph)

            # Add threshold lines
            self._add_threshold_lines()

            layout.addWidget(self.plot_widget)

        else:
            # Fallback to matplotlib
            if Figure is not None and FigureCanvasQTAgg is not None:
                self.figure = Figure(figsize=(8, 4))
                self.canvas = FigureCanvasQTAgg(self.figure)
                self.ax = self.figure.add_subplot(111)

                layout.addWidget(self.canvas)
            else:
                # No plotting library available
                msg = QLabel("No plotting library available.\nInstall pyqtgraph or matplotlib.")
                msg.setStyleSheet("color: red; font-weight: bold; padding: 20px;")
                msg.setAlignment(Qt.AlignCenter)
                layout.addWidget(msg)
                self.figure = None
                self.canvas = None
                self.ax = None

            # Fallback message
            if not PYQTGRAPH_AVAILABLE and Figure is not None:
                msg = QLabel("Note: Install pyqtgraph for better performance")
                msg.setStyleSheet("color: orange; font-style: italic;")
                layout.addWidget(msg)

        # Summary info
        self.summary_label = QLabel("No entropy data available")
        self.summary_label.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(self.summary_label)

        self.setLayout(layout)

    def _add_threshold_lines(self):
        """Add threshold lines to indicate entropy levels"""
        if not PYQTGRAPH_AVAILABLE:
            return

        # Medium threshold (6.0)
        medium_line = pg.InfiniteLine(
            pos=6.0,
            angle=0,
            pen=pg.mkPen(color=(255, 152, 0, 100), width=2, style=Qt.DashLine),
            label="Medium",
            labelOpts={"position": 0.95, "color": (255, 152, 0, 200)},
        )
        self.plot_widget.addItem(medium_line)

        # High threshold (7.0)
        high_line = pg.InfiniteLine(
            pos=7.0,
            angle=0,
            pen=pg.mkPen(color=(244, 67, 54, 100), width=2, style=Qt.DashLine),
            label="High",
            labelOpts={"position": 0.95, "color": (244, 67, 54, 200)},
        )
        self.plot_widget.addItem(high_line)

    def update_entropy_data(self, entropy_info: list[Any]):
        """Update the entropy visualization with new data.

        Args:
            entropy_info: List of entropy information objects with attributes:
                         section_name, entropy, packed, encrypted

        """
        self.entropy_data = entropy_info

        if not entropy_info:
            self.summary_label.setText("No entropy data available")
            return

        sections = []
        entropies = []
        colors = []

        packed_count = 0
        encrypted_count = 0
        max_entropy = 0

        for info in entropy_info:
            sections.append(info.section_name)
            entropy_val = info.entropy
            entropies.append(entropy_val)

            # Update statistics
            max_entropy = max(max_entropy, entropy_val)
            if info.packed:
                packed_count += 1
            if info.encrypted:
                encrypted_count += 1

            # Determine color based on entropy value
            if entropy_val >= 7.0:
                colors.append("#F44336")  # Red - High entropy
            elif entropy_val >= 6.0:
                colors.append("#FF9800")  # Orange - Medium entropy
            else:
                colors.append("#4CAF50")  # Green - Low entropy

        # Update plot
        if PYQTGRAPH_AVAILABLE:
            self._update_pyqtgraph(sections, entropies, colors)
        else:
            self._update_matplotlib(sections, entropies, colors)

        # Update summary
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0
        summary = f"Sections: {len(sections)} | "
        summary += f"Avg: {avg_entropy:.2f} | Max: {max_entropy:.2f}"

        if packed_count > 0:
            summary += f" | Packed: {packed_count}"
        if encrypted_count > 0:
            summary += f" | Encrypted: {encrypted_count}"

        self.summary_label.setText(summary)

    def _update_pyqtgraph(self, sections: list[str], entropies: list[float], colors: list[str]):
        """Update PyQtGraph visualization"""
        if not PYQTGRAPH_AVAILABLE:
            return

        # Clear existing items except threshold lines
        self.plot_widget.removeItem(self.bar_graph)

        # Create x positions
        x_pos = np.arange(len(sections))

        # Create brushes for each bar
        brushes = [pg.mkBrush(color) for color in colors]

        # Create new bar graph
        self.bar_graph = pg.BarGraphItem(
            x=x_pos,
            height=entropies,
            width=0.8,
            brushes=brushes,
        )

        # Make bars clickable
        self.bar_graph.sigClicked.connect(self._on_bar_clicked)

        self.plot_widget.addItem(self.bar_graph)

        # Update x-axis labels
        x_labels = [(i, name) for i, name in enumerate(sections)]
        x_axis = self.plot_widget.getAxis("bottom")
        x_axis.setTicks([x_labels])

        # Adjust view
        self.plot_widget.setXRange(-0.5, len(sections) - 0.5)

    def _update_matplotlib(self, sections: list[str], entropies: list[float], colors: list[str]):
        """Update matplotlib visualization (fallback)"""
        self.ax.clear()

        x_pos = np.arange(len(sections))
        bars = self.ax.bar(x_pos, entropies, color=colors, alpha=0.8)

        # Add value labels on bars
        for _i, (bar, entropy) in enumerate(zip(bars, entropies, strict=False)):
            height = bar.get_height()
            self.ax.text(
                bar.get_x() + bar.get_width()/2.,
                height + 0.05,
                f"{entropy:.2f}",
                ha="center",
                va="bottom",
                fontsize=8,
            )

        # Customize plot
        self.ax.set_xlabel("Section")
        self.ax.set_ylabel("Entropy (bits)")
        self.ax.set_title("Section Entropy Analysis")
        self.ax.set_xticks(x_pos)
        self.ax.set_xticklabels(sections, rotation=45, ha="right")
        self.ax.set_ylim(0, 8.1)

        # Add grid
        self.ax.grid(True, axis="y", alpha=0.3)

        # Add threshold lines
        self.ax.axhline(y=6.0, color="orange", linestyle="--", alpha=0.5, label="Medium")
        self.ax.axhline(y=7.0, color="red", linestyle="--", alpha=0.5, label="High")

        # Tight layout
        self.figure.tight_layout()

        # Redraw
        self.canvas.draw()

    def _on_bar_clicked(self, item, points):
        """Handle bar click in PyQtGraph"""
        if points:
            point = points[0]
            index = int(point.pos().x())
            if 0 <= index < len(self.entropy_data):
                section = self.entropy_data[index]
                self.section_clicked.emit(
                    section.section_name,
                    section.entropy,
                )

    def get_entropy_summary(self) -> dict:
        """Get summary statistics of entropy data"""
        if not self.entropy_data:
            return {
                "total_sections": 0,
                "average_entropy": 0,
                "max_entropy": 0,
                "packed_sections": 0,
                "encrypted_sections": 0,
                "high_entropy_sections": 0,
            }

        entropies = [info.entropy for info in self.entropy_data]

        return {
            "total_sections": len(self.entropy_data),
            "average_entropy": sum(entropies) / len(entropies),
            "max_entropy": max(entropies),
            "packed_sections": sum(1 for info in self.entropy_data if info.packed),
            "encrypted_sections": sum(1 for info in self.entropy_data if info.encrypted),
            "high_entropy_sections": sum(1 for e in entropies if e >= 7.0),
        }

    def export_graph(self, file_path: str):
        """Export the graph to an image file"""
        if PYQTGRAPH_AVAILABLE:
            # Export using PyQtGraph
            exporter = pg.exporters.ImageExporter(self.plot_widget.plotItem)
            exporter.export(file_path)
        else:
            # Export using matplotlib
            self.figure.savefig(file_path, dpi=150, bbox_inches="tight")

        logger.info(f"Entropy graph exported to: {file_path}")
