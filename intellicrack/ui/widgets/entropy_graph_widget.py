"""Entropy Visualization Widget.

Provides graphical entropy visualization for protection analysis using PyQtGraph.
Replaces text-only entropy display with interactive bar charts.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from collections.abc import Sequence
from typing import Any

from intellicrack.handlers.pyqt6_handler import QHBoxLayout, QLabel, Qt, QVBoxLayout, QWidget, pyqtSignal

from ...utils.logger import get_logger


try:
    from intellicrack.handlers.numpy_handler import (
        HAS_NUMPY,
        numpy as np,
    )
except ImportError:
    np = None
    HAS_NUMPY = False


logger = get_logger(__name__)

Figure: type[Any] | None = None
FigureCanvasQTAgg: type[Any] | None = None
plt: Any = None

try:
    import pyqtgraph as pg

    PYQTGRAPH_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in entropy_graph_widget: %s", e)
    PYQTGRAPH_AVAILABLE = False
    try:
        from intellicrack.handlers.matplotlib_handler import HAS_MATPLOTLIB, Figure, FigureCanvasQTAgg, plt

        if HAS_MATPLOTLIB and plt is not None:
            plt.style.use("dark_background")
    except ImportError as e:
        logger.exception("Import error in entropy_graph_widget: %s", e)


class EntropyGraphWidget(QWidget):
    """Interactive entropy visualization widget using PyQtGraph.

    Displays entropy values as a bar chart with color coding
    to indicate likelihood of packing/encryption.
    """

    section_clicked = pyqtSignal(str, float)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize entropy graph widget with data storage and UI setup.

        Args:
            parent: Parent widget for this widget. Defaults to None.
        """
        super().__init__(parent)
        self.entropy_data: list[Any] = []
        self.title_label: QLabel
        self.summary_label: QLabel
        self.plot_widget: Any
        self.bar_graph: Any
        self.figure: Any | None = None
        self.canvas: Any | None = None
        self.ax: Any | None = None
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI layout and create visualization components.

        Sets up the main layout with header section containing title and legend,
        plotting area (PyQtGraph or matplotlib fallback), and summary statistics.
        """
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
            if Figure is not None and FigureCanvasQTAgg is not None:
                self.figure = Figure(figsize=(8, 4))
                self.canvas = FigureCanvasQTAgg(self.figure)
                self.ax = self.figure.add_subplot(111)

                layout.addWidget(self.canvas)

                fallback_msg = QLabel("Note: Install pyqtgraph for better performance")
                fallback_msg.setStyleSheet("color: orange; font-style: italic;")
                layout.addWidget(fallback_msg)
            else:
                msg = QLabel("No plotting library available.\nInstall pyqtgraph or matplotlib.")
                msg.setStyleSheet("color: red; font-weight: bold; padding: 20px;")
                msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(msg)

        # Summary info
        self.summary_label = QLabel("No entropy data available")
        self.summary_label.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(self.summary_label)

        self.setLayout(layout)

    def _add_threshold_lines(self) -> None:
        """Add threshold lines to indicate entropy levels.

        Creates dashed horizontal lines at 6.0 and 7.0 bits to mark the boundaries
        between low, medium, and high entropy regions. Only operates when PyQtGraph
        is available.
        """
        if not PYQTGRAPH_AVAILABLE:
            return

        medium_line = pg.InfiniteLine(
            pos=6.0,
            angle=0,
            pen=pg.mkPen(color=(255, 152, 0, 100), width=2, style=Qt.PenStyle.DashLine),
            label="Medium",
            labelOpts={"position": 0.95, "color": (255, 152, 0, 200)},
        )
        self.plot_widget.addItem(medium_line)

        high_line = pg.InfiniteLine(
            pos=7.0,
            angle=0,
            pen=pg.mkPen(color=(244, 67, 54, 100), width=2, style=Qt.PenStyle.DashLine),
            label="High",
            labelOpts={"position": 0.95, "color": (244, 67, 54, 200)},
        )
        self.plot_widget.addItem(high_line)

    def update_entropy_data(self, entropy_info: list[Any]) -> None:
        """Update the entropy visualization with new data.

        Processes entropy data and updates the visualization with color-coded
        entropy values. Also calculates and displays summary statistics including
        packed and encrypted section counts.

        Args:
            entropy_info: List of entropy information objects with attributes:
                         section_name, entropy, packed, encrypted

        Returns:
            None.
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

    def _update_pyqtgraph(self, sections: list[str], entropies: list[float], colors: list[str]) -> None:
        """Update PyQtGraph visualization with new entropy bar data.

        Recreates the bar graph with color-coded entropy values and updates
        x-axis labels with section names. Only operates when PyQtGraph is available.

        Args:
            sections: List of section names for x-axis labels.
            entropies: List of entropy values for bar heights.
            colors: List of color codes for bar coloring.

        Returns:
            None.
        """
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
        x_labels = list(enumerate(sections))
        x_axis = self.plot_widget.getAxis("bottom")
        x_axis.setTicks([x_labels])

        # Adjust view
        self.plot_widget.setXRange(-0.5, len(sections) - 0.5)

    def _update_matplotlib(self, sections: list[str], entropies: list[float], colors: list[str]) -> None:
        """Update matplotlib visualization (fallback).

        Renders entropy data as a bar chart with value labels, threshold lines,
        and rotated section labels. Only used when PyQtGraph is not available.

        Args:
            sections: List of section names for x-axis labels.
            entropies: List of entropy values for bar heights.
            colors: List of color codes for bar coloring.

        Returns:
            None.
        """
        if self.ax is None or self.figure is None or self.canvas is None:
            return

        self.ax.clear()

        x_pos = np.arange(len(sections))
        bars = self.ax.bar(x_pos, entropies, color=colors, alpha=0.8)

        for bar, entropy in zip(bars, entropies, strict=False):
            height = bar.get_height()
            self.ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 0.05,
                f"{entropy:.2f}",
                ha="center",
                va="bottom",
                fontsize=8,
            )

        self.ax.set_xlabel("Section")
        self.ax.set_ylabel("Entropy (bits)")
        self.ax.set_title("Section Entropy Analysis")
        self.ax.set_xticks(x_pos)
        self.ax.set_xticklabels(sections, rotation=45, ha="right")
        self.ax.set_ylim(0, 8.1)

        self.ax.grid(True, axis="y", alpha=0.3)

        self.ax.axhline(y=6.0, color="orange", linestyle="--", alpha=0.5, label="Medium")
        self.ax.axhline(y=7.0, color="red", linestyle="--", alpha=0.5, label="High")

        self.figure.tight_layout()

        self.canvas.draw()

    def _on_bar_clicked(self, item: object, points: Sequence[object]) -> None:
        """Handle bar click in PyQtGraph.

        Emits section_clicked signal with the section name and entropy value
        when a bar is clicked. Safely extracts position data from the clicked point.

        Args:
            item: The clicked item from PyQtGraph.
            points: Sequence of point objects from the click event.
        """
        if points:
            point = points[0]
            if hasattr(point, "pos") and callable(point.pos):
                pos = point.pos()
                if hasattr(pos, "x") and callable(pos.x):
                    index = int(pos.x())
                    if 0 <= index < len(self.entropy_data):
                        section = self.entropy_data[index]
                        if hasattr(section, "section_name") and hasattr(section, "entropy"):
                            self.section_clicked.emit(
                                section.section_name,
                                section.entropy,
                            )

    def get_entropy_summary(self) -> dict[str, int | float]:
        """Get summary statistics of entropy data.

        Returns:
            Dictionary containing total sections, average entropy,
            maximum entropy, packed sections count, encrypted sections count,
            and high entropy sections count.
        """
        if not self.entropy_data:
            return {
                "total_sections": 0,
                "average_entropy": 0.0,
                "max_entropy": 0.0,
                "packed_sections": 0,
                "encrypted_sections": 0,
                "high_entropy_sections": 0,
            }

        entropies = [info.entropy for info in self.entropy_data]

        return {
            "total_sections": len(self.entropy_data),
            "average_entropy": sum(entropies) / len(entropies),
            "max_entropy": max(entropies),
            "packed_sections": sum(bool(info.packed) for info in self.entropy_data),
            "encrypted_sections": sum(bool(info.encrypted) for info in self.entropy_data),
            "high_entropy_sections": sum(e >= 7.0 for e in entropies),
        }

    def export_graph(self, file_path: str) -> None:
        """Export the graph to an image file.

        Saves the current entropy visualization to disk using either PyQtGraph
        or matplotlib depending on available libraries. Logs export status.

        Args:
            file_path: Path where the image file will be saved.

        Returns:
            None.
        """
        if PYQTGRAPH_AVAILABLE:
            exporter = pg.exporters.ImageExporter(self.plot_widget.plotItem)
            exporter.export(file_path)
        elif self.figure is not None:
            self.figure.savefig(file_path, dpi=150, bbox_inches="tight")
        else:
            logger.warning("No plotting library available for export")
            return

        logger.info("Entropy graph exported to: %s", file_path)
