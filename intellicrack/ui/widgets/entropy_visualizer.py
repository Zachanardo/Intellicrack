"""Entropy visualization widget for binary analysis."""
import math
from collections import Counter

import numpy as np
import pyqtgraph as pg
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class EntropyVisualizer(QWidget):
    """Widget for visualizing file entropy."""

    entropy_calculated = pyqtSignal(list, list)

    def __init__(self, parent=None):
        """Initialize entropy visualizer widget with binary entropy analysis and visualization."""
        super().__init__(parent)
        self.setMinimumHeight(200)
        self.setMinimumWidth(400)
        self.current_data = None
        self._setup_ui()

    def setup_ui(self):
        """Set up the entropy visualization UI."""
        layout = QVBoxLayout(self)

        # Create plot widget
        self.plot_widget = pg.PlotWidget(title="File Entropy Analysis")
        self.plot_widget.setLabel("left", "Entropy", units="bits")
        self.plot_widget.setLabel("bottom", "File Position", units="%")
        self.plot_widget.setYRange(0, 8)

        # Configure plot appearance
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.getPlotItem().getViewBox().setMouseEnabled(x=True, y=False)

        # Add entropy plot
        self.entropy_curve = self.plot_widget.plot(
            pen=pg.mkPen(color=(0, 255, 0), width=2),
            name="Entropy",
        )

        # Add threshold lines
        self.high_entropy_line = pg.InfiniteLine(
            pos=7.5,
            angle=0,
            pen=pg.mkPen("r", style=Qt.PenStyle.DashLine),
            label="High Entropy (7.5)",
        )
        self.plot_widget.addItem(self.high_entropy_line)

        self.low_entropy_line = pg.InfiniteLine(
            pos=1.0,
            angle=0,
            pen=pg.mkPen("b", style=Qt.PenStyle.DashLine),
            label="Low Entropy (1.0)",
        )
        self.plot_widget.addItem(self.low_entropy_line)

        # Add regions for different entropy levels
        self.high_entropy_region = pg.LinearRegionItem(
            values=(7.5, 8.0),
            orientation="horizontal",
            brush=pg.mkBrush(255, 0, 0, 50),
        )
        self.plot_widget.addItem(self.high_entropy_region)

        self.low_entropy_region = pg.LinearRegionItem(
            values=(0, 1.0),
            orientation="horizontal",
            brush=pg.mkBrush(0, 0, 255, 50),
        )
        self.plot_widget.addItem(self.low_entropy_region)

        # Info label
        self.info_label = QLabel("No data loaded")
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.plot_widget)
        layout.addWidget(self.info_label)

    def calculate_entropy(self, data: bytes, block_size: int = 1024) -> tuple:
        """Calculate Shannon entropy for data blocks."""
        if not data:
            return [], []

        entropy_values = []
        positions = []

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if len(block) < 64:  # Skip very small blocks
                continue

            # Calculate byte frequency
            byte_counts = Counter(block)
            block_len = len(block)

            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts.values():
                if count > 0:
                    probability = count / block_len
                    entropy -= probability * math.log2(probability)

            entropy_values.append(entropy)
            positions.append((i / len(data)) * 100)  # Position as percentage

        return positions, entropy_values

    def load_data(self, data: bytes, block_size: int = 1024):
        """Load binary data and calculate entropy."""
        self.file_data = data
        self.block_positions, self.entropy_data = self.calculate_entropy(data, block_size)
        self.update_plot()

    def update_plot(self):
        """Update the entropy plot."""
        if not self.entropy_data:
            self.info_label.setText("No entropy data available")
            return

        # Update plot
        self.entropy_curve.setData(self.block_positions, self.entropy_data)

        # Calculate statistics
        avg_entropy = np.mean(self.entropy_data)
        max_entropy = np.max(self.entropy_data)
        min_entropy = np.min(self.entropy_data)

        # Identify interesting regions
        high_entropy_blocks = sum(1 for e in self.entropy_data if e > 7.5)
        low_entropy_blocks = sum(1 for e in self.entropy_data if e < 1.0)

        # Update info label
        info_text = (
            f"Average Entropy: {avg_entropy:.2f} | "
            f"Min: {min_entropy:.2f} | Max: {max_entropy:.2f}\n"
            f"High Entropy Blocks: {high_entropy_blocks} | "
            f"Low Entropy Blocks: {low_entropy_blocks}"
        )
        self.info_label.setText(info_text)

        # Emit signal for other components
        self.entropy_calculated.emit(self.block_positions, self.entropy_data)

    def find_suspicious_regions(self) -> list[tuple]:
        """Find regions with suspicious entropy patterns."""
        suspicious = []

        if len(self.entropy_data) < 2:
            return suspicious

        # Look for sudden entropy changes
        for i in range(1, len(self.entropy_data)):
            diff = abs(self.entropy_data[i] - self.entropy_data[i-1])
            if diff > 3.0:  # Significant entropy change
                suspicious.append((
                    self.block_positions[i],
                    "Sudden entropy change",
                    f"Δ = {diff:.2f}",
                ))

        # Look for packed/encrypted sections
        for i, entropy in enumerate(self.entropy_data):
            if entropy > 7.8:
                suspicious.append((
                    self.block_positions[i],
                    "Possible encryption/compression",
                    f"Entropy = {entropy:.2f}",
                ))
            elif entropy < 0.5:
                suspicious.append((
                    self.block_positions[i],
                    "Possible padding/null bytes",
                    f"Entropy = {entropy:.2f}",
                ))

        return suspicious

    def clear(self):
        """Clear the visualization."""
        self.file_data = None
        self.entropy_data = []
        self.block_positions = []
        self.entropy_curve.setData([], [])
        self.info_label.setText("No data loaded")
