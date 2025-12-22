"""Entropy visualization widget for binary analysis.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import math
from collections import Counter
from typing import cast

import pyqtgraph as pg

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.pyqt6_handler import QLabel, Qt, QVBoxLayout, QWidget, pyqtSignal
from intellicrack.utils.logger import logger


class EntropyVisualizer(QWidget):
    """Widget for visualizing file entropy.

    Displays Shannon entropy calculations across blocks of binary data,
    identifying packed, encrypted, or compressed sections. Useful for
    analyzing software protection mechanisms in binary files.
    """

    entropy_calculated = pyqtSignal(list, list)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize entropy visualizer widget with binary entropy analysis and visualization.

        Args:
            parent: Optional parent widget for Qt object hierarchy.

        """
        super().__init__(parent)
        self.setMinimumHeight(200)
        self.setMinimumWidth(400)
        self.current_data: object = None
        self.file_data: bytes | None = None
        self.entropy_data: list[float] = []
        self.block_positions: list[float] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the entropy visualization UI.

        Creates plot widgets with entropy curve, threshold lines, and
        high/low entropy regions for visual analysis of binary data.
        """
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

    def calculate_entropy(self, data: bytes, block_size: int = 1024) -> tuple[list[float], list[float]]:
        """Calculate Shannon entropy for data blocks.

        Divides binary data into fixed-size blocks and calculates Shannon entropy
        for each block, identifying patterns indicating compression or encryption.

        Args:
            data: Binary data to analyze.
            block_size: Size of each analysis block in bytes.

        Returns:
            Tuple containing (positions, entropy_values) where positions are
            percentages through the file and entropy_values are Shannon entropy
            calculations ranging from 0 to 8.

        """
        if not data:
            return [], []

        entropy_values = []
        positions = []

        for i in range(0, len(data), block_size):
            block = data[i : i + block_size]
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

    def load_data(self, data: object, block_size: int = 1024) -> None:
        """Load binary data and calculate entropy with comprehensive error handling.

        Validates input data, calculates entropy statistics, and updates the
        visualization with proper error recovery.

        Args:
            data: Binary data to load and analyze.
            block_size: Size of each analysis block in bytes.

        Raises:
            TypeError: If data is not bytes type.
            ValueError: If data is empty or block_size is non-positive.

        """
        try:
            if not isinstance(data, (bytes, bytearray, memoryview)):
                error_msg = f"Expected bytes data, got {type(data)}"
                logger.error(error_msg)
                raise TypeError(error_msg)
            validated_data = cast(bytes | bytearray | memoryview, data)

            if not validated_data:
                error_msg = "Cannot process empty data"
                logger.error(error_msg)
                raise ValueError(error_msg)

            if block_size <= 0:
                error_msg = f"Block size must be positive, got {block_size}"
                logger.error(error_msg)
                raise ValueError(error_msg)

            if len(validated_data) < block_size:
                block_size = max(1, len(validated_data) // 4)  # Adaptive block size for small files

            normalized_data = bytes(validated_data)
            self.file_data = normalized_data
            self.block_positions, self.entropy_data = self.calculate_entropy(normalized_data, block_size)
            self.update_plot()

        except (TypeError, ValueError, MemoryError) as e:
            error_msg = f"Error loading entropy data: {e!s}"
            self.info_label.setText(error_msg)
            self.entropy_data = []
            self.block_positions = []
            self.entropy_curve.setData([], [])

    def update_plot(self) -> None:
        """Update the entropy plot with comprehensive error handling.

        Renders entropy data on the plot, calculates statistics, identifies
        suspicious regions, and emits signals for connected widgets.
        """
        try:
            if not self.entropy_data:
                self.info_label.setText("No entropy data available")
                return

            if len(self.entropy_data) != len(self.block_positions):
                error_msg = "Mismatch between entropy data and position data"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Update plot with validation
            if hasattr(self, "entropy_curve") and self.entropy_curve:
                self.entropy_curve.setData(self.block_positions, self.entropy_data)
            else:
                error_msg = "Entropy curve not properly initialized"
                logger.error(error_msg)
                raise AttributeError(error_msg)

            # Calculate statistics with error handling
            entropy_array = np.array(self.entropy_data)
            if len(entropy_array) == 0:
                error_msg = "Empty entropy data array"
                logger.error(error_msg)
                raise ValueError(error_msg)

            avg_entropy = np.mean(entropy_array)
            max_entropy = np.max(entropy_array)
            min_entropy = np.min(entropy_array)

            # Validate calculated values
            if np.isnan(avg_entropy) or np.isnan(max_entropy) or np.isnan(min_entropy):
                error_msg = "Invalid entropy calculations (NaN detected)"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Identify interesting regions
            high_entropy_blocks = sum(e > 7.5 for e in self.entropy_data)
            low_entropy_blocks = sum(e < 1.0 for e in self.entropy_data)

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

        except (ValueError, AttributeError, RuntimeError, TypeError) as e:
            error_msg = f"Error updating entropy plot: {e!s}"
            self.info_label.setText(error_msg)
            # Clear the plot on error
            if hasattr(self, "entropy_curve") and self.entropy_curve:
                self.entropy_curve.setData([], [])

    def find_suspicious_regions(self) -> list[tuple[float, str, str]]:
        """Find regions with suspicious entropy patterns.

        Identifies regions in the binary that may indicate encryption,
        compression, or padding based on entropy fluctuations and values.

        Returns:
            List of tuples (position_percent, description, details) for each
            suspicious region found.

        """
        suspicious: list[tuple[float, str, str]] = []

        if len(self.entropy_data) < 2:
            return suspicious

        # Look for sudden entropy changes
        for i in range(1, len(self.entropy_data)):
            diff = abs(self.entropy_data[i] - self.entropy_data[i - 1])
            if diff > 3.0:  # Significant entropy change
                suspicious.append(
                    (
                        self.block_positions[i],
                        "Sudden entropy change",
                        f"Δ = {diff:.2f}",
                    ),
                )

        # Look for packed/encrypted sections
        for i, entropy in enumerate(self.entropy_data):
            if entropy > 7.8:
                suspicious.append(
                    (
                        self.block_positions[i],
                        "Possible encryption/compression",
                        f"Entropy = {entropy:.2f}",
                    ),
                )
            elif entropy < 0.5:
                suspicious.append(
                    (
                        self.block_positions[i],
                        "Possible padding/null bytes",
                        f"Entropy = {entropy:.2f}",
                    ),
                )

        return suspicious

    def clear(self) -> None:
        """Clear the visualization.

        Resets all entropy data, clears the plot, and restores initial state.
        """
        self.file_data = None
        self.entropy_data = []
        self.block_positions = []
        self.entropy_curve.setData([], [])
        self.info_label.setText("No data loaded")


# Alias for backward compatibility
EntropyVisualizerWidget = EntropyVisualizer
