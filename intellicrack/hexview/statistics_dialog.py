"""Statistical Analysis Dialog for Hex Viewer.

This dialog provides an interface for displaying statistical analysis
of the current file or selected data.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
)

from ..utils.logger import get_logger
from .statistics import StatisticsCalculator

logger = get_logger(__name__)


class StatisticsWorker(QThread):
    """Worker thread for statistics calculation."""

    progress = pyqtSignal(int, int)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, data: bytes | None = None, file_path: str | None = None):
        """Initialize worker.

        Args:
            data: Binary data to process
            file_path: Path to file (if processing file instead of data)

        """
        super().__init__()
        self.data = data
        self.file_path = file_path
        self.calculator = StatisticsCalculator()
        self.calculator.set_progress_callback(self._progress_callback)

    def _progress_callback(self, current: int, total: int):
        """Progress callback for calculator.

        Args:
            current: Current progress
            total: Total items

        """
        self.progress.emit(current, total)

    def run(self):
        """Run statistics calculation."""
        try:
            # Get data if file path provided
            if self.data is None and self.file_path:
                with open(self.file_path, "rb") as f:
                    self.data = f.read()

            if self.data is None:
                raise ValueError("No data to analyze")

            # Calculate statistics
            results = self.calculator.calculate_all(self.data)
            self.result.emit(results)

        except Exception as e:
            self.error.emit(str(e))
            logger.error(f"Statistics calculation failed: {e}")


class StatisticsDialog(QDialog):
    """Dialog for displaying statistical analysis."""

    def __init__(self, parent=None, hex_viewer=None):
        """Initialize statistics dialog.

        Args:
            parent: Parent widget
            hex_viewer: Reference to hex viewer widget

        """
        super().__init__(parent)
        self.hex_viewer = hex_viewer
        self.worker = None
        self.init_ui()
        self.setWindowTitle("Statistical Analysis")
        self.resize(700, 600)

    def init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()

        # Data source selection
        source_group = QGroupBox("Data Source")
        source_layout = QVBoxLayout()

        self.entire_file_radio = QRadioButton("Entire file")
        self.entire_file_radio.setChecked(True)
        source_layout.addWidget(self.entire_file_radio)

        self.selection_radio = QRadioButton("Current selection")
        self.selection_radio.setEnabled(False)  # Will be enabled if selection exists
        source_layout.addWidget(self.selection_radio)

        # Check if there's a selection
        if self.hex_viewer and hasattr(self.hex_viewer, 'selection_start'):
            if self.hex_viewer.selection_start != -1 and self.hex_viewer.selection_end != -1:
                self.selection_radio.setEnabled(True)
                selection_size = self.hex_viewer.selection_end - self.hex_viewer.selection_start
                self.selection_radio.setText(f"Current selection ({selection_size} bytes)")

        source_group.setLayout(source_layout)
        layout.addWidget(source_group)

        # Tab widget for results
        self.tabs = QTabWidget()

        # Overview tab
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setFont(self.font())
        self.tabs.addTab(self.overview_text, "Overview")

        # Distribution tab
        self.distribution_text = QTextEdit()
        self.distribution_text.setReadOnly(True)
        self.distribution_text.setFont(self.font())
        self.tabs.addTab(self.distribution_text, "Distribution")

        # Patterns tab
        self.patterns_text = QTextEdit()
        self.patterns_text.setReadOnly(True)
        self.patterns_text.setFont(self.font())
        self.tabs.addTab(self.patterns_text, "Patterns")

        # File Type tab
        self.file_type_text = QTextEdit()
        self.file_type_text.setReadOnly(True)
        self.file_type_text.setFont(self.font())
        self.tabs.addTab(self.file_type_text, "File Type Analysis")

        layout.addWidget(self.tabs)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Dialog buttons
        button_box = QDialogButtonBox()

        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.analyze_data)
        button_box.addButton(self.analyze_btn, QDialogButtonBox.ButtonRole.ActionRole)

        self.copy_btn = QPushButton("Copy Results")
        self.copy_btn.clicked.connect(self.copy_results)
        self.copy_btn.setEnabled(False)
        button_box.addButton(self.copy_btn, QDialogButtonBox.ButtonRole.ActionRole)

        close_btn = button_box.addButton(QDialogButtonBox.StandardButton.Close)
        close_btn.clicked.connect(self.close)

        layout.addWidget(button_box)

        self.setLayout(layout)

    def analyze_data(self):
        """Start statistical analysis."""
        # Clear previous results
        self.overview_text.clear()
        self.distribution_text.clear()
        self.patterns_text.clear()
        self.file_type_text.clear()
        self.copy_btn.setEnabled(False)

        # Determine data source
        data = None
        file_path = None

        if self.selection_radio.isChecked() and self.selection_radio.isEnabled():
            # Get selected data
            if self.hex_viewer:
                start = self.hex_viewer.selection_start
                end = self.hex_viewer.selection_end
                if start != -1 and end != -1:
                    data = self.hex_viewer.file_handler.read_data(start, end - start)
                    if data is None:
                        self.overview_text.setPlainText("Failed to read selected data.")
                        return
                else:
                    self.overview_text.setPlainText("No selection available.")
                    return
            else:
                self.overview_text.setPlainText("Hex viewer not available.")
                return
        else:
            # Use entire file
            if self.hex_viewer and hasattr(self.hex_viewer, 'file_handler'):
                if hasattr(self.hex_viewer.file_handler, 'file_path'):
                    file_path = self.hex_viewer.file_handler.file_path
                else:
                    # Read entire file into memory
                    file_size = self.hex_viewer.file_handler.file_size
                    data = self.hex_viewer.file_handler.read_data(0, file_size)
                    if data is None:
                        self.overview_text.setPlainText("Failed to read file data.")
                        return
            else:
                self.overview_text.setPlainText("No file loaded.")
                return

        # Show progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(7)
        self.analyze_btn.setEnabled(False)

        # Create and start worker thread
        self.worker = StatisticsWorker(data, file_path)
        self.worker.progress.connect(self.update_progress)
        self.worker.result.connect(self.display_results)
        self.worker.error.connect(self.display_error)
        self.worker.start()

    def update_progress(self, current: int, total: int):
        """Update progress bar.

        Args:
            current: Current progress
            total: Total items

        """
        self.progress_bar.setValue(current)

    def display_results(self, results: dict):
        """Display analysis results.

        Args:
            results: Dictionary of analysis results

        """
        # Format overview
        overview = "Statistical Analysis Results\n"
        overview += "=" * 50 + "\n\n"

        # Data source info
        if self.selection_radio.isChecked() and self.selection_radio.isEnabled():
            if self.hex_viewer:
                start = self.hex_viewer.selection_start
                end = self.hex_viewer.selection_end
                overview += f"Data: Selection (offset {start:#x} to {end:#x})\n"
        else:
            if self.hex_viewer and hasattr(self.hex_viewer.file_handler, 'file_path'):
                overview += f"File: {self.hex_viewer.file_handler.file_path}\n"

        overview += f"Size: {results['size']} bytes\n\n"

        # Basic statistics
        overview += "Basic Statistics:\n"
        overview += f"  Entropy: {results['entropy']:.4f} bits ({results['entropy_percentage']:.1f}%)\n"
        overview += f"  Randomness Score: {results['randomness_score']:.1f}%\n"
        overview += f"  Compression Ratio: {results['compression_ratio']:.3f}\n"
        overview += f"  Chi-Square: {results['chi_square']:.2f}\n\n"

        overview += "Byte Statistics:\n"
        overview += f"  Min Byte: {results['min_byte']:#04x}\n"
        overview += f"  Max Byte: {results['max_byte']:#04x}\n"
        overview += f"  Mean Byte: {results['mean_byte']:.2f}\n\n"

        overview += "Character Types:\n"
        overview += f"  Null Bytes: {results['null_bytes']} ({results['null_percentage']:.1f}%)\n"
        overview += f"  Printable: {results['printable_chars']} ({results['printable_percentage']:.1f}%)\n"
        overview += f"  Control: {results['control_chars']} ({results['control_percentage']:.1f}%)\n"
        overview += f"  High Bytes: {results['high_bytes']} ({results['high_bytes_percentage']:.1f}%)\n"

        self.overview_text.setPlainText(overview)

        # Format distribution
        distribution = "Byte Distribution Histogram\n"
        distribution += "=" * 50 + "\n\n"

        if "histogram" in results:
            max_count = max(count for _, count in results["histogram"]) if results["histogram"] else 1
            for range_label, count in results["histogram"]:
                bar_len = int((count / max_count) * 40) if max_count > 0 else 0
                bar = "█" * bar_len
                distribution += f"{range_label:8s}: {bar} {count}\n"

        self.distribution_text.setPlainText(distribution)

        # Format patterns
        patterns = "Repeating Patterns\n"
        patterns += "=" * 50 + "\n\n"

        if "patterns" in results and results["patterns"]:
            for pattern, count in results["patterns"]:
                # Display pattern as hex
                hex_pattern = " ".join(f"{b:02X}" for b in pattern[:16])
                if len(pattern) > 16:
                    hex_pattern += "..."
                patterns += f"Pattern: {hex_pattern}\n"
                patterns += f"  Length: {len(pattern)} bytes\n"
                patterns += f"  Count: {count} occurrences\n\n"
        else:
            patterns += "No significant repeating patterns found.\n"

        self.patterns_text.setPlainText(patterns)

        # Format file type analysis
        file_type = "File Type Analysis\n"
        file_type += "=" * 50 + "\n\n"

        if "file_type_hints" in results and results["file_type_hints"]:
            file_type += "Detected Characteristics:\n"
            for hint in results["file_type_hints"]:
                file_type += f"  • {hint}\n"
        else:
            file_type += "No specific file type characteristics detected.\n"

        file_type += "\n\nEntropy Analysis:\n"
        entropy_val = results.get('entropy', 0)
        if entropy_val > 7.5:
            file_type += "  Very high entropy - likely encrypted or compressed\n"
        elif entropy_val > 6.5:
            file_type += "  High entropy - possibly compressed data\n"
        elif entropy_val > 5.0:
            file_type += "  Medium entropy - binary data or mixed content\n"
        elif entropy_val > 3.0:
            file_type += "  Low-medium entropy - structured data\n"
        else:
            file_type += "  Low entropy - likely text or highly structured data\n"

        self.file_type_text.setPlainText(file_type)

        # Enable copy button
        self.copy_btn.setEnabled(True)

        # Hide progress bar
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)

    def display_error(self, error: str):
        """Display error message.

        Args:
            error: Error message

        """
        self.overview_text.setPlainText(f"Error: {error}")
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)

    def copy_results(self):
        """Copy results to clipboard."""
        # Combine all tabs into one text
        text = "=== OVERVIEW ===\n"
        text += self.overview_text.toPlainText() + "\n\n"
        text += "=== DISTRIBUTION ===\n"
        text += self.distribution_text.toPlainText() + "\n\n"
        text += "=== PATTERNS ===\n"
        text += self.patterns_text.toPlainText() + "\n\n"
        text += "=== FILE TYPE ANALYSIS ===\n"
        text += self.file_type_text.toPlainText()

        if text:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(text)

            # Show brief confirmation
            original_text = self.copy_btn.text()
            self.copy_btn.setText("Copied!")
            QThread.msleep(1000)
            self.copy_btn.setText(original_text)
