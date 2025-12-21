"""Checksum/Hash Calculation Dialog for Hex Viewer.

This dialog provides an interface for calculating various checksums and hashes
for the current file or selected data.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..utils.logger import get_logger
from .checksums import ChecksumCalculator, calculate_checksum_chunked


logger = get_logger(__name__)


class ChecksumWorker(QThread):
    """Worker thread for checksum calculation."""

    progress = pyqtSignal(int, int)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, data: bytes | None = None, file_path: str | None = None) -> None:
        """Initialize worker.

        Args:
            data: Binary data to process
            file_path: Path to file (if processing file instead of data)

        """
        super().__init__()
        self.data = data
        self.file_path = file_path
        self.algorithms: list[str] = []
        self.calculator = ChecksumCalculator()
        self.calculator.set_progress_callback(self._progress_callback)

    def set_algorithms(self, algorithms: list[str]) -> None:
        """Set algorithms to calculate.

        Args:
            algorithms: List of algorithm names

        """
        self.algorithms = algorithms

    def _progress_callback(self, current: int, total: int) -> None:
        """Progress callback for calculator.

        Args:
            current: Current progress
            total: Total items

        """
        self.progress.emit(current, total)

    def run(self) -> None:
        """Run checksum calculation.

        Raises:
            ValueError: If neither data nor file path is provided

        """
        try:
            results = {}

            if self.data is not None:
                # Calculate for in-memory data
                results = self.calculator.calculate_selection(self.data, self.algorithms)
            elif self.file_path:
                # Calculate for file
                for algorithm in self.algorithms:
                    try:
                        result = calculate_checksum_chunked(self.file_path, algorithm)
                        results[algorithm] = result
                    except Exception as e:
                        results[algorithm] = f"Error: {e}"
                        logger.exception("Failed to calculate %s: %s", algorithm, e)
            else:
                error_msg = "No data or file path provided"
                logger.error(error_msg)
                raise ValueError(error_msg)

            self.result.emit(results)

        except Exception as e:
            self.error.emit(str(e))
            logger.exception("Checksum calculation failed: %s", e)


class ChecksumDialog(QDialog):
    """Dialog for calculating checksums and hashes."""

    def __init__(self, parent: QWidget | None = None, hex_viewer: object | None = None) -> None:
        """Initialize checksum dialog.

        Args:
            parent: Parent widget
            hex_viewer: Reference to hex viewer widget

        """
        super().__init__(parent)
        self.hex_viewer = hex_viewer
        self.worker: ChecksumWorker | None = None
        self.init_ui()
        self.setWindowTitle("Calculate Checksums")
        self.resize(600, 500)

    def init_ui(self) -> None:
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
        if (
            self.hex_viewer
            and hasattr(self.hex_viewer, "selection_start")
            and hasattr(self.hex_viewer, "selection_end")
            and (getattr(self.hex_viewer, "selection_start", -1) != -1 and getattr(self.hex_viewer, "selection_end", -1) != -1)
        ):
            self.selection_radio.setEnabled(True)
            selection_start = getattr(self.hex_viewer, "selection_start", 0)
            selection_end = getattr(self.hex_viewer, "selection_end", 0)
            selection_size = selection_end - selection_start
            self.selection_radio.setText(f"Current selection ({selection_size} bytes)")

        source_group.setLayout(source_layout)
        layout.addWidget(source_group)

        # Algorithm selection
        algo_group = QGroupBox("Algorithms")
        algo_layout = QVBoxLayout()

        # Quick select buttons
        button_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_algorithms)
        button_layout.addWidget(select_all_btn)

        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(self.select_no_algorithms)
        button_layout.addWidget(select_none_btn)

        button_layout.addStretch()
        algo_layout.addLayout(button_layout)

        # Algorithm checkboxes
        self.algorithm_checkboxes = {}
        algorithms = ["CRC-16", "CRC-32", "MD5", "SHA-1", "SHA-256", "SHA-512"]

        algo_grid_layout = QHBoxLayout()
        left_column = QVBoxLayout()
        right_column = QVBoxLayout()

        for i, algo in enumerate(algorithms):
            checkbox = QCheckBox(algo)
            checkbox.setChecked(True)  # Default to all selected
            self.algorithm_checkboxes[algo] = checkbox

            if i < 3:
                left_column.addWidget(checkbox)
            else:
                right_column.addWidget(checkbox)

        algo_grid_layout.addLayout(left_column)
        algo_grid_layout.addLayout(right_column)
        algo_grid_layout.addStretch()

        algo_layout.addLayout(algo_grid_layout)
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # Results area
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(self.font())  # Use monospace if available
        results_layout.addWidget(self.results_text)

        # Copy button
        copy_layout = QHBoxLayout()
        self.copy_btn = QPushButton("Copy Results")
        self.copy_btn.clicked.connect(self.copy_results)
        self.copy_btn.setEnabled(False)
        copy_layout.addWidget(self.copy_btn)
        copy_layout.addStretch()
        results_layout.addLayout(copy_layout)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Dialog buttons
        button_box = QDialogButtonBox()

        self.calculate_btn: QPushButton = QPushButton("Calculate")
        self.calculate_btn.clicked.connect(self.calculate_checksums)
        button_box.addButton(self.calculate_btn, QDialogButtonBox.ButtonRole.ActionRole)

        close_btn = button_box.addButton(QDialogButtonBox.StandardButton.Close)
        if close_btn is not None:
            close_btn.clicked.connect(self.close)

        layout.addWidget(button_box)

        self.setLayout(layout)

    def select_all_algorithms(self) -> None:
        """Select all algorithm checkboxes."""
        for checkbox in self.algorithm_checkboxes.values():
            checkbox.setChecked(True)

    def select_no_algorithms(self) -> None:
        """Deselect all algorithm checkboxes."""
        for checkbox in self.algorithm_checkboxes.values():
            checkbox.setChecked(False)

    def get_selected_algorithms(self) -> list[str]:
        """Get list of selected algorithms.

        Returns:
            List of algorithm names

        """
        return [algo for algo, checkbox in self.algorithm_checkboxes.items() if checkbox.isChecked()]

    def calculate_checksums(self) -> None:
        """Start checksum calculation."""
        # Get selected algorithms
        algorithms = self.get_selected_algorithms()
        if not algorithms:
            self.results_text.setPlainText("No algorithms selected.")
            return

        # Clear previous results
        self.results_text.clear()
        self.copy_btn.setEnabled(False)

        # Determine data source
        data = None
        file_path = None

        if self.selection_radio.isChecked() and self.selection_radio.isEnabled():
            # Get selected data
            if self.hex_viewer:
                start = getattr(self.hex_viewer, "selection_start", -1)
                end = getattr(self.hex_viewer, "selection_end", -1)
                if start != -1 and end != -1:
                    if file_handler := getattr(
                        self.hex_viewer, "file_handler", None
                    ):
                        data = file_handler.read_data(start, end - start)
                        if data is None:
                            self.results_text.setPlainText("Failed to read selected data.")
                            return
                else:
                    self.results_text.setPlainText("No selection available.")
                    return
            else:
                self.results_text.setPlainText("Hex viewer not available.")
                return
        elif self.hex_viewer and hasattr(self.hex_viewer, "file_handler"):
            file_handler = getattr(self.hex_viewer, "file_handler", None)
            if file_handler and hasattr(file_handler, "file_path"):
                file_path = getattr(file_handler, "file_path", None)
            else:
                # Read entire file into memory
                if file_handler:
                    file_size = getattr(file_handler, "file_size", 0)
                    data = file_handler.read_data(0, file_size)
                    if data is None:
                        self.results_text.setPlainText("Failed to read file data.")
                        return
        else:
            self.results_text.setPlainText("No file loaded.")
            return

        # Show progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(len(algorithms))
        self.calculate_btn.setEnabled(False)

        # Create and start worker thread
        self.worker = ChecksumWorker(data, file_path)
        if self.worker is not None:
            self.worker.set_algorithms(algorithms)
            self.worker.progress.connect(self.update_progress)
            self.worker.result.connect(self.display_results)
            self.worker.error.connect(self.display_error)
            self.worker.start()

    def update_progress(self, current: int, total: int) -> None:
        """Update progress bar.

        Args:
            current: Current progress
            total: Total items

        """
        self.progress_bar.setValue(current)

    def display_results(self, results: dict[str, str]) -> None:
        """Display calculation results.

        Args:
            results: Dictionary of algorithm names and results

        """
        # Format results
        text = "Checksum/Hash Results\n"
        text += "=" * 50 + "\n\n"

        # Determine data source info
        if self.selection_radio.isChecked() and self.selection_radio.isEnabled():
            if self.hex_viewer:
                start = getattr(self.hex_viewer, "selection_start", 0)
                end = getattr(self.hex_viewer, "selection_end", 0)
                text += f"Data: Selection (offset {start:#x} to {end:#x})\n"
                text += f"Size: {end - start} bytes\n\n"
        elif self.hex_viewer:
            file_handler = getattr(self.hex_viewer, "file_handler", None)
            if file_handler and hasattr(file_handler, "file_path"):
                file_path = getattr(file_handler, "file_path", "Unknown")
                file_size = getattr(file_handler, "file_size", 0)
                text += f"File: {file_path}\n"
                text += f"Size: {file_size} bytes\n\n"

        # Add results
        for algo, result in results.items():
            text += f"{algo:10s}: {result}\n"

        self.results_text.setPlainText(text)

        # Enable copy button
        self.copy_btn.setEnabled(True)

        # Hide progress bar
        self.progress_bar.setVisible(False)
        self.calculate_btn.setEnabled(True)

    def display_error(self, error: str) -> None:
        """Display error message.

        Args:
            error: Error message

        """
        self.results_text.setPlainText(f"Error: {error}")
        self.progress_bar.setVisible(False)
        self.calculate_btn.setEnabled(True)

    def copy_results(self) -> None:
        """Copy results to clipboard."""
        if text := self.results_text.toPlainText():
            from PyQt6.QtWidgets import QApplication

            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(text)

                # Show brief confirmation
                original_text = self.copy_btn.text()
                self.copy_btn.setText("Copied!")
                QThread.msleep(1000)
                self.copy_btn.setText(original_text)
