"""
Binary Similarity Search Dialog 

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import json
import logging
import os
from typing import Any, Dict, List, Optional

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QSlider,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from ...core.analysis.binary_similarity_search import BinarySimilaritySearch
    HAS_SIMILARITY_SEARCH = True
except ImportError:
    HAS_SIMILARITY_SEARCH = False

__all__ = ['BinarySimilaritySearchDialog']


class BinarySimilaritySearchDialog(QDialog):
    """
    Dialog for searching and comparing binary files for similarity.

    Provides an interface to search for binaries with similar characteristics
    and apply patterns from similar cracking attempts.
    """

    def __init__(self, binary_path: str, parent=None):
        """
        Initialize the binary similarity search dialog.

        Args:
            binary_path: Path to the binary file to analyze
            parent: Parent widget
        """
        # Initialize UI attributes
        self.db_info_label = None
        self.threshold_label = None
        self.results_table = None
        self.patterns_view = None
        self.status_label = None

        super().__init__(parent)
        self.binary_path = binary_path
        self.database_path = os.path.join(os.getcwd(), "binary_database.json")
        self.similar_binaries: List[Dict[str, Any]] = []
        self.search_thread = None

        if HAS_SIMILARITY_SEARCH:
            self.search_engine = BinarySimilaritySearch(self.database_path)
        else:
            self.search_engine = None

        self.setWindowTitle("Binary Similarity Search")
        self.setGeometry(100, 100, 900, 700)
        self.setModal(True)

        self.init_ui()
        self.load_database_info()

    def init_ui(self) -> None:
        """Initialize the user interface."""
        layout = QVBoxLayout(self)

        # Header with binary info
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel(f"<b>Target Binary:</b> {os.path.basename(self.binary_path)}"))
        header_layout.addStretch()

        # Database info
        self.db_info_label = QLabel("Database: Loading...")
        header_layout.addWidget(self.db_info_label)

        layout.addLayout(header_layout)

        # Main splitter
        splitter = QSplitter(Qt.Vertical)

        # Top panel - Search controls and results
        top_panel = QWidget()
        top_layout = QVBoxLayout(top_panel)

        # Search controls
        controls_layout = QHBoxLayout()

        controls_layout.addWidget(QLabel("Similarity Threshold:"))

        self.threshold_slider = QSlider(Qt.Horizontal)
        self.threshold_slider.setMinimum(1)
        self.threshold_slider.setMaximum(10)
        self.threshold_slider.setValue(7)  # Default 0.7
        self.threshold_slider.setTickPosition(QSlider.TicksBelow)
        self.threshold_slider.setTickInterval(1)
        controls_layout.addWidget(self.threshold_slider)

        self.threshold_label = QLabel("0.7")
        controls_layout.addWidget(self.threshold_label)

        self.threshold_slider.valueChanged.connect(self.update_threshold_label)

        search_btn = QPushButton("Search Similar Binaries")
        search_btn.clicked.connect(self.search_similar_binaries)
        controls_layout.addWidget(search_btn)

        add_to_db_btn = QPushButton("Add to Database")
        add_to_db_btn.clicked.connect(self.add_to_database)
        controls_layout.addWidget(add_to_db_btn)

        top_layout.addLayout(controls_layout)

        # Results table
        top_layout.addWidget(QLabel("<b>Similar Binaries:</b>"))

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Binary", "Similarity", "Path", "Patterns"])
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_table.itemSelectionChanged.connect(self.result_selected)

        top_layout.addWidget(self.results_table)

        splitter.addWidget(top_panel)

        # Bottom panel - Pattern details
        bottom_panel = QWidget()
        bottom_layout = QVBoxLayout(bottom_panel)

        bottom_layout.addWidget(QLabel("<b>Cracking Patterns:</b>"))

        self.patterns_view = QTextEdit()
        self.patterns_view.setReadOnly(True)
        bottom_layout.addWidget(self.patterns_view)

        # Apply pattern button
        apply_layout = QHBoxLayout()
        apply_layout.addStretch()

        self.apply_pattern_btn = QPushButton("Apply Selected Pattern")
        self.apply_pattern_btn.clicked.connect(self.apply_selected_pattern)
        self.apply_pattern_btn.setEnabled(False)
        apply_layout.addWidget(self.apply_pattern_btn)

        bottom_layout.addLayout(apply_layout)

        splitter.addWidget(bottom_panel)

        # Set initial sizes
        splitter.setSizes([400, 300])

        layout.addWidget(splitter)

        # Bottom buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

        # Status bar
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def load_database_info(self) -> None:
        """Load database information."""
        try:
            if os.path.exists(self.database_path):
                with open(self.database_path, "r", encoding="utf-8") as f:
                    database = json.load(f)
                    binary_count = len(database.get("binaries", []))
                    self.db_info_label.setText(f"Database: {binary_count} binaries")
            else:
                self.db_info_label.setText("Database: Not found (will be created)")
        except (OSError, ValueError, RuntimeError) as e:
            self.db_info_label.setText(f"Database Error: {e}")

    def update_threshold_label(self, value: int) -> None:
        """Update the threshold label when slider changes."""
        threshold = value / 10.0
        self.threshold_label.setText(f"{threshold:.1f}")

    def search_similar_binaries(self) -> None:
        """Search for similar binaries."""
        if not self.search_engine:
            QMessageBox.warning(
                self, "Error",
                "Binary similarity search engine not available. "
                "Please ensure all dependencies are installed."
            )
            return

        threshold = self.threshold_slider.value() / 10.0
        self.status_label.setText(f"Searching for similar binaries (threshold: {threshold:.1f})...")

        # Use QThread to avoid freezing the UI
        class SearchThread(QThread):
            """Thread for running binary similarity searches in the background."""
            result_signal = pyqtSignal(list)

            def __init__(self, search_engine, binary_path: str, threshold: float):
                super().__init__()
                self.search_engine = search_engine
                self.binary_path = binary_path
                self.threshold = threshold

            def run(self):
                """Execute binary similarity search in a separate thread."""
                try:
                    results = self.search_engine.search_similar_binaries(self.binary_path, self.threshold)
                    self.result_signal.emit(results)
                except (OSError, ValueError, RuntimeError) as e:
                    logging.error("Binary similarity search failed: %s", e)
                    # Emit empty list on error
                    self.result_signal.emit([])

        # Create and start thread
        self.search_thread = SearchThread(self.search_engine, self.binary_path, threshold)
        self.search_thread.result_signal.connect(self.show_search_results)
        self.search_thread.start()

    def show_search_results(self, results: List[Dict[str, Any]]) -> None:
        """Show search results in the table."""
        self.similar_binaries = results
        self.results_table.setRowCount(len(results))

        for i, result in enumerate(results):
            path = result.get("path", "")
            similarity = result.get("similarity", 0)
            patterns = result.get("cracking_patterns", [])

            self.results_table.setItem(i, 0, QTableWidgetItem(os.path.basename(path)))
            self.results_table.setItem(i, 1, QTableWidgetItem(f"{similarity:.2f}"))
            self.results_table.setItem(i, 2, QTableWidgetItem(path))
            self.results_table.setItem(i, 3, QTableWidgetItem(f"{len(patterns)} patterns"))

        if results:
            self.status_label.setText(f"Found {len(results)} similar binaries")
        else:
            self.status_label.setText("No similar binaries found")

    def result_selected(self) -> None:
        """Handle result selection in the table."""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            self.patterns_view.clear()
            self.apply_pattern_btn.setEnabled(False)
            return

        row = selected_rows[0].row()
        if row < 0 or row >= len(self.similar_binaries):
            return

        result = self.similar_binaries[row]
        patterns = result.get("cracking_patterns", [])

        if patterns:
            patterns_text = f"Cracking patterns for {os.path.basename(result.get('path', ''))}:\n\n"

            for i, pattern in enumerate(patterns):
                patterns_text += f"Pattern {i+1}:\n"
                patterns_text += f"{pattern}\n\n"

            self.patterns_view.setText(patterns_text)
            self.apply_pattern_btn.setEnabled(True)
        else:
            self.patterns_view.setText("No cracking patterns available for this binary")
            self.apply_pattern_btn.setEnabled(False)

    def apply_selected_pattern(self) -> None:
        """Apply the selected cracking pattern."""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if row < 0 or row >= len(self.similar_binaries):
            return

        result = self.similar_binaries[row]
        patterns = result.get("cracking_patterns", [])

        if not patterns:
            return

        # If multiple patterns, ask which one to apply
        pattern_to_apply = None
        if len(patterns) > 1:
            pattern_items = [f"Pattern {_i+1}" for _i in range(len(patterns))]
            pattern_index, ok = QInputDialog.getItem(
                self, "Select Pattern", "Choose a pattern to apply:", pattern_items, 0, False)

            if ok and pattern_index:
                index = pattern_items.index(pattern_index)
                pattern_to_apply = patterns[index]
        else:
            pattern_to_apply = patterns[0]

        if pattern_to_apply:
            # Ask for confirmation
            response = QMessageBox.question(
                self,
                "Apply Pattern",
                "Apply pattern from this similar binary?\n\nThis will attempt to apply the cracking pattern to your binary.",
                QMessageBox.Yes | QMessageBox.No
            )

            if response == QMessageBox.Yes:
                try:
                    # Get the parent app instance
                    parent = self.parent()

                    if parent and hasattr(parent, "apply_cracking_pattern"):
                        # Get the source binary path from the selected result
                        source_binary = result.get("path", "")
                        target_binary = self.binary_path

                        # Call the parent's apply_cracking_pattern method
                        parent.apply_cracking_pattern(source_binary, target_binary)
                        self.status_label.setText("Applied cracking pattern from similar binary")
                    else:
                        # Fallback: display the pattern for manual application
                        QMessageBox.information(
                            self, "Pattern Information",
                            f"Pattern from similar binary:\n\n{pattern_to_apply}\n\n"
                            "Please apply this pattern manually using the patch editor."
                        )
                        self.status_label.setText("Pattern displayed for manual application")

                except (OSError, ValueError, RuntimeError) as e:
                    QMessageBox.critical(self, "Error", f"Error applying pattern: {e}")

    def add_to_database(self) -> None:
        """Add the current binary to the similarity database."""
        if not self.search_engine:
            QMessageBox.warning(
                self, "Error",
                "Binary similarity search engine not available. "
                "Please ensure all dependencies are installed."
            )
            return

        # Ask for cracking patterns
        patterns_text, ok = QInputDialog.getMultiLineText(
            self,
            "Add to Database",
            "Enter cracking patterns for this binary (optional):",
            ""
        )

        if not ok:
            return

        patterns = []
        if patterns_text.strip():
            patterns = [patterns_text.strip()]

        # Add to database
        try:
            success = self.search_engine.add_binary(self.binary_path, patterns)

            if success:
                QMessageBox.information(
                    self,
                    "Success",
                    f"Added {os.path.basename(self.binary_path)} to the database"
                )
                self.load_database_info()
            else:
                QMessageBox.warning(
                    self,
                    "Error",
                    "Failed to add binary to database"
                )
        except (OSError, ValueError, RuntimeError) as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Error adding binary to database: {e}"
            )

    def get_selected_pattern(self) -> Optional[str]:
        """
        Get the currently selected pattern.

        Returns:
            Selected pattern text or None if no pattern selected
        """
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            return None

        row = selected_rows[0].row()
        if row < 0 or row >= len(self.similar_binaries):
            return None

        result = self.similar_binaries[row]
        patterns = result.get("cracking_patterns", [])

        if patterns:
            return patterns[0]  # Return first pattern

        return None

    def get_search_results(self) -> List[Dict[str, Any]]:
        """
        Get the current search results.

        Returns:
            List of similar binary results
        """
        return self.similar_binaries.copy()


def create_similarity_search_dialog(binary_path: str, parent=None) -> BinarySimilaritySearchDialog:
    """
    Factory function to create a BinarySimilaritySearchDialog.

    Args:
        binary_path: Path to binary for similarity search
        parent: Parent widget

    Returns:
        Configured dialog instance
    """
    return BinarySimilaritySearchDialog(binary_path, parent)
