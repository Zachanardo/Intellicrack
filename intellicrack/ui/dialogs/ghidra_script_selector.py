"""Ghidra Script Selector Dialog

Provides a user-friendly interface for selecting and managing Ghidra scripts.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    Qt,
    QTextEdit,
    QTimer,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...utils.logger import get_logger
from ...utils.tools.ghidra_script_manager import GhidraScript, get_script_manager

logger = get_logger(__name__)


class ScriptInfoWidget(QWidget):
    """Widget to display detailed script information."""

    def __init__(self, parent=None):
        """Initialize the ScriptInfoWidget with default values."""
        super().__init__(parent)
        self.current_script = None
        self._init_ui()

    def _init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()

        # Script name label
        self.name_label = QLabel("Select a script")
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.name_label.setFont(font)
        layout.addWidget(self.name_label)

        # Metadata section
        metadata_group = QGroupBox("Script Information")
        metadata_layout = QVBoxLayout()

        self.author_label = QLabel("Author: -")
        self.category_label = QLabel("Category: -")
        self.version_label = QLabel("Version: -")
        self.type_label = QLabel("Type: -")
        self.modified_label = QLabel("Last Modified: -")
        self.size_label = QLabel("Size: -")

        metadata_layout.addWidget(self.author_label)
        metadata_layout.addWidget(self.category_label)
        metadata_layout.addWidget(self.version_label)
        metadata_layout.addWidget(self.type_label)
        metadata_layout.addWidget(self.modified_label)
        metadata_layout.addWidget(self.size_label)

        metadata_group.setLayout(metadata_layout)
        layout.addWidget(metadata_group)

        # Description section
        desc_group = QGroupBox("Description")
        desc_layout = QVBoxLayout()

        self.description_text = QTextEdit()
        self.description_text.setReadOnly(True)
        self.description_text.setMaximumHeight(100)
        desc_layout.addWidget(self.description_text)

        desc_group.setLayout(desc_layout)
        layout.addWidget(desc_group)

        # Validation status
        self.validation_group = QGroupBox("Validation Status")
        validation_layout = QVBoxLayout()

        self.validation_label = QLabel("Not validated")
        self.validation_errors = QTextEdit()
        self.validation_errors.setReadOnly(True)
        self.validation_errors.setMaximumHeight(80)
        self.validation_errors.hide()

        validation_layout.addWidget(self.validation_label)
        validation_layout.addWidget(self.validation_errors)

        self.validation_group.setLayout(validation_layout)
        layout.addWidget(self.validation_group)

        # Tags
        self.tags_label = QLabel("Tags: None")
        layout.addWidget(self.tags_label)

        layout.addStretch()
        self.setLayout(layout)

    def update_script_info(self, script: GhidraScript | None):
        """Update displayed information for a script."""
        self.current_script = script

        if not script:
            self.name_label.setText("Select a script")
            self.author_label.setText("Author: -")
            self.category_label.setText("Category: -")
            self.version_label.setText("Version: -")
            self.type_label.setText("Type: -")
            self.modified_label.setText("Last Modified: -")
            self.size_label.setText("Size: -")
            self.description_text.clear()
            self.validation_label.setText("Not validated")
            self.validation_errors.hide()
            self.tags_label.setText("Tags: None")
            return

        # Update all fields
        self.name_label.setText(script.name)
        self.author_label.setText(f"Author: {script.author}")
        self.category_label.setText(f"Category: {script.category}")
        self.version_label.setText(f"Version: {script.version}")
        self.type_label.setText(f"Type: {script.type.upper()}")
        self.modified_label.setText(
            f"Last Modified: {script.last_modified.strftime('%Y-%m-%d %H:%M')}"
        )

        # Format size
        size_kb = script.size / 1024
        if size_kb < 1:
            size_str = f"{script.size} bytes"
        else:
            size_str = f"{size_kb:.1f} KB"
        self.size_label.setText(f"Size: {size_str}")

        self.description_text.setText(script.description)

        # Validation status
        if script.is_valid:
            self.validation_label.setText("✓ Valid script")
            self.validation_label.setStyleSheet("color: green;")
            self.validation_errors.hide()
        else:
            self.validation_label.setText("✗ Invalid script")
            self.validation_label.setStyleSheet("color: red;")
            self.validation_errors.setText("\n".join(script.validation_errors))
            self.validation_errors.show()

        # Tags
        if script.tags:
            self.tags_label.setText(f"Tags: {', '.join(script.tags)}")
        else:
            self.tags_label.setText("Tags: None")


class GhidraScriptSelector(QDialog):
    """Dialog for selecting Ghidra scripts."""

    # Signal emitted when a script is selected
    #: Emits script path (type: str)
    script_selected = pyqtSignal(str)

    def __init__(self, parent=None, show_invalid=False):
        """Initialize the GhidraScriptSelector with default values."""
        super().__init__(parent)
        self.script_manager = get_script_manager()
        self.show_invalid = show_invalid
        self.selected_script_path = None
        self._search_timer = None

        self.setWindowTitle("Select Ghidra Script")
        self.setModal(True)
        self.resize(900, 600)

        self._init_ui()
        self._load_scripts()

    def _init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()

        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search scripts by name, description, or tags...")
        self.search_input.textChanged.connect(self._on_search_changed)
        search_layout.addWidget(self.search_input)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh_scripts)
        search_layout.addWidget(self.refresh_btn)

        layout.addLayout(search_layout)

        # Main content splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left side - Script tree
        left_widget = QWidget()
        left_layout = QVBoxLayout()

        # Category filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Category:"))

        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.category_filter.currentTextChanged.connect(self._on_category_changed)
        filter_layout.addWidget(self.category_filter)

        self.show_invalid_check = QCheckBox("Show invalid scripts")
        self.show_invalid_check.setChecked(self.show_invalid)
        self.show_invalid_check.stateChanged.connect(self._on_show_invalid_changed)
        filter_layout.addWidget(self.show_invalid_check)

        left_layout.addLayout(filter_layout)

        # Script tree
        self.script_tree = QTreeWidget()
        self.script_tree.setHeaderLabels(["Script", "Type", "Status"])
        self.script_tree.itemSelectionChanged.connect(self._on_selection_changed)
        self.script_tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        left_layout.addWidget(self.script_tree)

        # Buttons for script management
        btn_layout = QHBoxLayout()

        self.add_script_btn = QPushButton("Add Script...")
        self.add_script_btn.clicked.connect(self._add_user_script)
        btn_layout.addWidget(self.add_script_btn)

        self.open_folder_btn = QPushButton("Open Scripts Folder")
        self.open_folder_btn.clicked.connect(self._open_scripts_folder)
        btn_layout.addWidget(self.open_folder_btn)

        left_layout.addLayout(btn_layout)

        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)

        # Right side - Script info
        self.info_widget = ScriptInfoWidget()
        splitter.addWidget(self.info_widget)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

        # Dialog buttons
        button_layout = QHBoxLayout()

        self.select_btn = QPushButton("Select")
        self.select_btn.setEnabled(False)
        self.select_btn.clicked.connect(self._on_select_clicked)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)

        # Add default script button
        self.use_default_btn = QPushButton("Use Default Analysis")
        self.use_default_btn.setToolTip("Use the default AdvancedAnalysis.java script")
        self.use_default_btn.clicked.connect(self._use_default_script)

        button_layout.addWidget(self.use_default_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.select_btn)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def _load_scripts(self):
        """Load and display scripts."""
        # Clear tree
        self.script_tree.clear()
        self.category_filter.clear()
        self.category_filter.addItem("All Categories")

        # Scan for scripts
        self.script_manager.scan_scripts()

        # Get categories
        categories_dict = self.script_manager.get_scripts_by_category()

        # Populate category filter
        for category in sorted(categories_dict.keys()):
            self.category_filter.addItem(category)

        # Populate tree
        self._populate_tree()

    def _populate_tree(self):
        """Populate the script tree based on current filters."""
        self.script_tree.clear()

        # Get current filters
        search_text = self.search_input.text().lower()
        selected_category = self.category_filter.currentText()

        # Get scripts
        if search_text:
            # Search mode
            scripts = self.script_manager.search_scripts(search_text)

            for script in scripts:
                if not self.show_invalid and not script.is_valid:
                    continue

                if selected_category != "All Categories" and script.category != selected_category:
                    continue

                self._add_script_item(script)
        else:
            # Category mode
            categories_dict = self.script_manager.get_scripts_by_category()

            if selected_category == "All Categories":
                # Show all categories
                for category, scripts in sorted(categories_dict.items()):
                    if not scripts:
                        continue

                    # Create category item
                    category_item = QTreeWidgetItem([category, "", ""])
                    category_item.setExpanded(True)
                    font = category_item.font(0)
                    font.setBold(True)
                    category_item.setFont(0, font)

                    # Add scripts
                    has_scripts = False
                    for script in scripts:
                        if not self.show_invalid and not script.is_valid:
                            continue

                        script_item = self._create_script_item(script)
                        category_item.addChild(script_item)
                        has_scripts = True

                    if has_scripts:
                        self.script_tree.addTopLevelItem(category_item)
            # Show single category
            elif selected_category in categories_dict:
                for script in categories_dict[selected_category]:
                    if not self.show_invalid and not script.is_valid:
                        continue

                    self._add_script_item(script)

        # Resize columns
        for i in range(3):
            self.script_tree.resizeColumnToContents(i)

    def _add_script_item(self, script: GhidraScript):
        """Add a script item to the tree."""
        item = self._create_script_item(script)
        self.script_tree.addTopLevelItem(item)

    def _create_script_item(self, script: GhidraScript):
        """Create a tree item for a script."""
        status = "✓ Valid" if script.is_valid else "✗ Invalid"
        item = QTreeWidgetItem([script.name, script.type.upper(), status])

        # Store script path in item data
        item.setData(0, Qt.UserRole, script.path)

        # Set colors
        if script.is_valid:
            item.setForeground(2, Qt.darkGreen)
        else:
            item.setForeground(2, Qt.GlobalColor.red)
            # Make invalid scripts slightly grayed out
            for i in range(3):
                item.setForeground(i, Qt.GlobalColor.darkGray)

        # Set tooltip
        tooltip = f"{script.description}\n\nPath: {script.path}"
        item.setToolTip(0, tooltip)

        return item

    def _on_selection_changed(self):
        """Handle selection change."""
        items = self.script_tree.selectedItems()

        if not items:
            self.info_widget.update_script_info(None)
            self.select_btn.setEnabled(False)
            return

        item = items[0]

        # Check if it's a category item
        script_path = item.data(0, Qt.UserRole)
        if not script_path:
            self.info_widget.update_script_info(None)
            self.select_btn.setEnabled(False)
            return

        # Get script
        script = self.script_manager.get_script(script_path)
        if script:
            self.info_widget.update_script_info(script)
            self.select_btn.setEnabled(script.is_valid)
            self.selected_script_path = script_path
        else:
            self.info_widget.update_script_info(None)
            self.select_btn.setEnabled(False)

    def _on_search_changed(self, text):
        """Handle search text change."""
        _ = text
        # Debounce search with timer
        if hasattr(self, "_search_timer"):
            self._search_timer.stop()

        self._search_timer = QTimer()
        self._search_timer.timeout.connect(self._populate_tree)
        self._search_timer.setSingleShot(True)
        self._search_timer.start(300)  # 300ms delay

    def _on_category_changed(self, category):
        """Handle category filter change."""
        _ = category
        self._populate_tree()

    def _on_show_invalid_changed(self, state):
        """Handle show invalid checkbox change."""
        self.show_invalid = state == Qt.Checked
        self._populate_tree()

    def _on_item_double_clicked(self, item, column):
        """Handle double-click on item."""
        _ = column
        script_path = item.data(0, Qt.UserRole)
        if script_path:
            script = self.script_manager.get_script(script_path)
            if script and script.is_valid:
                self._on_select_clicked()

    def _on_select_clicked(self):
        """Handle select button click."""
        if self.selected_script_path:
            self.script_selected.emit(self.selected_script_path)
            self.accept()

    def _use_default_script(self):
        """Use the default AdvancedAnalysis.java script."""
        # Emit special marker for default script
        self.script_selected.emit("__DEFAULT__")
        self.accept()

    def _refresh_scripts(self):
        """Refresh the script list."""
        self.script_manager.scan_scripts(force_rescan=True)
        self._load_scripts()

    def _add_user_script(self):
        """Add a user script."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Ghidra Script",
            "",
            "Ghidra Scripts (*.java *.py);;Java Scripts (*.java);;Python Scripts (*.py)",
        )

        if not file_path:
            return

        # Add script
        script = self.script_manager.add_user_script(file_path)

        if script:
            QMessageBox.information(
                self,
                "Script Added",
                f"Script '{script.name}' has been added to user scripts.",
            )
            self._refresh_scripts()
        else:
            QMessageBox.warning(
                self,
                "Failed to Add Script",
                "The script could not be added. Please check that it's a valid Ghidra script.",
            )

    def _open_scripts_folder(self):
        """Open the user scripts folder."""
        user_scripts_dir = "intellicrack/intellicrack/scripts/ghidra/user"
        os.makedirs(user_scripts_dir, exist_ok=True)

        # Platform-specific file manager opening
        import platform
        import subprocess

        system = platform.system()
        try:
            if system == "Windows" and hasattr(os, "startfile"):
                os.startfile(user_scripts_dir)  # pylint: disable=no-member
            elif system == "Darwin":  # macOS
                subprocess.run(["open", user_scripts_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603, S607
            else:  # Linux and others
                subprocess.run(["xdg-open", user_scripts_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603, S607
        except Exception as e:
            logger.error(f"Failed to open folder: {e}")
            QMessageBox.warning(
                self,
                "Error",
                f"Could not open folder: {user_scripts_dir}\n\nError: {e!s}",
            )

    def get_selected_script(self) -> str | None:
        """Get the selected script path."""
        return self.selected_script_path
