"""
Code Modification Dialog with Diff Viewer

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

from pathlib import Path
from typing import List

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PyQt5.QtWidgets import (
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...ai.intelligent_code_modifier import CodeChange, IntelligentCodeModifier, ModificationRequest
from ...ai.llm_backends import LLMManager
from ...utils.logger import get_logger

logger = get_logger(__name__)


class DiffSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for diff text."""

    def __init__(self, parent=None):
        super().__init__(parent)

        # Define colors for different diff elements
        self.formats = {}

        # Added lines (green)
        added_format = QTextCharFormat()
        added_format.setBackground(QColor(200, 255, 200))
        added_format.setForeground(QColor(0, 128, 0))
        self.formats['added'] = added_format

        # Deleted lines (red)
        deleted_format = QTextCharFormat()
        deleted_format.setBackground(QColor(255, 200, 200))
        deleted_format.setForeground(QColor(128, 0, 0))
        self.formats['deleted'] = deleted_format

        # Context lines (gray)
        context_format = QTextCharFormat()
        context_format.setForeground(QColor(128, 128, 128))
        self.formats['context'] = context_format

        # Header lines (blue)
        header_format = QTextCharFormat()
        header_format.setForeground(QColor(0, 0, 255))
        header_format.setFontWeight(QFont.Bold)
        self.formats['header'] = header_format

    def highlightBlock(self, text):
        """Highlight a block of diff text."""
        if not text:
            return

        if text.startswith('+++') or text.startswith('---'):
            self.setFormat(0, len(text), self.formats['header'])
        elif text.startswith('@@'):
            self.setFormat(0, len(text), self.formats['header'])
        elif text.startswith('+'):
            self.setFormat(0, len(text), self.formats['added'])
        elif text.startswith('-'):
            self.setFormat(0, len(text), self.formats['deleted'])
        elif text.startswith(' '):
            self.setFormat(0, len(text), self.formats['context'])


class ModificationAnalysisThread(QThread):
    """Thread for analyzing modification requests."""

    analysis_complete = pyqtSignal(list)  # List of CodeChange objects
    progress_updated = pyqtSignal(str)    # Progress message
    error_occurred = pyqtSignal(str)      # Error message

    def __init__(self, modifier: IntelligentCodeModifier, request: ModificationRequest):
        super().__init__()
        self.modifier = modifier
        self.request = request

    def run(self):
        """Run the analysis in background."""
        try:
            self.progress_updated.emit("Analyzing modification request...")
            changes = self.modifier.analyze_modification_request(self.request)
            self.analysis_complete.emit(changes)
        except Exception as e:
            self.error_occurred.emit(str(e))


class CodeModificationDialog(QDialog):
    """Dialog for intelligent code modification with diff viewing."""

    def __init__(self, project_root: str = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Intelligent Code Modification")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        # Initialize components
        self.project_root = project_root or str(Path.cwd())
        self.llm_manager = LLMManager()
        self.modifier = IntelligentCodeModifier(self.llm_manager)
        self.current_changes = []
        self.selected_changes = set()

        # Analysis thread
        self.analysis_thread = None

        self.setup_ui()
        self.load_project_context()

    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Main tabs
        tabs = QTabWidget()

        # Request tab
        request_tab = QWidget()
        self.setup_request_tab(request_tab)
        tabs.addTab(request_tab, "Modification Request")

        # Changes tab
        changes_tab = QWidget()
        self.setup_changes_tab(changes_tab)
        tabs.addTab(changes_tab, "Code Changes")

        # History tab
        history_tab = QWidget()
        self.setup_history_tab(history_tab)
        tabs.addTab(history_tab, "History")

        layout.addWidget(tabs)

        # Status bar
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)

        status_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        status_layout.addWidget(close_btn)

        layout.addLayout(status_layout)

    def setup_request_tab(self, tab_widget):
        """Set up the modification request tab."""
        layout = QVBoxLayout(tab_widget)

        # Request form
        form_group = QGroupBox("Modification Request")
        form_layout = QFormLayout(form_group)

        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(100)
        self.description_edit.setPlaceholderText("Describe what modifications you want to make...")
        form_layout.addRow("Description:", self.description_edit)

        # Target files
        files_layout = QHBoxLayout()

        self.target_files_list = QListWidget()
        self.target_files_list.setMaximumHeight(100)
        files_layout.addWidget(self.target_files_list)

        files_buttons_layout = QVBoxLayout()

        add_file_btn = QPushButton("Add File")
        add_file_btn.clicked.connect(self.add_target_file)
        files_buttons_layout.addWidget(add_file_btn)

        remove_file_btn = QPushButton("Remove")
        remove_file_btn.clicked.connect(self.remove_target_file)
        files_buttons_layout.addWidget(remove_file_btn)

        files_buttons_layout.addStretch()
        files_layout.addLayout(files_buttons_layout)

        form_layout.addRow("Target Files:", files_layout)

        # Requirements
        self.requirements_edit = QTextEdit()
        self.requirements_edit.setMaximumHeight(80)
        self.requirements_edit.setPlaceholderText("Enter requirements (one per line)...")
        form_layout.addRow("Requirements:", self.requirements_edit)

        # Constraints
        self.constraints_edit = QTextEdit()
        self.constraints_edit.setMaximumHeight(80)
        self.constraints_edit.setPlaceholderText("Enter constraints (one per line)...")
        form_layout.addRow("Constraints:", self.constraints_edit)

        layout.addWidget(form_group)

        # Analysis controls
        controls_layout = QHBoxLayout()

        self.analyze_btn = QPushButton("Analyze Modifications")
        self.analyze_btn.clicked.connect(self.analyze_modifications)
        controls_layout.addWidget(self.analyze_btn)

        self.clear_btn = QPushButton("Clear Request")
        self.clear_btn.clicked.connect(self.clear_request)
        controls_layout.addWidget(self.clear_btn)

        controls_layout.addStretch()

        # Project context info
        context_btn = QPushButton("Refresh Project Context")
        context_btn.clicked.connect(self.load_project_context)
        controls_layout.addWidget(context_btn)

        layout.addLayout(controls_layout)

        # Project context display
        context_group = QGroupBox("Project Context")
        context_layout = QVBoxLayout(context_group)

        self.context_info = QTextBrowser()
        self.context_info.setMaximumHeight(200)
        context_layout.addWidget(self.context_info)

        layout.addWidget(context_group)

    def setup_changes_tab(self, tab_widget):
        """Set up the code changes review tab."""
        layout = QVBoxLayout(tab_widget)

        # Main splitter
        main_splitter = QSplitter(Qt.Horizontal)

        # Left panel: Changes list
        left_panel = QFrame()
        left_panel.setFrameStyle(QFrame.StyledPanel)
        left_panel.setMaximumWidth(400)
        left_layout = QVBoxLayout(left_panel)

        left_layout.addWidget(QLabel("Proposed Changes"))

        self.changes_tree = QTreeWidget()
        self.changes_tree.setHeaderLabels([
            "Change", "File", "Type", "Confidence", "Status"
        ])
        self.changes_tree.setAlternatingRowColors(True)
        self.changes_tree.itemSelectionChanged.connect(self.on_change_selected)
        left_layout.addWidget(self.changes_tree)

        # Change controls
        controls_layout = QHBoxLayout()

        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.clicked.connect(self.select_all_changes)
        controls_layout.addWidget(self.select_all_btn)

        self.select_none_btn = QPushButton("Select None")
        self.select_none_btn.clicked.connect(self.select_no_changes)
        controls_layout.addWidget(self.select_none_btn)

        left_layout.addLayout(controls_layout)

        # Apply/Reject controls
        apply_layout = QHBoxLayout()

        self.apply_btn = QPushButton("Apply Selected")
        self.apply_btn.clicked.connect(self.apply_selected_changes)
        apply_layout.addWidget(self.apply_btn)

        self.reject_btn = QPushButton("Reject Selected")
        self.reject_btn.clicked.connect(self.reject_selected_changes)
        apply_layout.addWidget(self.reject_btn)

        left_layout.addLayout(apply_layout)

        main_splitter.addWidget(left_panel)

        # Right panel: Diff viewer
        right_panel = QFrame()
        right_panel.setFrameStyle(QFrame.StyledPanel)
        right_layout = QVBoxLayout(right_panel)

        # Change details
        details_group = QGroupBox("Change Details")
        details_layout = QVBoxLayout(details_group)

        self.change_details = QTextBrowser()
        self.change_details.setMaximumHeight(150)
        details_layout.addWidget(self.change_details)

        right_layout.addWidget(details_group)

        # Diff viewer
        diff_group = QGroupBox("Code Diff")
        diff_layout = QVBoxLayout(diff_group)

        # Diff view tabs
        self.diff_tabs = QTabWidget()

        # Unified diff
        self.unified_diff = QPlainTextEdit()
        self.unified_diff.setReadOnly(True)
        self.unified_diff.setFont(QFont("Consolas", 10))
        self.diff_highlighter = DiffSyntaxHighlighter(self.unified_diff.document())
        self.diff_tabs.addTab(self.unified_diff, "Unified Diff")

        # Side-by-side diff
        side_by_side_widget = QWidget()
        side_layout = QHBoxLayout(side_by_side_widget)

        # Original code
        original_group = QGroupBox("Original")
        original_layout = QVBoxLayout(original_group)
        self.original_code = QPlainTextEdit()
        self.original_code.setReadOnly(True)
        self.original_code.setFont(QFont("Consolas", 10))
        original_layout.addWidget(self.original_code)
        side_layout.addWidget(original_group)

        # Modified code
        modified_group = QGroupBox("Modified")
        modified_layout = QVBoxLayout(modified_group)
        self.modified_code = QPlainTextEdit()
        self.modified_code.setReadOnly(True)
        self.modified_code.setFont(QFont("Consolas", 10))
        modified_layout.addWidget(self.modified_code)
        side_layout.addWidget(modified_group)

        self.diff_tabs.addTab(side_by_side_widget, "Side by Side")

        diff_layout.addWidget(self.diff_tabs)
        right_layout.addWidget(diff_group)

        main_splitter.addWidget(right_panel)

        # Set splitter proportions
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)

        layout.addWidget(main_splitter)

    def setup_history_tab(self, tab_widget):
        """Set up the modification history tab."""
        layout = QVBoxLayout(tab_widget)

        # Controls
        controls_layout = QHBoxLayout()

        refresh_btn = QPushButton("Refresh History")
        refresh_btn.clicked.connect(self.refresh_history)
        controls_layout.addWidget(refresh_btn)

        controls_layout.addStretch()

        self.history_limit = QSpinBox()
        self.history_limit.setRange(10, 500)
        self.history_limit.setValue(50)
        controls_layout.addWidget(QLabel("Limit:"))
        controls_layout.addWidget(self.history_limit)

        layout.addLayout(controls_layout)

        # History tree
        self.history_tree = QTreeWidget()
        self.history_tree.setHeaderLabels([
            "Change ID", "File", "Description", "Type", "Status", "Confidence", "Date"
        ])

        header = self.history_tree.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

        self.history_tree.setAlternatingRowColors(True)
        layout.addWidget(self.history_tree)

    def load_project_context(self):
        """Load project context information."""
        try:
            self.status_label.setText("Loading project context...")

            # Gather context
            context = self.modifier.gather_project_context(self.project_root)

            # Display context info
            context_text = f"Project Root: {self.project_root}\n"
            context_text += f"Files Analyzed: {len(context)}\n\n"

            # Group by language
            languages = {}
            total_functions = 0
            total_classes = 0

            for file_path, file_context in context.items():
                lang = file_context.language
                if lang not in languages:
                    languages[lang] = []
                languages[lang].append(file_path)
                total_functions += len(file_context.functions)
                total_classes += len(file_context.classes)

            context_text += f"Total Functions: {total_functions}\n"
            context_text += f"Total Classes: {total_classes}\n\n"

            context_text += "Languages:\n"
            for lang, files in languages.items():
                context_text += f"  {lang}: {len(files)} files\n"

            self.context_info.setPlainText(context_text)
            self.status_label.setText("Project context loaded")

        except Exception as e:
            logger.error(f"Failed to load project context: {e}")
            self.status_label.setText("Failed to load project context")
            QMessageBox.warning(self, "Error", f"Failed to load project context:\n{e}")

    def add_target_file(self):
        """Add a target file to the request."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Target File", self.project_root,
            "Python Files (*.py);;JavaScript Files (*.js);;All Files (*)"
        )

        if file_path:
            # Make path relative to project root
            try:
                rel_path = Path(file_path).relative_to(self.project_root)
                self.target_files_list.addItem(str(rel_path))
            except ValueError:
                # File is outside project root
                self.target_files_list.addItem(file_path)

    def remove_target_file(self):
        """Remove selected target file."""
        current_row = self.target_files_list.currentRow()
        if current_row >= 0:
            self.target_files_list.takeItem(current_row)

    def clear_request(self):
        """Clear the modification request form."""
        self.description_edit.clear()
        self.target_files_list.clear()
        self.requirements_edit.clear()
        self.constraints_edit.clear()

    def analyze_modifications(self):
        """Analyze the modification request."""
        # Validate input
        description = self.description_edit.toPlainText().strip()
        if not description:
            QMessageBox.information(self, "Info", "Please enter a description.")
            return

        target_files = []
        for i in range(self.target_files_list.count()):
            file_path = self.target_files_list.item(i).text()
            if not Path(file_path).is_absolute():
                file_path = str(Path(self.project_root) / file_path)
            target_files.append(file_path)

        if not target_files:
            QMessageBox.information(self, "Info", "Please add at least one target file.")
            return

        # Create request
        requirements = [
            req.strip() for req in self.requirements_edit.toPlainText().split('\n')
            if req.strip()
        ]
        constraints = [
            constraint.strip() for constraint in self.constraints_edit.toPlainText().split('\n')
            if constraint.strip()
        ]

        request = self.modifier.create_modification_request(
            description=description,
            target_files=target_files,
            requirements=requirements,
            constraints=constraints
        )

        # Start analysis in background
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate

        self.analysis_thread = ModificationAnalysisThread(self.modifier, request)
        self.analysis_thread.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_thread.progress_updated.connect(self.status_label.setText)
        self.analysis_thread.error_occurred.connect(self.on_analysis_error)
        self.analysis_thread.start()

    def on_analysis_complete(self, changes: List[CodeChange]):
        """Handle completion of analysis."""
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        self.current_changes = changes
        self.populate_changes_tree()

        self.status_label.setText(f"Analysis complete. Found {len(changes)} potential changes.")

        if changes:
            # Switch to changes tab
            parent_widget = self.parent()
            if hasattr(parent_widget, 'setCurrentIndex'):
                parent_widget.setCurrentIndex(1)  # Changes tab

    def on_analysis_error(self, error_message: str):
        """Handle analysis error."""
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        self.status_label.setText("Analysis failed")
        QMessageBox.critical(self, "Analysis Error", f"Failed to analyze modifications:\n{error_message}")

    def populate_changes_tree(self):
        """Populate the changes tree with current changes."""
        self.changes_tree.clear()

        for change in self.current_changes:
            item = QTreeWidgetItem()

            # Create checkbox for selection
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Unchecked)

            # Set data
            item.setText(0, change.change_id)
            item.setText(1, Path(change.file_path).name)
            item.setText(2, change.modification_type.value)
            item.setText(3, f"{change.confidence:.2f}")
            item.setText(4, change.status.value)

            # Store change reference
            item.setData(0, Qt.UserRole, change)

            # Color code by confidence
            if change.confidence < 0.5:
                item.setBackground(0, QColor(255, 200, 200))  # Red for low confidence
            elif change.confidence < 0.7:
                item.setBackground(0, QColor(255, 255, 200))  # Yellow for medium confidence
            else:
                item.setBackground(0, QColor(200, 255, 200))  # Green for high confidence

            self.changes_tree.addTopLevelItem(item)

        # Resize columns
        for i in range(self.changes_tree.columnCount()):
            self.changes_tree.resizeColumnToContents(i)

    def on_change_selected(self):
        """Handle change selection."""
        current_item = self.changes_tree.currentItem()
        if not current_item:
            return

        change = current_item.data(0, Qt.UserRole)
        if not change:
            return

        # Update change details
        details_text = f"""
<h3>{change.description}</h3>
<p><b>File:</b> {change.file_path}</p>
<p><b>Type:</b> {change.modification_type.value}</p>
<p><b>Lines:</b> {change.start_line}-{change.end_line}</p>
<p><b>Confidence:</b> {change.confidence:.2f}</p>
<p><b>Status:</b> {change.status.value}</p>

<h4>Reasoning:</h4>
<p>{change.reasoning}</p>

<h4>Impact Analysis:</h4>
<p>{change.impact_analysis.get('impact', 'No impact analysis available')}</p>
"""
        self.change_details.setHtml(details_text)

        # Update diff views
        unified_diff = self.modifier.diff_generator.generate_unified_diff(
            change.original_code,
            change.modified_code,
            Path(change.file_path).name
        )
        self.unified_diff.setPlainText(unified_diff)

        # Update side-by-side view
        self.original_code.setPlainText(change.original_code)
        self.modified_code.setPlainText(change.modified_code)

    def select_all_changes(self):
        """Select all changes."""
        for i in range(self.changes_tree.topLevelItemCount()):
            item = self.changes_tree.topLevelItem(i)
            item.setCheckState(0, Qt.Checked)

    def select_no_changes(self):
        """Deselect all changes."""
        for i in range(self.changes_tree.topLevelItemCount()):
            item = self.changes_tree.topLevelItem(i)
            item.setCheckState(0, Qt.Unchecked)

    def get_selected_change_ids(self) -> List[str]:
        """Get IDs of selected changes."""
        change_ids = []
        for i in range(self.changes_tree.topLevelItemCount()):
            item = self.changes_tree.topLevelItem(i)
            if item.checkState(0) == Qt.Checked:
                change = item.data(0, Qt.UserRole)
                if change:
                    change_ids.append(change.change_id)
        return change_ids

    def apply_selected_changes(self):
        """Apply the selected changes."""
        change_ids = self.get_selected_change_ids()
        if not change_ids:
            QMessageBox.information(self, "Info", "Please select changes to apply.")
            return

        # Confirm application
        reply = QMessageBox.question(
            self, "Confirm Application",
            f"Apply {len(change_ids)} selected changes?\n\n"
            "This will modify the files. Backups will be created.",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        try:
            self.status_label.setText("Applying changes...")
            results = self.modifier.apply_changes(change_ids, create_backup=True)

            # Show results
            applied = len(results["applied"])
            failed = len(results["failed"])

            if failed == 0:
                QMessageBox.information(
                    self, "Success",
                    f"Successfully applied {applied} changes.\n\n"
                    f"Backups created: {len(results['backups_created'])}"
                )
            else:
                error_details = "\n".join(results["errors"])
                QMessageBox.warning(
                    self, "Partial Success",
                    f"Applied {applied} changes, {failed} failed.\n\n"
                    f"Errors:\n{error_details}"
                )

            # Refresh display
            self.populate_changes_tree()
            self.status_label.setText("Changes applied")

        except Exception as e:
            logger.error(f"Error applying changes: {e}")
            QMessageBox.critical(self, "Error", f"Error applying changes:\n{e}")
            self.status_label.setText("Error applying changes")

    def reject_selected_changes(self):
        """Reject the selected changes."""
        change_ids = self.get_selected_change_ids()
        if not change_ids:
            QMessageBox.information(self, "Info", "Please select changes to reject.")
            return

        try:
            results = self.modifier.reject_changes(change_ids)
            rejected = len(results["rejected"])

            QMessageBox.information(self, "Success", f"Rejected {rejected} changes.")

            # Refresh display
            self.populate_changes_tree()
            self.status_label.setText(f"Rejected {rejected} changes")

        except Exception as e:
            logger.error(f"Error rejecting changes: {e}")
            QMessageBox.critical(self, "Error", f"Error rejecting changes:\n{e}")

    def refresh_history(self):
        """Refresh the modification history."""
        try:
            limit = self.history_limit.value()
            history = self.modifier.get_modification_history(limit)

            self.history_tree.clear()

            for record in history:
                item = QTreeWidgetItem()
                item.setText(0, record["change_id"])
                item.setText(1, Path(record["file_path"]).name)
                item.setText(2, record["description"][:50] + "..." if len(record["description"]) > 50 else record["description"])
                item.setText(3, record["type"])
                item.setText(4, record["status"])
                item.setText(5, f"{record['confidence']:.2f}")
                item.setText(6, record["created_at"][:19])  # Remove microseconds

                # Color code by status
                status = record["status"]
                if status == "applied":
                    item.setBackground(0, QColor(200, 255, 200))  # Green
                elif status == "rejected":
                    item.setBackground(0, QColor(255, 200, 200))  # Red
                elif status == "failed":
                    item.setBackground(0, QColor(255, 128, 128))  # Dark red

                self.history_tree.addTopLevelItem(item)

            self.status_label.setText(f"Loaded {len(history)} history records")

        except Exception as e:
            logger.error(f"Error refreshing history: {e}")
            QMessageBox.critical(self, "Error", f"Error refreshing history:\n{e}")

    def closeEvent(self, event):
        """Handle dialog close."""
        # Cancel any running analysis
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_thread.terminate()
            self.analysis_thread.wait(1000)

        event.accept()
