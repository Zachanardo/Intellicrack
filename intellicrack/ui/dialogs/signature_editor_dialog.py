"""ICP Signature Editor Dialog.

Provides comprehensive signature creation and editing capabilities for the
Intellicrack Protection Engine (ICP). Allows users to create custom signatures,
modify existing ones, and test signatures against sample files.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import re
import time
from pathlib import Path

from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QColor,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStandardItem,
    QCloseEvent,
    QStandardItemModel,
    QSyntaxHighlighter,
    Qt,
    QTableView,
    QTabWidget,
    QTextCharFormat,
    QTextDocument,
    QTextEdit,
    QThread,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
    pyqtSlot,
)

from ...protection.unified_protection_engine import get_unified_engine
from ...utils.logger import get_logger


logger = get_logger(__name__)


class SignatureSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for ICP signature format."""

    def __init__(self, parent: QTextDocument) -> None:
        """Initialize the SignatureSyntaxHighlighter with default values.

        Args:
            parent: The QTextDocument to apply syntax highlighting to.
        """
        super().__init__(parent)
        self.highlighting_rules = []

        # Define colors
        keyword_color = QColor(86, 156, 214)  # Blue
        string_color = QColor(206, 145, 120)  # Orange
        comment_color = QColor(106, 153, 85)  # Green
        number_color = QColor(181, 206, 168)  # Light green
        operator_color = QColor(212, 212, 212)  # Light gray

        # Keyword patterns
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(keyword_color)
        keyword_format.setFontWeight(QFont.Weight.Bold)

        keywords = [
            "init",
            "ep",
            "section",
            "header",
            "overlay",
            "entrypoint",
            "size",
            "version",
            "options",
            "name",
            "type",
            "comment",
        ]

        for keyword in keywords:
            pattern = f"\\b{keyword}\\b"
            self.highlighting_rules.append((re.compile(pattern), keyword_format))

        # String patterns (quoted text)
        string_format = QTextCharFormat()
        string_format.setForeground(string_color)
        self.highlighting_rules.append((re.compile(r'"[^"]*"'), string_format))
        self.highlighting_rules.append((re.compile(r"'[^']*'"), string_format))

        # Comment patterns
        comment_format = QTextCharFormat()
        comment_format.setForeground(comment_color)
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((re.compile(r"//.*"), comment_format))
        self.highlighting_rules.append((re.compile(r"/\*.*\*/"), comment_format))

        # Hex patterns
        hex_format = QTextCharFormat()
        hex_format.setForeground(number_color)
        self.highlighting_rules.append((re.compile(r"\b[0-9A-Fa-f]{2,}\b"), hex_format))

        # Operators
        operator_format = QTextCharFormat()
        operator_format.setForeground(operator_color)
        operators = ["=", ":", "{", "}", "(", ")", "[", "]", "|", "&", "!"]
        for op in operators:
            escaped_op = re.escape(op)
            self.highlighting_rules.append((re.compile(escaped_op), operator_format))

    def highlightBlock(self, text: str | None) -> None:
        """Apply syntax highlighting to a block of text.

        Args:
            text: The text block to highlight, or None to skip.
        """
        if text is None:
            return
        for pattern, fmt in self.highlighting_rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, fmt)


class SignatureTestWorker(QThread):
    """Worker thread for testing signatures against files."""

    #: file_path, success, result, execution_time (type: str, bool, str, float)
    test_completed = pyqtSignal(str, bool, str, float)
    #: progress, current_file (type: int, str)
    progress_update = pyqtSignal(int, str)

    def __init__(self, signature_content: str, test_files: list[str]) -> None:
        """Initialize the SignatureTestWorker with default values.

        Args:
            signature_content: The signature content to test.
            test_files: List of file paths to test the signature against.
        """
        super().__init__()
        self.signature_content = signature_content
        self.test_files = test_files
        self.unified_engine = get_unified_engine()
        self.logger = logger

    def run(self) -> None:
        """Run signature tests.

        Tests the signature against all configured test files and emits
        progress and completion signals.
        """
        for i, file_path in enumerate(self.test_files):
            try:
                # Update progress
                progress = int((i / len(self.test_files)) * 100)
                self.progress_update.emit(progress, os.path.basename(file_path))

                # Test signature against file
                result = self._test_signature_on_file(file_path)

                # Emit result with execution time
                self.test_completed.emit(
                    file_path,
                    result["success"],
                    result["message"],
                    result.get("execution_time", 0.0),
                )

            except Exception as e:
                self.logger.exception("Exception in signature_editor_dialog: %s", e)
                self.test_completed.emit(file_path, False, f"Error: {e!s}", 0.0)

        # Final progress update
        self.progress_update.emit(100, "Complete")

    def _test_signature_on_file(self, file_path: str) -> dict[str, object]:
        """Test signature against a single file.

        Args:
            file_path: Path to the file to test.

        Returns:
            Dictionary with keys 'success' (bool), 'message' (str),
            and 'execution_time' (float).
        """
        test_start_time = time.time()
        try:
            # Create temporary signature file
            temp_sig_path = os.path.join(os.path.dirname(file_path), "temp_test_signature.sg")

            with open(temp_sig_path, "w", encoding="utf-8") as f:
                f.write(self.signature_content)

            # Analyze file with custom signature
            # Note: Custom signatures need to be loaded through the engine configuration
            result = self.unified_engine.analyze_file(
                file_path,
                deep_scan=True,
            )

            # Clean up temp file
            try:
                os.remove(temp_sig_path)
            except Exception as e:
                logger.debug("Failed to remove temporary signature file: %s", e)

            # Calculate execution time
            execution_time = time.time() - test_start_time

            # Check if signature detected something
            if result and result.icp_analysis:
                for detection in result.icp_analysis.all_detections:
                    if detection.name != "Unknown":
                        return {
                            "success": True,
                            "message": f"Detected: {detection.name} (confidence: {detection.confidence:.1%})",
                            "execution_time": execution_time,
                        }

            return {
                "success": False,
                "message": "Signature did not match this file",
                "execution_time": execution_time,
            }

        except Exception as e:
            execution_time = time.time() - test_start_time
            logger.exception("Exception in signature_editor_dialog: %s", e)
            return {
                "success": False,
                "message": f"Test failed: {e!s}",
                "execution_time": execution_time,
            }


class SignatureEditorDialog(QDialog):
    """Run signature editor dialog."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the signature editor dialog with UI components and data structures.

        Args:
            parent: Optional parent widget for the dialog.
        """
        super().__init__(parent)
        self.setWindowTitle("ICP Signature Editor")
        self.setModal(True)
        self.resize(1200, 800)

        # Logger
        self.logger = logger

        # Data
        self.current_signature_path: str | None = None
        self.signature_databases: dict[str, str] = {}  # name -> path
        self.current_signatures: list[dict[str, str]] = []
        self.test_worker: SignatureTestWorker | None = None
        self._category_selections: dict[str, str] = {}

        # UI Components
        self.signature_list: QListWidget
        self.signature_editor: QTextEdit
        self.syntax_highlighter: SignatureSyntaxHighlighter
        self.test_results_table: QTableView
        self.test_results_model: QStandardItemModel
        self.db_combo: QComboBox
        self.search_input: QLineEdit
        self.sig_info_text: QTextEdit
        self.sig_name_input: QLineEdit
        self.sig_type_combo: QComboBox
        self.sig_version_input: QLineEdit
        self.sig_description_input: QLineEdit
        self.test_files_list: QListWidget
        self.test_summary_label: QLabel
        self.template_category_list: QListWidget
        self.template_list: QListWidget
        self.template_preview: QTextEdit
        self.run_test_btn: QPushButton
        self.stop_test_btn: QPushButton
        self.new_sig_btn: QPushButton
        self.load_sig_btn: QPushButton
        self.save_sig_btn: QPushButton
        self.add_db_btn: QPushButton
        self.refresh_btn: QPushButton
        self.validate_btn: QPushButton
        self.format_btn: QPushButton
        self.insert_template_btn: QPushButton
        self.add_test_file_btn: QPushButton
        self.add_test_folder_btn: QPushButton
        self.clear_test_files_btn: QPushButton
        self.insert_template_to_editor_btn: QPushButton

        self.init_ui()
        self.load_signature_databases()

    def init_ui(self) -> None:
        """Initialize the user interface.

        Creates and arranges all UI components including toolbars, panels,
        and dialog buttons.
        """
        layout = QVBoxLayout()

        # Toolbar
        toolbar = self._create_toolbar()
        layout.addLayout(toolbar)

        # Main content area
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel: Signature browser
        left_panel = self._create_signature_browser()
        main_splitter.addWidget(left_panel)

        # Right panel: Editor and testing
        right_panel = self._create_editor_panel()
        main_splitter.addWidget(right_panel)

        # Set splitter proportions
        main_splitter.setSizes([300, 900])
        layout.addWidget(main_splitter)

        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Close,
        )
        button_box.accepted.connect(self.save_signature)
        button_box.rejected.connect(self.close)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def _create_toolbar(self) -> QHBoxLayout:
        """Create toolbar with main actions.

        Returns:
            QHBoxLayout: Horizontal layout containing toolbar buttons and controls.
        """
        layout = QHBoxLayout()

        # Database selection
        layout.addWidget(QLabel("Database:"))
        self.db_combo = QComboBox()
        self.db_combo.currentTextChanged.connect(self._on_db_combo_changed)
        layout.addWidget(self.db_combo)

        layout.addWidget(QLabel("|"))

        # File operations
        self.new_sig_btn = QPushButton("New Signature")
        self.new_sig_btn.clicked.connect(self.new_signature)
        layout.addWidget(self.new_sig_btn)

        self.load_sig_btn = QPushButton("Load Signature")
        self.load_sig_btn.clicked.connect(self.load_signature_file)
        layout.addWidget(self.load_sig_btn)

        self.save_sig_btn = QPushButton("Save Signature")
        self.save_sig_btn.clicked.connect(self.save_signature)
        layout.addWidget(self.save_sig_btn)

        layout.addWidget(QLabel("|"))

        # Database operations
        self.add_db_btn = QPushButton("Add Database")
        self.add_db_btn.clicked.connect(self.add_signature_database)
        layout.addWidget(self.add_db_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_signatures)
        layout.addWidget(self.refresh_btn)

        layout.addStretch()
        return layout

    def _on_db_combo_changed(self, text: str) -> None:
        """Handle database combo box change.

        Args:
            text: The newly selected database name.
        """
        self.load_signatures_from_database(text)

    def _create_signature_browser(self) -> QWidget:
        """Create signature browser panel.

        Returns:
            QWidget: Widget containing the signature browser UI.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Search
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.textChanged.connect(self._on_search_input_changed)
        self.search_input.setToolTip("Enter text to filter signatures by name")
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)

        # Signature list
        self.signature_list = QListWidget()
        self.signature_list.itemClicked.connect(self.load_signature_from_list)
        self.signature_list.setAlternatingRowColors(True)
        layout.addWidget(self.signature_list)

        # Signature info
        info_group = QGroupBox("Signature Info")
        info_layout = QVBoxLayout()

        self.sig_info_text = QTextEdit()
        self.sig_info_text.setReadOnly(True)
        self.sig_info_text.setMaximumHeight(150)
        self.sig_info_text.setFont(QFont("Consolas", 9))
        info_layout.addWidget(self.sig_info_text)

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        widget.setLayout(layout)
        return widget

    def _on_search_input_changed(self, text: str) -> None:
        """Handle search input change.

        Args:
            text: The current search input text.
        """
        self.filter_signatures(text)

    def _create_editor_panel(self) -> QWidget:
        """Create editor and testing panel.

        Returns:
            QWidget: Widget containing editor and testing tabs.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Tab widget for editor and testing
        tab_widget = QTabWidget()

        # Editor tab
        editor_tab = self._create_editor_tab()
        tab_widget.addTab(editor_tab, "Signature Editor")

        # Testing tab
        testing_tab = self._create_testing_tab()
        tab_widget.addTab(testing_tab, "Signature Testing")

        # Template tab
        template_tab = self._create_template_tab()
        tab_widget.addTab(template_tab, "Templates")

        layout.addWidget(tab_widget)
        widget.setLayout(layout)
        return widget

    def _create_editor_tab(self) -> QWidget:
        """Create signature editor tab.

        Returns:
            QWidget: Widget containing the signature editor UI.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Signature metadata
        metadata_group = QGroupBox("Signature Metadata")
        metadata_layout = QVBoxLayout()

        # Basic info
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("Name:"))
        self.sig_name_input = QLineEdit()
        info_layout.addWidget(self.sig_name_input)

        info_layout.addWidget(QLabel("Type:"))
        self.sig_type_combo = QComboBox()
        self.sig_type_combo.addItems(
            [
                "Packer",
                "Protector",
                "Compiler",
                "Installer",
                "Cryptor",
                "Virus",
                "Trojan",
                "Other",
            ],
        )
        info_layout.addWidget(self.sig_type_combo)

        info_layout.addWidget(QLabel("Version:"))
        self.sig_version_input = QLineEdit()
        info_layout.addWidget(self.sig_version_input)

        metadata_layout.addLayout(info_layout)

        # Description
        desc_layout = QHBoxLayout()
        desc_layout.addWidget(QLabel("Description:"))
        self.sig_description_input = QLineEdit()
        desc_layout.addWidget(self.sig_description_input)
        metadata_layout.addLayout(desc_layout)

        metadata_group.setLayout(metadata_layout)
        layout.addWidget(metadata_group)

        # Signature content editor
        editor_group = QGroupBox("Signature Content")
        editor_layout = QVBoxLayout()

        # Editor toolbar
        editor_toolbar = QHBoxLayout()

        self.validate_btn = QPushButton("Validate Syntax")
        self.validate_btn.clicked.connect(self.validate_signature_syntax)
        editor_toolbar.addWidget(self.validate_btn)

        self.format_btn = QPushButton("Format")
        self.format_btn.clicked.connect(self.format_signature)
        editor_toolbar.addWidget(self.format_btn)

        self.insert_template_btn = QPushButton("Insert Template")
        self.insert_template_btn.clicked.connect(self.show_template_menu)
        editor_toolbar.addWidget(self.insert_template_btn)

        editor_toolbar.addStretch()
        editor_layout.addLayout(editor_toolbar)

        # Text editor
        self.signature_editor = QTextEdit()
        self.signature_editor.setFont(QFont("Consolas", 11))
        self.signature_editor.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        if signature_doc := self.signature_editor.document():
            self.syntax_highlighter = SignatureSyntaxHighlighter(signature_doc)

        editor_layout.addWidget(self.signature_editor)
        editor_group.setLayout(editor_layout)
        layout.addWidget(editor_group)

        widget.setLayout(layout)
        return widget

    def _create_testing_tab(self) -> QWidget:
        """Create signature testing tab.

        Returns:
            QWidget: Widget containing the signature testing UI.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Test setup
        setup_group = QGroupBox("Test Setup")
        setup_layout = QVBoxLayout()

        # Test files selection
        files_layout = QHBoxLayout()
        files_layout.addWidget(QLabel("Test Files:"))

        self.test_files_list = QListWidget()
        self.test_files_list.setMaximumHeight(100)
        files_layout.addWidget(self.test_files_list)

        files_btn_layout = QVBoxLayout()
        self.add_test_file_btn = QPushButton("Add File")
        self.add_test_file_btn.clicked.connect(self.add_test_file)
        files_btn_layout.addWidget(self.add_test_file_btn)

        self.add_test_folder_btn = QPushButton("Add Folder")
        self.add_test_folder_btn.clicked.connect(self.add_test_folder)
        files_btn_layout.addWidget(self.add_test_folder_btn)

        self.clear_test_files_btn = QPushButton("Clear")
        self.clear_test_files_btn.clicked.connect(self.clear_test_files)
        files_btn_layout.addWidget(self.clear_test_files_btn)

        files_layout.addLayout(files_btn_layout)
        setup_layout.addLayout(files_layout)

        # Test controls
        test_controls = QHBoxLayout()
        self.run_test_btn = QPushButton("Run Tests")
        self.run_test_btn.clicked.connect(self.run_signature_tests)
        test_controls.addWidget(self.run_test_btn)

        self.stop_test_btn = QPushButton("Stop Tests")
        self.stop_test_btn.clicked.connect(self.stop_signature_tests)
        self.stop_test_btn.setEnabled(False)
        test_controls.addWidget(self.stop_test_btn)

        test_controls.addStretch()
        setup_layout.addLayout(test_controls)

        setup_group.setLayout(setup_layout)
        layout.addWidget(setup_group)

        # Test results
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout()

        # Results table
        self.test_results_model = QStandardItemModel()
        self.test_results_model.setHorizontalHeaderLabels(
            [
                "File",
                "Result",
                "Message",
                "File Size",
                "Time",
            ],
        )

        self.test_results_table = QTableView()
        self.test_results_table.setModel(self.test_results_model)
        self.test_results_table.setAlternatingRowColors(True)
        self.test_results_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)

        if header := self.test_results_table.horizontalHeader():
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        results_layout.addWidget(self.test_results_table)

        # Results summary
        self.test_summary_label = QLabel("No tests run")
        self.test_summary_label.setStyleSheet("color: #666; padding: 5px;")
        results_layout.addWidget(self.test_summary_label)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        widget.setLayout(layout)
        return widget

    def _create_template_tab(self) -> QWidget:
        """Create signature template tab.

        Returns:
            QWidget: Widget containing the template browser UI.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Template categories
        categories_group = QGroupBox("Template Categories")
        categories_layout = QHBoxLayout()

        self.template_category_list = QListWidget()

        # Load categories from templates module
        try:
            from ...data.signature_templates import SignatureTemplates

            categories = SignatureTemplates.get_all_categories()
        except ImportError:
            logger.debug("Signature templates module not available, using fallback categories")
            categories = [
                "Basic Patterns",
                "PE Headers",
                "Section Signatures",
                "Import Signatures",
                "String Signatures",
                "Complex Rules",
            ]

        self.template_category_list.addItems(categories)
        self.template_category_list.currentItemChanged.connect(self.load_template_category)
        categories_layout.addWidget(self.template_category_list)

        # Template list
        self.template_list = QListWidget()
        self.template_list.itemDoubleClicked.connect(self.insert_template)
        categories_layout.addWidget(self.template_list)

        categories_group.setLayout(categories_layout)
        layout.addWidget(categories_group)

        # Template preview
        preview_group = QGroupBox("Template Preview")
        preview_layout = QVBoxLayout()

        self.template_preview = QTextEdit()
        self.template_preview.setReadOnly(True)
        self.template_preview.setFont(QFont("Consolas", 10))
        self.template_preview.setMaximumHeight(200)
        preview_layout.addWidget(self.template_preview)

        # Template actions
        template_actions = QHBoxLayout()
        self.insert_template_to_editor_btn = QPushButton("Insert to Editor")
        self.insert_template_to_editor_btn.clicked.connect(self.insert_template)
        template_actions.addWidget(self.insert_template_to_editor_btn)

        template_actions.addStretch()
        preview_layout.addLayout(template_actions)

        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        widget.setLayout(layout)

        # Load initial template category
        if self.template_category_list.count() > 0:
            self.template_category_list.setCurrentRow(0)

        return widget

    def load_signature_databases(self) -> None:
        """Load available signature databases.

        Searches common directories for signature database files (.sg format)
        and populates the database combo box.
        """
        self.db_combo.clear()
        self.signature_databases.clear()

        # Look for signature databases in common locations
        search_paths = [
            Path(__file__).parent.parent.parent / "data" / "signatures",
            Path.home() / ".intellicrack" / "signatures",
            Path.cwd() / "signatures",
        ]

        for search_path in search_paths:
            if search_path.exists():
                for db_file in search_path.glob("*.sg"):
                    db_name = db_file.stem
                    self.signature_databases[db_name] = str(db_file)
                    self.db_combo.addItem(db_name)

        if self.signature_databases:
            self.load_signatures_from_database(self.db_combo.currentText())

    def load_signatures_from_database(self, db_name: str) -> None:
        """Load signatures from selected database.

        Args:
            db_name: The name of the database to load.
        """
        if not db_name or db_name not in self.signature_databases:
            return

        db_path = self.signature_databases[db_name]

        try:
            with open(db_path, encoding="utf-8") as f:
                content = f.read()

            # Parse signatures from file
            self.current_signatures = self._parse_signature_file(content)
            self._update_signature_list()

        except Exception as e:
            self.logger.exception("Exception in signature_editor_dialog: %s", e)
            QMessageBox.warning(self, "Load Error", f"Failed to load database {db_name}: {e!s}")

    def _parse_signature_file(self, content: str) -> list[dict[str, str]]:
        """Parse signature file content into individual signatures.

        Args:
            content: The signature file content to parse.

        Returns:
            list[dict[str, str]]: List of parsed signature dictionaries.
        """
        signatures: list[dict[str, str]] = []

        # Split content by signature blocks
        blocks = re.split(r"\n\s*\n", content.strip())

        for block in blocks:
            if not block.strip():
                continue

            sig_data: dict[str, str] = {
                "name": "Unknown",
                "type": "Other",
                "version": "",
                "description": "",
                "content": block.strip(),
            }

            # Extract metadata from comments
            lines = block.split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("//"):
                    comment = line[2:].strip()
                    if comment.startswith("Name:"):
                        sig_data["name"] = comment[5:].strip()
                    elif comment.startswith("Type:"):
                        sig_data["type"] = comment[5:].strip()
                    elif comment.startswith("Version:"):
                        sig_data["version"] = comment[8:].strip()
                    elif comment.startswith("Description:"):
                        sig_data["description"] = comment[12:].strip()

            signatures.append(sig_data)

        return signatures

    def _update_signature_list(self) -> None:
        """Update signature list display.

        Refreshes the signature list widget with current signatures, applying
        search filters and color coding.
        """
        self.signature_list.clear()

        search_term = self.search_input.text().lower()

        for sig in self.current_signatures:
            # Filter by search term
            if search_term and search_term not in sig["name"].lower():
                continue

            item = QListWidgetItem(f"{sig['name']} ({sig['type']})")
            item.setData(Qt.ItemDataRole.UserRole, sig)

            # Color code by type
            if sig["type"].lower() in ["packer", "protector"]:
                item.setBackground(QColor(255, 200, 200, 50))
            elif sig["type"].lower() in ["virus", "trojan"]:
                item.setBackground(QColor(255, 150, 150, 80))
            elif sig["type"].lower() == "compiler":
                item.setBackground(QColor(200, 255, 200, 50))

            self.signature_list.addItem(item)

    def filter_signatures(self, text: str) -> None:
        """Filter signatures by search text.

        Args:
            text: The search text to filter signatures.
        """
        self._update_signature_list()

    def load_signature_from_list(self, item: QListWidgetItem) -> None:
        """Load signature from list selection.

        Args:
            item: The selected list widget item.
        """
        sig_data_raw = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(sig_data_raw, dict):
            return
        sig_data: dict[str, str] = sig_data_raw

        # Load into editor
        self.sig_name_input.setText(sig_data["name"])
        self.sig_type_combo.setCurrentText(sig_data["type"])
        self.sig_version_input.setText(sig_data["version"])
        self.sig_description_input.setText(sig_data["description"])
        self.signature_editor.setPlainText(sig_data["content"])

        # Update info display
        self._update_signature_info(sig_data)

    def _update_signature_info(self, sig_data: dict[str, str]) -> None:
        """Update signature info display.

        Args:
            sig_data: Dictionary containing signature metadata and content.
        """
        info_text = f"""Name: {sig_data["name"]}
Type: {sig_data["type"]}
Version: {sig_data["version"]}
Description: {sig_data["description"]}

Content Preview:
{sig_data["content"][:200]}{"..." if len(sig_data["content"]) > 200 else ""}"""

        self.sig_info_text.setPlainText(info_text)

    def new_signature(self) -> None:
        """Create new signature.

        Clears editor and loads basic signature template.
        """
        self.current_signature_path = None

        # Clear editor
        self.sig_name_input.clear()
        self.sig_type_combo.setCurrentIndex(0)
        self.sig_version_input.clear()
        self.sig_description_input.clear()
        self.signature_editor.clear()
        self.sig_info_text.clear()

        # Insert basic template
        template = """// Name: New Signature
// Type: Other
// Version: 1.0
// Description: Description of what this signature detects

init:
{
    name = "New Signature";
    type = "Other";
    version = "1.0";
    description = "Description";
}

ep:
{
    // Entry point signature
    hex = "48 65 6C 6C 6F";  // "Hello" in hex
}
"""
        self.signature_editor.setPlainText(template)

    def load_signature_file(self) -> None:
        """Load signature from file.

        Opens file dialog and loads selected signature file into the editor.
        Extracts metadata from file comments.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Signature File",
            "",
            "Signature Files (*.sg *.sig);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

                self.current_signature_path = file_path
                self.signature_editor.setPlainText(content)

                # Try to extract metadata
                self._extract_metadata_from_content(content)

            except Exception as e:
                self.logger.exception("Exception in signature_editor_dialog: %s", e)
                QMessageBox.critical(self, "Load Error", f"Failed to load file: {e!s}")

    def _extract_metadata_from_content(self, content: str) -> None:
        """Extract metadata from signature content.

        Args:
            content: The signature content to extract metadata from.
        """
        lines = content.split("\n")

        for line in lines:
            line = line.strip()
            if line.startswith("//"):
                comment = line[2:].strip()
                if comment.startswith("Name:"):
                    self.sig_name_input.setText(comment[5:].strip())
                elif comment.startswith("Type:"):
                    type_val = comment[5:].strip()
                    index = self.sig_type_combo.findText(type_val)
                    if index >= 0:
                        self.sig_type_combo.setCurrentIndex(index)
                elif comment.startswith("Version:"):
                    self.sig_version_input.setText(comment[8:].strip())
                elif comment.startswith("Description:"):
                    self.sig_description_input.setText(comment[12:].strip())

    def save_signature(self) -> None:
        """Save current signature.

        Saves the current signature to a file, prompting for filename if needed.
        Adds metadata comments to the signature content.
        """
        if not self.signature_editor.toPlainText().strip():
            QMessageBox.warning(self, "Save Error", "No signature content to save")
            return

        file_path = self.current_signature_path

        if not file_path:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Signature",
                f"{self.sig_name_input.text() or 'signature'}.sg",
                "Signature Files (*.sg);;All Files (*.*)",
            )

        if file_path:
            try:
                # Build complete signature content
                content = self._build_signature_content()

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)

                self.current_signature_path = file_path
                QMessageBox.information(self, "Save Successful", f"Signature saved to {file_path}")

            except Exception as e:
                logger.exception("Exception in signature_editor_dialog: %s", e)
                QMessageBox.critical(self, "Save Error", f"Failed to save file: {e!s}")

    def _build_signature_content(self) -> str:
        """Build complete signature content with metadata.

        Returns:
            Complete signature content with metadata header.
        """
        metadata_header = f"""// Name: {self.sig_name_input.text()}
// Type: {self.sig_type_combo.currentText()}
// Version: {self.sig_version_input.text()}
// Description: {self.sig_description_input.text()}

"""

        signature_body = self.signature_editor.toPlainText()

        # Remove existing metadata comments to avoid duplication
        lines = signature_body.split("\n")
        filtered_lines = []

        for line in lines:
            stripped = line.strip()
            if not (
                stripped.startswith("// Name:")
                or stripped.startswith("// Type:")
                or stripped.startswith("// Version:")
                or stripped.startswith("// Description:")
            ):
                filtered_lines.append(line)

        return metadata_header + "\n".join(filtered_lines)

    def validate_signature_syntax(self) -> None:
        """Validate signature syntax.

        Checks for required sections, balanced braces, and valid hex patterns.
        Displays validation results in a message box.
        """
        content = self.signature_editor.toPlainText()

        if not content.strip():
            QMessageBox.warning(self, "Validation", "No content to validate")
            return

        # Basic syntax validation
        errors = []

        # Check for required sections
        if "init:" not in content:
            errors.append("Missing 'init:' section")

        # Check for balanced braces
        open_braces = content.count("{")
        close_braces = content.count("}")
        if open_braces != close_braces:
            errors.append(f"Unbalanced braces: {open_braces} open, {close_braces} close")

        # Check for hex pattern format
        hex_patterns = re.findall(r'hex\s*=\s*"([^"]*)"', content)
        errors.extend(f"Invalid hex pattern: {pattern}" for pattern in hex_patterns if not re.match(r"^[0-9A-Fa-f\s?*]*$", pattern))
        if errors:
            QMessageBox.warning(self, "Validation Errors", "\n".join(errors))
        else:
            QMessageBox.information(self, "Validation", "Signature syntax is valid")

    def format_signature(self) -> None:
        """Format signature content.

        Applies proper indentation to signature content based on brace nesting.
        """
        content = self.signature_editor.toPlainText()

        # Basic formatting
        lines = content.split("\n")
        formatted_lines = []
        indent_level = 0

        for line in lines:
            stripped = line.strip()

            if stripped.endswith("{"):
                formatted_lines.append("    " * indent_level + stripped)
                indent_level += 1
            elif stripped.startswith("}"):
                indent_level = max(0, indent_level - 1)
                formatted_lines.append("    " * indent_level + stripped)
            else:
                formatted_lines.append("    " * indent_level + stripped)

        self.signature_editor.setPlainText("\n".join(formatted_lines))

    def show_template_menu(self) -> None:
        """Show template insertion menu.

        Switches the tab widget to the template tab for template selection.
        """
        # Switch to template tab
        parent_widget = self.signature_editor.parent()
        while parent_widget and not isinstance(parent_widget, QTabWidget):
            parent_widget = parent_widget.parent()

        if isinstance(parent_widget, QTabWidget):
            parent_widget.setCurrentIndex(2)  # Template tab

    def load_template_category(self, current_item: QListWidgetItem | None, previous_item: QListWidgetItem | None) -> None:
        """Load templates for selected category.

        Args:
            current_item: The newly selected category item.
            previous_item: The previously selected category item.
        """
        if not current_item:
            return

        # Save state from previous category if needed
        if previous_item:
            previous_category = previous_item.text()
            if current_template_item := self.template_list.currentItem():
                selected_template = current_template_item.text()
                self._category_selections[previous_category] = selected_template
                logger.debug("Saved template selection '%s' for category '%s'", selected_template, previous_category)

        category = current_item.text()
        self.template_list.clear()

        templates = self._get_templates_for_category(category)

        for template_name in templates:
            self.template_list.addItem(template_name)

        # Restore previous selection for this category if available
        if category in self._category_selections:
            previous_selection = self._category_selections[category]
            for i in range(self.template_list.count()):
                template_item = self.template_list.item(i)
                if template_item and template_item.text() == previous_selection:
                    self.template_list.setCurrentRow(i)
                    self._update_template_preview()
                    logger.debug("Restored template selection '%s' for category '%s'", previous_selection, category)
                    return

        # Load first template preview if no previous selection
        if self.template_list.count() > 0:
            self.template_list.setCurrentRow(0)
            self._update_template_preview()

    def _get_templates_for_category(self, category: str) -> dict[str, str]:
        """Get templates for a specific category.

        Args:
            category: The template category name.

        Returns:
            Dictionary mapping template names to template content.
        """
        try:
            from ...data.signature_templates import SignatureTemplates

            templates_data = SignatureTemplates.get_templates_for_category(category)
            return {template_name: template_info["template"] for template_name, template_info in templates_data.items()}
        except ImportError:
            logger.warning("Signature templates module not available, using built-in templates")
            return self._get_builtin_templates(category)

    def _get_builtin_templates(self, category: str) -> dict[str, str]:
        """Fallback built-in templates.

        Args:
            category: The template category name.

        Returns:
            Dictionary mapping template names to template content.
        """
        if category == "Basic Patterns":
            return {
                "Simple Hex Pattern": """ep:
{
    hex = "48 65 6C 6C 6F";  // "Hello"
}""",
                "Wildcard Pattern": """ep:
{
    hex = "48 ?? 6C ?? 6F";  // "H?l?o" with wildcards
}""",
            }

        if category == "PE Headers":
            return {
                "DOS Header Check": """header:
{
    hex = "4D 5A";  // MZ signature
    offset = 0;
}""",
                "PE Header Check": """header:
{
    hex = "50 45 00 00";  // PE signature
    offset = "PE_OFFSET";
}""",
            }

        return {}

    def _update_template_preview(self) -> None:
        """Update template preview.

        Updates the preview text widget with the selected template content.
        """
        current_item = self.template_list.currentItem()
        if not current_item:
            return

        category_item = self.template_category_list.currentItem()
        if not category_item:
            return

        category = category_item.text()
        template_name = current_item.text()

        templates = self._get_templates_for_category(category)
        if template_name in templates:
            self.template_preview.setPlainText(templates[template_name])

    def insert_template(self) -> None:
        """Insert selected template into editor.

        Inserts the template preview content at the cursor position.
        """
        if template_content := self.template_preview.toPlainText():
            cursor = self.signature_editor.textCursor()
            cursor.insertText(template_content + "\n\n")

    def add_test_file(self) -> None:
        """Add individual test file.

        Opens file dialog to select and add a single test file.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Add Test File",
            "",
            "Executable Files (*.exe *.dll *.sys);;All Files (*.*)",
        )

        if file_path:
            self.test_files_list.addItem(file_path)

    def add_test_folder(self) -> None:
        """Add all files from folder for testing.

        Opens directory dialog and adds all executable files from selected folder.
        """
        if folder_path := QFileDialog.getExistingDirectory(
            self,
            "Add Test Folder",
        ):
            # Add all executable files from folder
            folder = Path(folder_path)
            for file_path in folder.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in [".exe", ".dll", ".sys"]:
                    self.test_files_list.addItem(str(file_path))

    def clear_test_files(self) -> None:
        """Clear test files list.

        Removes all files from the test files list.
        """
        self.test_files_list.clear()

    def run_signature_tests(self) -> None:
        """Run signature tests.

        Initiates signature testing against selected test files in a background thread.
        Updates UI with progress and results.
        """
        signature_content = self.signature_editor.toPlainText()
        if not signature_content.strip():
            QMessageBox.warning(self, "Test Error", "No signature content to test")
            return

        test_files: list[str] = []
        for i in range(self.test_files_list.count()):
            if test_item := self.test_files_list.item(i):
                test_files.append(test_item.text())
        if not test_files:
            QMessageBox.warning(self, "Test Error", "No test files selected")
            return

        # Clear previous results
        self.test_results_model.clear()
        self.test_results_model.setHorizontalHeaderLabels(
            [
                "File",
                "Result",
                "Message",
                "File Size",
                "Time",
            ],
        )

        # Disable test button, enable stop button
        self.run_test_btn.setEnabled(False)
        self.stop_test_btn.setEnabled(True)

        # Start test worker
        self.test_worker = SignatureTestWorker(signature_content, test_files)
        self.test_worker.test_completed.connect(self._on_test_completed)
        self.test_worker.progress_update.connect(self._on_test_progress)
        self.test_worker.finished.connect(self._on_tests_finished)
        self.test_worker.start()

    def stop_signature_tests(self) -> None:
        """Stop running signature tests.

        Terminates the currently running test worker thread.
        """
        if self.test_worker and self.test_worker.isRunning():
            self.test_worker.terminate()
            self.test_worker.wait()

        self._on_tests_finished()

    @pyqtSlot(str, bool, str, float)
    def _on_test_completed(self, file_path: str, success: bool, result: str, execution_time: float) -> None:
        """Handle individual test completion.

        Args:
            file_path: Path to the tested file.
            success: Whether the signature matched the file.
            result: Result message describing the match or failure.
            execution_time: Time taken to test the file in seconds.
        """
        row = self.test_results_model.rowCount()
        self.test_results_model.insertRow(row)

        # File name
        file_item = QStandardItem(os.path.basename(file_path))
        file_item.setToolTip(file_path)
        self.test_results_model.setItem(row, 0, file_item)

        # Result
        result_item = QStandardItem("MATCH" if success else "NO MATCH")
        result_item.setForeground(QColor("green") if success else QColor("red"))
        self.test_results_model.setItem(row, 1, result_item)

        # Message
        message_item = QStandardItem(result)
        self.test_results_model.setItem(row, 2, message_item)

        # File size
        try:
            size = os.path.getsize(file_path)
            size_str = f"{size:,} bytes"
        except OSError as e:
            logger.debug("Failed to get file size for %s: %s", file_path, e)
            size_str = "Unknown"

        size_item = QStandardItem(size_str)
        self.test_results_model.setItem(row, 3, size_item)

        # Execution time
        if execution_time < 1.0:
            time_str = f"{execution_time * 1000:.1f}ms"
        elif execution_time < 60.0:
            time_str = f"{execution_time:.2f}s"
        else:
            minutes = int(execution_time // 60)
            seconds = execution_time % 60
            time_str = f"{minutes}m {seconds:.1f}s"

        time_item = QStandardItem(time_str)
        self.test_results_model.setItem(row, 4, time_item)

    @pyqtSlot(int, str)
    def _on_test_progress(self, progress: int, current_file: str) -> None:
        """Handle test progress update.

        Args:
            progress: Current progress percentage (0-100).
            current_file: Name of the file currently being tested.
        """
        self.test_summary_label.setText(f"Testing: {current_file} ({progress}%)")

    def _on_tests_finished(self) -> None:
        """Handle test completion.

        Updates UI to reflect test completion and displays summary statistics.
        """
        # Re-enable test button, disable stop button
        self.run_test_btn.setEnabled(True)
        self.stop_test_btn.setEnabled(False)

        # Update summary
        total_tests = self.test_results_model.rowCount()
        matches = 0

        for row in range(total_tests):
            result_item = self.test_results_model.item(row, 1)
            if result_item and result_item.text() == "MATCH":
                matches += 1

        self.test_summary_label.setText(
            f"Tests completed: {matches}/{total_tests} matches ({matches / total_tests * 100:.1f}%)"
            if total_tests > 0
            else "No tests completed",
        )

        self.test_worker = None

    def add_signature_database(self) -> None:
        """Add new signature database.

        Opens file dialog to select and add a new signature database file.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Add Signature Database",
            "",
            "Signature Files (*.sg *.sig);;All Files (*.*)",
        )

        if file_path:
            db_name = Path(file_path).stem
            self.signature_databases[db_name] = file_path
            self.db_combo.addItem(db_name)
            self.db_combo.setCurrentText(db_name)

    def refresh_signatures(self) -> None:
        """Refresh signature list.

        Reloads the currently selected database and updates the signature list.
        """
        if current_db := self.db_combo.currentText():
            self.load_signatures_from_database(current_db)

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Handle dialog close with proper thread cleanup.

        Ensures any running test worker is properly terminated before
        closing the dialog to prevent resource leaks.

        Args:
            event: Close event from Qt framework.

        """
        if self.test_worker is not None and self.test_worker.isRunning():
            self.test_worker.quit()
            if not self.test_worker.wait(2000):
                self.test_worker.terminate()
                self.test_worker.wait()
            self.test_worker = None
        super().closeEvent(event)


def main() -> None:
    """Test the signature editor dialog.

    Entry point for testing the signature editor dialog in standalone mode.
    """
    app = QApplication([])

    dialog = SignatureEditorDialog()
    dialog.show()

    app.exec()


if __name__ == "__main__":
    main()
