"""Advanced Intellicrack Protection Detection Widget.

Enhanced UI for accessing Intellicrack's full protection analysis feature set including
entropy analysis, certificates, resources, heuristics, and custom signatures.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os

from intellicrack.handlers.pyqt6_handler import (
    QBrush,
    QCheckBox,
    QColor,
    QComboBox,
    QFileDialog,
    QFont,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QThread,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...protection.intellicrack_protection_advanced import (
    AdvancedProtectionAnalysis,
    EntropyInfo,
    ExportFormat,
    IntellicrackAdvancedProtection,
    ScanMode,
)
from ...utils.logger import get_logger

try:
    from intellicrack.handlers.matplotlib_handler import HAS_MATPLOTLIB, Figure, plt
    from intellicrack.handlers.matplotlib_handler import FigureCanvasQTAgg as FigureCanvas
except ImportError:
    HAS_MATPLOTLIB = False
    plt = None
    FigureCanvas = None
    Figure = None


logger = get_logger(__name__)


class AdvancedAnalysisThread(QThread):
    """Thread for running advanced protection analysis."""

    #: AdvancedProtectionAnalysis (type: object)
    analysis_complete = pyqtSignal(object)
    analysis_error = pyqtSignal(str)
    #: message, percentage (type: str, int)
    analysis_progress = pyqtSignal(str, int)

    def __init__(self, file_path: str, scan_mode: ScanMode, enable_heuristic: bool, extract_strings: bool):
        """Initialize advanced analysis thread with file path, scan configuration, and analysis options."""
        super().__init__()
        self.file_path = file_path
        self.scan_mode = scan_mode
        self.enable_heuristic = enable_heuristic
        self.extract_strings = extract_strings
        self.detector = IntellicrackAdvancedProtection()

    def run(self):
        """Run advanced protection analysis in background thread."""
        try:
            self.analysis_progress.emit("Initializing analysis...", 10)

            # Run advanced analysis
            self.analysis_progress.emit(f"Analyzing {os.path.basename(self.file_path)}...", 30)

            analysis = self.detector.detect_protections_advanced(
                self.file_path,
                scan_mode=self.scan_mode,
                enable_heuristic=self.enable_heuristic,
                extract_strings=self.extract_strings,
            )

            self.analysis_progress.emit("Analysis complete!", 100)
            self.analysis_complete.emit(analysis)

        except Exception as e:
            self.logger.error("Exception in intellicrack_advanced_protection_widget: %s", e)
            self.analysis_error.emit(str(e))


class EntropyGraphWidget(FigureCanvas):
    """Widget for displaying entropy graph."""

    def __init__(self, parent=None):
        """Initialize entropy graph widget with matplotlib figure and parent widget."""
        self.figure = Figure(figsize=(8, 4))
        super().__init__(self.figure)
        self.setParent(parent)

    def plot_entropy(self, entropy_data: list[EntropyInfo]):
        """Plot entropy data for sections."""
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        if not entropy_data:
            ax.text(
                0.5,
                0.5,
                "No entropy data available",
                ha="center",
                va="center",
                transform=ax.transAxes,
            )
            self.draw()
            return

        # Prepare data
        sections = [e.section_name for e in entropy_data]
        entropies = [e.entropy for e in entropy_data]
        colors = ["red" if e.packed else "green" for e in entropy_data]

        # Create bar chart
        bars = ax.bar(sections, entropies, color=colors)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.annotate(
                f"{height:.2f}",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),  # 3 points vertical offset
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
            )

        # Add threshold line
        ax.axhline(y=7.0, color="orange", linestyle="--", label="Packing threshold")
        ax.axhline(y=7.5, color="red", linestyle="--", label="Encryption threshold")

        # Customize
        ax.set_xlabel("Section")
        ax.set_ylabel("Entropy")
        ax.set_title("Section Entropy Analysis")
        ax.set_ylim(0, 8)
        ax.legend()

        # Rotate x labels
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)

        self.figure.tight_layout()
        self.draw()


class IntellicrackAdvancedProtectionWidget(QWidget):
    """Advanced widget for ICP protection detection with full feature access."""

    # Signals
    #: protection_name, bypass_recommendations (type: str, list)
    protection_detected = pyqtSignal(str, list)
    #: file_path (type: str)
    analysis_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize advanced protection widget with parent widget and UI components."""
        super().__init__(parent)
        self.current_analysis: AdvancedProtectionAnalysis | None = None
        self.analysis_thread: AdvancedAnalysisThread | None = None
        self.init_ui()

    def init_ui(self):
        """Initialize the advanced UI."""
        layout = QVBoxLayout()

        # Header with controls
        header_widget = self.create_header_widget()
        layout.addWidget(header_widget)

        # Main content area
        self.main_splitter = QSplitter(Qt.Horizontal)

        # Left panel - Results tree
        left_panel = self.create_left_panel()
        self.main_splitter.addWidget(left_panel)

        # Right panel - Detailed views
        right_panel = self.create_right_panel()
        self.main_splitter.addWidget(right_panel)

        self.main_splitter.setSizes([350, 650])
        layout.addWidget(self.main_splitter)

        # Status bar
        status_widget = self.create_status_widget()
        layout.addWidget(status_widget)

        self.setLayout(layout)

    def create_header_widget(self) -> QWidget:
        """Create header with controls."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Title row
        title_layout = QHBoxLayout()
        title_label = QLabel("Advanced Protection Detection (ICP)")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # Controls row
        controls_layout = QHBoxLayout()

        # File selection
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select file to analyze...")
        self.file_path_edit.setReadOnly(True)
        controls_layout.addWidget(self.file_path_edit)

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.on_browse_clicked)
        controls_layout.addWidget(self.browse_btn)

        # Scan mode
        controls_layout.addWidget(QLabel("Scan Mode:"))
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(["Normal", "Deep", "Heuristic", "All"])
        self.scan_mode_combo.setCurrentIndex(1)  # Default to Deep
        controls_layout.addWidget(self.scan_mode_combo)

        # Options
        self.heuristic_check = QCheckBox("Enable Heuristics")
        self.heuristic_check.setChecked(True)
        controls_layout.addWidget(self.heuristic_check)

        self.strings_check = QCheckBox("Extract Strings")
        self.strings_check.setChecked(True)
        controls_layout.addWidget(self.strings_check)

        # Analyze button
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.on_analyze_clicked)
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        controls_layout.addWidget(self.analyze_btn)

        layout.addLayout(controls_layout)

        widget.setLayout(layout)
        return widget

    def create_left_panel(self) -> QWidget:
        """Create left panel with results tree."""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Results tree
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Category", "Count", "Status"])
        self.results_tree.itemSelectionChanged.connect(self.on_tree_selection_changed)
        layout.addWidget(self.results_tree)

        widget.setLayout(layout)
        return widget

    def create_right_panel(self) -> QWidget:
        """Create right panel with detailed views."""
        self.details_tabs = QTabWidget()

        # Overview tab
        self.overview_widget = self.create_overview_widget()
        self.details_tabs.addTab(self.overview_widget, "Overview")

        # Detections tab
        self.detections_widget = self.create_detections_widget()
        self.details_tabs.addTab(self.detections_widget, "Detections")

        # Entropy tab
        self.entropy_widget = self.create_entropy_widget()
        self.details_tabs.addTab(self.entropy_widget, "Entropy Analysis")

        # Certificates tab
        self.certificates_widget = self.create_certificates_widget()
        self.details_tabs.addTab(self.certificates_widget, "Certificates")

        # Resources tab
        self.resources_widget = self.create_resources_widget()
        self.details_tabs.addTab(self.resources_widget, "Resources")

        # Strings tab
        self.strings_widget = self.create_strings_widget()
        self.details_tabs.addTab(self.strings_widget, "Suspicious Strings")

        # Heuristics tab
        self.heuristics_widget = self.create_heuristics_widget()
        self.details_tabs.addTab(self.heuristics_widget, "Heuristics")

        # Export tab
        self.export_widget = self.create_export_widget()
        self.details_tabs.addTab(self.export_widget, "Export")

        return self.details_tabs

    def create_overview_widget(self) -> QWidget:
        """Create overview widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        self.overview_text = QTextBrowser()
        self.overview_text.setOpenExternalLinks(True)
        layout.addWidget(self.overview_text)

        widget.setLayout(layout)
        return widget

    def create_detections_widget(self) -> QWidget:
        """Create detections widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Detections table
        self.detections_table = QTableWidget()
        self.detections_table.setColumnCount(5)
        self.detections_table.setHorizontalHeaderLabels(
            [
                "Name",
                "Type",
                "Version",
                "Confidence",
                "Bypass Available",
            ]
        )
        self.detections_table.horizontalHeader().setStretchLastSection(True)
        self.detections_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.detections_table.itemSelectionChanged.connect(self.on_detection_selected)
        layout.addWidget(self.detections_table)

        # Bypass recommendations
        self.bypass_text = QTextEdit()
        self.bypass_text.setReadOnly(True)
        self.bypass_text.setMaximumHeight(150)
        layout.addWidget(QLabel("Bypass Recommendations:"))
        layout.addWidget(self.bypass_text)

        widget.setLayout(layout)
        return widget

    def create_entropy_widget(self) -> QWidget:
        """Create entropy analysis widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Entropy graph
        self.entropy_graph = EntropyGraphWidget()
        layout.addWidget(self.entropy_graph)

        # Entropy details table
        self.entropy_table = QTableWidget()
        self.entropy_table.setColumnCount(5)
        self.entropy_table.setHorizontalHeaderLabels(
            [
                "Section",
                "Offset",
                "Size",
                "Entropy",
                "Status",
            ]
        )
        self.entropy_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.entropy_table)

        widget.setLayout(layout)
        return widget

    def create_certificates_widget(self) -> QWidget:
        """Create certificates widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        self.certificates_table = QTableWidget()
        self.certificates_table.setColumnCount(6)
        self.certificates_table.setHorizontalHeaderLabels(
            [
                "Subject",
                "Issuer",
                "Valid From",
                "Valid To",
                "Algorithm",
                "Status",
            ]
        )
        self.certificates_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.certificates_table)

        widget.setLayout(layout)
        return widget

    def create_resources_widget(self) -> QWidget:
        """Create resources widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        self.resources_table = QTableWidget()
        self.resources_table.setColumnCount(5)
        self.resources_table.setHorizontalHeaderLabels(
            [
                "Type",
                "Name",
                "Language",
                "Size",
                "Hash",
            ]
        )
        self.resources_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.resources_table)

        widget.setLayout(layout)
        return widget

    def create_strings_widget(self) -> QWidget:
        """Create suspicious strings widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.strings_filter = QLineEdit()
        self.strings_filter.textChanged.connect(self.filter_strings)
        filter_layout.addWidget(self.strings_filter)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Strings table
        self.strings_table = QTableWidget()
        self.strings_table.setColumnCount(4)
        self.strings_table.setHorizontalHeaderLabels(
            [
                "String",
                "Offset",
                "Encoding",
                "Suspicious",
            ]
        )
        self.strings_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.strings_table)

        widget.setLayout(layout)
        return widget

    def create_heuristics_widget(self) -> QWidget:
        """Create heuristics widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        self.heuristics_text = QTextEdit()
        self.heuristics_text.setReadOnly(True)
        layout.addWidget(self.heuristics_text)

        widget.setLayout(layout)
        return widget

    def create_export_widget(self) -> QWidget:
        """Create export widget."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Export format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Export Format:"))
        self.export_format_combo = QComboBox()
        self.export_format_combo.addItems(["JSON", "XML", "CSV", "HTML", "YARA"])
        format_layout.addWidget(self.export_format_combo)
        format_layout.addStretch()
        layout.addLayout(format_layout)

        # Export preview
        self.export_preview = QTextEdit()
        self.export_preview.setReadOnly(True)
        layout.addWidget(QLabel("Export Preview:"))
        layout.addWidget(self.export_preview)

        # Export buttons
        button_layout = QHBoxLayout()

        self.preview_btn = QPushButton("Update Preview")
        self.preview_btn.clicked.connect(self.update_export_preview)
        button_layout.addWidget(self.preview_btn)

        self.export_btn = QPushButton("Export to File")
        self.export_btn.clicked.connect(self.on_export_clicked)
        button_layout.addWidget(self.export_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        widget.setLayout(layout)
        return widget

    def create_status_widget(self) -> QWidget:
        """Create status widget."""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

        layout.addStretch()

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        layout.addWidget(self.progress_bar)

        widget.setLayout(layout)
        return widget

    def on_browse_clicked(self):
        """Handle browse button click."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Analyze",
            "",
            "All Executables (*.exe *.dll *.sys *.elf *.so *.dylib *.apk *.dex);;All Files (*.*)",
        )

        if file_path:
            self.file_path_edit.setText(file_path)

    def on_analyze_clicked(self):
        """Handle analyze button click."""
        file_path = self.file_path_edit.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file to analyze")
            return

        # Get scan mode
        scan_mode_text = self.scan_mode_combo.currentText()
        scan_mode_map = {
            "Normal": ScanMode.NORMAL,
            "Deep": ScanMode.DEEP,
            "Heuristic": ScanMode.HEURISTIC,
            "All": ScanMode.ALL,
        }
        scan_mode = scan_mode_map.get(scan_mode_text, ScanMode.NORMAL)

        # Disable UI during analysis
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        # Clear previous results
        self.clear_results()

        # Start analysis thread
        self.analysis_thread = AdvancedAnalysisThread(
            file_path,
            scan_mode,
            self.heuristic_check.isChecked(),
            self.strings_check.isChecked(),
        )
        self.analysis_thread.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_thread.analysis_error.connect(self.on_analysis_error)
        self.analysis_thread.analysis_progress.connect(self.on_analysis_progress)
        self.analysis_thread.start()

    def on_analysis_complete(self, analysis: AdvancedProtectionAnalysis):
        """Handle completed analysis."""
        self.current_analysis = analysis
        self.display_results(analysis)

        # Re-enable UI
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis complete")

        # Emit signals for detected protections
        for detection in analysis.detections:
            self.protection_detected.emit(
                detection.name,
                detection.bypass_recommendations,
            )

    def on_analysis_error(self, error_msg: str):
        """Handle analysis error."""
        QMessageBox.critical(self, "Analysis Error", f"Error: {error_msg}")
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis failed")

    def on_analysis_progress(self, message: str, percentage: int):
        """Update analysis progress."""
        self.status_label.setText(message)
        self.progress_bar.setValue(percentage)

    def display_results(self, analysis: AdvancedProtectionAnalysis):
        """Display analysis results."""
        # Update results tree
        self.update_results_tree(analysis)

        # Update overview
        self.update_overview(analysis)

        # Update detections
        self.update_detections(analysis)

        # Update entropy
        self.update_entropy(analysis)

        # Update certificates
        self.update_certificates(analysis)

        # Update resources
        self.update_resources(analysis)

        # Update strings
        self.update_strings(analysis)

        # Update heuristics
        self.update_heuristics(analysis)

    def update_results_tree(self, analysis: AdvancedProtectionAnalysis):
        """Update results tree."""
        self.results_tree.clear()

        # File info
        file_item = QTreeWidgetItem(self.results_tree)
        file_item.setText(0, "File Information")
        file_item.setText(1, "")
        file_item.setText(2, analysis.file_type)

        # Detections
        det_item = QTreeWidgetItem(self.results_tree)
        det_item.setText(0, "Detections")
        det_item.setText(1, str(len(analysis.detections)))
        det_item.setText(2, "Protected" if analysis.is_protected else "Clean")

        # Entropy
        ent_item = QTreeWidgetItem(self.results_tree)
        ent_item.setText(0, "Entropy Analysis")
        ent_item.setText(1, str(len(analysis.entropy_info)))
        packed_count = sum(1 for e in analysis.entropy_info if e.packed)
        ent_item.setText(2, f"{packed_count} packed" if packed_count > 0 else "Normal")

        # Certificates
        cert_item = QTreeWidgetItem(self.results_tree)
        cert_item.setText(0, "Certificates")
        cert_item.setText(1, str(len(analysis.certificates)))
        valid_certs = sum(1 for c in analysis.certificates if c.is_valid)
        cert_item.setText(2, f"{valid_certs} valid" if analysis.certificates else "None")

        # Resources
        res_item = QTreeWidgetItem(self.results_tree)
        res_item.setText(0, "Resources")
        res_item.setText(1, str(len(analysis.resources)))
        res_item.setText(2, "Present" if analysis.resources else "None")

        # Strings
        str_item = QTreeWidgetItem(self.results_tree)
        str_item.setText(0, "Suspicious Strings")
        str_item.setText(1, str(len(analysis.suspicious_strings)))
        str_item.setText(2, "Found" if analysis.suspicious_strings else "Clean")

        # Heuristics
        heur_item = QTreeWidgetItem(self.results_tree)
        heur_item.setText(0, "Heuristic Detections")
        heur_item.setText(1, str(len(analysis.heuristic_detections)))
        heur_item.setText(2, "Suspicious" if analysis.heuristic_detections else "Clean")

        self.results_tree.expandAll()

    def update_overview(self, analysis: AdvancedProtectionAnalysis):
        """Update overview tab."""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                h2 {{ color: #2196F3; }}
                .info {{ margin: 10px 0; }}
                .warning {{ color: #FF9800; }}
                .danger {{ color: #F44336; }}
                .success {{ color: #4CAF50; }}
            </style>
        </head>
        <body>
            <h2>Analysis Overview</h2>

            <div class="info">
                <strong>File:</strong> {os.path.basename(analysis.file_path)}<br>
                <strong>Path:</strong> {analysis.file_path}<br>
                <strong>Type:</strong> {analysis.file_type}<br>
                <strong>Architecture:</strong> {analysis.architecture}<br>
                <strong>Compiler:</strong> {analysis.compiler or "Unknown"}<br>
            </div>

            <h3>Protection Status</h3>
            <div class="info">
        """

        if analysis.is_protected:
            html += '<p class="danger">WARNING️ File is PROTECTED</p>'
        else:
            html += '<p class="success">OK No protection detected</p>'

        if analysis.is_packed:
            html += '<p class="warning">📦 File is PACKED</p>'

        if analysis.has_overlay:
            html += '<p class="warning">📎 File has OVERLAY data</p>'

        # Summary statistics
        html += f"""
            </div>

            <h3>Detection Summary</h3>
            <ul>
                <li>Total Detections: {len(analysis.detections)}</li>
                <li>Heuristic Detections: {len(analysis.heuristic_detections)}</li>
                <li>Suspicious Strings: {len(analysis.suspicious_strings)}</li>
                <li>Certificates: {len(analysis.certificates)}</li>
                <li>Resources: {len(analysis.resources)}</li>
            </ul>

            <h3>Security Analysis</h3>
        """

        # Import hash
        if analysis.import_hash:
            html += f"""
            <div class="info">
                <strong>Import Hash:</strong> {analysis.import_hash.imphash}<br>
                <strong>Similarity Hash:</strong> {analysis.similarity_hash or "N/A"}<br>
            </div>
            """

        html += """
        </body>
        </html>
        """

        self.overview_text.setHtml(html)

    def update_detections(self, analysis: AdvancedProtectionAnalysis):
        """Update detections table."""
        all_detections = analysis.detections + analysis.heuristic_detections

        self.detections_table.setRowCount(len(all_detections))

        for i, detection in enumerate(all_detections):
            # Name
            self.detections_table.setItem(i, 0, QTableWidgetItem(detection.name))

            # Type
            type_item = QTableWidgetItem(detection.type.value)
            if detection.type.value in ["protector", "cryptor"]:
                type_item.setForeground(QBrush(QColor(255, 0, 0)))
            elif detection.type.value == "packer":
                type_item.setForeground(QBrush(QColor(255, 152, 0)))
            self.detections_table.setItem(i, 1, type_item)

            # Version
            self.detections_table.setItem(i, 2, QTableWidgetItem(detection.version or "N/A"))

            # Confidence
            conf_item = QTableWidgetItem(f"{detection.confidence:.0f}%")
            if detection.confidence < 50:
                conf_item.setForeground(QBrush(QColor(255, 152, 0)))
            self.detections_table.setItem(i, 3, conf_item)

            # Bypass available
            bypass_available = "Yes" if detection.bypass_recommendations else "No"
            self.detections_table.setItem(i, 4, QTableWidgetItem(bypass_available))

    def update_entropy(self, analysis: AdvancedProtectionAnalysis):
        """Update entropy analysis."""
        # Update graph
        self.entropy_graph.plot_entropy(analysis.entropy_info)

        # Update table
        self.entropy_table.setRowCount(len(analysis.entropy_info))

        for i, entropy in enumerate(analysis.entropy_info):
            self.entropy_table.setItem(i, 0, QTableWidgetItem(entropy.section_name))
            self.entropy_table.setItem(i, 1, QTableWidgetItem(f"0x{entropy.offset:08X}"))
            self.entropy_table.setItem(i, 2, QTableWidgetItem(f"{entropy.size:,}"))

            entropy_item = QTableWidgetItem(f"{entropy.entropy:.3f}")
            if entropy.entropy > 7.5:
                entropy_item.setForeground(QBrush(QColor(255, 0, 0)))
            elif entropy.entropy > 7.0:
                entropy_item.setForeground(QBrush(QColor(255, 152, 0)))
            self.entropy_table.setItem(i, 3, entropy_item)

            status = "Normal"
            if entropy.encrypted:
                status = "Encrypted"
            elif entropy.packed:
                status = "Packed"
            self.entropy_table.setItem(i, 4, QTableWidgetItem(status))

    def update_certificates(self, analysis: AdvancedProtectionAnalysis):
        """Update certificates table."""
        self.certificates_table.setRowCount(len(analysis.certificates))

        for i, cert in enumerate(analysis.certificates):
            self.certificates_table.setItem(i, 0, QTableWidgetItem(cert.subject))
            self.certificates_table.setItem(i, 1, QTableWidgetItem(cert.issuer))
            self.certificates_table.setItem(i, 2, QTableWidgetItem(cert.valid_from))
            self.certificates_table.setItem(i, 3, QTableWidgetItem(cert.valid_to))
            self.certificates_table.setItem(i, 4, QTableWidgetItem(cert.algorithm))

            status = "Valid" if cert.is_valid else "Invalid"
            status_item = QTableWidgetItem(status)
            if not cert.is_valid:
                status_item.setForeground(QBrush(QColor(255, 0, 0)))
            self.certificates_table.setItem(i, 5, status_item)

    def update_resources(self, analysis: AdvancedProtectionAnalysis):
        """Update resources table."""
        self.resources_table.setRowCount(len(analysis.resources))

        for i, resource in enumerate(analysis.resources):
            self.resources_table.setItem(i, 0, QTableWidgetItem(resource.type))
            self.resources_table.setItem(i, 1, QTableWidgetItem(resource.name))
            self.resources_table.setItem(i, 2, QTableWidgetItem(resource.language))
            self.resources_table.setItem(i, 3, QTableWidgetItem(f"{resource.size:,}"))
            self.resources_table.setItem(i, 4, QTableWidgetItem(resource.data_hash[:16]))

    def update_strings(self, analysis: AdvancedProtectionAnalysis):
        """Update strings table."""
        self.strings_table.setRowCount(len(analysis.suspicious_strings))

        for i, string in enumerate(analysis.suspicious_strings):
            # Truncate long strings
            display_value = string.value[:100] + "..." if len(string.value) > 100 else string.value
            self.strings_table.setItem(i, 0, QTableWidgetItem(display_value))
            self.strings_table.setItem(i, 1, QTableWidgetItem(f"0x{string.offset:08X}"))
            self.strings_table.setItem(i, 2, QTableWidgetItem(string.encoding))

            suspicious_item = QTableWidgetItem("Yes" if string.suspicious else "No")
            if string.suspicious:
                suspicious_item.setForeground(QBrush(QColor(255, 152, 0)))
            self.strings_table.setItem(i, 3, suspicious_item)

    def update_heuristics(self, analysis: AdvancedProtectionAnalysis):
        """Update heuristics display."""
        heuristics_text = "=== Heuristic Analysis Results ===\n\n"

        if not analysis.heuristic_detections:
            heuristics_text += "No heuristic detections found.\n"
        else:
            heuristics_text += f"Found {len(analysis.heuristic_detections)} heuristic detections:\n\n"

            for i, detection in enumerate(analysis.heuristic_detections, 1):
                heuristics_text += f"{i}. {detection.name}\n"
                heuristics_text += f"   Type: {detection.type.value}\n"
                heuristics_text += f"   Confidence: {detection.confidence:.0f}%\n"
                if detection.details:
                    heuristics_text += f"   Details: {detection.details}\n"
                heuristics_text += "\n"

        self.heuristics_text.setText(heuristics_text)

    def on_tree_selection_changed(self):
        """Handle tree selection change."""
        items = self.results_tree.selectedItems()
        if not items:
            return

        category = items[0].text(0)

        # Switch to appropriate tab
        tab_map = {
            "File Information": 0,  # Overview
            "Detections": 1,
            "Entropy Analysis": 2,
            "Certificates": 3,
            "Resources": 4,
            "Suspicious Strings": 5,
            "Heuristic Detections": 6,
        }

        if category in tab_map:
            self.details_tabs.setCurrentIndex(tab_map[category])

    def on_detection_selected(self):
        """Handle detection selection."""
        current_row = self.detections_table.currentRow()
        if current_row < 0:
            return

        # Get detection
        all_detections = self.current_analysis.detections + self.current_analysis.heuristic_detections
        if current_row < len(all_detections):
            detection = all_detections[current_row]

            # Display bypass recommendations
            if detection.bypass_recommendations:
                bypass_text = f"Bypass recommendations for {detection.name}:\n\n"
                for i, rec in enumerate(detection.bypass_recommendations, 1):
                    bypass_text += f"{i}. {rec}\n"
            else:
                bypass_text = f"No specific bypass recommendations available for {detection.name}."

            self.bypass_text.setText(bypass_text)

    def filter_strings(self, text: str):
        """Filter strings table."""
        for i in range(self.strings_table.rowCount()):
            row_hidden = True
            for j in range(self.strings_table.columnCount()):
                item = self.strings_table.item(i, j)
                if item and text.lower() in item.text().lower():
                    row_hidden = False
                    break
            self.strings_table.setRowHidden(i, row_hidden)

    def update_export_preview(self):
        """Update export preview."""
        if not self.current_analysis:
            return

        format_text = self.export_format_combo.currentText()

        if format_text == "YARA":
            # Generate YARA rules
            detector = IntellicrackAdvancedProtection()
            preview = detector.export_to_yara(self.current_analysis)
        else:
            # Use standard export
            export_format = ExportFormat[format_text]
            self.logger.debug("Export format selected: %s", export_format)
            detector = IntellicrackAdvancedProtection()
            preview = detector.export_results(self.current_analysis, format_text.lower())

        self.export_preview.setText(preview)

    def on_export_clicked(self):
        """Handle export button click."""
        if not self.current_analysis:
            QMessageBox.warning(self, "Error", "No analysis results to export")
            return

        format_text = self.export_format_combo.currentText()
        ext = "yar" if format_text == "YARA" else format_text.lower()

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            f"icp_analysis.{ext}",
            f"{format_text} Files (*.{ext});;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(self.export_preview.toPlainText())

                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Results exported to:\n{file_path}",
                )
            except Exception as e:
                logger.error("Exception in intellicrack_advanced_protection_widget: %s", e)
                QMessageBox.critical(
                    self,
                    "Export Error",
                    f"Error exporting results:\n{e!s}",
                )

    def clear_results(self):
        """Clear all results."""
        self.results_tree.clear()
        self.overview_text.clear()
        self.detections_table.setRowCount(0)
        self.entropy_table.setRowCount(0)
        self.certificates_table.setRowCount(0)
        self.resources_table.setRowCount(0)
        self.strings_table.setRowCount(0)
        self.heuristics_text.clear()
        self.bypass_text.clear()
        self.export_preview.clear()
        self.current_analysis = None

    def set_binary_path(self, file_path: str):
        """Set binary path for analysis."""
        if file_path and os.path.exists(file_path):
            self.file_path_edit.setText(file_path)
            # Auto-analyze if configured
            if hasattr(self, "auto_analyze") and self.auto_analyze:
                self.on_analyze_clicked()
