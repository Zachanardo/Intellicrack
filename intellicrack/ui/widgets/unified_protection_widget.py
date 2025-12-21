"""Unified Protection Analysis Widget.

Provides a seamless, integrated protection analysis experience that combines
ICP, ML models, and heuristics without exposing the underlying tools.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Any

# Import for QDateTime
from PyQt6.QtCore import QDateTime, Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QFont, QMouseEvent
from PyQt6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...protection.icp_backend import get_icp_backend
from ...protection.unified_protection_engine import AnalysisSource, UnifiedProtectionEngine, UnifiedProtectionResult
from ...utils.logger import get_logger
from .entropy_graph_widget import EntropyGraphWidget
from .hex_viewer_widget import HexViewerWidget
from .string_extraction_widget import StringExtractionWidget


logger = get_logger(__name__)


class UnifiedAnalysisThread(QThread):
    """Thread for running unified protection analysis."""

    #: UnifiedProtectionResult (type: object)
    analysis_complete = pyqtSignal(object)
    analysis_error = pyqtSignal(str)
    #: message, percentage (type: str, int)
    analysis_progress = pyqtSignal(str, int)

    def __init__(self, file_path: str, deep_scan: bool = True) -> None:
        """Initialize unified analysis thread.

        Args:
            file_path: Path to file for analysis
            deep_scan: Whether to perform deep scanning analysis

        """
        super().__init__()
        self.file_path = file_path
        self.deep_scan = deep_scan
        self.engine = UnifiedProtectionEngine()

    def run(self) -> None:
        """Execute the unified protection analysis in background thread."""
        try:
            self.analysis_progress.emit("Initializing protection analysis...", 10)

            # Quick check first
            self.analysis_progress.emit("Performing quick scan...", 20)
            quick_summary = self.engine.get_quick_summary(self.file_path)

            if quick_summary["protected"]:
                self.analysis_progress.emit(
                    f"Detected {quick_summary['protection_count']} protection(s), analyzing...",
                    40,
                )

            # Full analysis
            self.analysis_progress.emit("Running comprehensive analysis...", 60)
            result = self.engine.analyze(self.file_path, deep_scan=self.deep_scan)

            self.analysis_progress.emit("Generating bypass strategies...", 90)

            self.analysis_progress.emit("Analysis complete!", 100)
            self.analysis_complete.emit(result)

        except Exception as e:
            logger.exception("Exception in unified_protection_widget: %s", e, exc_info=True)
            self.analysis_error.emit(str(e))


class ProtectionCard(QFrame):
    """Card widget for displaying individual protection."""

    #: Emit protection data when clicked (type: dict)
    clicked = pyqtSignal(dict)

    def __init__(self, protection_data: dict[str, Any], parent: QWidget | None = None) -> None:
        """Initialize protection card widget with analysis data and UI setup.

        Args:
            protection_data: Dictionary containing protection information including name, type, confidence, and source
            parent: Parent widget for Qt ownership hierarchy

        """
        super().__init__(parent)
        self.protection_data = protection_data
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the protection card UI."""
        self.setFrameStyle(QFrame.Box)
        self.setStyleSheet("""
            ProtectionCard {
                border: 2px solid #ddd;
                border-radius: 8px;
                background-color: #f9f9f9;
                padding: 10px;
            }
            ProtectionCard:hover {
                border-color: #4CAF50;
                background-color: #f0f8f0;
            }
        """)

        layout = QVBoxLayout()

        # Protection name
        name_label = QLabel(self.protection_data["name"])
        name_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(name_label)

        # Type and confidence
        info_layout = QHBoxLayout()

        type_label = QLabel(f"Type: {self.protection_data['type']}")
        type_label.setStyleSheet("color: #666;")
        info_layout.addWidget(type_label)

        confidence = self.protection_data.get("confidence", 0)
        conf_label = QLabel(f"Confidence: {confidence:.0f}%")

        if confidence >= 90:
            conf_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        elif confidence >= 70:
            conf_label.setStyleSheet("color: #FF9800;")
        else:
            conf_label.setStyleSheet("color: #F44336;")

        info_layout.addWidget(conf_label)
        info_layout.addStretch()

        layout.addLayout(info_layout)

        # Source indicator
        source = self.protection_data.get("source", AnalysisSource.ICP)
        source_text = self._get_source_text(source)
        source_label = QLabel(source_text)
        source_label.setStyleSheet("color: #999; font-size: 9px;")
        layout.addWidget(source_label)

        self.setLayout(layout)

    def _get_source_text(self, source: AnalysisSource) -> str:
        """Get user-friendly source text for display in the protection card.

        Args:
            source: The analysis source enum value indicating detection method

        Returns:
            Human-readable string describing the detection source

        """
        if source == AnalysisSource.PROTECTION_ENGINE:
            return "Pattern Analysis"
        if source == AnalysisSource.ML_MODEL:
            return "AI Detection"
        if source == AnalysisSource.HEURISTIC:
            return "Behavioral Analysis"
        if source == AnalysisSource.HYBRID:
            return "Multi-Engine Verification"
        return "Signature Match"

    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Handle mouse click event on the protection card.

        Args:
            event: The mouse event containing button and position information

        """
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.protection_data)
        super().mousePressEvent(event)


class UnifiedProtectionWidget(QWidget):
    """Run widget for unified protection analysis."""

    # Signals
    #: UnifiedProtectionResult (type: object)
    protection_analyzed = pyqtSignal(object)
    #: file_path, protection_data (type: str, dict)
    bypass_requested = pyqtSignal(str, dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the unified protection analysis widget.

        Args:
            parent: Parent widget or None for top-level widget

        """
        super().__init__(parent)
        self.current_result: UnifiedProtectionResult | None = None
        self.analysis_thread: UnifiedAnalysisThread | None = None
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Header section
        self._create_header_section(layout)

        # Main content area
        self.content_splitter = QSplitter(Qt.Horizontal)

        # Left panel - Overview
        left_widget = self._create_overview_panel()
        self.content_splitter.addWidget(left_widget)

        # Right panel - Details
        right_widget = self._create_details_panel()
        self.content_splitter.addWidget(right_widget)

        self.content_splitter.setSizes([400, 600])
        layout.addWidget(self.content_splitter)

        # Status bar
        self._create_status_bar(layout)

        self.setLayout(layout)

    def _create_header_section(self, parent_layout: QVBoxLayout) -> None:
        """Create header section with controls and file information.

        Args:
            parent_layout: The parent layout to add the header section to

        """
        header_widget = QWidget()
        header_layout = QVBoxLayout()

        # Title and controls
        title_layout = QHBoxLayout()

        title = QLabel("Protection Analysis")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title_layout.addWidget(title)

        title_layout.addStretch()

        # Analysis controls
        self.quick_scan_btn = QPushButton("Quick Scan")
        self.quick_scan_btn.clicked.connect(lambda: self.analyze_file(deep_scan=False))
        title_layout.addWidget(self.quick_scan_btn)

        self.deep_scan_btn = QPushButton("Deep Analysis")
        self.deep_scan_btn.clicked.connect(lambda: self.analyze_file(deep_scan=True))
        self.deep_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        title_layout.addWidget(self.deep_scan_btn)

        # Native ICP Features button
        self.icp_features_btn = QPushButton("ICP Analysis...")
        self.icp_features_btn.setToolTip("Access advanced ICP Engine features directly in the interface")
        self.icp_features_btn.clicked.connect(self.show_icp_features_dialog)
        self.icp_features_btn.setEnabled(False)  # Disabled until file is loaded
        title_layout.addWidget(self.icp_features_btn)

        header_layout.addLayout(title_layout)

        # File info
        self.file_info_label = QLabel("No file selected")
        self.file_info_label.setStyleSheet("color: #666; padding: 5px;")
        header_layout.addWidget(self.file_info_label)

        header_widget.setLayout(header_layout)
        parent_layout.addWidget(header_widget)

    def _create_overview_panel(self) -> QWidget:
        """Create overview panel with summary and protection cards.

        Returns:
            Widget containing the overview panel UI components

        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Summary card
        self.summary_group = QGroupBox("Summary")
        summary_layout = QVBoxLayout()

        self.summary_text = QLabel("No analysis performed")
        self.summary_text.setWordWrap(True)
        self.summary_text.setStyleSheet("padding: 10px;")
        summary_layout.addWidget(self.summary_text)

        self.summary_group.setLayout(summary_layout)
        layout.addWidget(self.summary_group)

        # Protection cards area
        protections_group = QGroupBox("Detected Protections")
        protections_layout = QVBoxLayout()

        # Scroll area for protection cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        self.cards_widget = QWidget()
        self.cards_layout = QVBoxLayout()
        self.cards_layout.setAlignment(Qt.AlignTop)
        self.cards_widget.setLayout(self.cards_layout)

        scroll.setWidget(self.cards_widget)
        protections_layout.addWidget(scroll)

        protections_group.setLayout(protections_layout)
        layout.addWidget(protections_group)

        widget.setLayout(layout)
        return widget

    def _create_details_panel(self) -> QTabWidget:
        """Create details panel with tabbed interface for analysis results.

        Returns:
            Tab widget containing analysis details, hex view, strings, entropy, bypass strategies, and technical info

        """
        self.details_tabs = QTabWidget()

        # Analysis Details tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.details_text, "Analysis Details")

        # Hex View tab (HIGH PRIORITY INTEGRATION)
        self.hex_viewer = HexViewerWidget()
        self.hex_viewer.offset_selected.connect(self._on_hex_offset_selected)
        self.details_tabs.addTab(self.hex_viewer, "Hex View")

        # String Extraction tab (HIGH PRIORITY INTEGRATION)
        self.string_extractor = StringExtractionWidget()
        self.string_extractor.string_selected.connect(self._on_string_selected)
        self.details_tabs.addTab(self.string_extractor, "Strings")

        # Entropy Visualization tab
        self.entropy_graph = EntropyGraphWidget()
        self.entropy_graph.section_clicked.connect(self._on_entropy_section_clicked)
        self.details_tabs.addTab(self.entropy_graph, "Entropy Analysis")

        # Bypass Strategies tab
        self.bypass_widget = self._create_bypass_widget()
        self.details_tabs.addTab(self.bypass_widget, "Bypass Strategies")

        # Technical Info tab
        self.tech_text = QTextEdit()
        self.tech_text.setReadOnly(True)
        self.tech_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.tech_text, "Technical Information")

        # Performance tab
        self.perf_text = QTextEdit()
        self.perf_text.setReadOnly(True)
        self.perf_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.perf_text, "Analysis Performance")

        return self.details_tabs

    def _create_bypass_widget(self) -> QWidget:
        """Create bypass strategies widget with export functionality.

        Returns:
            Widget containing bypass strategies display and export button

        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Strategies will be added dynamically
        self.strategies_layout = QVBoxLayout()
        self.strategies_layout.setAlignment(Qt.AlignTop)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        strategies_widget = QWidget()
        strategies_widget.setLayout(self.strategies_layout)
        scroll.setWidget(strategies_widget)

        layout.addWidget(scroll)

        # Export button
        export_btn = QPushButton("Export Bypass Guide")
        export_btn.clicked.connect(self.export_bypass_guide)
        layout.addWidget(export_btn)

        widget.setLayout(layout)
        return widget

    def _create_status_bar(self, parent_layout: QVBoxLayout) -> None:
        """Create status bar with progress indicator.

        Args:
            parent_layout: The parent layout to add the status bar to

        """
        status_widget = QWidget()
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #666;")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        status_layout.addWidget(self.progress_bar)

        status_widget.setLayout(status_layout)
        parent_layout.addWidget(status_widget)

    def analyze_file(self, file_path: str | None = None, deep_scan: bool = True) -> None:
        """Analyze a file for protections."""
        if not file_path:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Binary to Analyze",
                "",
                "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*.*)",
            )

        if not file_path or not os.path.exists(file_path):
            return

        # Store current file path
        self._current_file_path = file_path

        # Get AI coordination strategy suggestion if available
        try:
            from intellicrack.handlers.pyqt6_handler import QApplication

            main_window = next(
                (widget for widget in QApplication.allWidgets() if hasattr(widget, "ai_coordinator") and widget.ai_coordinator),
                None,
            )
            if main_window and hasattr(main_window.ai_coordinator, "suggest_strategy"):
                analysis_type = "complex_patterns" if deep_scan else "quick_check"
                suggested_strategy = main_window.ai_coordinator.suggest_strategy(file_path, analysis_type)
                logger.info("AI coordinator suggests strategy: %s for %s", suggested_strategy, analysis_type)

                # Update status to show strategy
                strategy_text = str(suggested_strategy).replace("AnalysisStrategy.", "").replace("_", " ").title()
                self.status_label.setText(f"Using {strategy_text} strategy for analysis")
            else:
                self.status_label.setText("Starting analysis...")
        except Exception as e:
            logger.debug("Could not get strategy suggestion: %s", e, exc_info=True)
            self.status_label.setText("Starting analysis...")

        # Update UI
        self.file_info_label.setText(f"Analyzing: {os.path.basename(file_path)}")
        self.quick_scan_btn.setEnabled(False)
        self.deep_scan_btn.setEnabled(False)
        self.icp_features_btn.setEnabled(True)  # Enable ICP features button
        self.progress_bar.setVisible(True)

        # Clear previous results
        self.clear_results()

        # Start analysis thread
        self.analysis_thread = UnifiedAnalysisThread(file_path, deep_scan)
        self.analysis_thread.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_thread.analysis_error.connect(self.on_analysis_error)
        self.analysis_thread.analysis_progress.connect(self.on_analysis_progress)
        self.analysis_thread.start()

    @pyqtSlot(object)
    def on_analysis_complete(self, result: UnifiedProtectionResult) -> None:
        """Handle analysis completion."""
        self.current_result = result
        self.display_results(result)

        # Load file in hex viewer and string extractor
        if hasattr(self, "_current_file_path") and self._current_file_path:
            self.hex_viewer.load_file(self._current_file_path)
            self.string_extractor.load_file(self._current_file_path)

            # Highlight protection-related regions if available
            if result.icp_analysis and result.icp_analysis.entropy_info:
                for entropy in result.icp_analysis.entropy_info:
                    if entropy.packed or entropy.encrypted:
                        # Highlight suspicious sections
                        self.hex_viewer.add_protection_highlight(
                            entropy.offset,
                            entropy.size,
                            f"{entropy.section_name} ({'Packed' if entropy.packed else 'Encrypted'})",
                        )

        # Re-enable buttons
        self.quick_scan_btn.setEnabled(True)
        self.deep_scan_btn.setEnabled(True)
        self.generate_script_btn.setEnabled(len(result.protections) > 0)
        self.progress_bar.setVisible(False)

        # Update status
        protection_count = len(result.protections)
        if protection_count > 0:
            self.status_label.setText(
                f"Analysis complete: {protection_count} protection(s) detected",
            )
        else:
            self.status_label.setText("Analysis complete: No protections detected")

        # Emit signal
        self.protection_analyzed.emit(result)

    @pyqtSlot(str)
    def on_analysis_error(self, error_msg: str) -> None:
        """Handle analysis error."""
        QMessageBox.critical(self, "Analysis Error", f"Error during analysis:\n{error_msg}")

        self.quick_scan_btn.setEnabled(True)
        self.deep_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis failed")

    @pyqtSlot(str, int)
    def on_analysis_progress(self, message: str, progress: int) -> None:
        """Update progress."""
        self.status_label.setText(message)
        self.progress_bar.setValue(progress)

    def display_results(self, result: UnifiedProtectionResult) -> None:
        """Display analysis results."""
        # Update summary
        self.update_summary(result)

        # Display protection cards
        self.display_protection_cards(result)

        # Update details
        self._update_analysis_details(result)

        # Display bypass strategies
        self.display_bypass_strategies(result)

        # Update technical info
        self.update_technical_info(result)

        # Update performance info
        self.update_performance_info(result)

        # Update entropy visualization
        self.update_entropy_graph(result)

    def update_details(self, result: UnifiedProtectionResult) -> None:
        """Update the analysis details display with comprehensive protection information.

        Populates the details text panel with formatted analysis results including
        protection overview, detection sources, and actionable recommendations.

        Args:
            result: The unified protection analysis result containing all detection data.

        """
        self._update_analysis_details(result)

    def _update_analysis_details(self, result: UnifiedProtectionResult) -> None:
        """Internal method to update the analysis details display.

        Args:
            result: The unified protection analysis result containing all detection data.

        """
        details = "=== Protection Analysis Details ===\n\n"

        details += f"File: {os.path.basename(result.file_path)}\n"
        details += f"Type: {result.file_type}\n"
        details += f"Architecture: {result.architecture}\n"
        details += f"Analysis Time: {result.analysis_time:.3f} seconds\n\n"

        if not result.protections:
            details += "No protections detected.\n\n"
            details += "This binary appears to have no software protection mechanisms.\n"
            details += "It may be suitable for direct analysis without bypass techniques.\n"
        else:
            details += f"Total Protections Detected: {len(result.protections)}\n"
            details += f"Overall Confidence: {result.confidence_score:.1f}%\n\n"

            details += "--- Detected Protections ---\n\n"

            for i, protection in enumerate(result.protections, 1):
                details += f"{i}. {protection['name']}\n"
                details += f"   Type: {protection['type']}\n"
                details += f"   Confidence: {protection.get('confidence', 0):.0f}%\n"

                source = protection.get("source", AnalysisSource.ICP)
                details += f"   Detection Source: {self._format_source(source)}\n"

                if protection.get("version"):
                    details += f"   Version: {protection['version']}\n"

                if protection.get("details"):
                    details += "   Details:\n"
                    for key, value in protection["details"].items():
                        details += f"      {key}: {value}\n"

                details += "\n"

            details += "--- Protection Status Flags ---\n\n"
            details += f"Packed Binary: {'Yes' if result.is_packed else 'No'}\n"
            details += f"Protected: {'Yes' if result.is_protected else 'No'}\n"
            details += f"Obfuscated: {'Yes' if result.is_obfuscated else 'No'}\n"
            details += f"Anti-Debugging: {'Detected' if result.has_anti_debug else 'Not Detected'}\n"
            details += f"Anti-VM: {'Detected' if result.has_anti_vm else 'Not Detected'}\n"
            details += f"Licensing Protection: {'Detected' if result.has_licensing else 'Not Detected'}\n\n"

            if result.has_licensing:
                details += "--- Licensing Analysis ---\n\n"
                details += "License protection mechanisms detected. Potential bypass approaches:\n"
                details += "  - Locate license validation routines\n"
                details += "  - Identify serial number algorithms\n"
                details += "  - Trace registration API calls\n"
                details += "  - Analyze time-based trial checks\n\n"

            if result.has_anti_debug:
                details += "--- Anti-Debugging Analysis ---\n\n"
                details += "Anti-debugging techniques detected. Consider:\n"
                details += "  - Using anti-anti-debug bypasses\n"
                details += "  - Patching IsDebuggerPresent checks\n"
                details += "  - Hooking NtQueryInformationProcess\n"
                details += "  - Using ScyllaHide or similar tools\n\n"

            if result.is_packed:
                details += "--- Packing Analysis ---\n\n"
                details += "Binary appears to be packed or compressed.\n"
                details += "Consider unpacking before further analysis:\n"
                details += "  - Use automatic unpacker tools\n"
                details += "  - Dump process memory at OEP\n"
                details += "  - Reconstruct import table\n\n"

        self.details_text.setPlainText(details)

    def update_summary(self, result: UnifiedProtectionResult) -> None:
        """Update summary display."""
        if not result.protections:
            summary = f"""
<h3>No Protections Detected</h3>
<p>File Type: {result.file_type}<br>
Architecture: {result.architecture}<br>
Analysis Time: {result.analysis_time:.2f}s</p>
<p style="color: #4CAF50;">This file appears to be unprotected.</p>
"""
        else:
            protection_types = {p["type"] for p in result.protections}
            summary = f"""
<h3>Protection Summary</h3>
<p>File Type: {result.file_type}<br>
Architecture: {result.architecture}<br>
Protections Found: {len(result.protections)}<br>
Overall Confidence: {result.confidence_score:.0f}%</p>
<p>Protection Types: {", ".join(protection_types)}</p>
"""

            if result.is_packed:
                summary += '<p style="color: #FF9800;">WARNING File is packed</p>'
            if result.has_anti_debug:
                summary += '<p style="color: #F44336;">🛡 Anti-debugging detected</p>'
            if result.has_licensing:
                summary += '<p style="color: #2196F3;">🔑 License protection detected</p>'

        self.summary_text.setText(summary)

    def display_protection_cards(self, result: UnifiedProtectionResult) -> None:
        """Display protection cards."""
        # Clear existing cards
        while self.cards_layout.count():
            child = self.cards_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Add new cards
        for protection in result.protections:
            card = ProtectionCard(protection)
            card.clicked.connect(self.on_protection_clicked)
            self.cards_layout.addWidget(card)

        # Add stretch at end
        self.cards_layout.addStretch()

    def on_protection_clicked(self, protection_data: dict[str, Any]) -> None:
        """Handle protection card click."""
        # Show details for this protection
        self.show_protection_details(protection_data)

        # Switch to details tab
        self.details_tabs.setCurrentIndex(0)

    def show_protection_details(self, protection: dict[str, Any]) -> None:
        """Show detailed information for a protection."""
        details = f"""
=== {protection["name"]} ===

Type: {protection["type"]}
Confidence: {protection.get("confidence", 0):.0f}%
Source: {self._format_source(protection.get("source", AnalysisSource.ICP))}

"""

        if protection.get("version"):
            details += f"Version: {protection['version']}\n"

        if "details" in protection:
            details += "\nAdditional Details:\n"
            for key, value in protection["details"].items():
                details += f"  {key}: {value}\n"

        if "bypass_recommendations" in protection:
            details += "\nBypass Recommendations:\n"
            for rec in protection["bypass_recommendations"]:
                details += f"   {rec}\n"

        self.details_text.setPlainText(details)

    def _format_source(self, source: AnalysisSource) -> str:
        """Format analysis source for display in technical information.

        Args:
            source: The analysis source enum value indicating detection method

        Returns:
            Human-readable description of the detection source

        """
        if source == AnalysisSource.PROTECTION_ENGINE:
            return "Pattern-based detection"
        if source == AnalysisSource.ML_MODEL:
            return "AI/ML analysis"
        if source == AnalysisSource.HEURISTIC:
            return "Heuristic analysis"
        if source == AnalysisSource.HYBRID:
            return "Multiple detection methods"
        return str(source)

    def display_bypass_strategies(self, result: UnifiedProtectionResult) -> None:
        """Display bypass strategies."""
        # Clear existing strategies
        while self.strategies_layout.count():
            child = self.strategies_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if not result.bypass_strategies:
            no_strategies = QLabel("No specific bypass strategies available for detected protections.")
            no_strategies.setStyleSheet("color: #666; padding: 20px;")
            self.strategies_layout.addWidget(no_strategies)
            return

        # Add strategy cards
        for strategy in result.bypass_strategies:
            strategy_card = self._create_strategy_card(strategy)
            self.strategies_layout.addWidget(strategy_card)

        self.strategies_layout.addStretch()

    def _create_strategy_card(self, strategy: dict[str, Any]) -> QGroupBox:
        """Create a bypass strategy card with difficulty and steps.

        Args:
            strategy: Dictionary containing strategy information including name, description, difficulty, tools, and steps

        Returns:
            Group box containing the formatted strategy information

        """
        card = QGroupBox(strategy["name"])
        layout = QVBoxLayout()

        # Description
        desc_label = QLabel(strategy["description"])
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        # Difficulty
        diff_layout = QHBoxLayout()
        diff_layout.addWidget(QLabel("Difficulty:"))

        difficulty = strategy.get("difficulty", "Unknown")
        diff_label = QLabel(difficulty)

        if difficulty == "Easy":
            diff_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        elif difficulty == "Medium":
            diff_label.setStyleSheet("color: #FF9800; font-weight: bold;")
        elif difficulty == "Hard":
            diff_label.setStyleSheet("color: #F44336; font-weight: bold;")

        diff_layout.addWidget(diff_label)
        diff_layout.addStretch()
        layout.addLayout(diff_layout)

        # Tools
        if "tools" in strategy:
            tools_label = QLabel(f"Tools: {', '.join(strategy['tools'])}")
            tools_label.setStyleSheet("color: #666;")
            layout.addWidget(tools_label)

        # Steps
        if "steps" in strategy:
            steps_label = QLabel("Steps:")
            steps_label.setStyleSheet("font-weight: bold; margin-top: 5px;")
            layout.addWidget(steps_label)

            for i, step in enumerate(strategy["steps"], 1):
                step_label = QLabel(f"{i}. {step}")
                step_label.setWordWrap(True)
                step_label.setStyleSheet("margin-left: 20px;")
                layout.addWidget(step_label)

        card.setLayout(layout)
        return card

    def update_technical_info(self, result: UnifiedProtectionResult) -> None:
        """Update technical information display."""
        tech_info = "=== Technical Analysis Details ===\n\n"

        tech_info += f"File: {result.file_path}\n"
        tech_info += f"Type: {result.file_type}\n"
        tech_info += f"Architecture: {result.architecture}\n\n"

        tech_info += "Protection Flags:\n"
        tech_info += f"  Packed: {result.is_packed}\n"
        tech_info += f"  Protected: {result.is_protected}\n"
        tech_info += f"  Obfuscated: {result.is_obfuscated}\n"
        tech_info += f"  Anti-Debug: {result.has_anti_debug}\n"
        tech_info += f"  Anti-VM: {result.has_anti_vm}\n"
        tech_info += f"  Licensing: {result.has_licensing}\n\n"

        if result.icp_analysis:
            tech_info += "ICP Analysis Results:\n"
            icp = result.icp_analysis

            if icp.entry_point:
                tech_info += f"  Entry Point: {icp.entry_point}\n"

            if icp.sections:
                tech_info += f"  Sections: {len(icp.sections)}\n"
                for section in icp.sections[:5]:
                    name = section.get("name", "Unknown")
                    size = section.get("size", 0)
                    tech_info += f"    - {name}: {size} bytes\n"

            if icp.entropy_info:
                tech_info += "\n  Entropy Analysis:\n"
                for entropy in icp.entropy_info:
                    tech_info += f"    - {entropy.section_name}: {entropy.entropy:.3f}"
                    if entropy.packed:
                        tech_info += " [PACKED]"
                    elif entropy.encrypted:
                        tech_info += " [ENCRYPTED]"
                    tech_info += "\n"

        self.tech_text.setPlainText(tech_info)

    def update_entropy_graph(self, result: UnifiedProtectionResult) -> None:
        """Update entropy visualization with analysis data."""
        if result.icp_analysis and hasattr(result.icp_analysis, "entropy_analysis"):
            # Update the entropy graph with ICP entropy data
            self.entropy_graph.update_entropy_data(result.icp_analysis.entropy_analysis)
        else:
            # No entropy data available
            self.entropy_graph.update_entropy_data([])

    def _on_entropy_section_clicked(self, section_name: str, entropy_value: float) -> None:
        """Handle entropy section click."""
        # Show details about the section
        msg = f"Section: {section_name}\nEntropy: {entropy_value:.4f}\n\n"
        if entropy_value >= 7.0:
            msg += "High entropy indicates possible encryption or compression."
        elif entropy_value >= 6.0:
            msg += "Medium entropy may indicate obfuscation or packed data."
        else:
            msg += "Low entropy is typical for normal code and data."

        QMessageBox.information(self, "Section Entropy Details", msg)

    def update_performance_info(self, result: UnifiedProtectionResult) -> None:
        """Update performance information."""
        perf_info = "=== Analysis Performance ===\n\n"

        perf_info += f"Total Analysis Time: {result.analysis_time:.3f} seconds\n"
        perf_info += f"Engines Used: {', '.join(result.engines_used)}\n\n"

        perf_info += "Detection Sources:\n"
        source_counts = {}
        for protection in result.protections:
            source = protection.get("source", AnalysisSource.ICP)
            source_counts[source] = source_counts.get(source, 0) + 1

        for source, count in source_counts.items():
            perf_info += f"  {self._format_source(source)}: {count} detection(s)\n"

        self.perf_text.setPlainText(perf_info)

    def clear_results(self) -> None:
        """Clear all results."""
        self.summary_text.setText("No analysis performed")

        # Clear cards
        while self.cards_layout.count():
            child = self.cards_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Clear text displays
        self.details_text.clear()
        self.tech_text.clear()
        self.perf_text.clear()

        # Clear strategies
        while self.strategies_layout.count():
            child = self.strategies_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        self.current_result = None

    def export_bypass_guide(self) -> None:
        """Export bypass strategies to file."""
        if not self.current_result or not self.current_result.bypass_strategies:
            QMessageBox.information(self, "No Data", "No bypass strategies to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Bypass Guide",
            "bypass_guide.md",
            "Markdown Files (*.md);;Text Files (*.txt);;All Files (*.*)",
        )

        if not file_path:
            return

        try:
            content = self._generate_bypass_guide()
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            QMessageBox.information(
                self,
                "Export Complete",
                f"Bypass guide exported to:\n{file_path}",
            )
        except Exception as e:
            logger.exception("Exception in unified_protection_widget: %s", e, exc_info=True)
            QMessageBox.critical(
                self,
                "Export Error",
                f"Error exporting bypass guide:\n{e!s}",
            )

    def _generate_bypass_guide(self) -> str:
        """Generate bypass guide content."""
        result = self.current_result

        guide = "# Protection Bypass Guide\n\n"
        guide += f"**File:** {os.path.basename(result.file_path)}\n"
        guide += f"**Analysis Date:** {QDateTime.currentDateTime().toString()}\n\n"

        guide += "## Detected Protections\n\n"
        for protection in result.protections:
            guide += f"- **{protection['name']}** ({protection['type']})\n"
            guide += f"  - Confidence: {protection.get('confidence', 0):.0f}%\n"
            if protection.get("version"):
                guide += f"  - Version: {protection['version']}\n"

        guide += "\n## Bypass Strategies\n\n"

        for i, strategy in enumerate(result.bypass_strategies, 1):
            guide += f"### {i}. {strategy['name']}\n\n"
            guide += f"{strategy['description']}\n\n"

            guide += f"**Difficulty:** {strategy.get('difficulty', 'Unknown')}\n\n"

            if "tools" in strategy:
                guide += f"**Required Tools:** {', '.join(strategy['tools'])}\n\n"

            if "steps" in strategy:
                guide += "**Steps:**\n\n"
                for j, step in enumerate(strategy["steps"], 1):
                    guide += f"{j}. {step}\n"
                guide += "\n"

        guide += "## Notes\n\n"
        guide += "This guide is generated based on automated analysis. "
        guide += "Actual bypass methods may vary depending on specific implementation details. "
        guide += "Always ensure you have proper authorization before attempting to bypass protections.\n"

        return guide

    def set_binary_path(self, file_path: str) -> None:
        """Set binary path for analysis."""
        if file_path and os.path.exists(file_path):
            self.file_info_label.setText(f"File: {os.path.basename(file_path)}")
            # Auto-analyze
            self.analyze_file(file_path, deep_scan=False)

    def show_icp_features_dialog(self) -> None:
        """Display native ICP Engine features in a comprehensive dialog.

        Opens a tabbed dialog showing detailed ICP analysis including:
        - Signature analysis with packer detection
        - Section analysis with entropy per section
        - Overall entropy analysis with interpretation
        - String extraction with offsets

        The analysis runs in a background thread to avoid blocking the UI.
        """
        if not hasattr(self, "_current_file_path") or not self._current_file_path:
            QMessageBox.information(
                self,
                "No File Loaded",
                "Please analyze a file first to access ICP features.",
            )
            return

        try:
            from ...dialogs.icp_features_dialog import ICPFeaturesDialog

            dialog = ICPFeaturesDialog(self._current_file_path, self)
            dialog.exec()
        except ImportError:
            # Create a simple features dialog inline for now
            self._show_inline_icp_features()
        except Exception as e:
            logger.exception("Failed to show ICP features dialog: %s", e, exc_info=True)
            QMessageBox.critical(
                self,
                "ICP Features Error",
                f"Failed to open ICP features:\n{e!s}",
            )

    def _show_inline_icp_features(self) -> None:
        """Display comprehensive native ICP analysis in tabbed dialog.

        Creates a modal dialog with four analysis tabs:
        1. Signature Analysis - File type, packers, and protection status
        2. Section Analysis - PE sections with addresses and characteristics
        3. Entropy Analysis - Shannon entropy with interpretation
        4. String Analysis - Extracted strings with file offsets

        All analysis is performed using the native ICP backend in a background
        thread to maintain UI responsiveness.
        """
        from PyQt6.QtCore import QThread, pyqtSignal
        from PyQt6.QtWidgets import QDialog, QProgressBar, QTabWidget, QTextEdit, QVBoxLayout

        dialog = QDialog(self)
        dialog.setWindowTitle("Native ICP Engine Analysis")
        dialog.resize(900, 700)

        layout = QVBoxLayout()

        # Progress bar
        progress = QProgressBar()
        layout.addWidget(progress)

        tabs = QTabWidget()

        # Create text widgets for each tab
        sig_text = QTextEdit()
        sig_text.setFont(QFont("Consolas", 9))
        tabs.addTab(sig_text, "Signature Analysis")

        section_text = QTextEdit()
        section_text.setFont(QFont("Consolas", 9))
        tabs.addTab(section_text, "Section Analysis")

        entropy_text = QTextEdit()
        entropy_text.setFont(QFont("Consolas", 9))
        tabs.addTab(entropy_text, "Entropy Analysis")

        strings_text = QTextEdit()
        strings_text.setFont(QFont("Consolas", 9))
        tabs.addTab(strings_text, "String Analysis")

        layout.addWidget(tabs)
        dialog.setLayout(layout)

        # Load ICP data in background
        class ICPAnalysisThread(QThread):
            analysis_complete = pyqtSignal(dict)
            progress_updated = pyqtSignal(int)

            def __init__(self, file_path: str) -> None:
                """Initialize ICP analysis thread.

                Args:
                    file_path: Path to the binary file to analyze

                """
                super().__init__()
                self.file_path = file_path

            def run(self) -> None:
                try:
                    backend = get_icp_backend()
                    self.progress_updated.emit(25)

                    # Get detailed analysis
                    analysis = backend.get_detailed_analysis(self.file_path)
                    self.progress_updated.emit(100)

                    self.analysis_complete.emit(analysis)
                except Exception as e:
                    logger.exception("ICP analysis error: %s", e, exc_info=True)
                    self.analysis_complete.emit({"error": str(e)})

        def update_analysis(analysis_data: dict[str, Any]) -> None:
            """Update the dialog with ICP analysis results.

            Args:
                analysis_data: Dictionary containing ICP analysis results including file type, entropy, sections, and strings

            """
            progress.setVisible(False)

            if "error" in analysis_data:
                sig_text.setPlainText(f"Error: {analysis_data['error']}")
                return

            # Signature Analysis
            sig_content = "=== Native ICP Signature Analysis ===\n\n"
            sig_content += f"File Type: {analysis_data.get('file_type', 'Unknown')}\n"
            sig_content += f"File Size: {analysis_data.get('file_size', 0)} bytes\n"
            sig_content += f"Overall Entropy: {analysis_data.get('entropy', 0.0):.4f}\n\n"

            packers = analysis_data.get("packers", [])
            if packers:
                sig_content += "Detected Packers/Protectors:\n"
                for packer in packers:
                    sig_content += f"   {packer}\n"
            else:
                sig_content += "No packers detected\n"

            sig_content += f"\nPacked: {'Yes' if analysis_data.get('is_packed') else 'No'}\n"
            sig_content += f"Encrypted: {'Yes' if analysis_data.get('is_encrypted') else 'No'}\n"

            sig_text.setPlainText(sig_content)

            # Section Analysis
            sections = analysis_data.get("sections", [])
            section_content = "=== Section Analysis ===\n\n"
            section_content += f"Total Sections: {len(sections)}\n\n"

            for i, section in enumerate(sections):
                section_content += f"Section {i + 1}: {section.get('name', 'Unknown')}\n"
                section_content += f"  Virtual Address: 0x{section.get('virtual_address', 0):08X}\n"
                section_content += f"  Virtual Size: {section.get('virtual_size', 0)} bytes\n"
                section_content += f"  Raw Size: {section.get('raw_size', 0)} bytes\n"
                section_content += f"  Raw Offset: 0x{section.get('raw_offset', 0):08X}\n"
                section_content += f"  Characteristics: 0x{section.get('characteristics', 0):08X}\n"
                section_content += f"  Entropy: {section.get('entropy', 0.0):.4f}\n\n"

            section_text.setPlainText(section_content)

            # Entropy Analysis
            entropy_content = "=== Entropy Analysis ===\n\n"
            entropy_content += f"Overall File Entropy: {analysis_data.get('entropy', 0.0):.6f}\n\n"

            if analysis_data.get("entropy", 0.0) > 7.5:
                entropy_content += "🔴 HIGH ENTROPY - Likely encrypted or compressed\n"
            elif analysis_data.get("entropy", 0.0) > 6.0:
                entropy_content += "🟡 MEDIUM ENTROPY - Possible obfuscation\n"
            else:
                entropy_content += "🟢 LOW ENTROPY - Normal code/data\n"

            entropy_content += "\nEntropy Interpretation:\n"
            entropy_content += " 0.0 - 4.0: Low entropy (normal code, text)\n"
            entropy_content += " 4.0 - 6.0: Medium entropy (mixed content)\n"
            entropy_content += " 6.0 - 7.5: High entropy (compressed/obfuscated)\n"
            entropy_content += " 7.5 - 8.0: Very high entropy (encrypted)\n\n"

            # Per-section entropy
            entropy_content += "Per-Section Entropy:\n"
            for section in sections:
                name = section.get("name", "Unknown")
                ent = section.get("entropy", 0.0)
                entropy_content += f"  {name}: {ent:.4f}\n"

            entropy_text.setPlainText(entropy_content)

            # String Analysis
            strings = analysis_data.get("strings", [])
            string_content = "=== String Analysis ===\n\n"
            string_content += f"Total Strings Found: {len(strings)}\n\n"

            if strings:
                string_content += "Sample Strings (first 50):\n\n"
                for _i, string_info in enumerate(strings[:50]):
                    offset = string_info.get("offset", 0)
                    string_val = string_info.get("string", "")
                    string_type = string_info.get("type", "ASCII")
                    string_content += f"0x{offset:08X}: [{string_type}] {string_val!r}\n"

                if len(strings) > 50:
                    string_content += f"\n... and {len(strings) - 50} more strings\n"
            else:
                string_content += "No strings found\n"

            strings_text.setPlainText(string_content)

        # Start analysis
        thread = ICPAnalysisThread(self._current_file_path)
        thread.analysis_complete.connect(update_analysis)
        thread.progress_updated.connect(progress.setValue)
        thread.start()

        # Show dialog
        dialog.exec()

    def generate_bypass_script(self) -> None:
        """Generate bypass script using the script generation handler."""
        if not self.current_result:
            QMessageBox.warning(self, "No Analysis", "Please analyze a file first.")
            return

        if not self.current_result.protections:
            QMessageBox.information(
                self,
                "No Protections",
                "No protections detected to generate bypass script.",
            )
            return

        # Create a simple dialog to choose script type

        script_type, ok = QInputDialog.getItem(
            self,
            "Select Script Type",
            "Choose the type of bypass script to generate:",
            ["Frida", "Ghidra"],
            0,
            False,
        )

        if ok:
            # Import the handler here to avoid circular imports
            from ...analysis.handlers.script_generation_handler import ScriptGenerationHandler

            # Create temporary handler for script generation
            handler = ScriptGenerationHandler(self)
            handler.current_result = self.current_result

            # Generate and show script
            handler.generate_script(script_type.lower(), self)

    def _on_hex_offset_selected(self, offset: int) -> None:
        """Handle hex viewer offset selection."""
        # Update technical info with offset details
        if self.current_result and self.current_result.icp_analysis and self.current_result.icp_analysis.sections:
            for section in self.current_result.icp_analysis.sections:
                section_start = section.get("virtual_address", 0)
                section_size = section.get("virtual_size", 0)
                if section_start <= offset < section_start + section_size:
                    info = f"\nOffset 0x{offset:X} is in section: {section.get('name', 'Unknown')}\n"
                    info += f"Section start: 0x{section_start:X}\n"
                    info += f"Offset in section: 0x{offset - section_start:X}\n"
                    self.tech_text.append(info)
                    break

    def _on_string_selected(self, offset: int, string: str) -> None:
        """Handle string selection from string extractor."""
        # Navigate hex viewer to the string offset
        self.hex_viewer.go_to_offset(offset)

        # Highlight the string in hex viewer
        self.hex_viewer.highlighted_regions.clear()  # Clear previous highlights
        self.hex_viewer.highlighted_regions.append(
            (offset, offset + len(string), QColor(255, 255, 0, 150)),  # Yellow highlight
        )
        self.hex_viewer.update_display()

        # Switch to hex view tab
        self.details_tabs.setCurrentWidget(self.hex_viewer)

        # Update technical info
        info = f"\nString at offset 0x{offset:X}:\n"
        info += f"Content: {string!r}\n"
        info += f"Length: {len(string)} bytes\n"
        self.tech_text.append(info)
