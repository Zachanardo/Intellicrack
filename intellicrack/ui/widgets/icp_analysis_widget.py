"""Intellicrack Protection Engine Analysis Widget

PyQt6 widget for displaying ICP engine analysis results.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio

from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...protection.icp_backend import ICPDetection, ICPScanResult, ScanMode, get_icp_backend
from ...utils.logger import get_logger

logger = get_logger(__name__)


class ICPAnalysisThread(QThread):
    """Background thread for ICP analysis"""

    #: ICPScanResult (type: object)
    result_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    progress_update = pyqtSignal(str)

    def __init__(self, file_path: str, scan_mode: ScanMode):
        """Initialize ICP analysis thread with file path, scan mode, and backend."""
        super().__init__()
        self.file_path = file_path
        self.scan_mode = scan_mode
        self._backend = get_icp_backend()

    def run(self):
        """Run analysis in background thread"""
        try:
            self.progress_update.emit(f"Analyzing {self.file_path}...")

            # Create event loop for async operation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Run analysis
            result = loop.run_until_complete(
                self._backend.analyze_file(self.file_path, self.scan_mode),
            )

            loop.close()

            if result.error:
                self.error_occurred.emit(result.error)
            else:
                self.result_ready.emit(result)

        except Exception as e:
            logger.error(f"ICP analysis thread error: {e}")
            self.error_occurred.emit(str(e))


class ICPAnalysisWidget(QWidget):
    """Widget for displaying ICP engine analysis results"""

    # Signals
    #: ICPScanResult (type: object)
    analysis_complete = pyqtSignal(object)
    #: ICPDetection (type: object)
    protection_selected = pyqtSignal(object)

    def __init__(self, parent=None):
        """Initialize the ICP analysis widget.

        Args:
            parent: Parent widget or None for top-level widget

        """
        super().__init__(parent)
        self._current_result: ICPScanResult | None = None
        self._analysis_thread: ICPAnalysisThread | None = None
        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout(self)

        # Header with controls
        header_layout = QHBoxLayout()

        # Title
        title = QLabel("Intellicrack Protection Engine")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Scan mode selector
        header_layout.addWidget(QLabel("Scan Mode:"))
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(
            [
                "Normal",
                "Deep",
                "Heuristic",
                "Aggressive",
                "All",
            ]
        )
        self.scan_mode_combo.setCurrentText("Deep")
        header_layout.addWidget(self.scan_mode_combo)

        # Analyze button
        self.analyze_btn = QPushButton("Analyze File")
        self.analyze_btn.clicked.connect(self.on_analyze_clicked)
        header_layout.addWidget(self.analyze_btn)

        layout.addLayout(header_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Main content area with splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left: Detection tree
        detections_group = QGroupBox("Detected Protections")
        detections_layout = QVBoxLayout(detections_group)

        self.detections_tree = QTreeWidget()
        self.detections_tree.setHeaderLabels(["Protection", "Type", "Confidence"])
        self.detections_tree.itemClicked.connect(self.on_detection_selected)
        detections_layout.addWidget(self.detections_tree)

        splitter.addWidget(detections_group)

        # Right: Details tabs
        self.details_tabs = QTabWidget()

        # Detection details tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_tabs.addTab(self.details_text, "Details")

        # Bypass recommendations tab
        self.bypass_text = QTextEdit()
        self.bypass_text.setReadOnly(True)
        self.details_tabs.addTab(self.bypass_text, "Bypass Methods")

        # Raw JSON tab
        self.raw_json_text = QTextEdit()
        self.raw_json_text.setReadOnly(True)
        self.raw_json_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.raw_json_text, "Raw Data")

        splitter.addWidget(self.details_tabs)
        splitter.setSizes([400, 600])

        layout.addWidget(splitter)

        # Status bar
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def analyze_file(self, file_path: str):
        """Start analysis of a file"""
        if self._analysis_thread and self._analysis_thread.isRunning():
            self.status_label.setText("Analysis already in progress")
            return

        # Get scan mode
        scan_mode_text = self.scan_mode_combo.currentText()
        scan_mode = ScanMode[scan_mode_text.upper()]

        # Create and start thread
        self._analysis_thread = ICPAnalysisThread(file_path, scan_mode)
        self._analysis_thread.result_ready.connect(self.on_analysis_complete)
        self._analysis_thread.error_occurred.connect(self.on_analysis_error)
        self._analysis_thread.progress_update.connect(self.on_progress_update)

        # Update UI
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate

        self._analysis_thread.start()

    @pyqtSlot()
    def on_analyze_clicked(self):
        """Handle analyze button click"""
        # This would typically open a file dialog
        # For now, emit a signal for the parent to handle
        self.status_label.setText("Select a file to analyze")

    @pyqtSlot(str)
    def on_progress_update(self, message: str):
        """Handle progress updates"""
        self.status_label.setText(message)

    @pyqtSlot(object)
    def on_analysis_complete(self, result: ICPScanResult):
        """Handle analysis completion"""
        self._current_result = result

        # Update UI
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        # Clear previous results
        self.detections_tree.clear()
        self.details_text.clear()
        self.bypass_text.clear()
        self.raw_json_text.clear()

        # Populate detections tree
        if result.file_infos:
            for file_info in result.file_infos:
                # Add file type as parent
                file_item = QTreeWidgetItem(
                    [
                        file_info.filetype,
                        f"Size: {file_info.size}",
                        "",
                    ]
                )
                self.detections_tree.addTopLevelItem(file_item)

                # Add detections as children
                for detection in file_info.detections:
                    detection_item = QTreeWidgetItem(
                        [
                            detection.name,
                            detection.type,
                            f"{detection.confidence * 100:.0f}%",
                        ]
                    )

                    # Color code by type
                    if detection.type == "Packer":
                        detection_item.setForeground(0, QBrush(QColor("#FF9800")))
                    elif detection.type == "Protector":
                        detection_item.setForeground(0, QBrush(QColor("#F44336")))
                    elif detection.type == "License":
                        detection_item.setForeground(0, QBrush(QColor("#2196F3")))

                    file_item.addChild(detection_item)

                file_item.setExpanded(True)

        # Update raw JSON
        if result.raw_json:
            import json

            self.raw_json_text.setText(
                json.dumps(result.raw_json, indent=2),
            )

        # Update status
        detection_count = len(result.all_detections)
        status = f"Analysis complete: {detection_count} protections detected"
        if result.is_packed:
            status += " [PACKED]"
        if result.is_protected:
            status += " [PROTECTED]"
        self.status_label.setText(status)

        # Emit signal
        self.analysis_complete.emit(result)

    @pyqtSlot(str)
    def on_analysis_error(self, error: str):
        """Handle analysis errors"""
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {error}")

    def on_detection_selected(self, item: QTreeWidgetItem, column: int):
        """Handle detection selection"""
        if not item.parent():  # Skip parent items
            return

        # Find the detection
        protection_name = item.text(0)
        detection = None

        if self._current_result:
            for file_info in self._current_result.file_infos:
                for det in file_info.detections:
                    if det.name == protection_name:
                        detection = det
                        break

        if detection:
            # Update details
            details = f"Protection: {detection.name}\n"
            details += f"Type: {detection.type}\n"
            details += f"Version: {detection.version or 'Unknown'}\n"
            details += f"Confidence: {detection.confidence * 100:.0f}%\n"
            if detection.info:
                details += f"\nAdditional Info:\n{detection.info}\n"
            if detection.string:
                details += f"\nDetection String:\n{detection.string}\n"

            self.details_text.setText(details)

            # Update bypass methods (would be enhanced with knowledge base)
            bypass_methods = self._get_bypass_methods(detection)
            self.bypass_text.setText(bypass_methods)

            # Emit signal
            self.protection_selected.emit(detection)

    def _get_bypass_methods(self, detection: ICPDetection) -> str:
        """Get bypass methods for a detection"""
        # This would integrate with the protection knowledge base
        # For now, provide generic recommendations

        methods = f"Bypass Methods for {detection.name}\n"
        methods += "=" * 50 + "\n\n"

        if detection.type == "Packer":
            methods += "1. Use unpacking tools (UPX, PEiD)\n"
            methods += "2. Dump process memory after unpacking\n"
            methods += "3. Set breakpoint at OEP (Original Entry Point)\n"
            methods += "4. Use Scylla for import reconstruction\n"

        elif detection.type == "Protector":
            methods += "1. Identify and bypass anti-debug checks\n"
            methods += "2. Use kernel-mode debugger\n"
            methods += "3. Patch integrity checks\n"
            methods += "4. Use hardware breakpoints\n"

        elif detection.type == "License":
            methods += "1. Locate license validation routines\n"
            methods += "2. Patch conditional jumps\n"
            methods += "3. Analyze license algorithm\n"
            methods += "4. Emulate license server responses\n"

        else:
            methods += "1. Analyze protection mechanism\n"
            methods += "2. Use appropriate debugging tools\n"
            methods += "3. Consider static and dynamic analysis\n"
            methods += "4. Check for known vulnerabilities\n"

        return methods

    def clear_results(self):
        """Clear all results"""
        self._current_result = None
        self.detections_tree.clear()
        self.details_text.clear()
        self.bypass_text.clear()
        self.raw_json_text.clear()
        self.status_label.setText("Ready")

    def get_current_result(self) -> ICPScanResult | None:
        """Get the current analysis result"""
        return self._current_result
