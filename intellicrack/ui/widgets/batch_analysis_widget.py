"""Batch Analysis Widget for File Browser Integration

Provides batch processing capabilities for analyzing multiple files with the
Intellicrack Protection Engine (ICP). Supports parallel processing, progress tracking,
and result aggregation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QBrush,
    QCheckBox,
    QColor,
    QComboBox,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
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


@dataclass
class BatchAnalysisResult:
    """Result of batch analysis for a single file"""

    file_path: str
    file_size: int
    analysis_time: float
    success: bool
    error_message: str = ""
    protections: list[dict[str, Any]] = field(default_factory=list)
    is_packed: bool = False
    is_protected: bool = False
    file_type: str = "Unknown"
    architecture: str = "Unknown"
    entropy: float = 0.0
    icp_detections: int = 0
    confidence_score: float = 0.0

    @property
    def status(self) -> str:
        """Get analysis status string"""
        if not self.success:
            return "Failed"
        if self.is_protected:
            return "Protected"
        if self.is_packed:
            return "Packed"
        return "Clean"


class BatchAnalysisWorker(QThread):
    """Worker thread for batch analysis"""

    # Signals
    #: current, total (type: int, int)
    progress_updated = pyqtSignal(int, int)
    #: file_path, result (type: str, BatchAnalysisResult)
    file_completed = pyqtSignal(str, BatchAnalysisResult)
    #: all results (type: list)
    analysis_finished = pyqtSignal(list)
    #: error message (type: str)
    error_occurred = pyqtSignal(str)

    def __init__(self, file_paths: list[str], max_workers: int = 4, deep_scan: bool = False):
        """Initialize batch analysis thread.

        Args:
            file_paths: List of file paths to analyze
            max_workers: Maximum number of worker threads for parallel processing
            deep_scan: Whether to perform deep scanning analysis

        """
        super().__init__()
        self.file_paths = file_paths
        self.max_workers = max_workers
        self.deep_scan = deep_scan
        self.cancelled = False
        self.unified_engine = get_unified_engine()

    def cancel(self):
        """Cancel the analysis"""
        self.cancelled = True

    def run(self):
        """Execute batch analysis"""
        try:
            results = []
            completed = 0
            total = len(self.file_paths)

            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_path = {
                    executor.submit(self._analyze_file, file_path): file_path
                    for file_path in self.file_paths
                }

                # Process completed tasks
                for future in as_completed(future_to_path):
                    if self.cancelled:
                        break

                    file_path = future_to_path[future]

                    try:
                        result = future.result()
                        results.append(result)
                        completed += 1

                        # Emit progress and completion signals
                        self.progress_updated.emit(completed, total)
                        self.file_completed.emit(file_path, result)

                    except Exception as e:
                        logger.error(f"Analysis failed for {file_path}: {e}")
                        # Create failed result
                        failed_result = BatchAnalysisResult(
                            file_path=file_path,
                            file_size=0,
                            analysis_time=0.0,
                            success=False,
                            error_message=str(e),
                        )
                        results.append(failed_result)
                        completed += 1
                        self.progress_updated.emit(completed, total)
                        self.file_completed.emit(file_path, failed_result)

            if not self.cancelled:
                self.analysis_finished.emit(results)

        except Exception as e:
            logger.error("Exception in batch_analysis_widget: %s", e)
            self.error_occurred.emit(f"Batch analysis failed: {e!s}")

    def _analyze_file(self, file_path: str) -> BatchAnalysisResult:
        """Analyze a single file"""
        start_time = time.time()

        try:
            # Get file size
            file_size = os.path.getsize(file_path)

            # Perform analysis
            result = self.unified_engine.analyze_file(file_path, deep_scan=self.deep_scan)
            analysis_time = time.time() - start_time

            # Extract information
            protections = result.protections if result else []
            is_packed = result.is_packed if result else False
            is_protected = result.is_protected if result else False
            file_type = result.file_type if result else "Unknown"
            architecture = result.architecture if result else "Unknown"
            entropy = result.entropy if result else 0.0

            # Count ICP detections and calculate confidence
            icp_detections = 0
            confidence_score = 0.0

            if result and result.icp_analysis and not result.icp_analysis.error:
                icp_detections = len(result.icp_analysis.all_detections)
                if result.icp_analysis.all_detections:
                    # Average confidence of all detections
                    total_confidence = sum(d.confidence for d in result.icp_analysis.all_detections)
                    confidence_score = total_confidence / len(result.icp_analysis.all_detections)

            return BatchAnalysisResult(
                file_path=file_path,
                file_size=file_size,
                analysis_time=analysis_time,
                success=True,
                protections=protections,
                is_packed=is_packed,
                is_protected=is_protected,
                file_type=file_type,
                architecture=architecture,
                entropy=entropy,
                icp_detections=icp_detections,
                confidence_score=confidence_score,
            )

        except Exception as e:
            analysis_time = time.time() - start_time
            logger.error(f"Failed to analyze {file_path}: {e}")

            return BatchAnalysisResult(
                file_path=file_path,
                file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                analysis_time=analysis_time,
                success=False,
                error_message=str(e),
            )


class BatchAnalysisWidget(QWidget):
    """Widget for batch analysis of multiple files"""

    # Signals
    #: file_path (type: str)
    file_selected = pyqtSignal(str)
    #: file_path for detailed analysis (type: str)
    analysis_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize the batch analysis widget with UI components and analysis functionality."""
        super().__init__(parent)
        self.results: list[BatchAnalysisResult] = []
        self.worker: BatchAnalysisWorker | None = None
        self.selected_files: list[str] = []
        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Control panel
        control_panel = self._create_control_panel()
        layout.addWidget(control_panel)

        # Main content area
        main_splitter = QSplitter(Qt.Vertical)

        # Results table
        self.results_table = self._create_results_table()
        main_splitter.addWidget(self.results_table)

        # Details panel
        details_panel = self._create_details_panel()
        main_splitter.addWidget(details_panel)

        main_splitter.setSizes([400, 200])
        layout.addWidget(main_splitter)

        # Status bar
        self.status_label = QLabel("Ready for batch analysis")
        self.status_label.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def _create_control_panel(self) -> QWidget:
        """Create control panel with analysis options"""
        panel = QWidget()
        layout = QVBoxLayout()

        # File selection
        file_group = QGroupBox("File Selection")
        file_layout = QHBoxLayout()

        self.select_files_btn = QPushButton("Select Files...")
        self.select_files_btn.clicked.connect(self.select_files)
        file_layout.addWidget(self.select_files_btn)

        self.select_folder_btn = QPushButton("Select Folder...")
        self.select_folder_btn.clicked.connect(self.select_folder)
        file_layout.addWidget(self.select_folder_btn)

        self.file_count_label = QLabel("0 files selected")
        file_layout.addWidget(self.file_count_label)

        file_layout.addStretch()
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_layout = QHBoxLayout()

        self.deep_scan_cb = QCheckBox("Deep Scan")
        self.deep_scan_cb.setToolTip("Perform thorough analysis (slower)")
        options_layout.addWidget(self.deep_scan_cb)

        options_layout.addWidget(QLabel("Max Threads:"))
        self.max_threads_spin = QSpinBox()
        self.max_threads_spin.setMinimum(1)
        self.max_threads_spin.setMaximum(16)
        self.max_threads_spin.setValue(4)
        options_layout.addWidget(self.max_threads_spin)

        self.file_filter_combo = QComboBox()
        self.file_filter_combo.addItems(
            [
                "All Files",
                "PE Files (*.exe, *.dll)",
                "Archives (*.zip, *.rar)",
                "Scripts (*.js, *.py)",
                "Documents (*.pdf, *.doc)",
            ]
        )
        options_layout.addWidget(self.file_filter_combo)

        options_layout.addStretch()
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Control buttons
        control_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Analysis")
        self.start_btn.clicked.connect(self.start_analysis)
        self.start_btn.setEnabled(False)
        control_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_analysis)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        control_layout.addWidget(self.clear_btn)

        self.export_btn = QPushButton("Export Results...")
        self.export_btn.clicked.connect(self.export_results)
        control_layout.addWidget(self.export_btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        control_layout.addWidget(self.progress_bar)

        control_layout.addStretch()
        layout.addLayout(control_layout)

        panel.setLayout(layout)
        return panel

    def _create_results_table(self) -> QTableWidget:
        """Create results table"""
        table = QTableWidget()

        # Set columns
        headers = [
            "File Name",
            "Path",
            "Size",
            "Status",
            "Type",
            "Architecture",
            "Protections",
            "ICP Detections",
            "Confidence",
            "Time (s)",
            "Details",
        ]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)

        # Configure table
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSortingEnabled(True)
        table.horizontalHeader().setStretchLastSection(True)

        # Connect signals
        table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        table.itemSelectionChanged.connect(self._on_selection_changed)

        return table

    def _create_details_panel(self) -> QWidget:
        """Create details panel for selected file"""
        panel = QWidget()
        layout = QVBoxLayout()

        # Details tabs
        self.details_tabs = QTabWidget()

        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.summary_text, "Summary")

        # Protections tab
        self.protections_text = QTextEdit()
        self.protections_text.setReadOnly(True)
        self.protections_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.protections_text, "Protections")

        # Error log tab
        self.error_log_text = QTextEdit()
        self.error_log_text.setReadOnly(True)
        self.error_log_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.error_log_text, "Errors")

        layout.addWidget(self.details_tabs)
        panel.setLayout(layout)

        return panel

    def select_files(self):
        """Select individual files for analysis"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Files for Batch Analysis",
            "",
            "All Files (*.*)",
        )

        if files:
            self.selected_files = files
            self._update_file_selection()

    def select_folder(self):
        """Select folder and scan for files"""
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder for Batch Analysis",
        )

        if folder:
            # Scan folder for files based on filter
            filter_type = self.file_filter_combo.currentText()
            files = self._scan_folder(folder, filter_type)

            if files:
                self.selected_files = files
                self._update_file_selection()
            else:
                QMessageBox.information(
                    self,
                    "No Files Found",
                    f"No matching files found in {folder}",
                )

    def _scan_folder(self, folder_path: str, filter_type: str) -> list[str]:
        """Scan folder for files matching filter"""
        files = []

        # Define file extensions for each filter
        extensions = {
            "All Files": None,
            "PE Files (*.exe, *.dll)": [".exe", ".dll", ".sys", ".scr"],
            "Archives (*.zip, *.rar)": [".zip", ".rar", ".7z", ".tar", ".gz"],
            "Scripts (*.js, *.py)": [".js", ".py", ".vbs", ".ps1", ".bat"],
            "Documents (*.pdf, *.doc)": [".pdf", ".doc", ".docx", ".rtf"],
        }

        target_extensions = extensions.get(filter_type)

        try:
            for root, _dirs, filenames in os.walk(folder_path):
                for filename in filenames:
                    file_path = os.path.join(root, filename)

                    # Check if file matches filter
                    if target_extensions is None:  # All files
                        files.append(file_path)
                    else:
                        file_ext = os.path.splitext(filename)[1].lower()
                        if file_ext in target_extensions:
                            files.append(file_path)

        except Exception as e:
            logger.error(f"Error scanning folder {folder_path}: {e}")

        return files

    def _update_file_selection(self):
        """Update UI after file selection"""
        count = len(self.selected_files)
        self.file_count_label.setText(f"{count} files selected")
        self.start_btn.setEnabled(count > 0)

        # Update status
        total_size = sum(os.path.getsize(f) for f in self.selected_files if os.path.exists(f))
        size_mb = total_size / (1024 * 1024)
        self.status_label.setText(f"Ready: {count} files ({size_mb:.1f} MB)")

    def start_analysis(self):
        """Start batch analysis"""
        if not self.selected_files:
            QMessageBox.warning(self, "No Files", "Please select files to analyze")
            return

        # Clear previous results
        self.results.clear()
        self.results_table.setRowCount(0)

        # Setup progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(self.selected_files))
        self.progress_bar.setValue(0)

        # Update UI state
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Analysis in progress...")

        # Start worker thread
        max_workers = self.max_threads_spin.value()
        deep_scan = self.deep_scan_cb.isChecked()

        self.worker = BatchAnalysisWorker(self.selected_files, max_workers, deep_scan)
        self.worker.progress_updated.connect(self._on_progress_updated)
        self.worker.file_completed.connect(self._on_file_completed)
        self.worker.analysis_finished.connect(self._on_analysis_finished)
        self.worker.error_occurred.connect(self._on_error_occurred)
        self.worker.start()

    def stop_analysis(self):
        """Stop current analysis"""
        if self.worker:
            self.worker.cancel()
            self.worker.wait()
            self.worker = None

        # Reset UI state
        self._reset_ui_state()
        self.status_label.setText("Analysis stopped")

    def clear_results(self):
        """Clear all results"""
        self.results.clear()
        self.results_table.setRowCount(0)
        self.summary_text.clear()
        self.protections_text.clear()
        self.error_log_text.clear()
        self.status_label.setText("Results cleared")

    def export_results(self):
        """Export results to CSV"""
        if not self.results:
            QMessageBox.information(self, "No Results", "No analysis results to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Batch Analysis Results",
            "batch_analysis_results.csv",
            "CSV Files (*.csv);;All Files (*.*)",
        )

        if file_path:
            try:
                self._export_to_csv(file_path)
                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Results exported to {file_path}",
                )
            except Exception as e:
                logger.error("Exception in batch_analysis_widget: %s", e)
                QMessageBox.critical(
                    self,
                    "Export Failed",
                    f"Failed to export results: {e!s}",
                )

    def _export_to_csv(self, file_path: str):
        """Export results to CSV file"""
        import csv

        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow(
                [
                    "File Name",
                    "File Path",
                    "Size (bytes)",
                    "Status",
                    "File Type",
                    "Architecture",
                    "Is Packed",
                    "Is Protected",
                    "Protection Count",
                    "ICP Detections",
                    "Confidence Score",
                    "Entropy",
                    "Analysis Time (s)",
                    "Protections",
                    "Error Message",
                ]
            )

            # Write data
            for result in self.results:
                protection_names = []
                if result.protections:
                    protection_names = [p.get("name", "Unknown") for p in result.protections]

                writer.writerow(
                    [
                        os.path.basename(result.file_path),
                        result.file_path,
                        result.file_size,
                        result.status,
                        result.file_type,
                        result.architecture,
                        result.is_packed,
                        result.is_protected,
                        len(result.protections),
                        result.icp_detections,
                        f"{result.confidence_score:.2f}",
                        f"{result.entropy:.2f}",
                        f"{result.analysis_time:.2f}",
                        "; ".join(protection_names),
                        result.error_message,
                    ]
                )

    @pyqtSlot(int, int)
    def _on_progress_updated(self, current: int, total: int):
        """Handle progress update"""
        self.progress_bar.setValue(current)
        progress_pct = (current / total) * 100 if total > 0 else 0
        self.status_label.setText(f"Analyzing... {current}/{total} ({progress_pct:.1f}%)")

    @pyqtSlot(str, BatchAnalysisResult)
    def _on_file_completed(self, file_path: str, result: BatchAnalysisResult):
        """Handle completed file analysis"""
        self.results.append(result)
        self._add_result_to_table(result)

    @pyqtSlot(list)
    def _on_analysis_finished(self, results: list[BatchAnalysisResult]):
        """Handle analysis completion"""
        self._reset_ui_state()

        # Update status with summary
        total = len(results)
        protected = sum(1 for r in results if r.is_protected)
        packed = sum(1 for r in results if r.is_packed)
        failed = sum(1 for r in results if not r.success)

        self.status_label.setText(
            f"Analysis complete: {total} files, {protected} protected, "
            f"{packed} packed, {failed} failed",
        )

    @pyqtSlot(str)
    def _on_error_occurred(self, error_message: str):
        """Handle analysis error"""
        self._reset_ui_state()
        QMessageBox.critical(self, "Analysis Error", error_message)
        self.status_label.setText("Analysis failed")

    def _reset_ui_state(self):
        """Reset UI to ready state"""
        self.progress_bar.setVisible(False)
        self.start_btn.setEnabled(len(self.selected_files) > 0)
        self.stop_btn.setEnabled(False)

    def _add_result_to_table(self, result: BatchAnalysisResult):
        """Add analysis result to table"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        # File name
        name_item = QTableWidgetItem(os.path.basename(result.file_path))
        self.results_table.setItem(row, 0, name_item)

        # Path
        path_item = QTableWidgetItem(result.file_path)
        path_item.setToolTip(result.file_path)
        self.results_table.setItem(row, 1, path_item)

        # Size
        size_mb = result.file_size / (1024 * 1024)
        size_item = QTableWidgetItem(f"{size_mb:.2f} MB")
        self.results_table.setItem(row, 2, size_item)

        # Status with color coding
        status_item = QTableWidgetItem(result.status)
        if result.status == "Protected":
            status_item.setBackground(QBrush(QColor(255, 200, 200)))  # Light red
        elif result.status == "Packed":
            status_item.setBackground(QBrush(QColor(255, 255, 200)))  # Light yellow
        elif result.status == "Failed":
            status_item.setBackground(QBrush(QColor(200, 200, 200)))  # Light gray
        else:
            status_item.setBackground(QBrush(QColor(200, 255, 200)))  # Light green
        self.results_table.setItem(row, 3, status_item)

        # Type
        type_item = QTableWidgetItem(result.file_type)
        self.results_table.setItem(row, 4, type_item)

        # Architecture
        arch_item = QTableWidgetItem(result.architecture)
        self.results_table.setItem(row, 5, arch_item)

        # Protection count
        prot_count = len(result.protections)
        prot_item = QTableWidgetItem(str(prot_count))
        self.results_table.setItem(row, 6, prot_item)

        # ICP detections
        icp_item = QTableWidgetItem(str(result.icp_detections))
        self.results_table.setItem(row, 7, icp_item)

        # Confidence
        conf_item = QTableWidgetItem(f"{result.confidence_score:.1f}%")
        self.results_table.setItem(row, 8, conf_item)

        # Analysis time
        time_item = QTableWidgetItem(f"{result.analysis_time:.2f}")
        self.results_table.setItem(row, 9, time_item)

        # Details button
        details_item = QTableWidgetItem("View Details")
        self.results_table.setItem(row, 10, details_item)

        # Auto-resize columns
        self.results_table.resizeColumnsToContents()

    def _on_cell_double_clicked(self, row: int, column: int):
        """Handle double click on table cell"""
        if row < len(self.results):
            result = self.results[row]
            if column == 10:  # Details column
                self._show_file_details(result)
            else:
                # Emit signal for external handlers
                self.file_selected.emit(result.file_path)

    def _on_selection_changed(self):
        """Handle table selection change"""
        current_row = self.results_table.currentRow()
        if 0 <= current_row < len(self.results):
            result = self.results[current_row]
            self._show_file_details(result)

    def _show_file_details(self, result: BatchAnalysisResult):
        """Show detailed information for selected file"""
        # Summary tab
        summary = f"File: {os.path.basename(result.file_path)}\n"
        summary += f"Path: {result.file_path}\n"
        summary += f"Size: {result.file_size:,} bytes ({result.file_size/(1024*1024):.2f} MB)\n"
        summary += f"Type: {result.file_type}\n"
        summary += f"Architecture: {result.architecture}\n"
        summary += f"Status: {result.status}\n"
        summary += f"Packed: {'Yes' if result.is_packed else 'No'}\n"
        summary += f"Protected: {'Yes' if result.is_protected else 'No'}\n"
        summary += f"Entropy: {result.entropy:.2f}\n"
        summary += f"ICP Detections: {result.icp_detections}\n"
        summary += f"Confidence: {result.confidence_score:.1f}%\n"
        summary += f"Analysis Time: {result.analysis_time:.2f} seconds\n"

        self.summary_text.setPlainText(summary)

        # Protections tab
        if result.protections:
            protections_text = "Detected Protections:\n\n"
            for i, prot in enumerate(result.protections, 1):
                protections_text += f"{i}. {prot.get('name', 'Unknown')}\n"
                protections_text += f"   Type: {prot.get('type', 'Unknown')}\n"
                protections_text += f"   Source: {prot.get('source', 'Unknown')}\n"
                protections_text += f"   Confidence: {prot.get('confidence', 0):.1f}%\n"
                if prot.get("version"):
                    protections_text += f"   Version: {prot['version']}\n"
                protections_text += "\n"
        else:
            protections_text = "No protections detected"

        self.protections_text.setPlainText(protections_text)

        # Error tab
        if result.error_message:
            self.error_log_text.setPlainText(f"Error: {result.error_message}")
        else:
            self.error_log_text.setPlainText("No errors")

    def add_files_from_list(self, file_paths: list[str]):
        """Add files from external source (e.g., file browser)"""
        self.selected_files.extend(file_paths)
        # Remove duplicates
        self.selected_files = list(set(self.selected_files))
        self._update_file_selection()

    def get_analysis_results(self) -> list[BatchAnalysisResult]:
        """Get current analysis results"""
        return self.results.copy()

    def get_statistics(self) -> dict[str, Any]:
        """Get analysis statistics"""
        if not self.results:
            return {}

        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        protected = sum(1 for r in self.results if r.is_protected)
        packed = sum(1 for r in self.results if r.is_packed)
        failed = total - successful

        avg_time = sum(r.analysis_time for r in self.results) / total if total > 0 else 0
        avg_confidence = (
            sum(r.confidence_score for r in self.results if r.success) / successful
            if successful > 0
            else 0
        )

        return {
            "total_files": total,
            "successful": successful,
            "failed": failed,
            "protected": protected,
            "packed": packed,
            "clean": successful - protected - packed,
            "average_analysis_time": avg_time,
            "average_confidence": avg_confidence,
            "success_rate": (successful / total) * 100 if total > 0 else 0,
        }
