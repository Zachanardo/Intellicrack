"""Report Manager Dialog for Intellicrack.

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

import hashlib
import logging
import os
import shutil
import subprocess  # noqa: S404
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Import common PyQt6 components
from intellicrack.handlers.pyqt6_handler import (
    HAS_PYQT,
    QCheckBox,
    QCloseEvent,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QThread,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from .base_dialog import BaseDialog


logger = logging.getLogger(__name__)


class ReportManagerConstants:
    """Constants for report manager dialog."""

    KB_SIZE = 1024
    PREVIEW_CHAR_LIMIT = 1000


class ReportGenerationThread(QThread):
    """Thread for generating reports without blocking the UI."""

    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    generation_finished = pyqtSignal(bool, str, str)

    def __init__(self, report_config: dict[str, Any], output_path: str) -> None:
        """Initialize the ReportGenerationThread with default values.

        Args:
            report_config: Configuration dictionary containing report settings and binary analysis data.
            output_path: File path where the generated report will be written.

        Returns:
            None

        """
        super().__init__()
        self.report_config = report_config
        self.output_path = output_path

    def run(self) -> None:
        """Generate report in background thread.

        Emits progress and status updates throughout the generation process via signals.
        Performs binary analysis, vulnerability analysis, and license mechanism analysis.

        """
        try:
            self.status_updated.emit("Initializing report generation...")
            self.progress_updated.emit(10)

            if binary_path := self.report_config.get("binary_path"):
                self.status_updated.emit("Collecting binary analysis data...")
                self.progress_updated.emit(20)

                binary_data = self._analyze_binary(binary_path)
                self.report_config.update(binary_data)

                self.status_updated.emit("Performing vulnerability analysis...")
                self.progress_updated.emit(40)

                vulnerability_data = self._analyze_vulnerabilities(binary_path)
                self.report_config.update(vulnerability_data)

                self.status_updated.emit("Scanning for license protection patterns...")
                self.progress_updated.emit(60)

                license_data = self._analyze_license_mechanisms(binary_path)
                self.report_config.update(license_data)

                self.status_updated.emit("Processing analysis results...")
                self.progress_updated.emit(75)

            self.status_updated.emit("Generating report document...")
            self.progress_updated.emit(85)

            report_content = self.generate_report_content()

            with open(self.output_path, "w", encoding="utf-8") as f:
                f.write(report_content)

            self.progress_updated.emit(100)
            self.status_updated.emit("Report generation complete")
            self.generation_finished.emit(True, "Report generated successfully", self.output_path)  # noqa: FBT003

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in report_manager_dialog")
            self.generation_finished.emit(False, f"Report generation failed: {e!s}", "")  # noqa: FBT003

    def _analyze_binary(self, binary_path: str) -> dict[str, object]:
        """Analyze binary file and extract metadata.

        Args:
            binary_path: Path to the binary file to analyze.

        Returns:
            Dictionary containing binary metadata including file size, hashes, and architecture.

        """
        data: dict[str, object] = {}
        try:
            path = Path(binary_path)
            if path.exists():
                stat = path.stat()
                data["file_size"] = stat.st_size

                with open(binary_path, "rb") as f:
                    content = f.read()
                    data["sha256_hash"] = hashlib.sha256(content).hexdigest()

                if binary_path.lower().endswith((".exe", ".dll")):
                    data["architecture"] = "x86/x64 (Windows PE)"
                elif binary_path.lower().endswith((".so",)):
                    data["architecture"] = "ELF (Linux)"
                elif binary_path.lower().endswith((".dylib",)):
                    data["architecture"] = "Mach-O (macOS)"
                else:
                    data["architecture"] = "Unknown"
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Binary info extraction failed for %s: %s", binary_path, e)

        return data

    def _analyze_vulnerabilities(self, binary_path: str) -> dict[str, object]:
        """Analyze binary for licensing vulnerability patterns.

        Args:
            binary_path: Path to the binary file to analyze.

        Returns:
            Dictionary containing vulnerability analysis results.

        """
        vulnerabilities = 0
        patterns = 0

        try:
            with open(binary_path, "rb") as f:
                content = f.read()

                if b"IsDebuggerPresent" in content:
                    vulnerabilities += 1
                    patterns += 1

                if b"GetTickCount" in content:
                    patterns += 1

                if b"VirtualAlloc" in content:
                    patterns += 1

                common_license_checks = [
                    b"license",
                    b"serial",
                    b"validation",
                    b"activation",
                    b"registration",
                ]
                for check in common_license_checks:
                    if check in content.lower():
                        vulnerabilities += 1

        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Vulnerability analysis failed for %s: %s", binary_path, e)

        data: dict[str, object] = {
            "vulnerabilities": vulnerabilities,
            "patterns": patterns,
        }
        return data

    def _analyze_license_mechanisms(self, binary_path: str) -> dict[str, object]:
        """Analyze binary for license protection mechanisms.

        Args:
            binary_path: Path to the binary file to analyze.

        Returns:
            Dictionary containing license mechanism analysis results.

        """
        license_checks = 0

        try:
            with open(binary_path, "rb") as f:
                content = f.read()

                license_indicators = [
                    b"license",
                    b"serial",
                    b"key",
                    b"activation",
                    b"registration",
                    b"expired",
                    b"trial",
                ]

                for indicator in license_indicators:
                    if indicator in content.lower():
                        license_checks += 1

        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Could not analyze binary for license checks: %s", e)

        data: dict[str, object] = {"license_checks": license_checks}
        return data

    def generate_report_content(self) -> str:
        """Generate report content based on configuration.

        Returns:
            Formatted markdown report string containing analysis results.

        """
        config = self.report_config

        vulns = config.get("vulnerabilities", 0)
        patterns = config.get("patterns", 0)
        license_checks = config.get("license_checks", 0)

        recommendations = []
        if vulns > 0:
            recommendations.append(
                f"- Found {vulns} potential vulnerability indicators. Review all license validation logic.",
            )
        if patterns > 0:
            recommendations.append(
                f"- Detected {patterns} suspicious patterns related to debugging/timing checks.",
            )
        if license_checks > 0:
            recommendations.append(
                f"- Identified {license_checks} license-related protection mechanisms requiring hardening.",
            )

        if not recommendations:
            recommendations.append("- No specific vulnerabilities detected in initial scan.")

        recommendations_text = "\n".join(recommendations)

        return f"""# Intellicrack Analysis Report

Generated: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}
Report Type: {config.get("type", "Unknown")}
Binary: {config.get("binary_path", "N/A")}

## Executive Summary

This report contains the analysis results for the specified binary file including binary metadata, vulnerability assessment, and license protection mechanism analysis.

## Analysis Details

### Binary Information
- File: {config.get("binary_path", "N/A")}
- Size: {config.get("file_size", "Unknown")} bytes
- Architecture: {config.get("architecture", "Unknown")}
- MD5: {config.get("md5_hash", "N/A")}
- SHA256: {config.get("sha256_hash", "N/A")}

### Analysis Results
- Vulnerabilities Found: {vulns}
- Suspicious Patterns: {patterns}
- License Checks Detected: {license_checks}

### Recommendations

Based on the analysis, the following recommendations are provided:

{recommendations_text}

## Detailed Findings

### Binary Protection Analysis
The binary was scanned for common licensing protection mechanisms and vulnerability patterns. The analysis examined:

1. License validation routines and serial key checking mechanisms
2. Debugging and anti-analysis protections
3. Trial period enforcement and activation checks
4. Registration verification and license key format validation

### Security Research Implications
This analysis is intended for authorized security research and defensive strengthening of licensing mechanisms. Developers should use these findings to improve their protection schemes.

## Conclusion

The analysis has been completed successfully. Please review the findings and implement the recommended security measures to strengthen your software's licensing protection mechanisms.

---
Generated by Intellicrack Analysis Platform
Report includes binary analysis, protection detection, and licensing mechanism assessment for security research purposes.
"""


class ReportManagerDialog(BaseDialog):
    """Dialog for managing Intellicrack reports."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ReportManagerDialog with default values.

        Args:
            parent: Parent widget for this dialog. Defaults to None.

        """
        super().__init__(parent)
        self.reports_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "reports")
        self.reports: dict[str, dict[str, Any]] = {}
        self.current_report: str | None = None

        self.binary_path_edit: QLineEdit
        self.browse_binary_btn: QPushButton
        self.browse_output_btn: QPushButton
        self.delete_btn: QPushButton
        self.duplicate_btn: QPushButton
        self.edit_btn: QPushButton
        self.generate_btn: QPushButton
        self.generation_thread: ReportGenerationThread | None = None
        self.include_detailed_logs: QCheckBox
        self.include_executive_summary: QCheckBox
        self.include_recommendations: QCheckBox
        self.include_screenshots: QCheckBox
        self.open_after_generation: QCheckBox
        self.output_format_combo: QComboBox
        self.output_path_edit: QLineEdit
        self.preview_btn: QPushButton
        self.progress_bar: QProgressBar
        self.report_name_edit: QLineEdit
        self.report_preview: QTextBrowser
        self.report_type_combo: QComboBox
        self.status_label: QLabel
        self.view_btn: QPushButton
        self.search_edit: QLineEdit
        self.type_filter: QComboBox
        self.date_filter: QComboBox
        self.reports_table: QTableWidget
        self.refresh_btn: QPushButton
        self.export_btn: QPushButton
        self.close_btn: QPushButton
        self.tab_widget: Any

        self.setup_ui()
        self.load_reports()
        self.refresh_report_list()

    # Note: finalize_widget_layout is now available in shared_ui_layouts.UILayoutHelpers

    def setup_ui(self) -> None:
        """Set up the user interface.

        Creates tabbed dialog with report management, generation, and template tabs.
        Initializes all UI components and connects signals.

        Returns:
            None

        """
        if not HAS_PYQT:
            logger.warning("PyQt6 not available, cannot create report manager dialog")
            return

        from ..shared_ui_layouts import UILayoutHelpers

        # Create main tabbed dialog layout
        layout, self.tab_widget = UILayoutHelpers.create_tabbed_dialog_layout(
            self,
            "Report Manager",
            (1000, 700),
            is_modal=True,
        )

        # Create and add tabs
        tab_specs = [
            ("Reports", self.create_reports_tab()),
            ("Generate Report", self.create_generate_tab()),
            ("Templates", self.create_templates_tab()),
        ]
        UILayoutHelpers.create_tabs_from_specs(self.tab_widget, tab_specs)

        # Create dialog buttons
        button_specs = [
            ("Refresh", self.refresh_report_list, False),
            ("Export Report...", self.export_report, False),
            ("Close", self.accept, True),
        ]
        buttons = UILayoutHelpers.create_dialog_buttons(button_specs, layout)

        # Store button references
        self.refresh_btn, self.export_btn, self.close_btn = buttons

        self.setLayout(layout)

    def create_reports_tab(self) -> QWidget:
        """Create the reports list tab.

        Returns:
            QWidget: Widget containing the reports list interface with search, filtering,
                and preview features.

        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Search and filter
        search_layout = QHBoxLayout()

        search_label = QLabel("Search:")
        self.search_edit = QLineEdit()
        self.search_edit.textChanged.connect(self.filter_reports)

        type_label = QLabel("Type:")
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All", "Vulnerability", "License", "Performance", "Custom"])
        self.type_filter.currentTextChanged.connect(self.filter_reports)

        date_label = QLabel("Date:")
        self.date_filter = QComboBox()
        self.date_filter.addItems(["All", "Today", "This Week", "This Month", "Custom"])
        self.date_filter.currentTextChanged.connect(self.filter_reports)

        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(type_label)
        search_layout.addWidget(self.type_filter)
        search_layout.addWidget(date_label)
        search_layout.addWidget(self.date_filter)
        search_layout.addStretch()

        layout.addLayout(search_layout)

        # Reports table
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(6)
        self.reports_table.setHorizontalHeaderLabels(
            [
                "Name",
                "Type",
                "Created",
                "Size",
                "Status",
                "Actions",
            ],
        )
        header = self.reports_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.reports_table.itemSelectionChanged.connect(self.on_report_selected)
        layout.addWidget(self.reports_table)

        # Report preview
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout()

        self.report_preview = QTextBrowser()
        self.report_preview.setMaximumHeight(200)
        preview_layout.addWidget(self.report_preview)

        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        # Report actions
        actions_layout = QHBoxLayout()

        self.view_btn = QPushButton("View Report")
        self.view_btn.clicked.connect(self.view_report)
        self.view_btn.setEnabled(False)

        self.edit_btn = QPushButton("Edit Report")
        self.edit_btn.clicked.connect(self.edit_report)
        self.edit_btn.setEnabled(False)

        self.duplicate_btn = QPushButton("Duplicate")
        self.duplicate_btn.clicked.connect(self.duplicate_report)
        self.duplicate_btn.setEnabled(False)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.clicked.connect(self.delete_report)
        self.delete_btn.setEnabled(False)

        actions_layout.addWidget(self.view_btn)
        actions_layout.addWidget(self.edit_btn)
        actions_layout.addWidget(self.duplicate_btn)
        actions_layout.addWidget(self.delete_btn)
        actions_layout.addStretch()

        layout.addLayout(actions_layout)

        widget.setLayout(layout)
        return widget

    def create_generate_tab(self) -> QWidget:
        """Create the generate report tab.

        Returns:
            QWidget: Widget containing report generation configuration and generation
                controls.

        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Report configuration
        config_group = QGroupBox("Report Configuration")
        config_layout = QFormLayout()

        self.report_name_edit = QLineEdit()
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems(["Vulnerability Analysis", "License Analysis", "Performance Analysis", "Custom"])

        self.binary_path_edit = QLineEdit()
        self.browse_binary_btn = QPushButton("Browse...")
        self.browse_binary_btn.clicked.connect(self.browse_binary)

        binary_layout = QHBoxLayout()
        binary_layout.addWidget(self.binary_path_edit)
        binary_layout.addWidget(self.browse_binary_btn)

        self.include_screenshots = QCheckBox("Include Screenshots")
        self.include_detailed_logs = QCheckBox("Include Detailed Logs")
        self.include_recommendations = QCheckBox("Include Recommendations")
        self.include_executive_summary = QCheckBox("Include Executive Summary")

        config_layout.addRow("Report Name:", self.report_name_edit)
        config_layout.addRow("Report Type:", self.report_type_combo)
        config_layout.addRow("Binary File:", binary_layout)
        config_layout.addRow("", self.include_screenshots)
        config_layout.addRow("", self.include_detailed_logs)
        config_layout.addRow("", self.include_recommendations)
        config_layout.addRow("", self.include_executive_summary)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # Output options
        output_group = QGroupBox("Output Options")
        output_layout = QFormLayout()

        self.output_format_combo = QComboBox()
        self.output_format_combo.addItems(["PDF", "HTML", "Markdown", "Text"])

        self.output_path_edit = QLineEdit()
        self.browse_output_btn = QPushButton("Browse...")
        self.browse_output_btn.clicked.connect(self.browse_output)

        output_path_layout = QHBoxLayout()
        output_path_layout.addWidget(self.output_path_edit)
        output_path_layout.addWidget(self.browse_output_btn)

        self.open_after_generation = QCheckBox("Open report after generation")

        output_layout.addRow("Output Format:", self.output_format_combo)
        output_layout.addRow("Output Path:", output_path_layout)
        output_layout.addRow("", self.open_after_generation)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        # Generation controls
        generation_layout = QHBoxLayout()

        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self.generate_report)

        self.preview_btn = QPushButton("Preview")
        self.preview_btn.clicked.connect(self.preview_report)

        generation_layout.addWidget(self.generate_btn)
        generation_layout.addWidget(self.preview_btn)
        generation_layout.addStretch()

        layout.addLayout(generation_layout)

        # Progress bar (initially hidden)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        from ..shared_ui_layouts import UILayoutHelpers

        return UILayoutHelpers.finalize_widget_layout(widget, layout)

    def create_templates_tab(self) -> QWidget:
        """Create the templates tab.

        Returns:
            QWidget: Widget containing template selection and management interface.

        """
        templates = [
            "Vulnerability Assessment Report",
            "License Compliance Report",
            "Performance Analysis Report",
            "Executive Summary Report",
            "Technical Deep Dive Report",
        ]

        widget = self.create_template_widget("Report Templates", templates)
        return widget

    def load_reports(self) -> None:
        """Load existing reports from the reports directory.

        Scans the reports directory and populates the reports dictionary with metadata
        for each report file found.

        """
        self.reports = {}

        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir, exist_ok=True)
            return

        for item in os.listdir(self.reports_dir):
            item_path = os.path.join(self.reports_dir, item)

            if os.path.isfile(item_path):
                # Get file info
                stat = Path(item_path).stat()

                # Determine report type from filename or content
                report_type = "Unknown"
                if "vulnerability" in item.lower():
                    report_type = "Vulnerability"
                elif "license" in item.lower():
                    report_type = "License"
                elif "performance" in item.lower():
                    report_type = "Performance"

                self.reports[item] = {
                    "name": item,
                    "path": item_path,
                    "type": report_type,
                    "created": datetime.fromtimestamp(stat.st_ctime),
                    "modified": datetime.fromtimestamp(stat.st_mtime),
                    "size": stat.st_size,
                    "status": "Complete",
                }

    def refresh_report_list(self) -> None:
        """Refresh the reports list display.

        Reloads reports from disk and updates the table UI.

        """
        self.load_reports()
        self.update_reports_table()

    def update_reports_table(self) -> None:
        """Update the reports table.

        Populates the reports table with all loaded reports and their metadata.

        """
        if not HAS_PYQT:
            return

        self.reports_table.setRowCount(len(self.reports))

        for row, (report_id, report_info) in enumerate(self.reports.items()):
            name_item = QTableWidgetItem(str(report_info["name"]))
            name_item.setData(Qt.ItemDataRole.UserRole, report_id)
            self.reports_table.setItem(row, 0, name_item)

            type_item = QTableWidgetItem(str(report_info["type"]))
            self.reports_table.setItem(row, 1, type_item)

            created_value = report_info["created"]
            if isinstance(created_value, datetime):
                created_str = created_value.strftime("%Y-%m-%d %H:%M")
            else:
                created_str = str(created_value)
            created_item = QTableWidgetItem(created_str)
            self.reports_table.setItem(row, 2, created_item)

            size_value = report_info["size"]
            if isinstance(size_value, int):
                size_str = self.format_file_size(size_value)
            else:
                size_str = str(size_value)
            size_item = QTableWidgetItem(size_str)
            self.reports_table.setItem(row, 3, size_item)

            status_item = QTableWidgetItem(str(report_info["status"]))
            self.reports_table.setItem(row, 4, status_item)

            # Actions
            actions_btn = QPushButton("Actions")
            self.reports_table.setCellWidget(row, 5, actions_btn)

    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format.

        Args:
            size_bytes: File size in bytes.

        Returns:
            Formatted file size string with appropriate unit (B, KB, or MB).

        """
        kb = ReportManagerConstants.KB_SIZE
        if size_bytes < kb:
            return f"{size_bytes} B"
        if size_bytes < kb * kb:
            return f"{size_bytes / kb:.1f} KB"
        return f"{size_bytes / (kb * kb):.1f} MB"

    def on_report_selected(self) -> None:
        """Handle report selection.

        Updates the current report selection and enables action buttons.

        """
        if not HAS_PYQT:
            return

        current_row = self.reports_table.currentRow()
        if current_row >= 0:
            if name_item := self.reports_table.item(current_row, 0):
                report_id_value = name_item.data(Qt.ItemDataRole.UserRole)
                if isinstance(report_id_value, str):
                    self.current_report = report_id_value
                    self.update_report_preview(report_id_value)
                    self.view_btn.setEnabled(True)
                    self.edit_btn.setEnabled(True)
                    self.duplicate_btn.setEnabled(True)
                    self.delete_btn.setEnabled(True)

    def update_report_preview(self, report_id: str) -> None:
        """Update the report preview.

        Args:
            report_id: Identifier of the report to preview.

        Displays the first 1000 characters of the report in the preview widget.

        """
        if report_id not in self.reports:
            return

        report_info = self.reports[report_id]
        report_path = report_info["path"]

        try:
            with open(report_path, encoding="utf-8") as f:
                content = f.read()

            limit = ReportManagerConstants.PREVIEW_CHAR_LIMIT
            preview = content[:limit]
            if len(content) > limit:
                preview += "\n\n... (truncated)"

            if self.report_preview is not None:
                self.report_preview.setPlainText(preview)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in report_manager_dialog")
            if self.report_preview is not None:
                self.report_preview.setPlainText(f"Error loading preview: {e!s}")

    def filter_reports(self) -> None:
        """Filter reports based on search criteria.

        Filters and displays reports based on the current search text and type filter settings.

        """
        if not HAS_PYQT:
            return

        search_text = self.search_edit.text().lower()
        selected_type = self.type_filter.currentText()

        self.reports_table.setRowCount(0)

        row = 0
        for report_id, report_info in self.reports.items():
            if selected_type != "All" and report_info.get("type", "") != selected_type:
                continue

            if search_text:
                name_str = str(report_info.get("name", "")).lower()
                type_str = str(report_info.get("type", "")).lower()

                if search_text not in name_str and search_text not in type_str:
                    continue

            self.reports_table.insertRow(row)

            name_item = QTableWidgetItem(str(report_info["name"]))
            name_item.setData(Qt.ItemDataRole.UserRole, report_id)
            self.reports_table.setItem(row, 0, name_item)

            type_item = QTableWidgetItem(str(report_info["type"]))
            self.reports_table.setItem(row, 1, type_item)

            created_value = report_info["created"]
            if isinstance(created_value, datetime):
                created_str = created_value.strftime("%Y-%m-%d %H:%M")
            else:
                created_str = str(created_value)
            created_item = QTableWidgetItem(created_str)
            self.reports_table.setItem(row, 2, created_item)

            size_value = report_info["size"]
            if isinstance(size_value, int):
                size_str = self.format_file_size(size_value)
            else:
                size_str = str(size_value)
            size_item = QTableWidgetItem(size_str)
            self.reports_table.setItem(row, 3, size_item)

            status_item = QTableWidgetItem(str(report_info["status"]))
            self.reports_table.setItem(row, 4, status_item)

            actions_btn = QPushButton("Actions")
            self.reports_table.setCellWidget(row, 5, actions_btn)

            row += 1

    def view_report(self) -> None:
        """View the selected report.

        Opens the selected report using the system default application.

        """
        if not self.current_report:
            return

        report_info = self.reports[self.current_report]
        report_path = report_info["path"]

        # Try to open with system default application
        try:
            if sys.platform == "win32":
                os.startfile(report_path)  # noqa: S606  # Legitimate report file opening for security research viewing
            elif sys.platform == "darwin":
                subprocess.run(["open", report_path], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            else:
                subprocess.run(["xdg-open", report_path], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in report_manager_dialog")
            if HAS_PYQT:
                QMessageBox.warning(self, "Warning", f"Could not open report: {e!s}")

    def edit_report(self) -> None:
        """Edit the selected report.

        Opens an edit dialog for modifying the selected report.

        """
        if not HAS_PYQT or not self.current_report:
            return

        report_info = self.reports.get(self.current_report)
        if not report_info:
            QMessageBox.warning(self, "Warning", "No report selected")
            return

        report_path = report_info.get("path", "")
        if not os.path.exists(report_path):
            QMessageBox.critical(self, "Error", f"Report file not found: {report_path}")
            return

        try:
            with open(report_path, encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            logger.exception("Failed to read report")
            QMessageBox.critical(self, "Error", f"Failed to read report: {e}")
            return

        from intellicrack.handlers.pyqt6_handler import QDialog, QDialogButtonBox, QPlainTextEdit

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Report: {self.current_report}")
        dialog.resize(800, 600)

        layout = QVBoxLayout(dialog)

        editor = QPlainTextEdit()
        editor.setPlainText(content)
        layout.addWidget(editor)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_content = editor.toPlainText()
            try:
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                self.refresh_report_list()
                QMessageBox.information(self, "Success", "Report saved successfully")
            except OSError as e:
                logger.exception("Failed to save report")
                QMessageBox.critical(self, "Error", f"Failed to save report: {e}")

    def duplicate_report(self) -> None:
        """Duplicate the selected report.

        Creates a copy of the selected report with a new name.

        """
        if not self.current_report:
            return

        report_info = self.reports[self.current_report]
        original_path = report_info["path"]

        # Create new filename
        base_name = os.path.splitext(self.current_report)[0]
        extension = os.path.splitext(self.current_report)[1]
        new_name = f"{base_name}_copy{extension}"
        new_path = os.path.join(self.reports_dir, new_name)

        try:
            shutil.copy2(original_path, new_path)
            self.refresh_report_list()

            if HAS_PYQT:
                QMessageBox.information(self, "Success", f"Report duplicated as: {new_name}")

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in report_manager_dialog")
            if HAS_PYQT:
                QMessageBox.critical(self, "Error", f"Failed to duplicate report: {e!s}")

    def delete_report(self) -> None:
        """Delete the selected report.

        Removes the selected report file after confirmation.

        """
        if not HAS_PYQT or not self.current_report:
            return

        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete report '{self.current_report}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                report_info = self.reports[self.current_report]
                os.remove(report_info["path"])

                self.refresh_report_list()
                self.report_preview.clear()

                # Disable action buttons
                self.view_btn.setEnabled(False)
                self.edit_btn.setEnabled(False)
                self.duplicate_btn.setEnabled(False)
                self.delete_btn.setEnabled(False)

                QMessageBox.information(self, "Success", "Report deleted successfully")

            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in report_manager_dialog")
                QMessageBox.critical(self, "Error", f"Failed to delete report: {e!s}")

    def browse_binary(self) -> None:
        """Browse for binary file.

        Opens file selection dialog to choose a binary file for analysis.

        """
        if not HAS_PYQT:
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Binary Files (*.exe *.dll *.so *.dylib);;All Files (*.*)",
        )

        if file_path:
            self.binary_path_edit.setText(file_path)

    def browse_output(self) -> None:
        """Browse for output directory.

        Opens directory selection dialog to choose where to save generated reports.

        """
        if not HAS_PYQT:
            return

        if dir_path := QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            self.reports_dir,
        ):
            self.output_path_edit.setText(dir_path)

    def generate_report(self) -> None:
        """Generate a new report.

        Validates inputs and spawns a background thread to generate the report.

        """
        if not HAS_PYQT:
            return

        # Validate inputs
        if not self.report_name_edit.text().strip():
            QMessageBox.warning(self, "Warning", "Please enter a report name")
            return

        if not self.binary_path_edit.text().strip():
            QMessageBox.warning(self, "Warning", "Please select a binary file")
            return

        # Prepare report configuration
        config = {
            "name": self.report_name_edit.text().strip(),
            "type": self.report_type_combo.currentText(),
            "binary_path": self.binary_path_edit.text().strip(),
            "format": self.output_format_combo.currentText(),
            "include_screenshots": self.include_screenshots.isChecked(),
            "include_detailed_logs": self.include_detailed_logs.isChecked(),
            "include_recommendations": self.include_recommendations.isChecked(),
            "include_executive_summary": self.include_executive_summary.isChecked(),
        }

        # Determine output path
        output_dir = self.output_path_edit.text().strip() or self.reports_dir
        output_filename = f"{config['name']}.txt"  # Simplified for demo
        output_path = os.path.join(output_dir, output_filename)

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.generate_btn.setEnabled(False)

        # Start generation thread
        self.generation_thread = ReportGenerationThread(config, output_path)
        self.generation_thread.progress_updated.connect(self.progress_bar.setValue)
        self.generation_thread.status_updated.connect(self.status_label.setText)
        self.generation_thread.generation_finished.connect(self.on_generation_finished)

        self.generation_thread.start()

    def on_generation_finished(self, success: bool, message: str, output_path: str) -> None:  # noqa: FBT001
        """Handle report generation completion.

        Args:
            success: Whether the report generation succeeded.
            message: Status message describing the result.
            output_path: Path to the generated report file.

        """
        if not HAS_PYQT:
            return

        self.progress_bar.setVisible(False)
        self.generate_btn.setEnabled(True)
        self.status_label.setText("")

        if success:
            QMessageBox.information(self, "Success", message)

            # Refresh reports list
            self.refresh_report_list()

            # Open report if requested
            if self.open_after_generation.isChecked() and output_path:
                try:
                    if sys.platform == "win32":
                        os.startfile(output_path)  # noqa: S606  # Legitimate report file opening for security research viewing
                    elif sys.platform == "darwin":
                        subprocess.run(["open", output_path], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    else:
                        subprocess.run(["xdg-open", output_path], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                except Exception:
                    logger.exception("Exception in report_manager_dialog")
        else:
            QMessageBox.critical(self, "Error", message)

    def preview_report(self) -> None:
        """Preview the report before generation.

        Shows a preview of what the generated report will look like.

        """
        if not HAS_PYQT:
            return

        from intellicrack.handlers.pyqt6_handler import QDialog, QDialogButtonBox

        report_config: dict[str, Any] = {
            "type": (getattr(self, "report_type_combo", None) and self.report_type_combo.currentText()) or "Analysis",
            "binary_path": (getattr(self, "binary_path_edit", None) and self.binary_path_edit.text()) or "N/A",
            "include_executive_summary": (getattr(self, "include_executive_summary", None) and self.include_executive_summary.isChecked()) or False,
            "include_detailed_logs": (getattr(self, "include_detailed_logs", None) and self.include_detailed_logs.isChecked()) or False,
            "include_recommendations": (getattr(self, "include_recommendations", None) and self.include_recommendations.isChecked()) or False,
        }

        binary_path = report_config.get("binary_path", "")
        if binary_path and binary_path != "N/A" and os.path.exists(binary_path):
            try:
                stat = Path(binary_path).stat()
                report_config["file_size"] = stat.st_size

                with open(binary_path, "rb") as f:
                    data = f.read()
                    report_config["md5_hash"] = hashlib.md5(data).hexdigest()  # noqa: S324
                    report_config["sha256_hash"] = hashlib.sha256(data).hexdigest()
            except OSError as e:
                logger.warning("Could not read binary for preview: %s", e)

        thread = ReportGenerationThread(report_config, "")
        preview_content = thread.generate_report_content()

        dialog = QDialog(self)
        dialog.setWindowTitle("Report Preview")
        dialog.resize(800, 600)

        layout = QVBoxLayout(dialog)

        preview_browser = QTextBrowser()
        preview_browser.setMarkdown(preview_content)
        layout.addWidget(preview_browser)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        dialog.exec()

    def export_report(self) -> None:
        """Export the selected report.

        Saves a copy of the selected report to a user-chosen location.

        """
        if not HAS_PYQT or not self.current_report:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            self.current_report,
            "All Files (*.*)",
        )

        if file_path:
            try:
                report_info = self.reports[self.current_report]
                shutil.copy2(report_info["path"], file_path)

                QMessageBox.information(self, "Success", f"Report exported to: {file_path}")

            except (OSError, ValueError, RuntimeError) as e:
                self.logger.exception("Error in report_manager_dialog")
                QMessageBox.critical(self, "Error", f"Failed to export report: {e!s}")

    def on_template_selected(self) -> None:
        """Handle template selection.

        Updates the template details display when a template is selected.

        Returns:
            None

        """
        if not HAS_PYQT:
            return

        if current_item := self.template_list.currentItem():
            template_name = current_item.text()

            # Update template description
            descriptions = {
                "Vulnerability Assessment Report": "Comprehensive vulnerability analysis with risk ratings and remediation recommendations.",
                "License Compliance Report": "Analysis of license usage and compliance issues with legal recommendations.",
                "Performance Analysis Report": "Detailed performance metrics and optimization suggestions.",
                "Executive Summary Report": "High-level overview suitable for management and stakeholders.",
                "Technical Deep Dive Report": "Detailed technical analysis for security professionals and developers.",
            }

            description = descriptions.get(template_name, "No description available.")
            if hasattr(self, "template_details") and self.template_details is not None:
                self.template_details.setPlainText(description)

            if hasattr(self, "use_template_btn") and self.use_template_btn is not None:
                self.use_template_btn.setEnabled(True)
            if hasattr(self, "edit_template_btn") and self.edit_template_btn is not None:
                self.edit_template_btn.setEnabled(True)

    def use_template(self) -> None:
        """Use the selected template for report generation.

        Switches to the generate tab and pre-populates fields based on the selected
        template.

        Returns:
            None

        """
        if current_item := self.template_list.currentItem():
            template_name = current_item.text()

            # Switch to generate tab and populate fields
            self.tab_widget.setCurrentIndex(1)

            # Set report type based on template
            if "Vulnerability" in template_name:
                self.report_type_combo.setCurrentText("Vulnerability Analysis")
            elif "License" in template_name:
                self.report_type_combo.setCurrentText("License Analysis")
            elif "Performance" in template_name:
                self.report_type_combo.setCurrentText("Performance Analysis")

            # Set default options based on template
            if "Executive" in template_name:
                self.include_executive_summary.setChecked(True)
                self.include_detailed_logs.setChecked(False)
            elif "Technical" in template_name:
                self.include_detailed_logs.setChecked(True)
                self.include_screenshots.setChecked(True)

    def edit_template(self) -> None:
        """Edit the selected template.

        Opens an editor for modifying the selected report template.

        Returns:
            None

        """
        if not HAS_PYQT:
            return

        if not hasattr(self, "template_list") or not self.template_list.currentItem():
            QMessageBox.warning(self, "Warning", "No template selected")
            return

        template_name = self.template_list.currentItem().text()
        templates_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "templates", "report_manager")
        os.makedirs(templates_dir, exist_ok=True)

        template_path = os.path.join(templates_dir, f"{template_name.replace(' ', '_').lower()}.json")

        template_data: dict[str, Any] = {
            "name": template_name,
            "description": f"Template for {template_name}",
            "sections": ["executive_summary", "analysis_details", "recommendations", "conclusion"],
            "include_executive_summary": True,
            "include_detailed_logs": False,
            "include_recommendations": True,
            "include_screenshots": False,
        }

        if os.path.exists(template_path):
            try:
                import json
                with open(template_path, encoding="utf-8") as f:
                    template_data = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                logger.warning("Could not load template: %s", e)

        from intellicrack.handlers.pyqt6_handler import QDialog, QDialogButtonBox

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Template: {template_name}")
        dialog.resize(600, 500)

        layout = QVBoxLayout(dialog)

        form_layout = QFormLayout()

        name_edit = QLineEdit(template_data.get("name", template_name))
        form_layout.addRow("Name:", name_edit)

        desc_edit = QLineEdit(template_data.get("description", ""))
        form_layout.addRow("Description:", desc_edit)

        sections_edit = QLineEdit(",".join(template_data.get("sections", [])))
        form_layout.addRow("Sections (comma-separated):", sections_edit)

        include_summary = QCheckBox()
        include_summary.setChecked(template_data.get("include_executive_summary", True))
        form_layout.addRow("Include Executive Summary:", include_summary)

        include_logs = QCheckBox()
        include_logs.setChecked(template_data.get("include_detailed_logs", False))
        form_layout.addRow("Include Detailed Logs:", include_logs)

        include_recs = QCheckBox()
        include_recs.setChecked(template_data.get("include_recommendations", True))
        form_layout.addRow("Include Recommendations:", include_recs)

        layout.addLayout(form_layout)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            import json

            updated_template: dict[str, Any] = {
                "name": name_edit.text(),
                "description": desc_edit.text(),
                "sections": [s.strip() for s in sections_edit.text().split(",") if s.strip()],
                "include_executive_summary": include_summary.isChecked(),
                "include_detailed_logs": include_logs.isChecked(),
                "include_recommendations": include_recs.isChecked(),
                "include_screenshots": template_data.get("include_screenshots", False),
            }

            try:
                with open(template_path, "w", encoding="utf-8") as f:
                    json.dump(updated_template, f, indent=2)
                QMessageBox.information(self, "Success", "Template saved successfully")
            except OSError as e:
                logger.exception("Failed to save template")
                QMessageBox.critical(self, "Error", f"Failed to save template: {e}")

    def _get_templates_dir(self) -> str:
        """Get the templates directory path.

        Creates the templates directory if it does not exist.

        Returns:
            Path to the report manager templates directory.

        """
        templates_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "templates", "report_manager")
        os.makedirs(templates_dir, exist_ok=True)
        return templates_dir

    def _build_template_form(self, layout: QVBoxLayout, template_name: str) -> dict[str, Any]:
        """Build template creation/edit form and return widget references.

        Creates a form with description, sections, and checkbox options for template customization.

        Args:
            layout: The vertical layout container to add the form to.
            template_name: Name of the template being created or edited.

        Returns:
            Dictionary containing widget references indexed by field name.

        """
        form_layout = QFormLayout()

        widgets: dict[str, Any] = {}
        widgets["desc_edit"] = QLineEdit(f"Custom template for {template_name}")
        form_layout.addRow("Description:", widgets["desc_edit"])

        widgets["sections_edit"] = QLineEdit("executive_summary,analysis_details,recommendations,conclusion")
        form_layout.addRow("Sections (comma-separated):", widgets["sections_edit"])

        for key, label, default in [
            ("include_summary", "Include Executive Summary:", True),
            ("include_logs", "Include Detailed Logs:", False),
            ("include_recs", "Include Recommendations:", True),
            ("include_screenshots", "Include Screenshots:", False),
        ]:
            widgets[key] = QCheckBox()
            widgets[key].setChecked(default)
            form_layout.addRow(label, widgets[key])

        layout.addLayout(form_layout)
        return widgets

    def create_template(self) -> None:
        """Create a new report template.

        Opens a dialog to create a new custom report template.

        Returns:
            None

        """
        if not HAS_PYQT:
            return

        from intellicrack.handlers.pyqt6_handler import QDialog, QDialogButtonBox, QInputDialog

        template_name, ok = QInputDialog.getText(self, "Create Template", "Enter template name:")
        if not ok or not template_name.strip():
            return

        template_name = template_name.strip()
        template_path = os.path.join(self._get_templates_dir(), f"{template_name.replace(' ', '_').lower()}.json")

        if os.path.exists(template_path):
            result = QMessageBox.question(
                self, "Template Exists", f"Template '{template_name}' already exists. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if result != QMessageBox.StandardButton.Yes:
                return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Create Template: {template_name}")
        dialog.resize(600, 500)

        layout = QVBoxLayout(dialog)
        widgets = self._build_template_form(layout, template_name)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._save_new_template(template_name, template_path, widgets)

    def _save_new_template(self, template_name: str, template_path: str, widgets: dict[str, Any]) -> None:
        """Save a new template to disk.

        Serializes template configuration to JSON file and updates the template list UI.

        Args:
            template_name: Name of the template to create.
            template_path: Full file system path where the template JSON will be saved.
            widgets: Dictionary of QWidget references containing form values.

        """
        import json

        new_template: dict[str, Any] = {
            "name": template_name,
            "description": widgets["desc_edit"].text(),
            "sections": [s.strip() for s in widgets["sections_edit"].text().split(",") if s.strip()],
            "include_executive_summary": widgets["include_summary"].isChecked(),
            "include_detailed_logs": widgets["include_logs"].isChecked(),
            "include_recommendations": widgets["include_recs"].isChecked(),
            "include_screenshots": widgets["include_screenshots"].isChecked(),
        }

        try:
            with open(template_path, "w", encoding="utf-8") as f:
                json.dump(new_template, f, indent=2)

            if hasattr(self, "template_list"):
                from intellicrack.handlers.pyqt6_handler import QListWidgetItem
                self.template_list.addItem(QListWidgetItem(template_name))

            QMessageBox.information(self, "Success", f"Template '{template_name}' created successfully")
        except OSError as e:
            logger.exception("Failed to create template")
            QMessageBox.critical(self, "Error", f"Failed to create template: {e}")

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Handle dialog close with proper thread cleanup.

        Ensures any running report generation thread is properly terminated
        before closing the dialog to prevent resource leaks.

        Args:
            event: Close event from Qt framework.

        """
        if self.generation_thread is not None and self.generation_thread.isRunning():
            self.generation_thread.quit()
            if not self.generation_thread.wait(2000):
                self.generation_thread.terminate()
                self.generation_thread.wait()
            self.generation_thread = None
        super().closeEvent(event)


# Export for external use
__all__ = ["ReportGenerationThread", "ReportManagerDialog"]
