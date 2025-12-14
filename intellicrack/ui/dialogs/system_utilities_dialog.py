"""System utilities dialog for system-level analysis tools."""

from __future__ import annotations

import json
import os
import time
from typing import TYPE_CHECKING, Any

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QColor,
    QComboBox,
    QDialog,
    QFileDialog,
    QFont,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPixmap,
    QProgressBar,
    QPushButton,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QThread,
    QTimer,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.utils.logger import logger as module_logger


if TYPE_CHECKING:
    from logging import Logger

    from PyQt6.QtGui import QCloseEvent

"""
System Utilities Dialog for Intellicrack.

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


class SystemUtilitiesWorker(QThread):
    """Background worker for system utility operations."""

    operation_completed = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)

    def __init__(self, operation: str, **kwargs: object) -> None:
        """Initialize the system utilities worker with operation type and parameters."""
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self.should_stop = False
        self._logger: Logger = module_logger

    def run(self) -> None:
        """Execute the system utility operation."""
        try:
            if self.operation == "extract_icon":
                self._extract_icon()
            elif self.operation == "system_info":
                self._get_system_info()
            elif self.operation == "check_dependencies":
                self._check_dependencies()
            elif self.operation == "process_list":
                self._get_process_list()
            elif self.operation == "optimize_memory":
                self._optimize_memory()
        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error in system_utilities_dialog")
            self.error_occurred.emit(str(e))

    def _extract_icon(self) -> None:
        """Extract icon from executable."""
        try:
            from ...utils.system.system_utils import extract_executable_icon

            file_path_obj = self.kwargs.get("file_path", "")
            output_path_obj = self.kwargs.get("output_path", "")
            file_path = str(file_path_obj) if file_path_obj else ""
            output_path = str(output_path_obj) if output_path_obj else ""

            self.progress_updated.emit(25, "Analyzing executable...")

            result = extract_executable_icon(file_path, output_path)

            self.progress_updated.emit(100, "Icon extraction completed")
            self.operation_completed.emit(result)

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error in system_utilities_dialog")
            self.error_occurred.emit(f"Icon extraction failed: {e!s}")

    def _get_system_info(self) -> None:
        """Get comprehensive system information."""
        try:
            from ...utils.system.system_utils import get_system_info

            self.progress_updated.emit(50, "Gathering system information...")

            result = get_system_info()

            self.progress_updated.emit(100, "System information collected")
            self.operation_completed.emit(result)

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error in system_utilities_dialog")
            self.error_occurred.emit(f"System info collection failed: {e!s}")

    def _check_dependencies(self) -> None:
        """Check system dependencies."""
        try:
            from ...utils.system.system_utils import check_dependencies

            self.progress_updated.emit(30, "Checking dependencies...")

            default_deps = {
                "python": "python3",
                "pip": "pip3",
                "git": "git",
            }
            result = check_dependencies(dependencies=default_deps)

            self.progress_updated.emit(100, "Dependency check completed")
            self.operation_completed.emit(result)

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error in system_utilities_dialog")
            self.error_occurred.emit(f"Dependency check failed: {e!s}")

    def _get_process_list(self) -> None:
        """Get running process list."""
        try:
            from ...utils.system.system_utils import get_process_list

            self.progress_updated.emit(50, "Enumerating processes...")

            result = get_process_list()

            self.progress_updated.emit(100, "Process enumeration completed")
            self.operation_completed.emit({"processes": result})

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error in system_utilities_dialog")
            self.error_occurred.emit(f"Process enumeration failed: {e!s}")

    def _optimize_memory(self) -> None:
        """Optimize system memory usage."""
        try:
            from ...utils.system.system_utils import optimize_memory_usage

            self.progress_updated.emit(50, "Optimizing memory usage...")

            result = optimize_memory_usage()

            self.progress_updated.emit(100, "Memory optimization completed")
            self.operation_completed.emit(result)

        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error in system_utilities_dialog")
            self.error_occurred.emit(f"Memory optimization failed: {e!s}")

    def stop(self) -> None:
        """Stop the worker thread."""
        self.should_stop = True


class SystemUtilitiesDialog(QDialog):
    """System Utilities Dialog with various system tools."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the system utilities dialog with UI components and system monitoring capabilities."""
        super().__init__(parent)
        self._logger: Logger = module_logger
        self.worker: SystemUtilitiesWorker | None = None
        self.current_results: dict[str, dict[str, Any]] = {}

        self.close_btn: QPushButton | None = None
        self.deps_check_btn: QPushButton | None = None
        self.deps_install_btn: QPushButton | None = None
        self.deps_table: QTableWidget | None = None
        self.memory_free_label: QLabel | None = None
        self.memory_percent_label: QLabel | None = None
        self.memory_results: QTextEdit | None = None
        self.memory_total_label: QLabel | None = None
        self.memory_used_label: QLabel | None = None
        self.opt_clear_cache: QCheckBox | None = None
        self.opt_compress_memory: QCheckBox | None = None
        self.opt_defrag_memory: QCheckBox | None = None
        self.optimize_memory_btn: QPushButton | None = None
        self.process_filter: QLineEdit | None = None
        self.process_kill_btn: QPushButton | None = None
        self.process_refresh_btn: QPushButton | None = None
        self.process_table: QTableWidget | None = None
        self.progress_bar: QProgressBar | None = None
        self.status_label: QLabel | None = None
        self.sysinfo_display: QTextEdit | None = None
        self.sysinfo_export_btn: QPushButton | None = None
        self.sysinfo_refresh_btn: QPushButton | None = None
        self.icon_file_edit: QLineEdit | None = None
        self.icon_browse_btn: QPushButton | None = None
        self.icon_output_edit: QLineEdit | None = None
        self.icon_output_browse_btn: QPushButton | None = None
        self.icon_format_combo: QComboBox | None = None
        self.icon_size_combo: QComboBox | None = None
        self.extract_icon_btn: QPushButton | None = None
        self.icon_preview: QLabel | None = None
        self.tabs: QTabWidget | None = None

        self.setWindowTitle("System Utilities")
        self.setMinimumSize(800, 600)
        self.setModal(True)

        self.setup_ui()
        self.connect_signals()

    def setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()

        self.setup_icon_tab()
        self.setup_sysinfo_tab()
        self.setup_dependencies_tab()
        self.setup_process_tab()
        self.setup_memory_tab()

        layout.addWidget(self.tabs)

        self.setup_footer(layout)

    def setup_icon_tab(self) -> None:
        """Set up icon extraction tab."""
        icon_widget = QWidget()
        layout = QVBoxLayout(icon_widget)

        file_group = QGroupBox("Executable File")
        file_layout = QHBoxLayout(file_group)

        self.icon_file_edit = QLineEdit()
        self.icon_file_edit.setText("")
        hint_style = "color: #888888;"
        self.icon_file_edit.setStyleSheet(f"QLineEdit {{ {hint_style} }}")

        self.icon_browse_btn = QPushButton("Browse")
        self.icon_browse_btn.clicked.connect(self.browse_icon_file)

        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.icon_file_edit)
        file_layout.addWidget(self.icon_browse_btn)

        layout.addWidget(file_group)

        output_group = QGroupBox("Output Options")
        output_layout = QGridLayout(output_group)

        self.icon_output_edit = QLineEdit()
        self.icon_output_edit.setText("")

        self.icon_output_browse_btn = QPushButton("Browse")
        self.icon_output_browse_btn.clicked.connect(self.browse_icon_output)

        output_layout.addWidget(QLabel("Output Directory:"), 0, 0)
        output_layout.addWidget(self.icon_output_edit, 0, 1)
        output_layout.addWidget(self.icon_output_browse_btn, 0, 2)

        output_layout.addWidget(QLabel("Format:"), 1, 0)
        self.icon_format_combo = QComboBox()
        self.icon_format_combo.addItems(["ICO", "PNG", "BMP", "JPG"])
        output_layout.addWidget(self.icon_format_combo, 1, 1)

        output_layout.addWidget(QLabel("Size:"), 2, 0)
        self.icon_size_combo = QComboBox()
        self.icon_size_combo.addItems(["Original", "16x16", "32x32", "48x48", "64x64", "128x128", "256x256"])
        output_layout.addWidget(self.icon_size_combo, 2, 1)

        layout.addWidget(output_group)

        self.extract_icon_btn = QPushButton("Extract Icon")
        self.extract_icon_btn.clicked.connect(self.extract_icon)
        self.extract_icon_btn.setObjectName("extractIconButton")
        layout.addWidget(self.extract_icon_btn)

        preview_group = QGroupBox("Icon Preview")
        preview_layout = QVBoxLayout(preview_group)

        self.icon_preview = QLabel()
        self.icon_preview.setMinimumHeight(150)
        self.icon_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_preview.setObjectName("iconPreview")
        self.icon_preview.setText("Icon preview will appear here")

        preview_layout.addWidget(self.icon_preview)
        layout.addWidget(preview_group)

        layout.addStretch()
        if self.tabs is not None:
            self.tabs.addTab(icon_widget, "Icon Extraction")

    def setup_sysinfo_tab(self) -> None:
        """Set up system information tab."""
        sysinfo_widget = QWidget()
        layout = QVBoxLayout(sysinfo_widget)

        controls_layout = QHBoxLayout()

        self.sysinfo_refresh_btn = QPushButton("Refresh System Info")
        self.sysinfo_refresh_btn.clicked.connect(self.get_system_info)

        self.sysinfo_export_btn = QPushButton("Export Info")
        self.sysinfo_export_btn.clicked.connect(self.export_system_info)

        controls_layout.addWidget(self.sysinfo_refresh_btn)
        controls_layout.addWidget(self.sysinfo_export_btn)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        self.sysinfo_display = QTextEdit()
        self.sysinfo_display.setFont(QFont("Consolas", 10))
        self.sysinfo_display.setReadOnly(True)

        layout.addWidget(self.sysinfo_display)

        QTimer.singleShot(100, self.get_system_info)

        if self.tabs is not None:
            self.tabs.addTab(sysinfo_widget, "System Info")

    def setup_dependencies_tab(self) -> None:
        """Set up dependency checker tab."""
        deps_widget = QWidget()
        layout = QVBoxLayout(deps_widget)

        controls_layout = QHBoxLayout()

        self.deps_check_btn = QPushButton("Check Dependencies")
        self.deps_check_btn.clicked.connect(self.check_dependencies)

        self.deps_install_btn = QPushButton("Install Missing")
        self.deps_install_btn.clicked.connect(self.install_dependencies)
        self.deps_install_btn.setEnabled(False)

        controls_layout.addWidget(self.deps_check_btn)
        controls_layout.addWidget(self.deps_install_btn)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        self.deps_table = QTableWidget()
        self.deps_table.setColumnCount(4)
        self.deps_table.setHorizontalHeaderLabels(
            [
                "Dependency",
                "Required",
                "Installed",
                "Status",
            ],
        )

        header = self.deps_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.deps_table)

        if self.tabs is not None:
            self.tabs.addTab(deps_widget, "Dependencies")

    def setup_process_tab(self) -> None:
        """Set up process manager tab."""
        process_widget = QWidget()
        layout = QVBoxLayout(process_widget)

        controls_layout = QHBoxLayout()

        self.process_refresh_btn = QPushButton("Refresh Processes")
        self.process_refresh_btn.clicked.connect(self.get_process_list)

        self.process_kill_btn = QPushButton("Kill Selected")
        self.process_kill_btn.clicked.connect(self.kill_selected_process)
        self.process_kill_btn.setEnabled(False)

        controls_layout.addWidget(QLabel("Filter:"))
        self.process_filter = QLineEdit()
        self.process_filter.setText("")
        self.process_filter.textChanged.connect(self.filter_processes)

        controls_layout.addWidget(self.process_refresh_btn)
        controls_layout.addWidget(self.process_kill_btn)
        controls_layout.addWidget(self.process_filter)

        layout.addLayout(controls_layout)

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(
            [
                "PID",
                "Name",
                "CPU %",
                "Memory",
                "Status",
            ],
        )
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.itemSelectionChanged.connect(self.on_process_selection_changed)

        header = self.process_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.process_table)

        if self.tabs is not None:
            self.tabs.addTab(process_widget, "Process Manager")

    def setup_memory_tab(self) -> None:
        """Set up memory optimizer tab."""
        memory_widget = QWidget()
        layout = QVBoxLayout(memory_widget)

        info_group = QGroupBox("Memory Information")
        info_layout = QGridLayout(info_group)

        self.memory_total_label = QLabel("Total: --")
        self.memory_used_label = QLabel("Used: --")
        self.memory_free_label = QLabel("Free: --")
        self.memory_percent_label = QLabel("Usage: --%")

        info_layout.addWidget(QLabel("Total Memory:"), 0, 0)
        info_layout.addWidget(self.memory_total_label, 0, 1)
        info_layout.addWidget(QLabel("Used Memory:"), 1, 0)
        info_layout.addWidget(self.memory_used_label, 1, 1)
        info_layout.addWidget(QLabel("Free Memory:"), 2, 0)
        info_layout.addWidget(self.memory_free_label, 2, 1)
        info_layout.addWidget(QLabel("Usage Percent:"), 3, 0)
        info_layout.addWidget(self.memory_percent_label, 3, 1)

        layout.addWidget(info_group)

        opt_group = QGroupBox("Optimization Options")
        opt_layout = QVBoxLayout(opt_group)

        self.opt_clear_cache = QCheckBox("Clear System Cache")
        self.opt_clear_cache.setChecked(True)

        self.opt_compress_memory = QCheckBox("Compress Memory")
        self.opt_compress_memory.setChecked(True)

        self.opt_defrag_memory = QCheckBox("Defragment Memory")

        opt_layout.addWidget(self.opt_clear_cache)
        opt_layout.addWidget(self.opt_compress_memory)
        opt_layout.addWidget(self.opt_defrag_memory)

        layout.addWidget(opt_group)

        self.optimize_memory_btn = QPushButton("Optimize Memory")
        self.optimize_memory_btn.clicked.connect(self.optimize_memory)
        self.optimize_memory_btn.setObjectName("optimizeMemoryButton")
        layout.addWidget(self.optimize_memory_btn)

        self.memory_results = QTextEdit()
        self.memory_results.setMaximumHeight(150)
        self.memory_results.setFont(QFont("Consolas", 10))
        layout.addWidget(QLabel("Optimization Results:"))
        layout.addWidget(self.memory_results)

        layout.addStretch()
        if self.tabs is not None:
            self.tabs.addTab(memory_widget, "Memory Optimizer")

    def setup_footer(self, layout: QVBoxLayout) -> None:
        """Set up footer with status and progress."""
        footer_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        footer_layout.addWidget(self.progress_bar)

        status_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("readyStatus")

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)

        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.close_btn)

        footer_layout.addLayout(status_layout)
        layout.addLayout(footer_layout)

    def connect_signals(self) -> None:
        """Connect internal signals."""
        pass

    def browse_icon_file(self) -> None:
        """Browse for executable file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Executable File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)",
        )
        if file_path and self.icon_file_edit is not None:
            self.icon_file_edit.setText(file_path)

    def browse_icon_output(self) -> None:
        """Browse for output directory."""
        if dir_path := QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
        ):
            if self.icon_output_edit is not None:
                self.icon_output_edit.setText(dir_path)

    def extract_icon(self) -> None:
        """Extract icon from executable."""
        if self.icon_file_edit is None:
            return
        file_path = self.icon_file_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Warning", "Please select a valid executable file.")
            return

        output_path = ""
        if self.icon_output_edit is not None:
            output_path = self.icon_output_edit.text().strip() or os.path.dirname(file_path)
        else:
            output_path = os.path.dirname(file_path)

        if self.status_label is not None:
            self.status_label.setText("Extracting icon...")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(True)
        if self.extract_icon_btn is not None:
            self.extract_icon_btn.setEnabled(False)

        format_text = ""
        if self.icon_format_combo is not None:
            format_text = self.icon_format_combo.currentText()
        size_text = ""
        if self.icon_size_combo is not None:
            size_text = self.icon_size_combo.currentText()

        self.worker = SystemUtilitiesWorker(
            "extract_icon",
            file_path=file_path,
            output_path=output_path,
            format=format_text,
            size=size_text,
        )
        self.worker.operation_completed.connect(self.on_icon_extracted)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_icon_extracted(self, result: dict[str, Any]) -> None:
        """Handle icon extraction completion."""
        self.current_results["icon_extraction"] = result

        output_path = result.get("output_path", "")
        if isinstance(output_path, str) and output_path and os.path.exists(output_path):
            try:
                pixmap = QPixmap(output_path)
                if not pixmap.isNull():
                    scaled_pixmap = pixmap.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    if self.icon_preview is not None:
                        self.icon_preview.setPixmap(scaled_pixmap)
                elif self.icon_preview is not None:
                    self.icon_preview.setText("Could not load extracted icon")
            except (OSError, ValueError, RuntimeError) as e:
                self._logger.exception("Error in system_utilities_dialog")
                if self.icon_preview is not None:
                    self.icon_preview.setText(f"Preview error: {e!s}")
        elif self.icon_preview is not None:
            self.icon_preview.setText("Icon extracted successfully")

        if self.status_label is not None:
            self.status_label.setText("Icon extraction completed")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(False)
        if self.extract_icon_btn is not None:
            self.extract_icon_btn.setEnabled(True)

    def get_system_info(self) -> None:
        """Get comprehensive system information."""
        if self.status_label is not None:
            self.status_label.setText("Gathering system information...")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(True)
        if self.sysinfo_refresh_btn is not None:
            self.sysinfo_refresh_btn.setEnabled(False)

        self.worker = SystemUtilitiesWorker("system_info")
        self.worker.operation_completed.connect(self.on_system_info_received)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_system_info_received(self, result: dict[str, Any]) -> None:
        """Handle system information reception."""
        self.current_results["system_info"] = result

        info_text = self.format_system_info(result)
        if self.sysinfo_display is not None:
            self.sysinfo_display.setPlainText(info_text)

        if self.status_label is not None:
            self.status_label.setText("System information updated")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(False)
        if self.sysinfo_refresh_btn is not None:
            self.sysinfo_refresh_btn.setEnabled(True)

    @staticmethod
    def format_system_info(info: dict[str, Any]) -> str:
        """Format system information for display."""
        text = "System Information\n"
        text += "=" * 50 + "\n\n"

        text += f"Operating System: {info.get('os', 'Unknown')}\n"
        text += f"Architecture: {info.get('arch', 'Unknown')}\n"
        text += f"Hostname: {info.get('hostname', 'Unknown')}\n"
        text += f"Username: {info.get('username', 'Unknown')}\n\n"

        if "hardware" in info:
            hw = info["hardware"]
            if isinstance(hw, dict):
                text += "Hardware Information:\n"
                text += f"  Processor: {hw.get('processor', 'Unknown')}\n"
                text += f"  Cores: {hw.get('cores', 'Unknown')}\n"
                text += f"  Memory: {hw.get('memory', 'Unknown')}\n"
                text += f"  Disk Space: {hw.get('disk', 'Unknown')}\n\n"

        if "python" in info:
            py = info["python"]
            if isinstance(py, dict):
                text += "Python Information:\n"
                text += f"  Version: {py.get('version', 'Unknown')}\n"
                text += f"  Executable: {py.get('executable', 'Unknown')}\n"
                text += f"  Platform: {py.get('platform', 'Unknown')}\n\n"

        if "network" in info:
            net = info["network"]
            if isinstance(net, dict):
                text += "Network Information:\n"
                for interface, details in net.items():
                    text += f"  {interface}: {details}\n"
                text += "\n"

        return text

    def export_system_info(self) -> None:
        """Export system information to file."""
        if "system_info" not in self.current_results:
            QMessageBox.warning(self, "Warning", "No system information to export. Refresh first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export System Information",
            f"system_info_{int(time.time())}.json",
            "JSON Files (*.json);;Text Files (*.txt)",
        )

        if file_path:
            try:
                if file_path.endswith(".json"):
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(self.current_results["system_info"], f, indent=2)
                else:
                    with open(file_path, "w", encoding="utf-8") as f:
                        if self.sysinfo_display is not None:
                            f.write(self.sysinfo_display.toPlainText())

                if self.status_label is not None:
                    self.status_label.setText(f"System info exported to {os.path.basename(file_path)}")
            except (OSError, ValueError, RuntimeError) as e:
                module_logger.error("Error in system_utilities_dialog: %s", e)
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e!s}")

    def check_dependencies(self) -> None:
        """Check system dependencies."""
        if self.status_label is not None:
            self.status_label.setText("Checking dependencies...")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(True)
        if self.deps_check_btn is not None:
            self.deps_check_btn.setEnabled(False)

        self.worker = SystemUtilitiesWorker("check_dependencies")
        self.worker.operation_completed.connect(self.on_dependencies_checked)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_dependencies_checked(self, result: dict[str, Any]) -> None:
        """Handle dependency check completion."""
        self.current_results["dependencies"] = result

        dependencies_raw = result.get("dependencies", {})
        if not isinstance(dependencies_raw, dict):
            dependencies_raw = {}
        dependencies: dict[str, dict[str, Any]] = dependencies_raw

        if self.deps_table is not None:
            self.deps_table.setRowCount(len(dependencies))

            missing_count = 0
            for i, (name, info) in enumerate(dependencies.items()):
                self.deps_table.setItem(i, 0, QTableWidgetItem(name))
                self.deps_table.setItem(i, 1, QTableWidgetItem(str(info.get("required", "Unknown"))))
                self.deps_table.setItem(i, 2, QTableWidgetItem(str(info.get("installed", "Not Found"))))

                status = "OK" if info.get("available", False) else "Missing"
                if status == "Missing":
                    missing_count += 1

                status_item = QTableWidgetItem(status)
                if status == "Missing":
                    status_item.setBackground(QColor(255, 200, 200))
                else:
                    status_item.setBackground(QColor(200, 255, 200))

                self.deps_table.setItem(i, 3, status_item)

            if self.deps_install_btn is not None:
                self.deps_install_btn.setEnabled(missing_count > 0)

            if self.status_label is not None:
                self.status_label.setText(f"Dependencies checked: {missing_count} missing")

        if self.progress_bar is not None:
            self.progress_bar.setVisible(False)
        if self.deps_check_btn is not None:
            self.deps_check_btn.setEnabled(True)

    def install_dependencies(self) -> None:
        """Install missing dependencies."""
        QMessageBox.information(
            self,
            "Install Dependencies",
            "Dependency installation would be implemented here.\n\n"
            "This would automatically install missing packages using:\n"
            " pip for Python packages\n"
            " System package managers\n"
            " Direct downloads for tools",
        )

    def get_process_list(self) -> None:
        """Get list of running processes."""
        if self.status_label is not None:
            self.status_label.setText("Enumerating processes...")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(True)
        if self.process_refresh_btn is not None:
            self.process_refresh_btn.setEnabled(False)

        self.worker = SystemUtilitiesWorker("process_list")
        self.worker.operation_completed.connect(self.on_process_list_received)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_process_list_received(self, result: dict[str, Any]) -> None:
        """Handle process list reception."""
        self.current_results["processes"] = result

        processes_raw = result.get("processes", [])
        if not isinstance(processes_raw, list):
            processes_raw = []
        processes: list[dict[str, Any]] = processes_raw

        if self.process_table is not None:
            self.process_table.setRowCount(len(processes))

            for i, proc in enumerate(processes):
                self.process_table.setItem(i, 0, QTableWidgetItem(str(proc.get("pid", ""))))
                self.process_table.setItem(i, 1, QTableWidgetItem(str(proc.get("name", ""))))
                self.process_table.setItem(i, 2, QTableWidgetItem(f"{proc.get('cpu_percent', 0):.1f}"))
                self.process_table.setItem(i, 3, QTableWidgetItem(str(proc.get("memory_info", ""))))
                self.process_table.setItem(i, 4, QTableWidgetItem(str(proc.get("status", ""))))

            if self.status_label is not None:
                self.status_label.setText(f"Found {len(processes)} running processes")

        if self.progress_bar is not None:
            self.progress_bar.setVisible(False)
        if self.process_refresh_btn is not None:
            self.process_refresh_btn.setEnabled(True)

    def filter_processes(self, filter_text: str) -> None:
        """Filter process table by name."""
        if self.process_table is None:
            return
        for i in range(self.process_table.rowCount()):
            if name_item := self.process_table.item(i, 1):
                show_row = filter_text.lower() in name_item.text().lower()
                self.process_table.setRowHidden(i, not show_row)

    def on_process_selection_changed(self) -> None:
        """Handle process selection change."""
        if self.process_table is None:
            return
        has_selection = len(self.process_table.selectedItems()) > 0
        if self.process_kill_btn is not None:
            self.process_kill_btn.setEnabled(has_selection)

    def kill_selected_process(self) -> None:
        """Kill the selected process."""
        if self.process_table is None:
            return
        selected_rows = {item.row() for item in self.process_table.selectedItems()}
        if not selected_rows:
            return

        row = next(iter(selected_rows))
        pid_item = self.process_table.item(row, 0)
        name_item = self.process_table.item(row, 1)

        if pid_item and name_item:
            pid = pid_item.text()
            name = name_item.text()

            reply = QMessageBox.question(
                self,
                "Kill Process",
                f"Are you sure you want to kill process '{name}' (PID: {pid})?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                try:
                    from ...utils.system.system_utils import kill_process

                    if result := kill_process(int(pid)):
                        module_logger.info("Process %s (PID: %s) killed (result: %s)", name, pid, result)
                        QMessageBox.information(self, "Success", f"Process {name} killed successfully.")
                        self.get_process_list()
                    else:
                        QMessageBox.warning(self, "Failed", f"Failed to kill process {name}")

                except (OSError, ValueError, RuntimeError) as e:
                    module_logger.error("Error in system_utilities_dialog: %s", e)
                    QMessageBox.critical(self, "Error", f"Failed to kill process: {e!s}")

    def optimize_memory(self) -> None:
        """Optimize system memory."""
        if self.status_label is not None:
            self.status_label.setText("Optimizing memory...")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(True)
        if self.optimize_memory_btn is not None:
            self.optimize_memory_btn.setEnabled(False)

        self.worker = SystemUtilitiesWorker("optimize_memory")
        self.worker.operation_completed.connect(self.on_memory_optimized)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_memory_optimized(self, result: dict[str, Any]) -> None:
        """Handle memory optimization completion."""
        self.current_results["memory_optimization"] = result

        results_text = "Memory Optimization Results:\n"
        results_text += "=" * 30 + "\n\n"

        for key, value in result.items():
            results_text += f"{key.replace('_', ' ').title()}: {value}\n"

        if self.memory_results is not None:
            self.memory_results.setPlainText(results_text)

        if self.status_label is not None:
            self.status_label.setText("Memory optimization completed")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(False)
        if self.optimize_memory_btn is not None:
            self.optimize_memory_btn.setEnabled(True)

    def on_progress_updated(self, value: int, message: str) -> None:
        """Handle progress updates."""
        if self.progress_bar is not None:
            self.progress_bar.setValue(value)
        if self.status_label is not None:
            self.status_label.setText(message)

    def on_error(self, error_msg: str) -> None:
        """Handle worker thread errors."""
        QMessageBox.critical(self, "Error", error_msg)
        if self.status_label is not None:
            self.status_label.setText("Error occurred")
        if self.progress_bar is not None:
            self.progress_bar.setVisible(False)

        if self.extract_icon_btn is not None:
            self.extract_icon_btn.setEnabled(True)
        if self.sysinfo_refresh_btn is not None:
            self.sysinfo_refresh_btn.setEnabled(True)
        if self.deps_check_btn is not None:
            self.deps_check_btn.setEnabled(True)
        if self.process_refresh_btn is not None:
            self.process_refresh_btn.setEnabled(True)
        if self.optimize_memory_btn is not None:
            self.optimize_memory_btn.setEnabled(True)

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Handle dialog close event."""
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        if event is not None:
            event.accept()


def show_system_utilities_dialog(parent: QWidget | None = None) -> int:
    """Show the system utilities dialog."""
    dialog = SystemUtilitiesDialog(parent)
    return dialog.exec()
