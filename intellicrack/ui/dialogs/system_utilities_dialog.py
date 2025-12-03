"""System utilities dialog for system-level analysis tools."""

import json
import os
import time

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
from intellicrack.utils.logger import logger


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
            self.logger.error("Error in system_utilities_dialog: %s", e)
            self.error_occurred.emit(str(e))

    def _extract_icon(self) -> None:
        """Extract icon from executable."""
        try:
            from ...utils.system.system_utils import extract_executable_icon

            file_path = self.kwargs.get("file_path", "")
            output_path = self.kwargs.get("output_path", "")

            self.progress_updated.emit(25, "Analyzing executable...")

            result = extract_executable_icon(file_path, output_path)

            self.progress_updated.emit(100, "Icon extraction completed")
            self.operation_completed.emit(result)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in system_utilities_dialog: %s", e)
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
            self.logger.error("Error in system_utilities_dialog: %s", e)
            self.error_occurred.emit(f"System info collection failed: {e!s}")

    def _check_dependencies(self) -> None:
        """Check system dependencies."""
        try:
            from ...utils.system.system_utils import check_dependencies

            self.progress_updated.emit(30, "Checking dependencies...")

            # Provide a default set of dependencies to check
            default_deps = {
                "python": "python3",
                "pip": "pip3",
                "git": "git",
            }
            result = check_dependencies(dependencies=default_deps)

            self.progress_updated.emit(100, "Dependency check completed")
            self.operation_completed.emit(result)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in system_utilities_dialog: %s", e)
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
            self.logger.error("Error in system_utilities_dialog: %s", e)
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
            self.logger.error("Error in system_utilities_dialog: %s", e)
            self.error_occurred.emit(f"Memory optimization failed: {e!s}")

    def stop(self) -> None:
        """Stop the worker thread."""
        self.should_stop = True


class SystemUtilitiesDialog(QDialog):
    """System Utilities Dialog with various system tools."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the system utilities dialog with UI components and system monitoring capabilities."""
        # Initialize UI attributes
        self.close_btn = None
        self.deps_check_btn = None
        self.deps_install_btn = None
        self.deps_table = None
        self.memory_free_label = None
        self.memory_percent_label = None
        self.memory_results = None
        self.memory_total_label = None
        self.memory_used_label = None
        self.opt_clear_cache = None
        self.opt_compress_memory = None
        self.opt_defrag_memory = None
        self.optimize_memory_btn = None
        self.process_filter = None
        self.process_kill_btn = None
        self.process_refresh_btn = None
        self.process_table = None
        self.progress_bar = None
        self.status_label = None
        self.sysinfo_display = None
        self.sysinfo_export_btn = None
        self.sysinfo_refresh_btn = None
        super().__init__(parent)
        self.worker = None
        self.current_results = {}

        self.setWindowTitle("System Utilities")
        self.setMinimumSize(800, 600)
        self.setModal(True)

        self.setup_ui()
        self.connect_signals()

    def setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Tabs for different utilities
        self.tabs = QTabWidget()

        # Icon Extraction Tab
        self.setup_icon_tab()

        # System Information Tab
        self.setup_sysinfo_tab()

        # Dependency Checker Tab
        self.setup_dependencies_tab()

        # Process Manager Tab
        self.setup_process_tab()

        # Memory Optimizer Tab
        self.setup_memory_tab()

        layout.addWidget(self.tabs)

        # Status and controls
        self.setup_footer(layout)

    def setup_icon_tab(self) -> None:
        """Set up icon extraction tab."""
        icon_widget = QWidget()
        layout = QVBoxLayout(icon_widget)

        # File selection
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

        # Output options
        output_group = QGroupBox("Output Options")
        output_layout = QGridLayout(output_group)

        self.icon_output_edit = QLineEdit()
        self.icon_output_edit.setText("")

        self.icon_output_browse_btn = QPushButton("Browse")
        self.icon_output_browse_btn.clicked.connect(self.browse_icon_output)

        output_layout.addWidget(QLabel("Output Directory:"), 0, 0)
        output_layout.addWidget(self.icon_output_edit, 0, 1)
        output_layout.addWidget(self.icon_output_browse_btn, 0, 2)

        # Format options
        output_layout.addWidget(QLabel("Format:"), 1, 0)
        self.icon_format_combo = QComboBox()
        self.icon_format_combo.addItems(["ICO", "PNG", "BMP", "JPG"])
        output_layout.addWidget(self.icon_format_combo, 1, 1)

        # Size options
        output_layout.addWidget(QLabel("Size:"), 2, 0)
        self.icon_size_combo = QComboBox()
        self.icon_size_combo.addItems(["Original", "16x16", "32x32", "48x48", "64x64", "128x128", "256x256"])
        output_layout.addWidget(self.icon_size_combo, 2, 1)

        layout.addWidget(output_group)

        # Extract button
        self.extract_icon_btn = QPushButton("Extract Icon")
        self.extract_icon_btn.clicked.connect(self.extract_icon)
        self.extract_icon_btn.setObjectName("extractIconButton")
        layout.addWidget(self.extract_icon_btn)

        # Preview area
        preview_group = QGroupBox("Icon Preview")
        preview_layout = QVBoxLayout(preview_group)

        self.icon_preview = QLabel()
        self.icon_preview.setMinimumHeight(150)
        self.icon_preview.setAlignment(Qt.AlignCenter)
        self.icon_preview.setObjectName("iconPreview")
        self.icon_preview.setText("Icon preview will appear here")

        preview_layout.addWidget(self.icon_preview)
        layout.addWidget(preview_group)

        layout.addStretch()
        self.tabs.addTab(icon_widget, "Icon Extraction")

    def setup_sysinfo_tab(self) -> None:
        """Set up system information tab."""
        sysinfo_widget = QWidget()
        layout = QVBoxLayout(sysinfo_widget)

        # Controls
        controls_layout = QHBoxLayout()

        self.sysinfo_refresh_btn = QPushButton("Refresh System Info")
        self.sysinfo_refresh_btn.clicked.connect(self.get_system_info)

        self.sysinfo_export_btn = QPushButton("Export Info")
        self.sysinfo_export_btn.clicked.connect(self.export_system_info)

        controls_layout.addWidget(self.sysinfo_refresh_btn)
        controls_layout.addWidget(self.sysinfo_export_btn)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        # Information display
        self.sysinfo_display = QTextEdit()
        self.sysinfo_display.setFont(QFont("Consolas", 10))
        self.sysinfo_display.setReadOnly(True)

        layout.addWidget(self.sysinfo_display)

        # Auto-refresh on tab show
        QTimer.singleShot(100, self.get_system_info)

        self.tabs.addTab(sysinfo_widget, "System Info")

    def setup_dependencies_tab(self) -> None:
        """Set up dependency checker tab."""
        deps_widget = QWidget()
        layout = QVBoxLayout(deps_widget)

        # Controls
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

        # Dependencies table
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
        header.setSectionResizeMode(0, QHeaderView.Stretch)

        layout.addWidget(self.deps_table)

        self.tabs.addTab(deps_widget, "Dependencies")

    def setup_process_tab(self) -> None:
        """Set up process manager tab."""
        process_widget = QWidget()
        layout = QVBoxLayout(process_widget)

        # Controls
        controls_layout = QHBoxLayout()

        self.process_refresh_btn = QPushButton("Refresh Processes")
        self.process_refresh_btn.clicked.connect(self.get_process_list)

        self.process_kill_btn = QPushButton("Kill Selected")
        self.process_kill_btn.clicked.connect(self.kill_selected_process)
        self.process_kill_btn.setEnabled(False)

        # Filter
        controls_layout.addWidget(QLabel("Filter:"))
        self.process_filter = QLineEdit()
        self.process_filter.setText("")
        self.process_filter.textChanged.connect(self.filter_processes)

        controls_layout.addWidget(self.process_refresh_btn)
        controls_layout.addWidget(self.process_kill_btn)
        controls_layout.addWidget(self.process_filter)

        layout.addLayout(controls_layout)

        # Process table
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
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.itemSelectionChanged.connect(self.on_process_selection_changed)

        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        layout.addWidget(self.process_table)

        self.tabs.addTab(process_widget, "Process Manager")

    def setup_memory_tab(self) -> None:
        """Set up memory optimizer tab."""
        memory_widget = QWidget()
        layout = QVBoxLayout(memory_widget)

        # Memory info
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

        # Optimization options
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

        # Optimize button
        self.optimize_memory_btn = QPushButton("Optimize Memory")
        self.optimize_memory_btn.clicked.connect(self.optimize_memory)
        self.optimize_memory_btn.setObjectName("optimizeMemoryButton")
        layout.addWidget(self.optimize_memory_btn)

        # Results
        self.memory_results = QTextEdit()
        self.memory_results.setMaximumHeight(150)
        self.memory_results.setFont(QFont("Consolas", 10))
        layout.addWidget(QLabel("Optimization Results:"))
        layout.addWidget(self.memory_results)

        layout.addStretch()
        self.tabs.addTab(memory_widget, "Memory Optimizer")

    def setup_footer(self, layout: QVBoxLayout) -> None:
        """Set up footer with status and progress."""
        footer_layout = QVBoxLayout()

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        footer_layout.addWidget(self.progress_bar)

        # Status and close
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
        # Connect tool signals
        if hasattr(self, "icon_browser_btn") and hasattr(self, "browse_icon_file"):
            self.icon_browser_btn.clicked.connect(self.browse_icon_file)

        if hasattr(self, "icon_extract_btn") and hasattr(self, "extract_icon"):
            self.icon_extract_btn.clicked.connect(self.extract_icon)

        if hasattr(self, "sysinfo_refresh_btn") and hasattr(self, "refresh_system_info"):
            self.sysinfo_refresh_btn.clicked.connect(self.refresh_system_info)

        if hasattr(self, "dependency_check_btn") and hasattr(self, "check_dependencies"):
            self.dependency_check_btn.clicked.connect(self.check_dependencies)

        if hasattr(self, "process_refresh_btn") and hasattr(self, "refresh_process_list"):
            self.process_refresh_btn.clicked.connect(self.refresh_process_list)

        if hasattr(self, "process_filter") and hasattr(self, "filter_processes"):
            self.process_filter.textChanged.connect(self.filter_processes)

        if hasattr(self, "process_kill_btn") and hasattr(self, "kill_selected_process"):
            self.process_kill_btn.clicked.connect(self.kill_selected_process)

        if hasattr(self, "file_monitor_btn") and hasattr(self, "toggle_file_monitor"):
            self.file_monitor_btn.clicked.connect(self.toggle_file_monitor)

        if hasattr(self, "file_monitor_path") and hasattr(self, "browse_monitor_path"):
            self.file_monitor_browse_btn.clicked.connect(self.browse_monitor_path)

        if hasattr(self, "registry_search_btn") and hasattr(self, "search_registry"):
            self.registry_search_btn.clicked.connect(self.search_registry)

        if hasattr(self, "registry_delete_btn") and hasattr(self, "delete_registry_key"):
            self.registry_delete_btn.clicked.connect(self.delete_registry_key)

        if hasattr(self, "file_shredder_browse_btn") and hasattr(self, "browse_shred_file"):
            self.file_shredder_browse_btn.clicked.connect(self.browse_shred_file)

        if hasattr(self, "file_shredder_shred_btn") and hasattr(self, "shred_file"):
            self.file_shredder_shred_btn.clicked.connect(self.shred_file)

        if hasattr(self, "env_editor_add_btn") and hasattr(self, "add_env_variable"):
            self.env_editor_add_btn.clicked.connect(self.add_env_variable)

        if hasattr(self, "env_editor_delete_btn") and hasattr(self, "delete_env_variable"):
            self.env_editor_delete_btn.clicked.connect(self.delete_env_variable)

        if hasattr(self, "env_editor_save_btn") and hasattr(self, "save_env_variables"):
            self.env_editor_save_btn.clicked.connect(self.save_env_variables)

        # Connect close button
        if hasattr(self, "close_btn"):
            self.close_btn.clicked.connect(self.close)

        # Connect worker signals
        if hasattr(self, "worker_thread"):
            self.worker_thread.operation_completed.connect(self.handle_operation_completed)
            self.worker_thread.progress_updated.connect(self.update_progress)
            self.worker_thread.error_occurred.connect(self.handle_error)

    def browse_icon_file(self) -> None:
        """Browse for executable file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Executable File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)",
        )
        if file_path:
            self.icon_file_edit.setText(file_path)

    def browse_icon_output(self) -> None:
        """Browse for output directory."""
        if dir_path := QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
        ):
            self.icon_output_edit.setText(dir_path)

    def extract_icon(self) -> None:
        """Extract icon from executable."""
        file_path = self.icon_file_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Warning", "Please select a valid executable file.")
            return

        output_path = self.icon_output_edit.text().strip() or os.path.dirname(file_path)

        self.status_label.setText("Extracting icon...")
        self.progress_bar.setVisible(True)
        self.extract_icon_btn.setEnabled(False)

        # Start worker thread
        self.worker = SystemUtilitiesWorker(
            "extract_icon",
            file_path=file_path,
            output_path=output_path,
            format=self.icon_format_combo.currentText(),
            size=self.icon_size_combo.currentText(),
        )
        self.worker.operation_completed.connect(self.on_icon_extracted)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_icon_extracted(self, result: dict[str, object]) -> None:
        """Handle icon extraction completion."""
        self.current_results["icon_extraction"] = result

        # Try to display the extracted icon
        if "output_path" in result and os.path.exists(result["output_path"]):
            try:
                pixmap = QPixmap(result["output_path"])
                if not pixmap.isNull():
                    # Scale to preview size
                    scaled_pixmap = pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.icon_preview.setPixmap(scaled_pixmap)
                else:
                    self.icon_preview.setText("Could not load extracted icon")
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in system_utilities_dialog: %s", e)
                self.icon_preview.setText(f"Preview error: {e!s}")
        else:
            self.icon_preview.setText("Icon extracted successfully")

        self.status_label.setText("Icon extraction completed")
        self.progress_bar.setVisible(False)
        self.extract_icon_btn.setEnabled(True)

    def get_system_info(self) -> None:
        """Get comprehensive system information."""
        self.status_label.setText("Gathering system information...")
        self.progress_bar.setVisible(True)
        self.sysinfo_refresh_btn.setEnabled(False)

        # Start worker thread
        self.worker = SystemUtilitiesWorker("system_info")
        self.worker.operation_completed.connect(self.on_system_info_received)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_system_info_received(self, result: dict[str, object]) -> None:
        """Handle system information reception."""
        self.current_results["system_info"] = result

        # Format and display the information
        info_text = self.format_system_info(result)
        self.sysinfo_display.setPlainText(info_text)

        self.status_label.setText("System information updated")
        self.progress_bar.setVisible(False)
        self.sysinfo_refresh_btn.setEnabled(True)

    def format_system_info(self, info: dict[str, object]) -> str:
        """Format system information for display."""
        text = "System Information\n"
        text += "=" * 50 + "\n\n"

        # Basic system info
        text += f"Operating System: {info.get('os', 'Unknown')}\n"
        text += f"Architecture: {info.get('arch', 'Unknown')}\n"
        text += f"Hostname: {info.get('hostname', 'Unknown')}\n"
        text += f"Username: {info.get('username', 'Unknown')}\n\n"

        # Hardware info
        if "hardware" in info:
            hw = info["hardware"]
            text += "Hardware Information:\n"
            text += f"  Processor: {hw.get('processor', 'Unknown')}\n"
            text += f"  Cores: {hw.get('cores', 'Unknown')}\n"
            text += f"  Memory: {hw.get('memory', 'Unknown')}\n"
            text += f"  Disk Space: {hw.get('disk', 'Unknown')}\n\n"

        # Python info
        if "python" in info:
            py = info["python"]
            text += "Python Information:\n"
            text += f"  Version: {py.get('version', 'Unknown')}\n"
            text += f"  Executable: {py.get('executable', 'Unknown')}\n"
            text += f"  Platform: {py.get('platform', 'Unknown')}\n\n"

        # Network info
        if "network" in info:
            net = info["network"]
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
                        f.write(self.sysinfo_display.toPlainText())

                self.status_label.setText(f"System info exported to {os.path.basename(file_path)}")
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in system_utilities_dialog: %s", e)
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e!s}")

    def check_dependencies(self) -> None:
        """Check system dependencies."""
        self.status_label.setText("Checking dependencies...")
        self.progress_bar.setVisible(True)
        self.deps_check_btn.setEnabled(False)

        # Start worker thread
        self.worker = SystemUtilitiesWorker("check_dependencies")
        self.worker.operation_completed.connect(self.on_dependencies_checked)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_dependencies_checked(self, result: dict[str, object]) -> None:
        """Handle dependency check completion."""
        self.current_results["dependencies"] = result

        # Populate dependencies table
        dependencies = result.get("dependencies", {})
        self.deps_table.setRowCount(len(dependencies))

        missing_count = 0
        for i, (name, info) in enumerate(dependencies.items()):
            self.deps_table.setItem(i, 0, QTableWidgetItem(name))
            self.deps_table.setItem(i, 1, QTableWidgetItem(info.get("required", "Unknown")))
            self.deps_table.setItem(i, 2, QTableWidgetItem(info.get("installed", "Not Found")))

            status = "OK" if info.get("available", False) else "Missing"
            if status == "Missing":
                missing_count += 1

            status_item = QTableWidgetItem(status)
            if status == "Missing":
                status_item.setBackground(QColor(255, 200, 200))  # Light red
            else:
                status_item.setBackground(QColor(200, 255, 200))  # Light green

            self.deps_table.setItem(i, 3, status_item)

        # Enable install button if there are missing dependencies
        self.deps_install_btn.setEnabled(missing_count > 0)

        self.status_label.setText(f"Dependencies checked: {missing_count} missing")
        self.progress_bar.setVisible(False)
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
        self.status_label.setText("Enumerating processes...")
        self.progress_bar.setVisible(True)
        self.process_refresh_btn.setEnabled(False)

        # Start worker thread
        self.worker = SystemUtilitiesWorker("process_list")
        self.worker.operation_completed.connect(self.on_process_list_received)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_process_list_received(self, result: dict[str, object]) -> None:
        """Handle process list reception."""
        self.current_results["processes"] = result

        # Populate process table
        processes = result.get("processes", [])
        self.process_table.setRowCount(len(processes))

        for i, proc in enumerate(processes):
            self.process_table.setItem(i, 0, QTableWidgetItem(str(proc.get("pid", ""))))
            self.process_table.setItem(i, 1, QTableWidgetItem(proc.get("name", "")))
            self.process_table.setItem(i, 2, QTableWidgetItem(f"{proc.get('cpu_percent', 0):.1f}"))
            self.process_table.setItem(i, 3, QTableWidgetItem(proc.get("memory_info", "")))
            self.process_table.setItem(i, 4, QTableWidgetItem(proc.get("status", "")))

        self.status_label.setText(f"Found {len(processes)} running processes")
        self.progress_bar.setVisible(False)
        self.process_refresh_btn.setEnabled(True)

    def filter_processes(self, filter_text: str) -> None:
        """Filter process table by name."""
        for i in range(self.process_table.rowCount()):
            if name_item := self.process_table.item(i, 1):
                show_row = filter_text.lower() in name_item.text().lower()
                self.process_table.setRowHidden(i, not show_row)

    def on_process_selection_changed(self) -> None:
        """Handle process selection change."""
        has_selection = len(self.process_table.selectedItems()) > 0
        self.process_kill_btn.setEnabled(has_selection)

    def kill_selected_process(self) -> None:
        """Kill the selected process."""
        selected_rows = {item.row() for item in self.process_table.selectedItems()}
        if not selected_rows:
            return

        # Get PID from first selected row
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
                QMessageBox.Yes | QMessageBox.No,
            )

            if reply == QMessageBox.Yes:
                try:
                    from ...utils.system.system_utils import kill_process

                    if result := kill_process(int(pid)):
                        logger.info(f"Process {name} (PID: {pid}) killed (result: {result})")
                        QMessageBox.information(self, "Success", f"Process {name} killed successfully.")
                        # Refresh process list
                        self.get_process_list()
                    else:
                        QMessageBox.warning(self, "Failed", f"Failed to kill process {name}")

                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in system_utilities_dialog: %s", e)
                    QMessageBox.critical(self, "Error", f"Failed to kill process: {e!s}")

    def optimize_memory(self) -> None:
        """Optimize system memory."""
        self.status_label.setText("Optimizing memory...")
        self.progress_bar.setVisible(True)
        self.optimize_memory_btn.setEnabled(False)

        # Start worker thread
        self.worker = SystemUtilitiesWorker("optimize_memory")
        self.worker.operation_completed.connect(self.on_memory_optimized)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_memory_optimized(self, result: dict[str, object]) -> None:
        """Handle memory optimization completion."""
        self.current_results["memory_optimization"] = result

        # Display results
        results_text = "Memory Optimization Results:\n"
        results_text += "=" * 30 + "\n\n"

        for key, value in result.items():
            results_text += f"{key.replace('_', ' ').title()}: {value}\n"

        self.memory_results.setPlainText(results_text)

        self.status_label.setText("Memory optimization completed")
        self.progress_bar.setVisible(False)
        self.optimize_memory_btn.setEnabled(True)

    def on_progress_updated(self, value: int, message: str) -> None:
        """Handle progress updates."""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)

    def on_error(self, error_msg: str) -> None:
        """Handle worker thread errors."""
        QMessageBox.critical(self, "Error", error_msg)
        self.status_label.setText("Error occurred")
        self.progress_bar.setVisible(False)

        # Re-enable buttons
        self.extract_icon_btn.setEnabled(True)
        self.sysinfo_refresh_btn.setEnabled(True)
        self.deps_check_btn.setEnabled(True)
        self.process_refresh_btn.setEnabled(True)
        self.optimize_memory_btn.setEnabled(True)

    def closeEvent(self, event: object) -> None:
        """Handle dialog close event."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()


# Convenience function for main app integration
def show_system_utilities_dialog(parent: QWidget | None = None) -> int:
    """Show the system utilities dialog."""
    dialog = SystemUtilitiesDialog(parent)
    return dialog.exec()
