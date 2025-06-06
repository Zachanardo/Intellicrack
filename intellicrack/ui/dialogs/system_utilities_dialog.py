"""
System Utilities Dialog for Intellicrack.

This module provides access to various system utilities including
icon extraction, system information, dependency checking, and process management.
"""

import json
import os
import time

try:
    from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import QColor, QFont, QIcon, QPixmap
    from PyQt5.QtWidgets import (
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    # Fallback for environments without PyQt5
    class QDialog:
        pass
    def pyqtSignal(*args, **kwargs):
        return lambda: None
    Qt = None


class SystemUtilitiesWorker(QThread):
    """Background worker for system utility operations."""

    operation_completed = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)

    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self.should_stop = False

    def run(self):
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
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _extract_icon(self):
        """Extract icon from executable."""
        try:
            from ...utils.system_utils import extract_executable_icon

            file_path = self.kwargs.get('file_path', '')
            output_path = self.kwargs.get('output_path', '')

            self.progress_updated.emit(25, "Analyzing executable...")

            result = extract_executable_icon(file_path, output_path)

            self.progress_updated.emit(100, "Icon extraction completed")
            self.operation_completed.emit(result)

        except Exception as e:
            self.error_occurred.emit(f"Icon extraction failed: {str(e)}")

    def _get_system_info(self):
        """Get comprehensive system information."""
        try:
            from ...utils.system_utils import get_system_info

            self.progress_updated.emit(50, "Gathering system information...")

            result = get_system_info()

            self.progress_updated.emit(100, "System information collected")
            self.operation_completed.emit(result)

        except Exception as e:
            self.error_occurred.emit(f"System info collection failed: {str(e)}")

    def _check_dependencies(self):
        """Check system dependencies."""
        try:
            from ...utils.system_utils import check_dependencies

            self.progress_updated.emit(30, "Checking dependencies...")

            # Provide a default set of dependencies to check
            default_deps = {
                'python': 'python3',
                'pip': 'pip3',
                'git': 'git'
            }
            result = check_dependencies(dependencies=default_deps)

            self.progress_updated.emit(100, "Dependency check completed")
            self.operation_completed.emit(result)

        except Exception as e:
            self.error_occurred.emit(f"Dependency check failed: {str(e)}")

    def _get_process_list(self):
        """Get running process list."""
        try:
            from ...utils.system_utils import get_process_list

            self.progress_updated.emit(50, "Enumerating processes...")

            result = get_process_list()

            self.progress_updated.emit(100, "Process enumeration completed")
            self.operation_completed.emit({'processes': result})

        except Exception as e:
            self.error_occurred.emit(f"Process enumeration failed: {str(e)}")

    def _optimize_memory(self):
        """Optimize system memory usage."""
        try:
            from ...utils.system_utils import optimize_memory_usage

            self.progress_updated.emit(50, "Optimizing memory usage...")

            result = optimize_memory_usage()

            self.progress_updated.emit(100, "Memory optimization completed")
            self.operation_completed.emit(result)

        except Exception as e:
            self.error_occurred.emit(f"Memory optimization failed: {str(e)}")

    def stop(self):
        """Stop the worker thread."""
        self.should_stop = True


class SystemUtilitiesDialog(QDialog):
    """System Utilities Dialog with various system tools."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.current_results = {}

        self.setWindowTitle("System Utilities")
        self.setMinimumSize(800, 600)
        self.setModal(True)

        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        """Setup the user interface."""
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

    def setup_icon_tab(self):
        """Setup icon extraction tab."""
        icon_widget = QWidget()
        layout = QVBoxLayout(icon_widget)

        # File selection
        file_group = QGroupBox("Executable File")
        file_layout = QHBoxLayout(file_group)

        self.icon_file_edit = QLineEdit()
        self.icon_file_edit.setPlaceholderText("Select executable file to extract icon from...")

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
        self.icon_output_edit.setPlaceholderText("Output directory (optional)")

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
        self.extract_icon_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        layout.addWidget(self.extract_icon_btn)

        # Preview area
        preview_group = QGroupBox("Icon Preview")
        preview_layout = QVBoxLayout(preview_group)

        self.icon_preview = QLabel()
        self.icon_preview.setMinimumHeight(150)
        self.icon_preview.setAlignment(Qt.AlignCenter)
        self.icon_preview.setStyleSheet("QLabel { border: 1px solid gray; background-color: white; }")
        self.icon_preview.setText("Icon preview will appear here")

        preview_layout.addWidget(self.icon_preview)
        layout.addWidget(preview_group)

        layout.addStretch()
        self.tabs.addTab(icon_widget, "Icon Extraction")

    def setup_sysinfo_tab(self):
        """Setup system information tab."""
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

    def setup_dependencies_tab(self):
        """Setup dependency checker tab."""
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
        self.deps_table.setHorizontalHeaderLabels([
            "Dependency", "Required", "Installed", "Status"
        ])

        header = self.deps_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)

        layout.addWidget(self.deps_table)

        self.tabs.addTab(deps_widget, "Dependencies")

    def setup_process_tab(self):
        """Setup process manager tab."""
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
        self.process_filter.setPlaceholderText("Filter by process name...")
        self.process_filter.textChanged.connect(self.filter_processes)

        controls_layout.addWidget(self.process_refresh_btn)
        controls_layout.addWidget(self.process_kill_btn)
        controls_layout.addWidget(self.process_filter)

        layout.addLayout(controls_layout)

        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels([
            "PID", "Name", "CPU %", "Memory", "Status"
        ])
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.itemSelectionChanged.connect(self.on_process_selection_changed)

        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        layout.addWidget(self.process_table)

        self.tabs.addTab(process_widget, "Process Manager")

    def setup_memory_tab(self):
        """Setup memory optimizer tab."""
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
        self.optimize_memory_btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; }")
        layout.addWidget(self.optimize_memory_btn)

        # Results
        self.memory_results = QTextEdit()
        self.memory_results.setMaximumHeight(150)
        self.memory_results.setFont(QFont("Consolas", 10))
        layout.addWidget(QLabel("Optimization Results:"))
        layout.addWidget(self.memory_results)

        layout.addStretch()
        self.tabs.addTab(memory_widget, "Memory Optimizer")

    def setup_footer(self, layout):
        """Setup footer with status and progress."""
        footer_layout = QVBoxLayout()

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        footer_layout.addWidget(self.progress_bar)

        # Status and close
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("QLabel { color: #666; }")

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)

        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.close_btn)

        footer_layout.addLayout(status_layout)
        layout.addLayout(footer_layout)

    def connect_signals(self):
        """Connect internal signals."""
        pass

    def browse_icon_file(self):
        """Browse for executable file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Executable File", "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
        )
        if file_path:
            self.icon_file_edit.setText(file_path)

    def browse_icon_output(self):
        """Browse for output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory"
        )
        if dir_path:
            self.icon_output_edit.setText(dir_path)

    def extract_icon(self):
        """Extract icon from executable."""
        file_path = self.icon_file_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Warning", "Please select a valid executable file.")
            return

        output_path = self.icon_output_edit.text().strip()
        if not output_path:
            output_path = os.path.dirname(file_path)

        self.status_label.setText("Extracting icon...")
        self.progress_bar.setVisible(True)
        self.extract_icon_btn.setEnabled(False)

        # Start worker thread
        self.worker = SystemUtilitiesWorker(
            "extract_icon",
            file_path=file_path,
            output_path=output_path,
            format=self.icon_format_combo.currentText(),
            size=self.icon_size_combo.currentText()
        )
        self.worker.operation_completed.connect(self.on_icon_extracted)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_icon_extracted(self, result):
        """Handle icon extraction completion."""
        self.current_results['icon_extraction'] = result

        # Try to display the extracted icon
        if 'output_path' in result and os.path.exists(result['output_path']):
            try:
                pixmap = QPixmap(result['output_path'])
                if not pixmap.isNull():
                    # Scale to preview size
                    scaled_pixmap = pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.icon_preview.setPixmap(scaled_pixmap)
                else:
                    self.icon_preview.setText("Could not load extracted icon")
            except Exception as e:
                self.icon_preview.setText(f"Preview error: {str(e)}")
        else:
            self.icon_preview.setText("Icon extracted successfully")

        self.status_label.setText("Icon extraction completed")
        self.progress_bar.setVisible(False)
        self.extract_icon_btn.setEnabled(True)

    def get_system_info(self):
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

    def on_system_info_received(self, result):
        """Handle system information reception."""
        self.current_results['system_info'] = result

        # Format and display the information
        info_text = self.format_system_info(result)
        self.sysinfo_display.setPlainText(info_text)

        self.status_label.setText("System information updated")
        self.progress_bar.setVisible(False)
        self.sysinfo_refresh_btn.setEnabled(True)

    def format_system_info(self, info):
        """Format system information for display."""
        text = "System Information\n"
        text += "=" * 50 + "\n\n"

        # Basic system info
        text += f"Operating System: {info.get('os', 'Unknown')}\n"
        text += f"Architecture: {info.get('arch', 'Unknown')}\n"
        text += f"Hostname: {info.get('hostname', 'Unknown')}\n"
        text += f"Username: {info.get('username', 'Unknown')}\n\n"

        # Hardware info
        if 'hardware' in info:
            hw = info['hardware']
            text += "Hardware Information:\n"
            text += f"  Processor: {hw.get('processor', 'Unknown')}\n"
            text += f"  Cores: {hw.get('cores', 'Unknown')}\n"
            text += f"  Memory: {hw.get('memory', 'Unknown')}\n"
            text += f"  Disk Space: {hw.get('disk', 'Unknown')}\n\n"

        # Python info
        if 'python' in info:
            py = info['python']
            text += "Python Information:\n"
            text += f"  Version: {py.get('version', 'Unknown')}\n"
            text += f"  Executable: {py.get('executable', 'Unknown')}\n"
            text += f"  Platform: {py.get('platform', 'Unknown')}\n\n"

        # Network info
        if 'network' in info:
            net = info['network']
            text += "Network Information:\n"
            for interface, details in net.items():
                text += f"  {interface}: {details}\n"
            text += "\n"

        return text

    def export_system_info(self):
        """Export system information to file."""
        if 'system_info' not in self.current_results:
            QMessageBox.warning(self, "Warning", "No system information to export. Refresh first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export System Information",
            f"system_info_{int(time.time())}.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )

        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.current_results['system_info'], f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write(self.sysinfo_display.toPlainText())

                self.status_label.setText(f"System info exported to {os.path.basename(file_path)}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {str(e)}")

    def check_dependencies(self):
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

    def on_dependencies_checked(self, result):
        """Handle dependency check completion."""
        self.current_results['dependencies'] = result

        # Populate dependencies table
        dependencies = result.get('dependencies', {})
        self.deps_table.setRowCount(len(dependencies))

        missing_count = 0
        for i, (name, info) in enumerate(dependencies.items()):
            self.deps_table.setItem(i, 0, QTableWidgetItem(name))
            self.deps_table.setItem(i, 1, QTableWidgetItem(info.get('required', 'Unknown')))
            self.deps_table.setItem(i, 2, QTableWidgetItem(info.get('installed', 'Not Found')))

            status = "OK" if info.get('available', False) else "Missing"
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

    def install_dependencies(self):
        """Install missing dependencies."""
        QMessageBox.information(
            self, "Install Dependencies",
            "Dependency installation would be implemented here.\n\n"
            "This would automatically install missing packages using:\n"
            "• pip for Python packages\n"
            "• System package managers\n"
            "• Direct downloads for tools"
        )

    def get_process_list(self):
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

    def on_process_list_received(self, result):
        """Handle process list reception."""
        self.current_results['processes'] = result

        # Populate process table
        processes = result.get('processes', [])
        self.process_table.setRowCount(len(processes))

        for i, proc in enumerate(processes):
            self.process_table.setItem(i, 0, QTableWidgetItem(str(proc.get('pid', ''))))
            self.process_table.setItem(i, 1, QTableWidgetItem(proc.get('name', '')))
            self.process_table.setItem(i, 2, QTableWidgetItem(f"{proc.get('cpu_percent', 0):.1f}"))
            self.process_table.setItem(i, 3, QTableWidgetItem(proc.get('memory_info', '')))
            self.process_table.setItem(i, 4, QTableWidgetItem(proc.get('status', '')))

        self.status_label.setText(f"Found {len(processes)} running processes")
        self.progress_bar.setVisible(False)
        self.process_refresh_btn.setEnabled(True)

    def filter_processes(self, filter_text):
        """Filter process table by name."""
        for i in range(self.process_table.rowCount()):
            name_item = self.process_table.item(i, 1)
            if name_item:
                show_row = filter_text.lower() in name_item.text().lower()
                self.process_table.setRowHidden(i, not show_row)

    def on_process_selection_changed(self):
        """Handle process selection change."""
        has_selection = len(self.process_table.selectedItems()) > 0
        self.process_kill_btn.setEnabled(has_selection)

    def kill_selected_process(self):
        """Kill the selected process."""
        selected_rows = set()
        for item in self.process_table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            return

        # Get PID from first selected row
        row = list(selected_rows)[0]
        pid_item = self.process_table.item(row, 0)
        name_item = self.process_table.item(row, 1)

        if pid_item and name_item:
            pid = pid_item.text()
            name = name_item.text()

            reply = QMessageBox.question(
                self, "Kill Process",
                f"Are you sure you want to kill process '{name}' (PID: {pid})?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                try:
                    from ...utils.system_utils import kill_process
                    result = kill_process(int(pid))

                    if result:
                        QMessageBox.information(self, "Success", f"Process {name} killed successfully.")
                        # Refresh process list
                        self.get_process_list()
                    else:
                        QMessageBox.warning(self, "Failed", f"Failed to kill process {name}")

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to kill process: {str(e)}")

    def optimize_memory(self):
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

    def on_memory_optimized(self, result):
        """Handle memory optimization completion."""
        self.current_results['memory_optimization'] = result

        # Display results
        results_text = "Memory Optimization Results:\n"
        results_text += "=" * 30 + "\n\n"

        for key, value in result.items():
            results_text += f"{key.replace('_', ' ').title()}: {value}\n"

        self.memory_results.setPlainText(results_text)

        self.status_label.setText("Memory optimization completed")
        self.progress_bar.setVisible(False)
        self.optimize_memory_btn.setEnabled(True)

    def on_progress_updated(self, value, message):
        """Handle progress updates."""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)

    def on_error(self, error_msg):
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

    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()


# Convenience function for main app integration
def show_system_utilities_dialog(parent=None):
    """Show the system utilities dialog."""
    dialog = SystemUtilitiesDialog(parent)
    return dialog.exec_()
