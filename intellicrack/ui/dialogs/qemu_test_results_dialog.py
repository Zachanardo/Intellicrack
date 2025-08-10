"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QDialog,
    QDialogButtonBox,
    QFont,
    QLabel,
    QProgressBar,
    QPushButton,
    Qt,
    QTabWidget,
    QTextCursor,
    QTextEdit,
    QThread,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...ai.qemu_test_manager import ExecutionResult, QEMUTestManager
from ...utils.logger import get_logger

"""
QEMU Test Results Dialog

Shows real execution results from QEMU sandbox testing.
"""

logger = get_logger(__name__)


@dataclass
class TestResults:
    """Container for real test results from QEMU execution."""

    success: bool
    duration: float
    output: str
    errors: list[str]
    warnings: list[str]
    memory_changes: list[dict[str, Any]]
    api_calls: list[dict[str, Any]]
    network_activity: list[dict[str, Any]]
    file_operations: list[dict[str, Any]]
    process_state: str
    exit_code: int


class QEMUExecutionThread(QThread):
    """Thread for running scripts in QEMU and capturing real output."""

    output_update = pyqtSignal(str)
    progress_update = pyqtSignal(int, str)
    execution_complete = pyqtSignal(TestResults)

    def __init__(
        self,
        qemu_manager: QEMUTestManager,
        snapshot_id: str,
        script_content: str,
        binary_path: str,
        script_type: str,
    ):
        """Initialize the QEMUExecutionThread with default values."""
        super().__init__()
        self.qemu_manager = qemu_manager
        self.snapshot_id = snapshot_id
        self.script_content = script_content
        self.binary_path = binary_path
        self.script_type = script_type
        self.start_time = None

    def run(self):
        """Execute script in QEMU and capture real results."""
        self.start_time = time.time()

        try:
            # Update progress
            self.progress_update.emit(10, "Starting QEMU VM...")

            # Execute based on script type
            if self.script_type == "frida":
                result = self._execute_frida_script()
            elif self.script_type == "ghidra":
                result = self._execute_ghidra_script()
            else:
                result = self._execute_generic_script()

            # Parse and emit results
            test_results = self._parse_execution_results(result)
            self.execution_complete.emit(test_results)

        except Exception as e:
            logger.error(f"QEMU execution failed: {e}")
            error_results = TestResults(
                success=False,
                duration=time.time() - self.start_time,
                output="",
                errors=[str(e)],
                warnings=[],
                memory_changes=[],
                api_calls=[],
                network_activity=[],
                file_operations=[],
                process_state="error",
                exit_code=-1,
            )
            self.execution_complete.emit(error_results)

    def _execute_frida_script(self) -> ExecutionResult:
        """Execute Frida script and capture real output."""
        self.progress_update.emit(30, "Loading target binary in VM...")

        # Real execution with output streaming
        def output_callback(line: str):
            self.output_update.emit(line)

        # Execute with real-time output capture
        result = self.qemu_manager.test_frida_script_with_callback(
            self.snapshot_id,
            self.script_content,
            self.binary_path,
            output_callback,
        )

        return result

    def _parse_execution_results(self, result: ExecutionResult) -> TestResults:
        """Parse real execution results into structured format."""
        duration = time.time() - self.start_time

        # Parse output for specific patterns
        output_lines = result.output.split("\n")
        memory_changes = []
        api_calls = []
        warnings = []

        for line in output_lines:
            # Parse real Frida output patterns
            if "Found" in line and "at 0x" in line:
                # Extract real memory addresses
                addr_match = re.search(r"at (0x[0-9a-fA-F]+)", line)
                if addr_match:
                    memory_changes.append(
                        {
                            "type": "discovery",
                            "address": addr_match.group(1),
                            "description": line,
                        }
                    )

            elif "Patched" in line or "Hooked" in line:
                # Extract patching/hooking info
                api_calls.append(
                    {
                        "type": "hook",
                        "description": line,
                        "timestamp": datetime.now().isoformat(),
                    }
                )

            elif "WARNING" in line or "Warning" in line:
                warnings.append(line)

        # Determine process state from output
        process_state = "running"
        if "Process terminated" in result.output:
            process_state = "terminated"
        elif "crashed" in result.output.lower():
            process_state = "crashed"

        return TestResults(
            success=result.success,
            duration=duration,
            output=result.output,
            errors=[result.error] if result.error else [],
            warnings=warnings,
            memory_changes=memory_changes,
            api_calls=api_calls,
            network_activity=[],  # Could be enhanced with network monitoring
            file_operations=[],  # Could be enhanced with file monitoring
            process_state=process_state,
            exit_code=result.exit_code,
        )


class QEMUTestResultsDialog(QDialog):
    """Dialog showing real QEMU test execution results."""

    def __init__(self, parent=None, script_info=None, qemu_manager=None):
        """Initialize the QEMUTestResultsDialog with default values."""
        super().__init__(parent)
        self.script_info = script_info or {}
        self.qemu_manager = qemu_manager or QEMUTestManager()
        self.test_results = None
        self.execution_thread = None

        self.setup_ui()
        self.start_execution()

    def setup_ui(self):
        """Create the UI for showing real test results."""
        self.setWindowTitle("QEMU Test Results")
        self.setMinimumSize(800, 600)

        layout = QVBoxLayout(self)

        # Status section
        self.status_widget = self._create_status_widget()
        layout.addWidget(self.status_widget)

        # Main content area
        self.tab_widget = QTabWidget()

        # Real-time output tab
        self.output_tab = self._create_output_tab()
        self.tab_widget.addTab(self.output_tab, "Script Output")

        # Analysis tab
        self.analysis_tab = self._create_analysis_tab()
        self.tab_widget.addTab(self.analysis_tab, "Analysis")

        # Memory changes tab
        self.memory_tab = self._create_memory_tab()
        self.tab_widget.addTab(self.memory_tab, "Memory Changes")

        # API calls tab
        self.api_tab = self._create_api_tab()
        self.tab_widget.addTab(self.api_tab, "API Calls")

        layout.addWidget(self.tab_widget)

        # Action buttons
        self.button_box = self._create_buttons()
        layout.addWidget(self.button_box)

    def _create_status_widget(self) -> QWidget:
        """Create status display widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Status label
        self.status_label = QLabel("Executing script in QEMU...")
        self.status_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(self.status_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        # Duration label
        self.duration_label = QLabel("Duration: 0.0s")
        layout.addWidget(self.duration_label)

        return widget

    def _create_output_tab(self) -> QWidget:
        """Create real-time output display."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.output_text)

        return widget

    def _create_analysis_tab(self) -> QWidget:
        """Create analysis summary tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.analysis_tree = QTreeWidget()
        self.analysis_tree.setHeaderLabels(["Category", "Details"])
        layout.addWidget(self.analysis_tree)

        return widget

    def _create_memory_tab(self) -> QWidget:
        """Create memory changes display."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.memory_tree = QTreeWidget()
        self.memory_tree.setHeaderLabels(["Address", "Original", "Modified", "Description"])
        layout.addWidget(self.memory_tree)

        return widget

    def _create_api_tab(self) -> QWidget:
        """Create API calls display."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.api_tree = QTreeWidget()
        self.api_tree.setHeaderLabels(["Timestamp", "API", "Parameters", "Result"])
        layout.addWidget(self.api_tree)

        return widget

    def _create_buttons(self) -> QDialogButtonBox:
        """Create action buttons."""
        button_box = QDialogButtonBox()

        # Run on Host button (enabled after successful test)
        self.run_host_btn = QPushButton("Run on Host")
        self.run_host_btn.setEnabled(False)
        self.run_host_btn.clicked.connect(self.run_on_host)
        button_box.addButton(self.run_host_btn, QDialogButtonBox.ActionRole)

        # Modify Script button
        self.modify_btn = QPushButton("Modify Script")
        self.modify_btn.clicked.connect(self.modify_script)
        button_box.addButton(self.modify_btn, QDialogButtonBox.ActionRole)

        # Export Results button
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.export_results)
        button_box.addButton(self.export_btn, QDialogButtonBox.ActionRole)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_box.addButton(close_btn, QDialogButtonBox.RejectRole)

        return button_box

    def start_execution(self):
        """Start script execution in QEMU."""
        # Create snapshot for testing
        snapshot_id = self.qemu_manager.create_script_test_snapshot(
            self.script_info.get("binary_path", ""),
            self.script_info.get("platform", "windows"),
        )

        # Start execution thread
        self.execution_thread = QEMUExecutionThread(
            self.qemu_manager,
            snapshot_id,
            self.script_info.get("script_content", ""),
            self.script_info.get("binary_path", ""),
            self.script_info.get("script_type", "frida"),
        )

        # Connect signals
        self.execution_thread.output_update.connect(self.update_output)
        self.execution_thread.progress_update.connect(self.update_progress)
        self.execution_thread.execution_complete.connect(self.display_results)

        # Start execution
        self.execution_thread.start()

    def update_output(self, line: str):
        """Update real-time output display."""
        self.output_text.append(line)
        # Auto-scroll to bottom
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.output_text.setTextCursor(cursor)

    def update_progress(self, value: int, message: str):
        """Update progress bar."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"{message} - {value}%")

    def display_results(self, results: TestResults):
        """Display the real test results."""
        self.test_results = results

        # Update status
        if results.success:
            self.status_label.setText("Status: SUCCESS")
            self.status_label.setStyleSheet("color: green;")
            self.run_host_btn.setEnabled(True)
        else:
            self.status_label.setText("Status: FAILED")
            self.status_label.setStyleSheet("color: red;")

        self.duration_label.setText(f"Duration: {results.duration:.1f} seconds")
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Test Complete")

        # Populate analysis tree
        self._populate_analysis(results)

        # Populate memory changes
        self._populate_memory_changes(results)

        # Populate API calls
        self._populate_api_calls(results)

    def _populate_analysis(self, results: TestResults):
        """Populate analysis tree with real results."""
        self.analysis_tree.clear()

        # Summary
        summary_item = QTreeWidgetItem(["Summary", ""])
        summary_item.addChild(QTreeWidgetItem(["Success", str(results.success)]))
        summary_item.addChild(QTreeWidgetItem(["Exit Code", str(results.exit_code)]))
        summary_item.addChild(QTreeWidgetItem(["Process State", results.process_state]))
        summary_item.addChild(QTreeWidgetItem(["Duration", f"{results.duration:.1f}s"]))
        self.analysis_tree.addTopLevelItem(summary_item)

        # Issues
        if results.errors or results.warnings:
            issues_item = QTreeWidgetItem(["Issues Detected", ""])
            for error in results.errors:
                error_item = QTreeWidgetItem(["Error", error])
                error_item.setForeground(1, Qt.GlobalColor.red)
                issues_item.addChild(error_item)
            for warning in results.warnings:
                warning_item = QTreeWidgetItem(["Warning", warning])
                warning_item.setForeground(1, Qt.darkYellow)
                issues_item.addChild(warning_item)
            self.analysis_tree.addTopLevelItem(issues_item)

        # Statistics
        stats_item = QTreeWidgetItem(["Statistics", ""])
        stats_item.addChild(QTreeWidgetItem(["Memory Changes", str(len(results.memory_changes))]))
        stats_item.addChild(QTreeWidgetItem(["API Calls", str(len(results.api_calls))]))
        stats_item.addChild(
            QTreeWidgetItem(["Network Activity", str(len(results.network_activity))])
        )
        stats_item.addChild(QTreeWidgetItem(["File Operations", str(len(results.file_operations))]))
        self.analysis_tree.addTopLevelItem(stats_item)

        self.analysis_tree.expandAll()

    def _populate_memory_changes(self, results: TestResults):
        """Populate memory changes with real data."""
        self.memory_tree.clear()

        for change in results.memory_changes:
            item = QTreeWidgetItem(
                [
                    change.get("address", "Unknown"),
                    change.get("original", "N/A"),
                    change.get("patched", "N/A"),
                    change.get("description", ""),
                ]
            )
            self.memory_tree.addTopLevelItem(item)

    def _populate_api_calls(self, results: TestResults):
        """Populate API calls with real data."""
        self.api_tree.clear()

        for call in results.api_calls:
            item = QTreeWidgetItem(
                [
                    call.get("timestamp", "N/A"),
                    call.get("api", "Unknown"),
                    call.get("parameters", ""),
                    call.get("result", ""),
                ]
            )
            self.api_tree.addTopLevelItem(item)

    def run_on_host(self):
        """User chose to run the script on host after reviewing results."""
        self.accept()
        # Return indicator to run on host
        self.result_action = "run_on_host"

    def modify_script(self):
        """User wants to modify the script based on results."""
        self.accept()
        self.result_action = "modify_script"

    def export_results(self):
        """Export test results to file."""
        if not self.test_results:
            return

        # Export as JSON with all real data
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "script_info": self.script_info,
            "results": {
                "success": self.test_results.success,
                "duration": self.test_results.duration,
                "output": self.test_results.output,
                "errors": self.test_results.errors,
                "warnings": self.test_results.warnings,
                "memory_changes": self.test_results.memory_changes,
                "api_calls": self.test_results.api_calls,
                "process_state": self.test_results.process_state,
                "exit_code": self.test_results.exit_code,
            },
        }

        # Save to file
        from intellicrack.handlers.pyqt6_handler import QFileDialog

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Test Results",
            f"qemu_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)",
        )

        if filename:
            with open(filename, "w") as f:
                json.dump(export_data, f, indent=2)
            logger.info(f"Exported test results to {filename}")
