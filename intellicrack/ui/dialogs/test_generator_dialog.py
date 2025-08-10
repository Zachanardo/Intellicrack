"""Test generator dialog for creating automated test cases.

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
import os
import subprocess
import sys
from typing import Any, Dict

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox, QFileDialog, QFont, QGroupBox, QHBoxLayout, QLabel,
    QListWidget, QMessageBox, QProgressBar, QPushButton, QSpinBox,
    QSplitter, Qt, QTabWidget, QTextEdit, QThread, QVBoxLayout,
    QWidget, pyqtSignal,
)

from intellicrack.logger import logger

from ...tools.plugin_test_generator import MockDataGenerator, PluginTestGenerator, PluginTestRunner
from .plugin_dialog_base import PluginDialogBase

"""
Test Generator Dialog for Intellicrack plugins.

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





class TestGenerationThread(QThread):
    """Thread for generating and running tests"""

    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, plugin_path: str, options: Dict[str, Any]):
        """Initialize the TestGenerationThread with default values."""
        super().__init__()
        self.plugin_path = plugin_path
        self.options = options
        self.runner = PluginTestRunner()

    def run(self):
        """Generate and run tests"""
        try:
            self.progress.emit("Analyzing plugin structure...")

            # Generate tests
            results = self.runner.generate_and_run_tests(self.plugin_path)

            self.progress.emit("Running tests...")

            # Run tests if requested
            if self.options.get('run_tests', True):
                # Run pytest
                cmd = [sys.executable, '-m', 'pytest', results['test_file'], '-v']
                if self.options.get('coverage', True):
                    cmd.extend(['--cov', os.path.dirname(self.plugin_path)])

                process = subprocess.run(cmd, capture_output=True, text=True)
                results['test_output'] = process.stdout + process.stderr
                results['test_passed'] = process.returncode == 0

            self.finished.emit(results)

        except Exception as e:
            logger.error("Exception in test_generator_dialog: %s", e)
            self.error.emit(str(e))


class TestGeneratorDialog(PluginDialogBase):
    """Dialog for generating and managing plugin tests"""

    def __init__(self, parent=None, plugin_path=None):
        """Initialize the TestGeneratorDialog with default values."""
        self.generator = PluginTestGenerator()
        self.mock_generator = MockDataGenerator()
        self.generation_thread = None
        super().__init__(parent, plugin_path)

    def init_dialog(self):
        """Initialize the test generator dialog"""
        self.setWindowTitle("Plugin Test Generator")
        self.setMinimumSize(900, 700)
        self.setup_ui()

    def setup_ui(self):
        """Set up the dialog UI"""
        layout = QVBoxLayout(self)

        # Plugin selection (using base class method)
        plugin_layout = self.create_plugin_selection_layout()
        layout.addLayout(plugin_layout)

        # Main content
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Options
        options_widget = self.create_options_panel()
        splitter.addWidget(options_widget)

        # Right panel - Results
        self.tab_widget = QTabWidget()

        # Generated test tab
        self.test_code_edit = QTextEdit()
        self.test_code_edit.setFont(QFont("Consolas", 10))
        self.tab_widget.addTab(self.test_code_edit, "Generated Tests")

        # Test results tab
        self.results_widget = self.create_results_widget()
        self.tab_widget.addTab(self.results_widget, "Test Results")

        # Coverage tab
        self.coverage_widget = self.create_coverage_widget()
        self.tab_widget.addTab(self.coverage_widget, "Coverage Report")

        # Mock data tab
        self.mock_widget = self.create_mock_widget()
        self.tab_widget.addTab(self.mock_widget, "Mock Data")

        splitter.addWidget(self.tab_widget)
        splitter.setSizes([300, 600])

        layout.addWidget(splitter)

        # Bottom controls
        control_layout = QHBoxLayout()

        self.generate_btn = QPushButton("🔧 Generate Tests")
        self.generate_btn.clicked.connect(self.generate_tests)
        self.generate_btn.setEnabled(False)
        control_layout.addWidget(self.generate_btn)

        self.run_btn = QPushButton("▶️ Run Tests")
        self.run_btn.clicked.connect(self.run_tests)
        self.run_btn.setEnabled(False)
        control_layout.addWidget(self.run_btn)

        self.save_btn = QPushButton("💾 Save Tests")
        self.save_btn.clicked.connect(self.save_tests)
        self.save_btn.setEnabled(False)
        control_layout.addWidget(self.save_btn)

        control_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        control_layout.addWidget(self.progress_bar)

        layout.addLayout(control_layout)

    def create_options_panel(self) -> QWidget:
        """Create options panel"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Test generation options
        gen_group = QGroupBox("Generation Options")
        gen_layout = QVBoxLayout(gen_group)

        self.include_edge_cases_cb = QCheckBox("Include edge case tests")
        self.include_edge_cases_cb.setChecked(True)
        gen_layout.addWidget(self.include_edge_cases_cb)

        self.include_invalid_input_cb = QCheckBox("Include invalid input tests")
        self.include_invalid_input_cb.setChecked(True)
        gen_layout.addWidget(self.include_invalid_input_cb)

        self.include_mocks_cb = QCheckBox("Generate mock objects")
        self.include_mocks_cb.setChecked(True)
        gen_layout.addWidget(self.include_mocks_cb)

        self.include_fixtures_cb = QCheckBox("Generate test fixtures")
        self.include_fixtures_cb.setChecked(True)
        gen_layout.addWidget(self.include_fixtures_cb)

        layout.addWidget(gen_group)

        # Test execution options
        exec_group = QGroupBox("Execution Options")
        exec_layout = QVBoxLayout(exec_group)

        self.run_after_generation_cb = QCheckBox("Run tests after generation")
        self.run_after_generation_cb.setChecked(True)
        exec_layout.addWidget(self.run_after_generation_cb)

        self.generate_coverage_cb = QCheckBox("Generate coverage report")
        self.generate_coverage_cb.setChecked(True)
        exec_layout.addWidget(self.generate_coverage_cb)

        self.stop_on_failure_cb = QCheckBox("Stop on first failure")
        exec_layout.addWidget(self.stop_on_failure_cb)

        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (seconds):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        timeout_layout.addWidget(self.timeout_spin)
        exec_layout.addLayout(timeout_layout)

        layout.addWidget(exec_group)

        # Test templates
        template_group = QGroupBox("Test Templates")
        template_layout = QVBoxLayout(template_group)

        self.template_list = QListWidget()
        self.template_list.addItems([
            "Basic Plugin Tests",
            "Binary Analysis Tests",
            "Network Plugin Tests",
            "Frida Hook Tests",
            "Vulnerability Scanner Tests",
            "Performance Tests"
        ])
        template_layout.addWidget(self.template_list)

        layout.addWidget(template_group)

        layout.addStretch()
        return widget

    def create_results_widget(self) -> QWidget:
        """Create test results widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Summary
        self.summary_label = QLabel("No tests run yet")
        self.summary_label.setStyleSheet("font-size: 14px; padding: 10px;")
        layout.addWidget(self.summary_label)

        # Test output
        self.test_output = QTextEdit()
        self.test_output.setReadOnly(True)
        self.test_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.test_output)

        return widget

    def create_coverage_widget(self) -> QWidget:
        """Create coverage report widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Coverage summary
        self.coverage_summary = QLabel("No coverage data available")
        self.coverage_summary.setStyleSheet("font-size: 14px; padding: 10px;")
        layout.addWidget(self.coverage_summary)

        # Coverage details
        self.coverage_text = QTextEdit()
        self.coverage_text.setReadOnly(True)
        self.coverage_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.coverage_text)

        # Uncovered lines
        uncovered_group = QGroupBox("Uncovered Lines")
        uncovered_layout = QVBoxLayout(uncovered_group)

        self.uncovered_list = QListWidget()
        uncovered_layout.addWidget(self.uncovered_list)

        layout.addWidget(uncovered_group)

        return widget

    def create_mock_widget(self) -> QWidget:
        """Create mock data widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Mock data types
        mock_group = QGroupBox("Available Mock Data")
        mock_layout = QVBoxLayout(mock_group)

        # Binary mock
        binary_btn = QPushButton("Generate Mock Binary")
        binary_btn.clicked.connect(self.generate_mock_binary)
        mock_layout.addWidget(binary_btn)

        # Network mock
        network_btn = QPushButton("Generate Mock Network Data")
        network_btn.clicked.connect(self.generate_mock_network)
        mock_layout.addWidget(network_btn)

        # Registry mock
        registry_btn = QPushButton("Generate Mock Registry Data")
        registry_btn.clicked.connect(self.generate_mock_registry)
        mock_layout.addWidget(registry_btn)

        layout.addWidget(mock_group)

        # Mock data viewer
        self.mock_viewer = QTextEdit()
        self.mock_viewer.setFont(QFont("Consolas", 9))
        layout.addWidget(self.mock_viewer)

        # Save mock data button
        save_mock_btn = QPushButton("Save Mock Data")
        save_mock_btn.clicked.connect(self.save_mock_data)
        layout.addWidget(save_mock_btn)

        return widget

    def load_plugin(self, path: str):
        """Load a plugin for testing"""
        # Call the base class method first
        if not super().load_plugin(path):
            return False

        # Add test generator-specific functionality
        self.generate_btn.setEnabled(True)

        # Clear previous results
        self.test_code_edit.clear()
        self.test_output.clear()
        self.coverage_text.clear()

        return True

    def generate_tests(self):
        """Generate tests for the plugin"""
        if not self.plugin_path:
            return

        try:
            # Generate test code
            test_code = self.generator.generate_tests_for_file(self.plugin_path)

            # Display generated code
            self.test_code_edit.setPlainText(test_code)

            # Switch to test code tab
            self.tab_widget.setCurrentIndex(0)

            # Enable buttons
            self.run_btn.setEnabled(True)
            self.save_btn.setEnabled(True)

            # Run tests if option is checked
            if self.run_after_generation_cb.isChecked():
                self.run_tests()

        except Exception as e:
            logger.error("Exception in test_generator_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Failed to generate tests:\n{str(e)}")

    def run_tests(self):
        """Run the generated tests"""
        if not self.test_code_edit.toPlainText():
            QMessageBox.warning(self, "No Tests", "Please generate tests first.")
            return

        # Prepare options
        options = {
            'run_tests': True,
            'coverage': self.generate_coverage_cb.isChecked(),
            'stop_on_failure': self.stop_on_failure_cb.isChecked(),
            'timeout': self.timeout_spin.value()
        }

        # Save test file temporarily
        test_dir = os.path.join(os.path.dirname(self.plugin_path), 'tests')
        os.makedirs(test_dir, exist_ok=True)

        test_filename = f"test_{os.path.basename(self.plugin_path)}"
        test_path = os.path.join(test_dir, test_filename)

        with open(test_path, 'w') as f:
            f.write(self.test_code_edit.toPlainText())

        # Start test thread
        self.generation_thread = TestGenerationThread(self.plugin_path, options)
        self.generation_thread.progress.connect(self.on_progress)
        self.generation_thread.finished.connect(self.on_tests_finished)
        self.generation_thread.error.connect(self.on_error)

        # Update UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.generate_btn.setEnabled(False)
        self.run_btn.setEnabled(False)

        self.generation_thread.start()

    def on_progress(self, message: str):
        """Handle progress updates"""
        self.test_output.append(message)

    def on_tests_finished(self, results: Dict[str, Any]):
        """Handle test completion"""
        # Update UI
        self.progress_bar.setVisible(False)
        self.generate_btn.setEnabled(True)
        self.run_btn.setEnabled(True)

        # Display results
        self.test_output.append("\n" + "="*50 + "\n")
        self.test_output.append(results.get('test_output', 'No output'))

        # Update summary
        if results.get('test_passed'):
            self.summary_label.setText("✅ All tests passed!")
            self.summary_label.setStyleSheet("color: green; font-size: 14px; padding: 10px;")
        else:
            self.summary_label.setText("❌ Some tests failed")
            self.summary_label.setStyleSheet("color: red; font-size: 14px; padding: 10px;")

        # Switch to results tab
        self.tab_widget.setCurrentIndex(1)

        # Update coverage if available
        if 'coverage' in results:
            self.update_coverage_display(results['coverage'])

    def on_error(self, error: str):
        """Handle test errors"""
        self.progress_bar.setVisible(False)
        self.generate_btn.setEnabled(True)
        self.run_btn.setEnabled(True)

        QMessageBox.critical(self, "Test Error", f"Failed to run tests:\n{error}")

    def update_coverage_display(self, coverage: Dict[str, Any]):
        """Update coverage display"""
        # Update summary
        total = coverage.get('total_coverage', 0)
        self.coverage_summary.setText(f"Total Coverage: {total}%")

        if total >= 80:
            color = "green"
        elif total >= 60:
            color = "orange"
        else:
            color = "red"

        self.coverage_summary.setStyleSheet(f"color: {color}; font-size: 14px; padding: 10px;")

        # Update uncovered lines
        self.uncovered_list.clear()
        for line in coverage.get('missing_lines', []):
            self.uncovered_list.addItem(f"Line {line}")

    def save_tests(self):
        """Save generated tests"""
        if not self.test_code_edit.toPlainText():
            QMessageBox.warning(self, "No Tests", "No tests to save.")
            return

        # Ask for save location
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Tests",
            f"test_{os.path.basename(self.plugin_path)}",
            "Python Files (*.py);;All Files (*.*)"
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.test_code_edit.toPlainText())

                QMessageBox.information(self, "Saved", f"Tests saved to:\n{file_path}")

            except Exception as e:
                self.logger.error("Exception in test_generator_dialog: %s", e)
                QMessageBox.critical(self, "Error", f"Failed to save tests:\n{str(e)}")

    def generate_mock_binary(self):
        """Generate mock binary data"""
        binary_data = self.mock_generator.create_mock_binary('pe')

        # Display hex view
        hex_view = []
        for i in range(0, min(len(binary_data), 512), 16):
            hex_line = ' '.join(f'{b:02x}' for b in binary_data[i:i+16])
            ascii_line = ''.join(chr(b) if 32 <= b < 127 else '.' for b in binary_data[i:i+16])
            hex_view.append(f"{i:08x}: {hex_line:<48} {ascii_line}")

        self.mock_viewer.setPlainText('\n'.join(hex_view))
        self.mock_viewer.append(f"\n\nTotal size: {len(binary_data)} bytes")

    def generate_mock_network(self):
        """Generate mock network data"""
        network_data = self.mock_generator.create_mock_network_data()

        import json
        self.mock_viewer.setPlainText(json.dumps(network_data, indent=2))

    def generate_mock_registry(self):
        """Generate mock registry data"""
        registry_data = self.mock_generator.create_mock_registry_data()

        import json
        self.mock_viewer.setPlainText(json.dumps(registry_data, indent=2))

    def save_mock_data(self):
        """Save mock data to file"""
        content = self.mock_viewer.toPlainText()
        if not content:
            QMessageBox.warning(self, "No Data", "No mock data to save.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Mock Data",
            "mock_data.txt",
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*.*)"
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(content)

                QMessageBox.information(self, "Saved", f"Mock data saved to:\n{file_path}")

            except Exception as e:
                self.logger.error("Exception in test_generator_dialog: %s", e)
                QMessageBox.critical(self, "Error", f"Failed to save mock data:\n{str(e)}")
