"""Symbolic execution for Intellicrack UI.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

import logging
import os
from pathlib import Path

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    Qt,
    QTextEdit,
    QVBoxLayout,
)
from intellicrack.utils.log_message import log_error, log_info, log_warning


class SymbolicExecution:
    """Symbolic execution analysis UI integration.

    This class provides a UI wrapper around Intellicrack's comprehensive
    symbolic execution engine for automatic vulnerability discovery and
    path exploration in binary analysis.
    """

    def __init__(self) -> None:
        """Initialize symbolic execution with existing engine integration."""
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.engine_available: bool = False
        self.angr_available: bool = False
        self.engine_class: type[object] | None = None

        self.max_paths: int = 100
        self.timeout: int = 300
        self.memory_limit: int = 4096
        self.vulnerability_types: list[str] = [
            "buffer_overflow",
            "format_string",
            "use_after_free",
            "command_injection",
            "sql_injection",
            "path_traversal",
        ]

        self._initialize_symbolic_execution()

        self.progress_dialog: QDialog | None = None
        self.current_analysis: dict[str, object] | None = None
        self.progress_bar: QProgressBar | None = None
        self.status_label: QLabel | None = None
        self.results_text: QTextEdit | None = None

    def _initialize_symbolic_execution(self) -> None:
        """Initialize symbolic execution using existing engine."""
        try:
            # Check for angr availability
            try:
                import importlib.util

                angr_spec = importlib.util.find_spec("angr")
                claripy_spec = importlib.util.find_spec("claripy")

                if angr_spec is not None and claripy_spec is not None:
                    self.angr_available = True
                    log_info("Angr framework available for symbolic execution", category="SYMBOLIC")
                else:
                    self.angr_available = False
                    log_warning(
                        "Angr framework not available - symbolic execution will use fallback mode",
                        category="SYMBOLIC",
                    )
            except ImportError:
                self.angr_available = False
                log_warning(
                    "Angr framework not available - symbolic execution will use fallback mode",
                    category="SYMBOLIC",
                )

            # Import existing symbolic execution engine
            from intellicrack.core.analysis.symbolic_executor import SymbolicExecutionEngine

            self.engine_class = SymbolicExecutionEngine
            self.engine_available = True

            log_info(
                "Symbolic execution initialized successfully",
                category="SYMBOLIC",
                context={
                    "angr_available": self.angr_available,
                    "max_paths": self.max_paths,
                    "timeout": self.timeout,
                },
            )

        except ImportError as e:
            self.logger.error(f"Failed to initialize symbolic execution engine: {e}")
            self.engine_available = False
            log_error(
                "Symbolic execution engine initialization failed", category="SYMBOLIC", exception=e
            )

    def run_symbolic_execution(self, app: object) -> None:
        """Run symbolic execution analysis with UI integration.

        Args:
            app: Main application instance with binary data and UI signals

        """
        try:
            log_info("Starting symbolic execution analysis", category="SYMBOLIC")

            # Get binary path from application
            binary_path = self._get_binary_path(app)
            if not binary_path:
                log_error("No binary file available for symbolic execution", category="SYMBOLIC")
                if hasattr(app, "update_output"):
                    app.update_output.emit("[ERROR] No binary loaded for symbolic execution")
                return

            # Show configuration dialog if needed
            if not self._show_configuration_dialog(app):
                log_info("Symbolic execution cancelled by user", category="SYMBOLIC")
                return

            # Show progress dialog
            self._show_progress_dialog(app, binary_path)

            # Check engine availability
            if not self.engine_available:
                log_error("Symbolic execution engine not available", category="SYMBOLIC")
                if hasattr(app, "update_output"):
                    app.update_output.emit("[ERROR] Symbolic execution engine not available")
                return

            # Update progress
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    f"[SYMBOLIC] Initializing symbolic execution for {Path(binary_path).name}..."
                )
                if self.angr_available:
                    app.update_output.emit("[SYMBOLIC] Using angr framework for advanced analysis")
                else:
                    app.update_output.emit("[SYMBOLIC] Using fallback mode (angr not available)")

            # Initialize symbolic execution engine
            engine = self.engine_class(
                binary_path=binary_path,
                max_paths=self.max_paths,
                timeout=self.timeout,
                memory_limit=self.memory_limit,
            )

            # Update progress
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    f"[SYMBOLIC] Exploring paths with max_paths={self.max_paths}, timeout={self.timeout}s"
                )

            # Run symbolic execution analysis
            results = self._run_symbolic_analysis(app, engine)

            # Process and display results
            self._process_analysis_results(app, results, binary_path)

            log_info(
                "Symbolic execution analysis completed successfully",
                category="SYMBOLIC",
                context={
                    "binary_path": binary_path,
                    "results_count": len(results.get("vulnerabilities", [])),
                },
            )

        except Exception as e:
            self.logger.error(f"Symbolic execution failed: {e}")
            log_error("Symbolic execution analysis failed", category="SYMBOLIC", exception=e)

            if hasattr(app, "update_output"):
                app.update_output.emit(f"[ERROR] Symbolic execution failed: {e}")

        finally:
            self._hide_progress_dialog()

    def _get_binary_path(self, app: object) -> str | None:
        """Extract binary path from application state.

        Args:
            app: Main application instance with binary data and UI signals

        Returns:
            Path to the binary file, or None if no valid binary is found

        """
        try:
            # Check various possible locations for binary path
            if hasattr(app, "current_file") and app.current_file and (os.path.exists(app.current_file) and os.path.isfile(app.current_file)):
                return app.current_file

            # Try to get from loaded binary path
            if hasattr(app, "loaded_binary_path") and app.loaded_binary_path and (os.path.exists(app.loaded_binary_path) and os.path.isfile(
                                app.loaded_binary_path
                            )):
                return app.loaded_binary_path

            # Check if there's a selected file in file browser
            if hasattr(app, "file_browser") and hasattr(app.file_browser, "selected_file") and app.file_browser.selected_file and (os.path.exists(app.file_browser.selected_file) and os.path.isfile(
                                app.file_browser.selected_file
                            )):
                return app.file_browser.selected_file

            return None

        except Exception as e:
            self.logger.error(f"Failed to get binary path: {e}")
            return None

    def _show_configuration_dialog(self, app: object) -> bool:
        """Show configuration dialog for symbolic execution parameters.

        Args:
            app: Main application instance with binary data and UI signals

        Returns:
            True if user clicked OK, False if cancelled

        """
        try:
            if not hasattr(app, "centralWidget") or not app.centralWidget():
                return True  # Use defaults if no UI available

            dialog = QDialog(app.centralWidget())
            dialog.setWindowTitle("Symbolic Execution Configuration")
            dialog.setWindowFlags(Qt.WindowType.Tool)
            dialog.setModal(True)
            dialog.resize(450, 400)

            layout = QVBoxLayout(dialog)

            # Exploration parameters group
            params_group = QGroupBox("Exploration Parameters")
            params_layout = QFormLayout(params_group)

            # Max paths
            max_paths_spin = QSpinBox()
            max_paths_spin.setRange(10, 1000)
            max_paths_spin.setValue(self.max_paths)
            params_layout.addRow("Max Paths:", max_paths_spin)

            # Timeout
            timeout_spin = QSpinBox()
            timeout_spin.setRange(30, 3600)
            timeout_spin.setValue(self.timeout)
            timeout_spin.setSuffix(" seconds")
            params_layout.addRow("Timeout:", timeout_spin)

            # Memory limit
            memory_spin = QSpinBox()
            memory_spin.setRange(512, 16384)
            memory_spin.setValue(self.memory_limit)
            memory_spin.setSuffix(" MB")
            params_layout.addRow("Memory Limit:", memory_spin)

            layout.addWidget(params_group)

            # Vulnerability types group
            vuln_group = QGroupBox("Vulnerability Types to Analyze")
            vuln_layout = QVBoxLayout(vuln_group)

            vuln_checkboxes = {}
            vuln_descriptions = {
                "buffer_overflow": "Buffer overflow vulnerabilities",
                "format_string": "Format string vulnerabilities",
                "use_after_free": "Use-after-free memory errors",
                "command_injection": "Command injection vulnerabilities",
                "sql_injection": "SQL injection vulnerabilities",
                "path_traversal": "Path traversal vulnerabilities",
            }

            for vuln_type in self.vulnerability_types:
                checkbox = QCheckBox(vuln_descriptions.get(vuln_type, vuln_type))
                checkbox.setChecked(True)
                vuln_checkboxes[vuln_type] = checkbox
                vuln_layout.addWidget(checkbox)

            layout.addWidget(vuln_group)

            # Buttons
            button_layout = QHBoxLayout()
            ok_button = QPushButton("Start Analysis")
            cancel_button = QPushButton("Cancel")

            button_layout.addWidget(ok_button)
            button_layout.addWidget(cancel_button)
            layout.addLayout(button_layout)

            # Connect signals
            ok_button.clicked.connect(dialog.accept)
            cancel_button.clicked.connect(dialog.reject)

            # Show dialog
            if dialog.exec() == QDialog.DialogCode.Accepted:
                # Update configuration
                self.max_paths = max_paths_spin.value()
                self.timeout = timeout_spin.value()
                self.memory_limit = memory_spin.value()

                # Update vulnerability types
                self.vulnerability_types = [
                    vuln_type
                    for vuln_type, checkbox in vuln_checkboxes.items()
                    if checkbox.isChecked()
                ]

                return True
            return False

        except Exception as e:
            self.logger.error(f"Failed to show configuration dialog: {e}")
            return True  # Use defaults on error

    def _show_progress_dialog(self, app: object, binary_path: str) -> None:
        """Show progress dialog for symbolic execution.

        Args:
            app: Main application instance with binary data and UI signals
            binary_path: Path to the binary file being analyzed

        """
        try:
            if not hasattr(app, "centralWidget") or not app.centralWidget():
                return

            self.progress_dialog = QDialog(app.centralWidget())
            self.progress_dialog.setWindowTitle("Symbolic Execution Analysis")
            self.progress_dialog.setWindowFlags(Qt.WindowType.Tool)
            self.progress_dialog.setModal(True)
            self.progress_dialog.resize(500, 300)

            layout = QVBoxLayout(self.progress_dialog)

            # Info group
            info_group = QGroupBox("Analysis Information")
            info_layout = QGridLayout(info_group)

            info_layout.addWidget(QLabel("Binary:"), 0, 0)
            info_layout.addWidget(QLabel(Path(binary_path).name), 0, 1)

            info_layout.addWidget(QLabel("Max Paths:"), 1, 0)
            info_layout.addWidget(QLabel(str(self.max_paths)), 1, 1)

            info_layout.addWidget(QLabel("Timeout:"), 2, 0)
            info_layout.addWidget(QLabel(f"{self.timeout}s"), 2, 1)

            info_layout.addWidget(QLabel("Engine:"), 3, 0)
            engine_label = "Angr" if self.angr_available else "Fallback"
            info_layout.addWidget(QLabel(engine_label), 3, 1)

            layout.addWidget(info_group)

            # Progress group
            progress_group = QGroupBox("Analysis Progress")
            progress_layout = QVBoxLayout(progress_group)

            self.progress_bar = QProgressBar()
            self.progress_bar.setRange(0, 0)  # Indeterminate
            progress_layout.addWidget(self.progress_bar)

            self.status_label = QLabel("Initializing symbolic execution...")
            progress_layout.addWidget(self.status_label)

            # Results area
            self.results_text = QTextEdit()
            self.results_text.setReadOnly(True)
            self.results_text.setMaximumHeight(100)
            progress_layout.addWidget(self.results_text)

            layout.addWidget(progress_group)

            # Show dialog
            self.progress_dialog.show()

        except Exception as e:
            self.logger.error(f"Failed to show progress dialog: {e}")

    def _hide_progress_dialog(self) -> None:
        """Hide progress dialog."""
        try:
            if self.progress_dialog:
                self.progress_dialog.close()
                self.progress_dialog = None
        except Exception as e:
            self.logger.error(f"Failed to hide progress dialog: {e}")

    def _run_symbolic_analysis(self, app: object, engine: object) -> dict[str, object]:
        """Run the actual symbolic analysis.

        Args:
            app: Main application instance with binary data and UI signals
            engine: Symbolic execution engine instance

        Returns:
            Dictionary containing analysis results including vulnerabilities, paths explored, and execution time

        """
        results: dict[str, object] = {
            "vulnerabilities": [],
            "paths_explored": 0,
            "coverage": {},
            "constraints": [],
            "crashed_states": [],
            "execution_time": 0,
        }

        try:
            # Update progress
            if hasattr(self, "status_label") and self.status_label:
                self.status_label.setText("Running symbolic execution...")

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    f"[SYMBOLIC] Analyzing vulnerability types: {', '.join(self.vulnerability_types)}"
                )

            # Run vulnerability analysis using existing engine
            if hasattr(engine, "analyze_vulnerabilities"):
                vuln_results = engine.analyze_vulnerabilities(self.vulnerability_types)
                results["vulnerabilities"] = vuln_results.get("vulnerabilities", [])
                results["paths_explored"] = vuln_results.get("paths_explored", 0)
                results["execution_time"] = vuln_results.get("execution_time", 0)

                if hasattr(self, "status_label") and self.status_label:
                    self.status_label.setText(
                        f"Found {len(results['vulnerabilities'])} potential vulnerabilities"
                    )

            else:
                # Fallback analysis if method doesn't exist
                log_warning(
                    "Engine doesn't support vulnerability analysis, performing basic path exploration",
                    category="SYMBOLIC",
                )
                results = self._fallback_analysis(app, engine)

            return results

        except Exception as e:
            self.logger.error(f"Symbolic analysis execution failed: {e}")
            results["error"] = str(e)
            return results

    def _check_buffer_overflow_constraint(self, constraint: object) -> bool:
        """Check if a constraint indicates potential buffer overflow.

        Args:
            constraint: Symbolic constraint object from the execution engine

        Returns:
            True if the constraint indicates a potential buffer overflow vulnerability

        """
        try:
            constraint_str = str(constraint).lower()
            # Look for common buffer overflow patterns
            overflow_indicators = [
                "buffer",
                "memcpy",
                "strcpy",
                "strcat",
                "sprintf",
                "gets",
                "scanf",
            ]

            # Check for size comparisons that might indicate overflow
            if any(indicator in constraint_str for indicator in overflow_indicators) and (">" in constraint_str or ">=" in constraint_str):
                import re

                size_pattern = r"\b(\d+)\b"
                sizes = re.findall(size_pattern, constraint_str)
                for size in sizes:
                    if int(size) > 0x10000:  # Suspiciously large size
                        return True

            # Check for array index out of bounds
            if ("array" in constraint_str or "index" in constraint_str) and any(op in constraint_str for op in [">=", ">", "out_of_bounds"]):
                return True

        except Exception as e:
            log_warning(f"Failed to check memory access constraint: {e}", category="SYMBOLIC")
        return False

    def _check_integer_overflow_constraint(self, constraint: object) -> bool:
        """Check if a constraint indicates potential integer overflow.

        Args:
            constraint: Symbolic constraint object from the execution engine

        Returns:
            True if the constraint indicates a potential integer overflow vulnerability

        """
        try:
            constraint_str = str(constraint).lower()

            # Look for integer overflow patterns
            overflow_patterns = [
                "0xffffffff",  # Max 32-bit value
                "0x7fffffff",  # Max signed 32-bit
                "0xffffffffffffffff",  # Max 64-bit value
                "0x7fffffffffffffff",  # Max signed 64-bit
                "overflow",
                "wrap",
                "underflow",
            ]

            if any(pattern in constraint_str for pattern in overflow_patterns):
                return True

            # Check for arithmetic operations near boundaries
            if any(op in constraint_str for op in ["+", "-", "*"]):
                import re

                # Look for large numbers in arithmetic
                hex_pattern = r"0x[0-9a-fA-F]{8,}"
                if large_nums := re.findall(hex_pattern, constraint_str):
                    for num_str in large_nums:
                        try:
                            num = int(num_str, 16)
                            # Check if number is near max values
                            if num > 0x7FFFFFF0 or num > 0x7FFFFFFFFFFFFFF0:
                                return True
                        except ValueError:
                            pass

        except Exception as e:
            log_warning(f"Failed to check integer overflow constraint: {e}", category="SYMBOLIC")
        return False

    def _fallback_analysis(self, app: object, engine: object) -> dict[str, object]:
        """Fallback analysis when full engine features are not available.

        Args:
            app: Main application instance with binary data and UI signals
            engine: Symbolic execution engine instance

        Returns:
            Dictionary containing analysis results from fallback mode

        """
        results: dict[str, object] = {
            "vulnerabilities": [],
            "paths_explored": 0,
            "coverage": {},
            "execution_time": 0,
            "fallback_mode": True,
        }

        try:
            if hasattr(app, "update_output"):
                app.update_output.emit("[SYMBOLIC] Running fallback symbolic analysis...")

            # Basic path exploration if available
            if hasattr(engine, "explore_paths"):
                path_results = engine.explore_paths()
                results["paths_explored"] = len(path_results.get("paths", []))

                # Analyze paths for real vulnerabilities
                for path in path_results.get("paths", []):
                    # Check for buffer overflow conditions
                    if hasattr(path, "constraints"):
                        for constraint in path.constraints:
                            if self._check_buffer_overflow_constraint(constraint):
                                results["vulnerabilities"].append(
                                    {
                                        "type": "buffer_overflow",
                                        "description": "Potential buffer overflow detected",
                                        "severity": "high",
                                        "location": f"0x{path.addr:x}"
                                        if hasattr(path, "addr")
                                        else "unknown",
                                        "constraint": str(constraint),
                                    },
                                )

                            if self._check_integer_overflow_constraint(constraint):
                                results["vulnerabilities"].append(
                                    {
                                        "type": "integer_overflow",
                                        "description": "Potential integer overflow detected",
                                        "severity": "medium",
                                        "location": f"0x{path.addr:x}"
                                        if hasattr(path, "addr")
                                        else "unknown",
                                        "constraint": str(constraint),
                                    },
                                )

                    # Check for use-after-free conditions
                    if hasattr(path, "memory_accesses"):
                        freed_addrs = set()
                        for access in path.memory_accesses:
                            if access.type == "free":
                                freed_addrs.add(access.addr)
                            elif access.type in ["read", "write"] and access.addr in freed_addrs:
                                results["vulnerabilities"].append(
                                    {
                                        "type": "use_after_free",
                                        "description": f"Use-after-free detected at address 0x{access.addr:x}",
                                        "severity": "critical",
                                        "location": f"0x{access.pc:x}"
                                        if hasattr(access, "pc")
                                        else "unknown",
                                    },
                                )

                    # Check for null pointer dereferences
                    if hasattr(path, "memory_accesses"):
                        for access in path.memory_accesses:
                            if access.addr == 0 or (
                                access.addr < 0x1000 and access.type in ["read", "write"]
                            ):
                                results["vulnerabilities"].append(
                                    {
                                        "type": "null_pointer_dereference",
                                        "description": "Null pointer dereference detected",
                                        "severity": "high",
                                        "location": f"0x{access.pc:x}"
                                        if hasattr(access, "pc")
                                        else "unknown",
                                        "address": f"0x{access.addr:x}",
                                    },
                                )

            if results["paths_explored"] > 0 and not results["vulnerabilities"] and hasattr(app, "update_output"):
                app.update_output.emit(
                    f"[SYMBOLIC] Analysis complete: {results['paths_explored']} paths explored, no vulnerabilities found",
                )

            return results

        except Exception as e:
            self.logger.error(f"Fallback analysis failed: {e}")
            results["error"] = str(e)
            return results

    def _process_analysis_results(
        self, app: object, results: dict[str, object], binary_path: str
    ) -> None:
        """Process and display symbolic execution results.

        Args:
            app: Main application instance with binary data and UI signals
            results: Dictionary containing analysis results
            binary_path: Path to the binary file that was analyzed

        """
        try:
            if not results:
                return

            # Update progress dialog status
            if hasattr(self, "status_label") and self.status_label:
                vuln_count = len(results.get("vulnerabilities", []))
                self.status_label.setText(f"Analysis complete: {vuln_count} findings")

            # Display results summary
            if hasattr(app, "update_output"):
                paths_explored = results.get("paths_explored", 0)
                execution_time = results.get("execution_time", 0)
                vulnerabilities = results.get("vulnerabilities", [])

                app.update_output.emit(
                    f"[SYMBOLIC] Exploration completed: {paths_explored} paths analyzed"
                )
                app.update_output.emit(f"[SYMBOLIC] Analysis time: {execution_time:.2f} seconds")
                app.update_output.emit(f"[SYMBOLIC] Vulnerabilities found: {len(vulnerabilities)}")

                # Display vulnerability details
                for i, vuln in enumerate(vulnerabilities[:5]):  # Show first 5
                    vuln_type = vuln.get("type", "unknown")
                    severity = vuln.get("severity", "unknown")
                    description = vuln.get("description", "No description")
                    app.update_output.emit(
                        f"[SYMBOLIC] Vuln {i + 1}: {vuln_type} ({severity}) - {description}"
                    )

                if len(vulnerabilities) > 5:
                    app.update_output.emit(
                        f"[SYMBOLIC] ... and {len(vulnerabilities) - 5} more findings"
                    )

                # Check for errors
                if "error" in results:
                    app.update_output.emit(
                        f"[SYMBOLIC] Analysis completed with errors: {results['error']}"
                    )

                # Display additional results in progress dialog
                if hasattr(self, "results_text") and self.results_text:
                    summary = f"Paths: {paths_explored}\nTime: {execution_time:.2f}s\nFindings: {len(vulnerabilities)}"
                    self.results_text.setText(summary)

            # Store results for further processing
            self.current_analysis = results

        except Exception as e:
            self.logger.error(f"Failed to process symbolic execution results: {e}")
            if hasattr(app, "update_output"):
                app.update_output.emit(f"[ERROR] Failed to process symbolic execution results: {e}")

    def get_analysis_status(self) -> dict[str, object]:
        """Get current symbolic execution status and capabilities.

        Returns:
            Dictionary containing status information

        """
        return {
            "engine_available": self.engine_available,
            "angr_available": self.angr_available,
            "current_analysis": self.current_analysis is not None,
            "configuration": {
                "max_paths": self.max_paths,
                "timeout": self.timeout,
                "memory_limit": self.memory_limit,
                "vulnerability_types": self.vulnerability_types,
            },
        }

    def cleanup(self) -> None:
        """Cleanup symbolic execution resources."""
        try:
            self._hide_progress_dialog()
            self.current_analysis = None

            log_info("Symbolic execution cleanup completed", category="SYMBOLIC")

        except Exception as e:
            self.logger.error(f"Symbolic execution cleanup failed: {e}")
