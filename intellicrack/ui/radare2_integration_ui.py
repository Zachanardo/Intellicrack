"""Comprehensive Radare2 UI Integration for Intellicrack.

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

import json
import logging
import os
from typing import Any, Protocol, cast

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFont,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QThread,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.utils.type_safety import validate_type

from ..core.analysis.cfg_explorer import CFGExplorer
from ..core.analysis.radare2_ai_integration import R2AIEngine
from ..core.analysis.radare2_bypass_generator import R2BypassGenerator

# Import all radare2 analysis engines
from ..core.analysis.radare2_decompiler import R2DecompilationEngine
from ..core.analysis.radare2_imports import R2ImportExportAnalyzer
from ..core.analysis.radare2_scripting import R2ScriptingEngine
from ..core.analysis.radare2_strings import R2StringAnalyzer
from ..core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine


class R2AnalysisWorker(QThread):
    """Worker thread for radare2 analysis operations."""

    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    analysis_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, binary_path: str, analysis_type: str, options: dict[str, Any]) -> None:
        """Initialize the radare2 analysis worker with binary path and analysis options."""
        super().__init__()
        self.binary_path = binary_path
        self.analysis_type = analysis_type
        self.options = options
        self.logger = logging.getLogger(__name__)

    def run(self) -> None:
        """Execute analysis in background thread."""
        try:
            self.status_updated.emit(f"Starting {self.analysis_type} analysis...")
            self.progress_updated.emit(10)

            if self.analysis_type == "comprehensive":
                result = self._run_comprehensive_analysis()
            elif self.analysis_type == "decompilation":
                result = self._run_decompilation_analysis()
            elif self.analysis_type == "vulnerability":
                result = self._run_vulnerability_analysis()
            elif self.analysis_type == "strings":
                result = self._run_string_analysis()
            elif self.analysis_type == "imports":
                result = self._run_import_analysis()
            elif self.analysis_type == "cfg":
                result = self._run_cfg_analysis()
            elif self.analysis_type == "ai":
                result = self._run_ai_analysis()
            elif self.analysis_type == "bypass":
                result = self._run_bypass_analysis()
            else:
                error_msg = f"Unknown analysis type: {self.analysis_type}"
                self.logger.exception(error_msg)
                raise ValueError(error_msg)

            self.progress_updated.emit(100)
            self.status_updated.emit(f"{self.analysis_type} analysis completed")
            self.analysis_completed.emit(result)

        except Exception as e:
            self.logger.exception("Analysis failed: %s", e)
            self.error_occurred.emit(str(e))

    def _run_comprehensive_analysis(self) -> dict[str, Any]:
        """Run comprehensive radare2 analysis."""
        results: dict[str, Any] = {
            "binary_path": self.binary_path,
            "analysis_type": "comprehensive",
            "components": {},
        }

        # Initialize all engines
        engines: dict[str, object] = {
            "decompiler": R2DecompilationEngine(self.binary_path),
            "vulnerability": R2VulnerabilityEngine(self.binary_path),
            "strings": R2StringAnalyzer(self.binary_path),
            "imports": R2ImportExportAnalyzer(self.binary_path),
            "ai": R2AIEngine(self.binary_path),
            "cfg": CFGExplorer(self.binary_path),
            "scripting": R2ScriptingEngine(self.binary_path),
        }

        total_components = len(engines)
        current_progress = 10

        for i, (name, engine) in enumerate(engines.items()):
            try:
                self.status_updated.emit(f"Running {name} analysis...")

                result: Any = None
                if name == "decompiler" and hasattr(engine, "analyze_license_functions"):
                    result = engine.analyze_license_functions()
                elif name == "vulnerability" and hasattr(engine, "analyze_vulnerabilities"):
                    result = engine.analyze_vulnerabilities()
                elif name == "strings" and hasattr(engine, "analyze_all_strings"):
                    result = engine.analyze_all_strings()
                elif name == "imports" and hasattr(engine, "analyze_imports_exports"):
                    result = engine.analyze_imports_exports()
                elif name == "ai" and hasattr(engine, "analyze_with_ai"):
                    result = engine.analyze_with_ai()
                elif name == "cfg" and hasattr(engine, "analyze_cfg"):
                    result = engine.analyze_cfg()
                elif name == "scripting" and hasattr(engine, "execute_license_analysis_workflow"):
                    result = engine.execute_license_analysis_workflow()
                else:
                    result = f"Unknown analysis component: {name}"

                components = validate_type(results["components"], dict)
                components[name] = result

                # Update progress
                current_progress = 10 + int((i + 1) / total_components * 80)
                self.progress_updated.emit(current_progress)

            except Exception as e:
                self.logger.warning("Component %s failed: %s", name, e)
                components = validate_type(results["components"], dict)
                components[name] = {"error": str(e)}

        return results

    def _run_decompilation_analysis(self) -> dict[str, Any]:
        """Run decompilation analysis."""
        engine = R2DecompilationEngine(self.binary_path)
        self.progress_updated.emit(50)
        return engine.analyze_license_functions()

    def _run_vulnerability_analysis(self) -> dict[str, Any]:
        """Run vulnerability analysis."""
        engine = R2VulnerabilityEngine(self.binary_path)
        self.progress_updated.emit(50)
        return engine.analyze_vulnerabilities()

    def _run_string_analysis(self) -> dict[str, Any]:
        """Run string analysis."""
        engine = R2StringAnalyzer(self.binary_path)
        self.progress_updated.emit(50)
        return engine.analyze_all_strings()

    def _run_import_analysis(self) -> dict[str, Any]:
        """Run import/export analysis."""
        engine = R2ImportExportAnalyzer(self.binary_path)
        self.progress_updated.emit(50)
        return engine.analyze_imports_exports()

    def _run_cfg_analysis(self) -> dict[str, Any]:
        """Run CFG analysis."""
        engine = CFGExplorer(self.binary_path)
        self.progress_updated.emit(50)
        return engine.analyze_cfg()

    def _run_ai_analysis(self) -> dict[str, Any]:
        """Run AI analysis."""
        engine = R2AIEngine(self.binary_path)
        self.progress_updated.emit(50)
        return engine.analyze_with_ai()

    def _run_bypass_analysis(self) -> dict[str, Any]:
        """Run bypass generation analysis."""
        engine = R2BypassGenerator(self.binary_path)
        self.progress_updated.emit(50)
        return engine.generate_comprehensive_bypass()


class R2ConfigurationDialog(QDialog):
    """Dialog for configuring radare2 analysis options."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the radare2 configuration dialog with UI setup."""
        super().__init__(parent)
        self.setWindowTitle("Radare2 Analysis Configuration")
        self.setMinimumSize(500, 600)
        self.config: dict[str, Any] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up configuration dialog UI."""
        layout = QVBoxLayout(self)

        # Analysis options
        analysis_group = QGroupBox("Analysis Options")
        analysis_layout = QFormLayout(analysis_group)

        self.analysis_depth = QComboBox()
        self.analysis_depth.addItems(["Basic (aa)", "Extended (aaa)", "Comprehensive (aaaa)"])
        self.analysis_depth.setCurrentIndex(1)
        analysis_layout.addRow("Analysis Depth:", self.analysis_depth)

        self.max_functions = QSpinBox()
        self.max_functions.setRange(10, 10000)
        self.max_functions.setValue(1000)
        analysis_layout.addRow("Max Functions:", self.max_functions)

        self.timeout_seconds = QSpinBox()
        self.timeout_seconds.setRange(30, 3600)
        self.timeout_seconds.setValue(300)
        analysis_layout.addRow("Timeout (seconds):", self.timeout_seconds)

        layout.addWidget(analysis_group)

        # Feature toggles
        features_group = QGroupBox("Feature Selection")
        features_layout = QVBoxLayout(features_group)

        self.enable_decompilation = QCheckBox("Decompilation Analysis")
        self.enable_decompilation.setChecked(True)

        self.enable_vulnerability = QCheckBox("Vulnerability Detection")
        self.enable_vulnerability.setChecked(True)

        self.enable_strings = QCheckBox("String Analysis")
        self.enable_strings.setChecked(True)

        self.enable_imports = QCheckBox("Import/Export Analysis")
        self.enable_imports.setChecked(True)

        self.enable_cfg = QCheckBox("Control Flow Graph")
        self.enable_cfg.setChecked(True)

        self.enable_ai = QCheckBox("AI Analysis")
        self.enable_ai.setChecked(False)

        self.enable_bypass = QCheckBox("Bypass Generation")
        self.enable_bypass.setChecked(False)

        features_layout.addWidget(self.enable_decompilation)
        features_layout.addWidget(self.enable_vulnerability)
        features_layout.addWidget(self.enable_strings)
        features_layout.addWidget(self.enable_imports)
        features_layout.addWidget(self.enable_cfg)
        features_layout.addWidget(self.enable_ai)
        features_layout.addWidget(self.enable_bypass)

        layout.addWidget(features_group)

        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QFormLayout(advanced_group)

        self.radare2_path = QLineEdit()
        if hasattr(self.radare2_path, "setToolTip"):
            self.radare2_path.setToolTip("Leave empty for system PATH")
        advanced_layout.addRow("Radare2 Path:", self.radare2_path)

        self.custom_flags = QLineEdit()
        self.custom_flags.setText("-e anal.depth=3 -e anal.bb.maxsize=64")
        if hasattr(self.custom_flags, "setToolTip"):
            self.custom_flags.setToolTip("Custom radare2 flags for analysis")
        advanced_layout.addRow("Custom Flags:", self.custom_flags)

        layout.addWidget(advanced_group)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_configuration(self) -> dict[str, Any]:
        """Get configuration from dialog."""
        return {
            "analysis_depth": self.analysis_depth.currentText(),
            "max_functions": self.max_functions.value(),
            "timeout_seconds": self.timeout_seconds.value(),
            "enable_decompilation": self.enable_decompilation.isChecked(),
            "enable_vulnerability": self.enable_vulnerability.isChecked(),
            "enable_strings": self.enable_strings.isChecked(),
            "enable_imports": self.enable_imports.isChecked(),
            "enable_cfg": self.enable_cfg.isChecked(),
            "enable_ai": self.enable_ai.isChecked(),
            "enable_bypass": self.enable_bypass.isChecked(),
            "radare2_path": self.radare2_path.text().strip() or None,
            "custom_flags": self.custom_flags.text().strip() or None,
        }


class R2ResultsViewer(QWidget):
    """Widget for displaying comprehensive radare2 analysis results."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the radare2 results viewer with UI components."""
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.results_data: dict[str, Any] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up results viewer UI."""
        layout = QVBoxLayout(self)

        # Results navigation
        nav_layout = QHBoxLayout()

        self.component_selector = QComboBox()
        self.component_selector.currentTextChanged.connect(self._on_component_changed)
        nav_layout.addWidget(QLabel("Component:"))
        nav_layout.addWidget(self.component_selector)

        nav_layout.addStretch()

        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self._export_results)
        nav_layout.addWidget(self.export_button)

        layout.addLayout(nav_layout)

        # Results display
        self.results_tabs = QTabWidget()
        layout.addWidget(self.results_tabs)

    def display_results(self, results: dict[str, Any]) -> None:
        """Display analysis results."""
        self.results_data = results

        # Clear existing data
        self.component_selector.clear()
        self.results_tabs.clear()

        if "components" in results:
            # Multi-component results
            for component, data in results["components"].items():
                self.component_selector.addItem(component.title())
                self._create_component_tab(component, data)
        else:
            # Single component results
            self._create_component_tab("Analysis", results)

    def _create_component_tab(self, component: str, data: dict[str, Any]) -> None:
        """Create tab for component results."""
        tab_widget = QWidget()
        layout = QVBoxLayout(tab_widget)

        # Summary section
        summary_group = QGroupBox("Summary")
        summary_layout = QVBoxLayout(summary_group)

        summary_text = QTextEdit()
        summary_text.setMaximumHeight(100)
        summary_text.setReadOnly(True)
        summary_text.setPlainText(self._generate_summary(data))
        summary_layout.addWidget(summary_text)

        layout.addWidget(summary_group)

        # Detailed results
        details_group = QGroupBox("Detailed Results")
        details_layout = QVBoxLayout(details_group)

        if component.lower() == "vulnerability":
            self._create_vulnerability_view(details_layout, data)
        elif component.lower() == "strings":
            self._create_strings_view(details_layout, data)
        elif component.lower() == "imports":
            self._create_imports_view(details_layout, data)
        elif component.lower() == "cfg":
            self._create_cfg_view(details_layout, data)
        elif component.lower() == "ai":
            self._create_ai_view(details_layout, data)
        else:
            self._create_generic_view(details_layout, data)

        layout.addWidget(details_group)

        self.results_tabs.addTab(tab_widget, component.title())

    def _generate_summary(self, data: dict[str, Any]) -> str:
        """Generate summary text for component."""
        if "error" in data:
            return f"Analysis failed: {data['error']}"

        summary_parts = []

        # Count various result types
        if "license_functions" in data:
            count = len(data["license_functions"])
            summary_parts.append(f"License functions: {count}")

        if "vulnerabilities" in data:
            count = len(data["vulnerabilities"])
            summary_parts.append(f"Vulnerabilities: {count}")

        if "buffer_overflows" in data:
            count = len(data["buffer_overflows"])
            summary_parts.append(f"Buffer overflows: {count}")

        if "license_strings" in data:
            count = len(data["license_strings"])
            summary_parts.append(f"License strings: {count}")

        if "imports" in data:
            count = len(data["imports"])
            summary_parts.append(f"Imports: {count}")

        if "functions_analyzed" in data:
            count = data["functions_analyzed"]
            summary_parts.append(f"Functions analyzed: {count}")

        return " | ".join(summary_parts) if summary_parts else "Analysis completed"

    def _create_vulnerability_view(self, layout: QVBoxLayout, data: dict[str, Any]) -> None:
        """Create vulnerability-specific view."""
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Type", "Function", "Address", "Severity"])

        vulnerabilities: list[dict[str, str]] = []

        for category in [
            "buffer_overflows",
            "format_string_bugs",
            "integer_overflows",
            "use_after_free",
            "double_free",
            "code_injection",
        ]:
            if category in data:
                vulnerabilities.extend(
                    {
                        "type": category.replace("_", " ").title(),
                        "function": vuln.get("function", "Unknown"),
                        "address": vuln.get("address", "Unknown"),
                        "severity": vuln.get("severity", "Medium"),
                    }
                    for vuln in data[category]
                )
        table.setRowCount(len(vulnerabilities))

        for i, vuln in enumerate(vulnerabilities):
            table.setItem(i, 0, QTableWidgetItem(vuln["type"]))
            table.setItem(i, 1, QTableWidgetItem(vuln["function"]))
            table.setItem(i, 2, QTableWidgetItem(str(vuln["address"])))
            table.setItem(i, 3, QTableWidgetItem(vuln["severity"]))

        table.resizeColumnsToContents()
        layout.addWidget(table)

    def _create_strings_view(self, layout: QVBoxLayout, data: dict[str, Any]) -> None:
        """Create strings-specific view."""
        # String categories tabs
        strings_tabs = QTabWidget()

        categories = [
            "license_strings",
            "crypto_strings",
            "error_message_strings",
            "debug_strings",
            "suspicious_patterns",
        ]

        for category in categories:
            if category in data:
                strings_widget = QListWidget()
                for string_data in data[category]:
                    if isinstance(string_data, dict):
                        item_text = f"{string_data.get('string', 'N/A')} @ {string_data.get('address', 'N/A')}"
                    else:
                        item_text = str(string_data)
                    strings_widget.addItem(item_text)

                strings_tabs.addTab(strings_widget, category.replace("_", " ").title())

        layout.addWidget(strings_tabs)

    def _create_imports_view(self, layout: QVBoxLayout, data: dict[str, Any]) -> None:
        """Create imports-specific view."""
        splitter = QSplitter()

        # Imports list
        imports_widget = QTreeWidget()
        imports_widget.setHeaderLabels(["Import", "Library", "Category"])

        if "imports" in data:
            for imp in data["imports"]:
                item = QTreeWidgetItem(
                    [
                        imp.get("name", "Unknown"),
                        imp.get("library", "Unknown"),
                        imp.get("category", "Unknown"),
                    ],
                )
                imports_widget.addTopLevelItem(item)

        # API categories
        categories_widget = QTreeWidget()
        categories_widget.setHeaderLabels(["Category", "Count"])

        if "api_categories" in data:
            for category, apis in data["api_categories"].items():
                item = QTreeWidgetItem([category.replace("_", " ").title(), str(len(apis))])
                categories_widget.addTopLevelItem(item)

        splitter.addWidget(imports_widget)
        splitter.addWidget(categories_widget)
        layout.addWidget(splitter)

    def _create_cfg_view(self, layout: QVBoxLayout, data: dict[str, Any]) -> None:
        """Create CFG-specific view."""
        # CFG metrics
        metrics_text = QTextEdit()
        metrics_text.setMaximumHeight(200)
        metrics_text.setReadOnly(True)

        metrics_info = []
        if "functions_analyzed" in data:
            metrics_info.append(f"Functions analyzed: {data['functions_analyzed']}")
        if "complexity_metrics" in data:
            complexity = data["complexity_metrics"]
            metrics_info.extend((
                f"Nodes: {complexity.get('nodes', 0)}",
                f"Edges: {complexity.get('edges', 0)}",
                f"Cyclomatic complexity: {complexity.get('cyclomatic_complexity', 0)}",
            ))
        metrics_text.setPlainText("\n".join(metrics_info))
        layout.addWidget(metrics_text)

        # License patterns
        if "license_patterns" in data:
            patterns_widget = QTableWidget()
            patterns_widget.setColumnCount(3)
            patterns_widget.setHorizontalHeaderLabels(["Type", "Address", "Disassembly"])

            patterns = data["license_patterns"]
            patterns_widget.setRowCount(len(patterns))

            for i, pattern in enumerate(patterns):
                patterns_widget.setItem(i, 0, QTableWidgetItem(pattern.get("type", "Unknown")))
                patterns_widget.setItem(i, 1, QTableWidgetItem(str(pattern.get("op_addr", "Unknown"))))
                patterns_widget.setItem(i, 2, QTableWidgetItem(pattern.get("disasm", "Unknown")))

            layout.addWidget(patterns_widget)

    def _create_ai_view(self, layout: QVBoxLayout, data: dict[str, Any]) -> None:
        """Create AI analysis-specific view."""
        ai_tabs = QTabWidget()

        # License detection
        if "ai_license_detection" in data:
            license_widget = QTextEdit()
            license_widget.setReadOnly(True)
            license_data = data["ai_license_detection"]
            license_text = f"""
Has License Validation: {license_data.get("has_license_validation", False)}
Confidence: {license_data.get("confidence", 0):.2f}
License Complexity: {license_data.get("license_complexity", "Unknown")}
Bypass Difficulty: {license_data.get("bypass_difficulty", "Unknown")}
Validation Methods: {", ".join(license_data.get("validation_methods", []))}
            """
            license_widget.setPlainText(license_text.strip())
            ai_tabs.addTab(license_widget, "License Detection")

        # Vulnerability prediction
        if "ai_vulnerability_prediction" in data:
            vuln_widget = QTreeWidget()
            vuln_widget.setHeaderLabels(["Vulnerability Type", "Probability", "Predicted"])

            vuln_data = data["ai_vulnerability_prediction"]
            if "vulnerability_predictions" in vuln_data:
                for vuln_type, prediction in vuln_data["vulnerability_predictions"].items():
                    item = QTreeWidgetItem(
                        [
                            vuln_type.replace("_", " ").title(),
                            f"{prediction.get('probability', 0):.3f}",
                            str(prediction.get("predicted", False)),
                        ],
                    )
                    vuln_widget.addTopLevelItem(item)

            ai_tabs.addTab(vuln_widget, "Vulnerability Prediction")

        layout.addWidget(ai_tabs)

    def _create_generic_view(self, layout: QVBoxLayout, data: dict[str, Any]) -> None:
        """Create generic JSON view."""
        text_widget = QTextEdit()
        text_widget.setReadOnly(True)
        text_widget.setFont(QFont("Consolas", 9))

        try:
            formatted_json = json.dumps(data, indent=2, default=str)
            text_widget.setPlainText(formatted_json)
        except Exception as e:
            self.logger.exception("Exception in radare2_integration_ui: %s", e)
            text_widget.setPlainText(f"Error formatting results: {e}\n\n{data!s}")

        layout.addWidget(text_widget)

    def _on_component_changed(self, component: str) -> None:
        """Handle component selection change."""
        # Find corresponding tab and activate it
        for i in range(self.results_tabs.count()):
            if self.results_tabs.tabText(i).lower() == component.lower():
                self.results_tabs.setCurrentIndex(i)
                break

    def _export_results(self) -> None:
        """Export results to file."""
        if not self.results_data:
            QMessageBox.information(self, "Export", "No results to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "radare2_analysis_results.json",
            "JSON Files (*.json)",
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.results_data, f, indent=2, default=str)
                QMessageBox.information(self, "Export", f"Results exported to {file_path}")
            except Exception as e:
                self.logger.exception("Exception in radare2_integration_ui: %s", e)
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {e}")


class R2IntegrationWidget(QWidget):
    """Run widget for radare2 integration UI."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the radare2 integration widget with UI components and analysis functionality."""
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.binary_path: str | None = None
        self.current_worker: R2AnalysisWorker | None = None
        self.analysis_config: dict[str, Any] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up main UI."""
        layout = QVBoxLayout(self)

        # Header section
        header_layout = QHBoxLayout()

        header_label = QLabel("Radare2 Advanced Analysis Integration")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        header_layout.addWidget(header_label)

        header_layout.addStretch()

        self.config_button = QPushButton("Configure Analysis")
        self.config_button.clicked.connect(self._configure_analysis)
        header_layout.addWidget(self.config_button)

        layout.addLayout(header_layout)

        # File selection
        file_group = QGroupBox("Binary File Selection")
        file_layout = QHBoxLayout(file_group)

        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("font-weight: bold; padding: 5px;")

        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self._browse_file)

        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_label, 1)
        file_layout.addWidget(self.browse_button)

        layout.addWidget(file_group)

        # Quick analysis buttons
        actions_group = QGroupBox("Quick Analysis")
        actions_layout = QGridLayout(actions_group)

        self.buttons: dict[str, QPushButton] = {}

        button_configs = [
            ("Comprehensive", "comprehensive", "Run complete radare2 analysis"),
            ("Decompilation", "decompilation", "Analyze license functions"),
            ("Vulnerabilities", "vulnerability", "Detect security vulnerabilities"),
            ("Strings", "strings", "Analyze strings and patterns"),
            ("Imports", "imports", "Analyze imports and exports"),
            ("CFG Analysis", "cfg", "Control flow graph analysis"),
            ("AI Analysis", "ai", "AI-enhanced pattern recognition"),
            ("Bypass Generation", "bypass", "Generate license bypasses"),
        ]

        for i, (name, analysis_type, tooltip) in enumerate(button_configs):
            button = QPushButton(name)
            button.setToolTip(tooltip)
            button.clicked.connect(lambda checked, t=analysis_type: self._start_analysis(t))
            button.setEnabled(False)

            row, col = divmod(i, 4)
            actions_layout.addWidget(button, row, col)
            self.buttons[analysis_type] = button

        layout.addWidget(actions_group)

        # Progress and status
        progress_group = QGroupBox("Analysis Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #666;")
        progress_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)

        layout.addWidget(progress_group)

        # Results viewer
        self.results_viewer = R2ResultsViewer()
        layout.addWidget(self.results_viewer)

    def set_binary_path(self, path: str) -> None:
        """Set binary path for analysis."""
        self.binary_path = path
        self.file_label.setText(os.path.basename(path) if path else "No file selected")

        # Enable/disable buttons
        enabled = bool(path and os.path.exists(path))
        for button in self.buttons.values():
            button.setEnabled(enabled)

    def _browse_file(self) -> None:
        """Browse for binary file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "All Files (*)",
        )

        if file_path:
            self.set_binary_path(file_path)

    def _configure_analysis(self) -> None:
        """Open configuration dialog."""
        dialog = R2ConfigurationDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.analysis_config = dialog.get_configuration()
            self.status_label.setText("Configuration updated")

    def _start_analysis(self, analysis_type: str) -> None:
        """Start analysis of specified type."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first")
            return

        if self.current_worker and self.current_worker.isRunning():
            QMessageBox.information(self, "Analysis Running", "An analysis is already in progress")
            return

        # Disable buttons during analysis
        for button in self.buttons.values():
            button.setEnabled(False)

        # Setup progress display
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.status_label.setText(f"Starting {analysis_type} analysis...")

        # Start worker thread
        self.current_worker = R2AnalysisWorker(self.binary_path, analysis_type, self.analysis_config)
        self.current_worker.progress_updated.connect(self.progress_bar.setValue)
        self.current_worker.status_updated.connect(self.status_label.setText)
        self.current_worker.analysis_completed.connect(self._on_analysis_completed)
        self.current_worker.error_occurred.connect(self._on_analysis_error)
        self.current_worker.finished.connect(self._on_analysis_finished)

        self.current_worker.start()

    def _on_analysis_completed(self, results: dict[str, Any]) -> None:
        """Handle completed analysis."""
        self.results_viewer.display_results(results)
        self.status_label.setText("Analysis completed successfully")

    def _on_analysis_error(self, error: str) -> None:
        """Handle analysis error."""
        self.status_label.setText(f"Analysis failed: {error}")
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed:\n{error}")

    def _on_analysis_finished(self) -> None:
        """Handle analysis thread finished."""
        # Re-enable buttons
        for button in self.buttons.values():
            button.setEnabled(True)

        self.progress_bar.setVisible(False)
        self.current_worker = None


def create_radare2_tab(parent: QWidget | None = None) -> QWidget:
    """Create and return the radare2 integration tab widget."""
    return R2IntegrationWidget(parent)


class _MainAppProtocol(Protocol):
    """Protocol for main application object."""

    tab_widget: object
    binary_path: str | None


def integrate_with_main_app(main_app: _MainAppProtocol) -> bool:
    """Integrate radare2 UI with main application."""
    try:
        if hasattr(main_app, "tab_widget") and hasattr(main_app.tab_widget, "addTab"):
            r2_widget = R2IntegrationWidget(None)
            validate_type(main_app.tab_widget, QTabWidget).addTab(r2_widget, "Radare2 Analysis")

            if hasattr(main_app, "binary_path") and main_app.binary_path is not None:
                r2_widget.set_binary_path(main_app.binary_path)

            setattr(main_app, "radare2_widget", r2_widget)

            return True
    except Exception as e:
        logging.getLogger(__name__).exception("Failed to integrate radare2 UI: %s", e)
        return False

    return False


__all__ = [
    "R2AnalysisWorker",
    "R2ConfigurationDialog",
    "R2IntegrationWidget",
    "R2ResultsViewer",
    "create_radare2_tab",
    "integrate_with_main_app",
]
