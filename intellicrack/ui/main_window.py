"""Main Application Window.

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

import os
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QAction,
    QApplication,
    QCheckBox,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QIcon,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    Qt,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ..ai.ai_assistant_enhanced import IntellicrackAIAssistant, create_ai_assistant_widget
from ..analysis.analysis_result_orchestrator import AnalysisResultOrchestrator
from ..analysis.handlers.llm_handler import LLMHandler
from ..analysis.handlers.report_generation_handler import ReportGenerationHandler
from ..analysis.handlers.script_generation_handler import ScriptGenerationHandler

# Local imports
from ..config import CONFIG
from ..core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
from ..core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine
from ..utils.logger import get_logger
from ..utils.resource_helper import get_resource_path
from .dialogs.export_dialog import ExportDialog
from .dialogs.program_selector_dialog import show_program_selector
from .dialogs.signature_editor_dialog import SignatureEditorDialog
from .widgets.icp_analysis_widget import ICPAnalysisWidget
from .widgets.unified_protection_widget import UnifiedProtectionWidget

# Configure module logger
logger = get_logger(__name__)


class IntellicrackMainWindow(QMainWindow):
    """Main application window for Intellicrack.

    A comprehensive reverse engineering and security analysis framework.

    This class provides the primary user interface with multiple tabs for different
    analysis capabilities including binary analysis, vulnerability detection,
    memory forensics, network monitoring, and report generation.
    """

    # PyQt signals for thread-safe communication
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    update_progress = pyqtSignal(int)
    clear_output = pyqtSignal()

    def __init__(self):
        """Initialize the main Intellicrack application window."""
        super().__init__()

        # Initialize logger
        self.logger = logger
        self.logger.info("Initializing main application window")

        # Initialize core attributes
        self.binary_path: str | None = None
        self.analyze_results: list[str] = []
        self.binary_info: dict[str, Any] | None = None

        # Initialize analyzers
        self.vulnerability_engine = AdvancedVulnerabilityEngine()
        self.binary_analyzer = MultiFormatBinaryAnalyzer()
        self.ai_assistant = IntellicrackAIAssistant()

        # Initialize analysis orchestrator and handlers
        self.analysis_orchestrator = AnalysisResultOrchestrator()
        self.llm_handler = LLMHandler()
        self.script_handler = ScriptGenerationHandler()
        self.report_handler = ReportGenerationHandler()

        # Register handlers with orchestrator
        self.analysis_orchestrator.register_handler(self.llm_handler)
        self.analysis_orchestrator.register_handler(self.script_handler)
        self.analysis_orchestrator.register_handler(self.report_handler)

        # Setup UI
        self._setup_ui()
        self._setup_signals()
        self._setup_status_bar()
        self._setup_menu_bar()

        # Apply initial settings
        self._apply_initial_settings()

        self.logger.info("Main window initialization completed")

    def _setup_ui(self):
        """Set up the main user interface."""
        self.setWindowTitle("Intellicrack - Advanced Binary Analysis Framework")
        self.setGeometry(100, 100, 1400, 900)

        # Central widget with tab system

        # Initialize UI attributes
        self.analysis_output = None
        self.auto_save_results_cb = None
        self.clear_results_button = None
        self.entropy_analysis_cb = None
        self.export_analysis_cb = None
        self.export_results_button = None
        self.import_analysis_cb = None
        self.info_display = None
        self.results_display = None
        self.verbose_logging_cb = None
        self.vulnerability_scan_cb = None
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Setup individual tabs
        self._setup_dashboard_tab()
        self._setup_analysis_tab()
        self._setup_results_tab()
        self._setup_protection_tab()
        self._setup_ai_assistant_tab()
        self._setup_settings_tab()

    def _setup_dashboard_tab(self):
        """Set up the main dashboard tab."""
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)

        # File selection section
        file_group = QGroupBox("Binary File Selection")
        file_layout = QHBoxLayout(file_group)

        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("font-weight: bold; color: #333;")

        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self._browse_for_file)

        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_path_label, 1)
        file_layout.addWidget(self.browse_button)

        layout.addWidget(file_group)

        # Quick actions section
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QVBoxLayout(actions_group)

        # Action buttons
        button_layout = QHBoxLayout()

        self.analyze_button = QPushButton("Analyze Binary")
        self.analyze_button.clicked.connect(self._run_analysis)
        self.analyze_button.setEnabled(False)

        self.scan_vulnerabilities_button = QPushButton("Scan Vulnerabilities")
        self.scan_vulnerabilities_button.clicked.connect(self._scan_vulnerabilities)
        self.scan_vulnerabilities_button.setEnabled(False)

        self.generate_report_button = QPushButton("Generate Report")
        self.generate_report_button.clicked.connect(self._generate_report)
        self.generate_report_button.setEnabled(False)

        self.protection_analysis_button = QPushButton("Analyze Protection")
        self.protection_analysis_button.clicked.connect(self._analyze_current_protection)
        self.protection_analysis_button.setEnabled(False)

        button_layout.addWidget(self.analyze_button)
        button_layout.addWidget(self.scan_vulnerabilities_button)
        button_layout.addWidget(self.protection_analysis_button)
        button_layout.addWidget(self.generate_report_button)

        actions_layout.addLayout(button_layout)
        layout.addWidget(actions_group)

        # Information display
        info_group = QGroupBox("Binary Information")
        info_layout = QVBoxLayout(info_group)

        self.info_display = QTextEdit()
        self.info_display.setReadOnly(True)
        self.info_display.setMaximumHeight(200)
        info_layout.addWidget(self.info_display)

        layout.addWidget(info_group)
        layout.addStretch()

        self.tab_widget.addTab(dashboard_widget, "Dashboard")

    def _setup_analysis_tab(self):
        """Set up the analysis tab."""
        analysis_widget = QWidget()
        layout = QVBoxLayout(analysis_widget)

        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)

        self.vulnerability_scan_cb = QCheckBox("Vulnerability Scanning")
        self.vulnerability_scan_cb.setChecked(True)

        self.entropy_analysis_cb = QCheckBox("Entropy Analysis")
        self.entropy_analysis_cb.setChecked(True)

        self.import_analysis_cb = QCheckBox("Import Table Analysis")
        self.import_analysis_cb.setChecked(True)

        self.export_analysis_cb = QCheckBox("Export Table Analysis")
        self.export_analysis_cb.setChecked(False)

        options_layout.addWidget(self.vulnerability_scan_cb)
        options_layout.addWidget(self.entropy_analysis_cb)
        options_layout.addWidget(self.import_analysis_cb)
        options_layout.addWidget(self.export_analysis_cb)

        layout.addWidget(options_group)

        # Analysis output
        output_group = QGroupBox("Analysis Output")
        output_layout = QVBoxLayout(output_group)

        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setFont(QFont("Consolas", 9))
        output_layout.addWidget(self.analysis_output)

        layout.addWidget(output_group)

        self.tab_widget.addTab(analysis_widget, "Analysis")

    def _setup_results_tab(self):
        """Set up the results tab."""
        results_widget = QWidget()
        layout = QVBoxLayout(results_widget)

        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setFont(QFont("Consolas", 9))
        layout.addWidget(self.results_display)

        # Action buttons
        button_layout = QHBoxLayout()

        self.clear_results_button = QPushButton("Clear Results")
        self.clear_results_button.clicked.connect(self._clear_results)

        self.export_results_button = QPushButton("Export Results")
        self.export_results_button.clicked.connect(self._export_results)

        button_layout.addWidget(self.clear_results_button)
        button_layout.addWidget(self.export_results_button)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        self.tab_widget.addTab(results_widget, "Results")

    def _setup_protection_tab(self):
        """Set up the protection analysis tab."""
        # Create container widget with vertical splitter
        protection_container = QWidget()
        container_layout = QVBoxLayout(protection_container)

        # Create splitter for two widgets

        splitter = QSplitter(Qt.Vertical)

        # Add unified protection widget
        self.protection_widget = UnifiedProtectionWidget()
        splitter.addWidget(self.protection_widget)

        # Add ICP analysis widget
        self.icp_widget = ICPAnalysisWidget()
        splitter.addWidget(self.icp_widget)

        # Set initial sizes (60% unified, 40% ICP)
        splitter.setSizes([400, 300])

        container_layout.addWidget(splitter)

        # Connect signals
        self.protection_widget.protection_analyzed.connect(self._on_unified_protection_analyzed)
        self.protection_widget.protection_analyzed.connect(self.analysis_orchestrator.on_protection_analyzed)
        self.protection_widget.bypass_requested.connect(self._on_bypass_requested)

        # Connect ICP widget signals
        self.icp_widget.analysis_complete.connect(self._on_icp_analysis_complete)
        self.icp_widget.analysis_complete.connect(self.analysis_orchestrator.on_icp_analysis_complete)
        self.icp_widget.protection_selected.connect(self._on_icp_protection_selected)

        # Connect handler signals
        self.script_handler.script_ready.connect(self._on_script_ready)
        self.report_handler.report_ready.connect(self._on_report_ready)

        self.tab_widget.addTab(protection_container, "Protection Analysis")

    def _setup_ai_assistant_tab(self):
        """Set up the AI assistant tab."""
        # Create the AI assistant widget using the function from ai_assistant_enhanced.py
        ai_widget = create_ai_assistant_widget()

        # Store reference to the AI widget for potential future use
        self.ai_assistant_widget = ai_widget

        # Add the widget to the tab
        self.tab_widget.addTab(ai_widget, "AI Assistant")

    def _setup_settings_tab(self):
        """Set up the settings tab."""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)

        # Analysis settings
        analysis_group = QGroupBox("Analysis Settings")
        analysis_layout = QVBoxLayout(analysis_group)

        self.verbose_logging_cb = QCheckBox("Verbose Logging")
        self.verbose_logging_cb.setChecked(CONFIG.get("verbose_logging", False))

        self.auto_save_results_cb = QCheckBox("Auto-save Results")
        self.auto_save_results_cb.setChecked(CONFIG.get("auto_save_results", True))

        analysis_layout.addWidget(self.verbose_logging_cb)
        analysis_layout.addWidget(self.auto_save_results_cb)

        layout.addWidget(analysis_group)
        layout.addStretch()

        self.tab_widget.addTab(settings_widget, "Settings")

    def _setup_signals(self):
        """Set up signal connections."""
        self.update_output.connect(self._on_update_output)
        self.update_status.connect(self._on_update_status)
        self.update_progress.connect(self._on_update_progress)
        self.clear_output.connect(self._on_clear_output)

    def _setup_status_bar(self):
        """Set up the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setToolTip("Shows progress of current analysis or operation")
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setToolTip("Current application status and messages")
        self.status_bar.showMessage("Intellicrack initialized successfully")

    def _setup_menu_bar(self):
        """Set up the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open Binary...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.setToolTip("Open a binary file for analysis (EXE, DLL, SO, ELF, or other executable formats)")
        open_action.triggered.connect(self._browse_for_file)
        file_menu.addAction(open_action)

        program_selector_action = QAction("Program Selector...", self)
        program_selector_action.setShortcut("Ctrl+Shift+O")
        program_selector_action.setToolTip("Select a running process from the system to attach and analyze")
        program_selector_action.triggered.connect(self._show_program_selector)
        file_menu.addAction(program_selector_action)

        file_menu.addSeparator()

        export_action = QAction("Export Analysis Results...", self)
        export_action.setShortcut("Ctrl+Shift+E")
        export_action.setToolTip("Export current analysis results to various formats (PDF, JSON, XML, or HTML)")
        export_action.triggered.connect(self._export_analysis_results)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setToolTip("Close Intellicrack and save current session state")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Analysis menu
        analysis_menu = menubar.addMenu("Analysis")

        analyze_action = QAction("Analyze Binary", self)
        analyze_action.setShortcut("F5")
        analyze_action.setToolTip("Run comprehensive analysis on the loaded binary including static and dynamic analysis")
        analyze_action.triggered.connect(self._run_analysis)
        analysis_menu.addAction(analyze_action)

        vulnerability_action = QAction("Scan Vulnerabilities", self)
        vulnerability_action.setShortcut("F6")
        vulnerability_action.setToolTip(
            "Scan for security vulnerabilities including buffer overflows, format strings, and common weaknesses"
        )
        vulnerability_action.triggered.connect(self._scan_vulnerabilities)
        analysis_menu.addAction(vulnerability_action)

        analysis_menu.addSeparator()

        protection_action = QAction("Analyze Protection", self)
        protection_action.setShortcut("F7")
        protection_action.setToolTip("Detect and analyze protection mechanisms such as packers, obfuscators, and anti-debugging techniques")
        protection_action.triggered.connect(self._analyze_current_protection)
        analysis_menu.addAction(protection_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        generate_report_action = QAction("Generate Report...", self)
        generate_report_action.setShortcut("Ctrl+R")
        generate_report_action.setToolTip("Generate a comprehensive analysis report with findings, vulnerabilities, and recommendations")
        generate_report_action.triggered.connect(self._generate_report)
        tools_menu.addAction(generate_report_action)

        generate_script_action = QAction("Generate Bypass Script...", self)
        generate_script_action.setShortcut("Ctrl+B")
        generate_script_action.setToolTip("Create automated bypass scripts for detected protection mechanisms using AI assistance")
        generate_script_action.triggered.connect(self._generate_bypass_script_menu)
        tools_menu.addAction(generate_script_action)

        tools_menu.addSeparator()

        signature_editor_action = QAction("ICP Signature Editor...", self)
        signature_editor_action.setShortcut("Ctrl+E")
        signature_editor_action.setToolTip("Edit and manage Intellicrack Protection signatures for enhanced detection capabilities")
        signature_editor_action.triggered.connect(self._open_signature_editor)
        tools_menu.addAction(signature_editor_action)

        export_results_action = QAction("Export Results...", self)
        export_results_action.setShortcut("Ctrl+Shift+X")
        export_results_action.setToolTip("Export analysis results and findings to external formats for documentation or sharing")
        export_results_action.triggered.connect(self._export_analysis_results)
        tools_menu.addAction(export_results_action)

    def _apply_initial_settings(self):
        """Apply initial application settings."""
        # Set window icon if available
        icon_path = get_resource_path("assets/icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

    # Slot methods for signal handling
    def _on_update_output(self, message: str):
        """Handle output updates."""
        self.analysis_output.append(message)
        self.analysis_output.ensureCursorVisible()

    def _on_update_status(self, message: str):
        """Handle status updates."""
        self.status_bar.showMessage(message)

    def _on_update_progress(self, value: int):
        """Handle progress updates."""
        self.progress_bar.setVisible(value > 0)
        self.progress_bar.setValue(value)
        if value >= 100:
            self.progress_bar.setVisible(False)

    def _on_clear_output(self):
        """Handle clear output requests."""
        self.analysis_output.clear()
        self.results_display.clear()

    # Action methods
    def _browse_for_file(self):
        """Browse for a binary file to analyze."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "All Files (*)",
        )

        if file_path:
            self.binary_path = file_path
            self.file_path_label.setText(os.path.basename(file_path))
            self.file_path_label.setToolTip(file_path)

            # Load binary into app context for proper state management
            try:
                from ..core.app_context import get_app_context

                app_context = get_app_context()
                if app_context.load_binary(file_path):
                    self.logger.info("Binary loaded into app context: %s", file_path)
                else:
                    self.logger.warning("Failed to load binary into app context: %s", file_path)
            except Exception as e:
                self.logger.error("Error loading binary into app context: %s", e)

            # Enable analysis buttons
            self.analyze_button.setEnabled(True)
            self.scan_vulnerabilities_button.setEnabled(True)
            self.protection_analysis_button.setEnabled(True)

            self.update_status.emit(f"Selected: {os.path.basename(file_path)}")
            self.logger.info("Selected binary file: %s", file_path)

            # Auto-trigger ICP analysis when file is opened
            self._auto_trigger_icp_analysis(file_path)

    def _auto_trigger_icp_analysis(self, file_path: str):
        """Auto-trigger ICP analysis when a file is opened."""
        try:
            self.logger.info(f"Auto-triggering ICP analysis for: {os.path.basename(file_path)}")
            self.update_status.emit(f"Analyzing protection for {os.path.basename(file_path)}...")

            # Trigger ICP analysis
            self.icp_widget.analyze_file(file_path)

            # Switch to Protection Analysis tab for immediate feedback
            self.tab_widget.setCurrentIndex(3)  # Protection Analysis tab

        except Exception as e:
            self.logger.error(f"Auto-trigger ICP analysis error: {e}")
            # Don't show a popup for auto-trigger failures, just log

    def _show_program_selector(self):
        """Show the program selector dialog."""
        try:
            self.logger.info("Opening Program Selector")

            # Show the program selector dialog
            result = show_program_selector(self)

            if result:
                program_info = result["program_info"]
                installation_folder = result["installation_folder"]
                licensing_files = result["licensing_files"]
                auto_analyze = result["auto_analyze"]

                self.logger.info(f"Selected program: {program_info['display_name']}")

                # Update UI with selected program
                if program_info.get("executable_paths"):
                    # Use the first executable path as the binary to analyze
                    selected_executable = program_info["executable_paths"][0]
                    self.binary_path = selected_executable
                    self.file_path_label.setText(f"{program_info['display_name']} ({os.path.basename(selected_executable)})")
                    self.file_path_label.setToolTip(
                        f"Program: {program_info['display_name']}\nPath: {selected_executable}\nInstall Location: {installation_folder}"
                    )

                    # Load binary into app context for proper state management
                    try:
                        from ..core.app_context import get_app_context

                        app_context = get_app_context()
                        metadata = {
                            "program_name": program_info["display_name"],
                            "installation_folder": installation_folder,
                            "discovery_method": program_info.get("discovery_method", "program_selector"),
                            "licensing_files_count": len(licensing_files),
                        }
                        if app_context.load_binary(selected_executable, metadata):
                            self.logger.info("Program binary loaded into app context: %s", selected_executable)
                        else:
                            self.logger.warning("Failed to load program binary into app context: %s", selected_executable)
                    except Exception as e:
                        self.logger.error("Error loading program binary into app context: %s", e)

                    # Enable analysis buttons
                    self.analyze_button.setEnabled(True)
                    self.scan_vulnerabilities_button.setEnabled(True)
                    self.protection_analysis_button.setEnabled(True)
                    self.generate_report_button.setEnabled(True)

                    # Display program information
                    program_details = f"""Selected Program Information:
Name: {program_info["display_name"]}
Version: {program_info.get("version", "Unknown")}
Publisher: {program_info.get("publisher", "Unknown")}
Architecture: {program_info.get("architecture", "Unknown")}
Install Location: {installation_folder}
Executable: {selected_executable}
Discovery Method: {program_info.get("discovery_method", "Unknown")}
Confidence Score: {program_info.get("confidence_score", 0):.2f}
Analysis Priority: {program_info.get("analysis_priority", 0)}

Licensing Files Found: {len(licensing_files)}"""

                    if licensing_files:
                        program_details += "\nHigh-Priority Licensing Files:"
                        for lic_file in licensing_files[:5]:  # Show top 5
                            program_details += f"\n- {os.path.basename(lic_file['path'])} (Priority: {lic_file['priority']})"

                    self.info_display.setPlainText(program_details)

                    status_msg = f"Selected: {program_info['display_name']} from {program_info.get('discovery_method', 'unknown')}"
                    self.update_status.emit(status_msg)

                    # Auto-trigger ICP analysis for selected program
                    self._auto_trigger_icp_analysis(selected_executable)

                    # Auto-analyze if requested
                    if auto_analyze and licensing_files:
                        QMessageBox.information(
                            self,
                            "Auto-Analysis",
                            f"Starting automatic analysis of {program_info['display_name']} and {len(licensing_files)} licensing files.",
                        )
                        self._run_analysis()
                else:
                    QMessageBox.warning(
                        self,
                        "No Executable Found",
                        f"No executable files found for {program_info['display_name']}. Please select a different program.",
                    )

        except Exception as e:
            self.logger.error(f"Error in Program Selector: {e}")
            QMessageBox.critical(
                self,
                "Program Selector Error",
                f"An error occurred while opening the Program Selector:\n{e!s}",
            )

    def _run_analysis(self):
        """Run binary analysis."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please select a binary file first.")
            return

        self.update_status.emit("Running binary analysis...")
        self.update_progress.emit(10)

        try:
            # Run multi-format analysis
            self.update_output.emit("=== BINARY ANALYSIS ===")
            self.update_output.emit(f"Analyzing: {self.binary_path}")

            # Identify format
            binary_format = self.binary_analyzer.identify_format(self.binary_path)
            self.update_output.emit(f"Detected format: {binary_format}")

            self.update_progress.emit(50)

            # Run analysis
            analysis_results = self.binary_analyzer.analyze_binary(self.binary_path)

            if "error" in analysis_results:
                self.update_output.emit(f"Error: {analysis_results['error']}")
            else:
                self._display_analysis_results(analysis_results)

                # Run AI-enhanced complex analysis
                self.update_progress.emit(70)
                self.update_output.emit("\n=== AI-ENHANCED COMPLEX ANALYSIS ===")
                self.update_status.emit("Running AI-enhanced analysis...")

                try:
                    # Prepare ML results if available
                    ml_results = {
                        "confidence": 0.85,
                        "predictions": [],
                    }

                    # Extract protection detections if available
                    if hasattr(self, "protection_results") and self.protection_results:
                        ml_results["predictions"] = self.protection_results

                    # Run AI complex analysis
                    ai_analysis = self.ai_assistant.analyze_binary_complex(
                        self.binary_path,
                        ml_results,
                    )

                    # Display AI analysis results
                    if ai_analysis and not ai_analysis.get("error"):
                        self.update_output.emit(f"AI Confidence: {ai_analysis.get('confidence', 0.0):.2%}")

                        if ai_analysis.get("findings"):
                            self.update_output.emit("\nFindings:")
                            for finding in ai_analysis["findings"]:
                                self.update_output.emit(f"  • {finding}")

                        if ai_analysis.get("recommendations"):
                            self.update_output.emit("\nRecommendations:")
                            for rec in ai_analysis["recommendations"]:
                                self.update_output.emit(f"  → {rec}")

                        if ai_analysis.get("ml_integration"):
                            ml_info = ai_analysis["ml_integration"]
                            self.update_output.emit(f"\nML Integration Confidence: {ml_info.get('ml_confidence', 0.0):.2%}")

                except Exception as e:
                    self.logger.warning(f"AI complex analysis failed: {e!s}")
                    self.update_output.emit(f"AI analysis unavailable: {e!s}")

                self.generate_report_button.setEnabled(True)

            self.update_progress.emit(100)
            self.update_status.emit("Analysis completed")

        except (OSError, ValueError, RuntimeError) as e:
            self.update_output.emit(f"Analysis error: {e!s}")
            self.update_status.emit("Analysis failed")
            self.logger.error(f"Analysis error: {e!s}")

    def _scan_vulnerabilities(self):
        """Run vulnerability scanning."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please select a binary file first.")
            return

        self.update_status.emit("Scanning for vulnerabilities...")
        self.update_progress.emit(10)

        try:
            self.update_output.emit("=== VULNERABILITY SCAN ===")
            self.update_output.emit(f"Scanning: {self.binary_path}")

            self.update_progress.emit(30)

            # Run vulnerability scan
            vulnerabilities = self.vulnerability_engine.scan_binary(self.binary_path)

            self.update_progress.emit(80)

            if vulnerabilities:
                self.update_output.emit(f"Found {len(vulnerabilities)} vulnerabilities:")
                for _vuln in vulnerabilities:
                    self.update_output.emit(f"  - {_vuln.get('type', 'Unknown')}: {_vuln.get('risk', 'Unknown risk')}")
            else:
                self.update_output.emit("No vulnerabilities detected.")

            self.update_progress.emit(100)
            self.update_status.emit("Vulnerability scan completed")

        except (OSError, ValueError, RuntimeError) as e:
            self.update_output.emit(f"Vulnerability scan error: {e!s}")
            self.update_status.emit("Vulnerability scan failed")
            self.logger.error(f"Vulnerability scan error: {e!s}")

    def _generate_report(self):
        """Generate analysis report."""
        self.update_status.emit("Generating report...")
        self.update_output.emit("=== REPORT GENERATION ===")
        self.update_output.emit("Report generation not yet implemented in this refactored version.")
        self.update_status.emit("Ready")

    def _display_analysis_results(self, results: dict[str, Any]):
        """Display analysis results in the results tab."""
        self.results_display.clear()

        # Format results for display
        result_text = "=== ANALYSIS RESULTS ===\\n"
        result_text += f"Format: {results.get('format', 'Unknown')}\\n"

        if "machine" in results:
            result_text += f"Machine: {results['machine']}\\n"

        if "timestamp" in results:
            result_text += f"Timestamp: {results['timestamp']}\\n"

        if "sections" in results:
            result_text += f"\\nSections ({len(results['sections'])}):\\n"
            for _section in results["sections"][:10]:  # Limit to first 10
                result_text += f"  {_section.get('name', 'Unknown')}: {_section.get('virtual_size', 'N/A')} bytes\\n"

        if "imports" in results:
            result_text += f"\\nImports ({len(results['imports'])}):\\n"
            for _imp in results["imports"][:5]:  # Limit to first 5
                result_text += f"  {_imp.get('dll', 'Unknown')}: {len(_imp.get('functions', []))} functions\\n"

        self.results_display.setPlainText(result_text)

        # Switch to results tab
        self.tab_widget.setCurrentIndex(2)

    def _clear_results(self):
        """Clear all results."""
        self.results_display.clear()
        self.analysis_output.clear()
        self.analyze_results.clear()
        self.update_status.emit("Results cleared")

    def _export_results(self):
        """Export results to file."""
        if not self.results_display.toPlainText():
            QMessageBox.information(self, "Information", "No results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "analysis_results.txt",
            "Text Files (*.txt);;All Files (*)",
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.results_display.toPlainText())

                QMessageBox.information(self, "Success", f"Results exported to {file_path}")
                self.update_status.emit(f"Results exported to {os.path.basename(file_path)}")

            except (OSError, ValueError, RuntimeError) as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {e!s}")
                self.logger.error(f"Export error: {e!s}")

    def _analyze_protection(self, file_path: str):
        """Analyze protection for the given file."""
        try:
            # Update status
            self.update_status.emit(f"Analyzing protection for {os.path.basename(file_path)}...")

            # Use unified protection widget
            self.protection_widget.analyze_file(file_path)

            # Also trigger ICP analysis
            self.icp_widget.analyze_file(file_path)

            # Switch to protection tab
            self.tab_widget.setCurrentIndex(3)  # Protection Analysis tab

        except Exception as e:
            self.logger.error(f"Protection analysis error: {e}")
            QMessageBox.critical(self, "Error", f"Protection analysis failed: {e!s}")

    def _generate_bypass_script(self, file_path: str, protection_type: str):
        """Generate bypass script for the detected protection."""
        try:
            from ..ai.protection_aware_script_gen import ProtectionAwareScriptGenerator

            generator = ProtectionAwareScriptGenerator()
            result = generator.generate_bypass_script(file_path, "frida")

            if result["success"]:
                # Show script in a dialog or new tab
                msg = f"Generated {protection_type} bypass script:\n\n"
                msg += f"Approach: {result['approach']}\n"
                msg += f"Confidence: {result['confidence']:.0%}\n"
                msg += f"Difficulty: {result['difficulty']}\n\n"
                msg += "Script saved to clipboard."

                # Copy script to clipboard

                clipboard = QApplication.clipboard()
                clipboard.setText(result["script"])

                QMessageBox.information(self, "Bypass Script Generated", msg)
            else:
                QMessageBox.warning(
                    self,
                    "Script Generation Failed",
                    f"Failed to generate bypass script: {result.get('error', 'Unknown error')}",
                )

        except Exception as e:
            self.logger.error(f"Script generation error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to generate bypass script: {e!s}")

    def _analyze_current_protection(self):
        """Analyze protection for the currently selected binary."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please select a binary file first.")
            return

        self._analyze_protection(self.binary_path)

    def _on_unified_protection_analyzed(self, result):
        """Handle unified protection analysis completion."""
        self.logger.info(f"Protection analysis complete: {len(result.protections)} protections found")

        # Update results display
        result_text = "\n=== PROTECTION ANALYSIS COMPLETE ===\n"
        result_text += f"File: {os.path.basename(result.file_path)}\n"
        result_text += f"Type: {result.file_type}\n"
        result_text += f"Protections Found: {len(result.protections)}\n"
        result_text += f"Confidence: {result.confidence_score:.0f}%\n"

        if result.protections:
            result_text += "\nDetected Protections:\n"
            for protection in result.protections:
                result_text += f"  • {protection['name']} ({protection['type']}) - {protection.get('confidence', 0):.0f}%\n"

        self.results_display.append(result_text)

        # Update status
        if result.protections:
            self.update_status.emit(f"Analysis complete: {len(result.protections)} protection(s) detected")
        else:
            self.update_status.emit("Analysis complete: No protections detected")

    def _on_bypass_requested(self, file_path: str, protection_data: dict[str, Any]):
        """Handle bypass script generation request."""
        self.logger.info(f"Bypass requested for: {protection_data['name']}")
        self._generate_bypass_script(file_path, protection_data["type"])

    def _on_script_ready(self, script_data: dict):
        """Handle script generation completion."""
        self.logger.info(f"Script ready: {script_data.get('type', 'Unknown')} with {script_data.get('confidence', 0):.0%} confidence")
        # The script handler will show its own dialog

    def _on_report_ready(self, report_data: dict):
        """Handle report generation completion."""
        self.logger.info(f"Report saved to: {report_data.get('path', 'Unknown')}")
        self.update_status.emit(f"Report saved: {os.path.basename(report_data.get('path', ''))}")

    def _on_icp_analysis_complete(self, result):
        """Handle ICP analysis completion."""
        self.logger.info(f"ICP analysis complete: {len(result.all_detections)} detections")

        # Update results display
        result_text = "\n=== ICP ENGINE ANALYSIS ===\n"
        result_text += f"File Type: {result.file_infos[0].filetype if result.file_infos else 'Unknown'}\n"
        result_text += f"Packed: {'Yes' if result.is_packed else 'No'}\n"
        result_text += f"Protected: {'Yes' if result.is_protected else 'No'}\n"

        if result.all_detections:
            result_text += "\nDetections:\n"
            for detection in result.all_detections:
                result_text += f"  • {detection.name} [{detection.type}]\n"
                if detection.version:
                    result_text += f"    Version: {detection.version}\n"

        self.results_display.append(result_text)

        # Trigger ICP analysis when unified analysis completes
        if hasattr(self, "binary_path") and self.binary_path:
            self.icp_widget.analyze_file(self.binary_path)

    def _on_icp_protection_selected(self, detection):
        """Handle ICP protection selection."""
        self.logger.info(f"ICP protection selected: {detection.name}")

        # Could trigger additional analysis or bypass generation
        # For now, just log the selection

    def _generate_report(self):
        """Generate comprehensive analysis report."""
        import datetime
        import json
        from pathlib import Path

        self.update_status.emit("Generating report...")
        self.update_output.emit("=== REPORT GENERATION ===")

        try:
            # Collect all analysis data
            report_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "binary_path": self.binary_path or "No file loaded",
                "binary_info": {},
                "analysis_results": {},
                "vulnerabilities": [],
                "protections": [],
                "bypass_techniques": [],
                "recommendations": [],
            }

            # Add binary info if available
            if self.binary_info:
                report_data["binary_info"] = {
                    "name": self.binary_info.get("name", "Unknown"),
                    "size": self.binary_info.get("size", 0),
                    "type": self.binary_info.get("type", "Unknown"),
                    "architecture": self.binary_info.get("arch", "Unknown"),
                    "platform": self.binary_info.get("platform", "Unknown"),
                    "entry_point": hex(self.binary_info.get("entry_point", 0)),
                    "sections": self.binary_info.get("sections", []),
                    "imports": self.binary_info.get("imports", [])[:10],  # Top 10 imports
                    "exports": self.binary_info.get("exports", [])[:10],  # Top 10 exports
                }

            # Add analysis results
            if self.analyze_results:
                report_data["analysis_results"] = {
                    "protections_found": self.analyze_results.get("protections", []),
                    "packers_detected": self.analyze_results.get("packers", []),
                    "anti_debug_techniques": self.analyze_results.get("anti_debug", []),
                    "obfuscation_methods": self.analyze_results.get("obfuscation", []),
                    "cryptographic_usage": self.analyze_results.get("crypto", []),
                    "license_checks": self.analyze_results.get("license_checks", []),
                    "network_activity": self.analyze_results.get("network", []),
                    "file_operations": self.analyze_results.get("file_ops", []),
                    "registry_operations": self.analyze_results.get("registry_ops", []),
                }

            # Add vulnerability scan results if available
            if hasattr(self, "vulnerability_results") and self.vulnerability_results:
                for vuln in self.vulnerability_results:
                    report_data["vulnerabilities"].append(
                        {
                            "type": vuln.get("type", "Unknown"),
                            "severity": vuln.get("severity", "Unknown"),
                            "description": vuln.get("description", ""),
                            "location": vuln.get("location", ""),
                            "exploit_difficulty": vuln.get("exploit_difficulty", "Unknown"),
                            "mitigation": vuln.get("mitigation", ""),
                        }
                    )

            # Add protection analysis results
            if hasattr(self.protection_widget, "analysis_result") and self.protection_widget.analysis_result:
                prot_result = self.protection_widget.analysis_result
                for protection in prot_result.get("protections", []):
                    report_data["protections"].append(
                        {
                            "name": protection.get("name", "Unknown"),
                            "type": protection.get("type", "Unknown"),
                            "strength": protection.get("strength", "Unknown"),
                            "details": protection.get("details", {}),
                            "bypass_feasibility": protection.get("bypass_feasibility", "Unknown"),
                        }
                    )

                # Add bypass techniques
                for bypass in prot_result.get("bypasses", []):
                    report_data["bypass_techniques"].append(
                        {
                            "target_protection": bypass.get("target", "Unknown"),
                            "technique": bypass.get("technique", "Unknown"),
                            "success_rate": bypass.get("success_rate", "Unknown"),
                            "implementation": bypass.get("implementation", ""),
                            "requirements": bypass.get("requirements", []),
                        }
                    )

            # Generate recommendations based on findings
            if report_data["vulnerabilities"]:
                critical_vulns = [v for v in report_data["vulnerabilities"] if v["severity"] == "Critical"]
                high_vulns = [v for v in report_data["vulnerabilities"] if v["severity"] == "High"]

                if critical_vulns:
                    report_data["recommendations"].append(
                        {
                            "priority": "Critical",
                            "category": "Security",
                            "recommendation": f"Address {len(critical_vulns)} critical vulnerabilities immediately",
                            "details": "Critical vulnerabilities pose immediate risk and should be patched urgently",
                        }
                    )

                if high_vulns:
                    report_data["recommendations"].append(
                        {
                            "priority": "High",
                            "category": "Security",
                            "recommendation": f"Fix {len(high_vulns)} high-severity vulnerabilities",
                            "details": "High severity issues should be addressed in the next update cycle",
                        }
                    )

            if report_data["protections"]:
                weak_protections = [p for p in report_data["protections"] if p["strength"] in ["Weak", "Very Weak"]]
                if weak_protections:
                    report_data["recommendations"].append(
                        {
                            "priority": "Medium",
                            "category": "Protection",
                            "recommendation": f"Strengthen {len(weak_protections)} weak protection mechanisms",
                            "details": "Consider implementing stronger protection techniques or layered defenses",
                        }
                    )

            # Generate report formats
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"intellicrack_report_{timestamp}"

            # Generate JSON report
            json_report_path = (
                Path(self.binary_path).parent / f"{base_filename}.json" if self.binary_path else Path(f"{base_filename}.json")
            )
            with open(json_report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)

            # Generate HTML report
            html_report_path = (
                Path(self.binary_path).parent / f"{base_filename}.html" if self.binary_path else Path(f"{base_filename}.html")
            )
            html_content = self._generate_html_report(report_data)
            with open(html_report_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            # Generate markdown report
            md_report_path = Path(self.binary_path).parent / f"{base_filename}.md" if self.binary_path else Path(f"{base_filename}.md")
            md_content = self._generate_markdown_report(report_data)
            with open(md_report_path, "w", encoding="utf-8") as f:
                f.write(md_content)

            # Display summary in UI
            self.update_output.emit("Report generated successfully!")
            self.update_output.emit(f"  - JSON: {json_report_path}")
            self.update_output.emit(f"  - HTML: {html_report_path}")
            self.update_output.emit(f"  - Markdown: {md_report_path}")
            self.update_output.emit("")
            self.update_output.emit("=== REPORT SUMMARY ===")
            self.update_output.emit(f"Binary: {report_data['binary_path']}")
            self.update_output.emit(f"Timestamp: {report_data['timestamp']}")
            self.update_output.emit(f"Vulnerabilities Found: {len(report_data['vulnerabilities'])}")
            self.update_output.emit(f"Protections Detected: {len(report_data['protections'])}")
            self.update_output.emit(f"Bypass Techniques: {len(report_data['bypass_techniques'])}")
            self.update_output.emit(f"Recommendations: {len(report_data['recommendations'])}")

            self.update_status.emit("Report generation complete")

        except Exception as e:
            self.update_output.emit(f"Report generation error: {e!s}")
            self.update_status.emit("Report generation failed")
            self.logger.error(f"Report generation error: {e!s}")

    def _generate_html_report(self, report_data: dict) -> str:
        """Generate HTML formatted report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intellicrack Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; border-bottom: 1px solid #ecf0f1; padding-bottom: 5px; }}
        h3 {{ color: #7f8c8d; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }}
        .info-card {{ background: #ecf0f1; padding: 15px; border-radius: 5px; }}
        .info-card h4 {{ margin: 0 0 10px 0; color: #2c3e50; }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #e67e22; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #95a5a6; }}
        .protection-strong {{ color: #27ae60; font-weight: bold; }}
        .protection-medium {{ color: #f39c12; }}
        .protection-weak {{ color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #3498db; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ecf0f1; }}
        tr:hover {{ background: #f8f9fa; }}
        .recommendation {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }}
        .timestamp {{ color: #95a5a6; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Intellicrack Analysis Report</h1>
        <p class="timestamp">Generated: {report_data["timestamp"]}</p>

        <h2>Binary Information</h2>
        <div class="info-grid">
            <div class="info-card">
                <h4>File Path</h4>
                <p>{report_data["binary_path"]}</p>
            </div>
            <div class="info-card">
                <h4>Architecture</h4>
                <p>{report_data["binary_info"].get("architecture", "Unknown")}</p>
            </div>
            <div class="info-card">
                <h4>Platform</h4>
                <p>{report_data["binary_info"].get("platform", "Unknown")}</p>
            </div>
            <div class="info-card">
                <h4>Entry Point</h4>
                <p>{report_data["binary_info"].get("entry_point", "Unknown")}</p>
            </div>
        </div>

        <h2>Vulnerabilities ({len(report_data["vulnerabilities"])})</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Location</th>
            </tr>
            {"".join([f'<tr><td>{v["type"]}</td><td class="severity-{v["severity"].lower()}">{v["severity"]}</td><td>{v["description"]}</td><td>{v["location"]}</td></tr>' for v in report_data["vulnerabilities"]])}
        </table>

        <h2>Protection Mechanisms ({len(report_data["protections"])})</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Strength</th>
                <th>Bypass Feasibility</th>
            </tr>
            {"".join([f'<tr><td>{p["name"]}</td><td>{p["type"]}</td><td class="protection-{p["strength"].lower()}">{p["strength"]}</td><td>{p["bypass_feasibility"]}</td></tr>' for p in report_data["protections"]])}
        </table>

        <h2>Recommendations</h2>
        {"".join([f'<div class="recommendation"><strong>[{r["priority"]}]</strong> {r["recommendation"]}<br><small>{r["details"]}</small></div>' for r in report_data["recommendations"]])}
    </div>
</body>
</html>"""
        return html

    def _generate_markdown_report(self, report_data: dict) -> str:
        """Generate Markdown formatted report."""
        md = f"""# Intellicrack Analysis Report

**Generated:** {report_data["timestamp"]}

## Binary Information

- **File Path:** {report_data["binary_path"]}
- **Architecture:** {report_data["binary_info"].get("architecture", "Unknown")}
- **Platform:** {report_data["binary_info"].get("platform", "Unknown")}
- **Entry Point:** {report_data["binary_info"].get("entry_point", "Unknown")}

## Analysis Results

### Protections Found
{chr(10).join(["- " + p for p in report_data["analysis_results"].get("protections_found", [])])}

### Packers Detected
{chr(10).join(["- " + p for p in report_data["analysis_results"].get("packers_detected", [])])}

### Anti-Debug Techniques
{chr(10).join(["- " + t for t in report_data["analysis_results"].get("anti_debug_techniques", [])])}

## Vulnerabilities ({len(report_data["vulnerabilities"])})

| Type | Severity | Description | Location |
|------|----------|-------------|----------|
{chr(10).join([f"| {v['type']} | **{v['severity']}** | {v['description']} | {v['location']} |" for v in report_data["vulnerabilities"]])}

## Protection Mechanisms ({len(report_data["protections"])})

| Name | Type | Strength | Bypass Feasibility |
|------|------|----------|-------------------|
{chr(10).join([f"| {p['name']} | {p['type']} | **{p['strength']}** | {p['bypass_feasibility']} |" for p in report_data["protections"]])}

## Bypass Techniques ({len(report_data["bypass_techniques"])})

{chr(10).join([f"### {b['technique']}\n- **Target:** {b['target_protection']}\n- **Success Rate:** {b['success_rate']}\n- **Requirements:** {', '.join(b['requirements'])}\n" for b in report_data["bypass_techniques"]])}

## Recommendations

{chr(10).join([f"### [{r['priority']}] {r['recommendation']}\n{r['details']}\n" for r in report_data["recommendations"]])}

---
*Report generated by Intellicrack - Advanced Binary Analysis Platform*
"""
        return md

    def _generate_bypass_script_menu(self):
        """Generate bypass script from menu."""
        if not self.script_handler.current_result:
            QMessageBox.warning(
                self,
                "No Analysis Available",
                "Please perform a protection analysis first before generating scripts.",
            )
            return

        # Use the script handler to generate script
        self.script_handler.generate_script("frida", self)

    def _open_signature_editor(self):
        """Open the ICP signature editor dialog."""
        try:
            editor_dialog = SignatureEditorDialog(self)
            editor_dialog.exec()
        except Exception as e:
            QMessageBox.critical(
                self,
                "Signature Editor Error",
                f"Failed to open signature editor: {e!s}",
            )
            self.logger.error(f"Failed to open signature editor: {e}")

    def _export_analysis_results(self):
        """Export analysis results to various formats."""
        try:
            # Get current analysis results
            analysis_results = None

            # Try to get results from the orchestrator
            if hasattr(self, "analysis_orchestrator") and self.analysis_orchestrator:
                results = self.analysis_orchestrator.get_current_results()
                if results:
                    analysis_results = {
                        "file_info": getattr(results, "file_info", {}),
                        "icp_analysis": getattr(results, "icp_analysis", None),
                        "protections": getattr(results, "protections", []),
                        "file_type": getattr(results, "file_type", "Unknown"),
                        "architecture": getattr(results, "architecture", "Unknown"),
                        "is_protected": getattr(results, "is_protected", False),
                    }

            # Open export dialog
            export_dialog = ExportDialog(analysis_results, self)
            export_dialog.exec()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to open export dialog: {e!s}",
            )
            self.logger.error(f"Failed to open export dialog: {e}")


# Export the main window class
__all__ = ["IntellicrackMainWindow"]
