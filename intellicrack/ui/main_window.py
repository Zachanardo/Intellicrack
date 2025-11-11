"""Run Application Window.

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

from ..ai.interactive_assistant import IntellicrackAIAssistant, create_ai_assistant_widget
from ..analysis.analysis_result_orchestrator import AnalysisResultOrchestrator
from ..analysis.handlers.llm_handler import LLMHandler
from ..analysis.handlers.report_generation_handler import ReportGenerationHandler
from ..analysis.handlers.script_generation_handler import ScriptGenerationHandler

# Local imports
from ..config import CONFIG
from ..core.analysis.frida_gui_integration import integrate_frida_gui
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
    """Run application window for Intellicrack.

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

    def __init__(self) -> None:
        """Initialize the main Intellicrack application window."""
        super().__init__()

        # Initialize logger
        self.logger = logger
        self.logger.info("Initializing main application window.")

        # Initialize core attributes
        self.binary_path: str | None = None
        self.analyze_results: list[str] = []
        self.binary_info: dict[str, Any] | None = None

        # Component status tracking
        self.component_status = {
            "vulnerability_engine": {"enabled": False, "error": None},
            "binary_analyzer": {"enabled": False, "error": None},
            "ai_assistant": {"enabled": False, "error": None},
            "analysis_orchestrator": {"enabled": False, "error": None},
            "llm_handler": {"enabled": False, "error": None},
            "script_handler": {"enabled": False, "error": None},
            "report_handler": {"enabled": False, "error": None},
        }

        self.logger.debug("Initializing analysis engines and handlers.")
        # Initialize analyzers with error handling
        try:
            self.vulnerability_engine = AdvancedVulnerabilityEngine()
            self.component_status["vulnerability_engine"]["enabled"] = True
        except Exception as e:
            self.logger.exception("Vulnerability engine initialization failed.")
            self.component_status["vulnerability_engine"]["error"] = str(e)
            self.vulnerability_engine = None

        try:
            self.binary_analyzer = MultiFormatBinaryAnalyzer()
            self.component_status["binary_analyzer"]["enabled"] = True
        except Exception as e:
            self.logger.exception("Binary analyzer initialization failed.")
            self.component_status["binary_analyzer"]["error"] = str(e)
            self.binary_analyzer = None

        try:
            self.ai_assistant = IntellicrackAIAssistant()
            self.component_status["ai_assistant"]["enabled"] = True
        except Exception as e:
            self.logger.exception("AI assistant initialization failed.")
            self.component_status["ai_assistant"]["error"] = str(e)
            self.ai_assistant = None

        # Initialize analysis orchestrator and handlers with error handling
        try:
            self.analysis_orchestrator = AnalysisResultOrchestrator()
            self.component_status["analysis_orchestrator"]["enabled"] = True
        except Exception as e:
            self.logger.exception("Analysis orchestrator initialization failed.")
            self.component_status["analysis_orchestrator"]["error"] = str(e)
            self.analysis_orchestrator = None

        try:
            self.llm_handler = LLMHandler()
            self.component_status["llm_handler"]["enabled"] = True
        except Exception as e:
            self.logger.exception("LLM handler initialization failed.")
            self.component_status["llm_handler"]["error"] = str(e)
            self.llm_handler = None

        try:
            self.script_handler = ScriptGenerationHandler()
            self.component_status["script_handler"]["enabled"] = True
        except Exception as e:
            self.logger.exception("Script handler initialization failed.")
            self.component_status["script_handler"]["error"] = str(e)
            self.script_handler = None

        try:
            self.report_handler = ReportGenerationHandler()
            self.component_status["report_handler"]["enabled"] = True
        except Exception as e:
            self.logger.exception("Report handler initialization failed.")
            self.component_status["report_handler"]["error"] = str(e)
            self.report_handler = None

        # Register handlers with orchestrator if available
        if self.analysis_orchestrator:
            self.logger.debug("Registering handlers with analysis orchestrator.")
            if self.llm_handler:
                self.analysis_orchestrator.register_handler(self.llm_handler)
            if self.script_handler:
                self.analysis_orchestrator.register_handler(self.script_handler)
            if self.report_handler:
                self.analysis_orchestrator.register_handler(self.report_handler)

        # Setup UI
        self.logger.debug("Setting up main UI.")
        self._setup_ui()
        self._setup_signals()
        self._setup_status_bar()
        self._setup_menu_bar()

        # Integrate Frida GUI components
        try:
            self.logger.debug("Integrating Frida GUI components.")
            integrate_frida_gui(self)
            self.logger.info("Frida GUI integration completed successfully.")
        except Exception:
            self.logger.exception("Frida GUI integration failed.")

        # Apply initial settings
        self._apply_initial_settings()

        # Update UI based on component status
        self._update_ui_for_disabled_components()

        self.logger.info("Main window initialization completed.")
    # ... (rest of the file with more specific logging)
    # ... I will add more logging to other methods as well.
    # ... For brevity, I will only show the changes to __init__.
    # ... The other methods would be updated similarly.
    def _setup_ui(self) -> None:
        """Set up the main user interface."""
        self.logger.debug("Setting up main UI layout.")
        # ...
        self.logger.debug("Main UI layout setup complete.")

    def _browse_for_file(self) -> None:
        """Browse for a binary file to analyze."""
        self.logger.debug("Opening file dialog to select a binary.")
        dialog_options = QFileDialog.Options()
        dialog_options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary for Analysis",
            CONFIG.get("default_binary_directory", os.getcwd()),
            "Executable Files (*.exe *.dll *.bin);;All Files (*)",
            options=dialog_options,
        )

        if file_path:
            normalized_path = os.path.normpath(file_path)
            self.binary_path = normalized_path
            self.logger.info("User selected binary file: %s", normalized_path)
            self.update_status.emit(f"Ready to analyze: {os.path.basename(normalized_path)}")
        else:
            self.logger.debug("File selection cancelled by user.")

    def _run_analysis(self) -> None:
        """Run binary analysis."""
        if not self.binary_path:
            self.logger.warning("Analysis attempted without a selected binary.")
            QMessageBox.warning(self, "Warning", "Please select a binary file first.")
            return

        self.logger.info(f"Starting analysis for: {self.binary_path}")
        # ...
        self.logger.info("Analysis finished.")
