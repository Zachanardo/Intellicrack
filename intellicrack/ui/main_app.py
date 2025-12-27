"""Intellicrack Main Application Module.

This module provides the main graphical user interface for the Intellicrack application,
a comprehensive binary analysis and security research toolkit. The application integrates
multiple analysis engines, AI-powered assistance, and specialized tools for reverse
engineering, vulnerability research, and security testing.

Main Classes:
    IntellicrackApp: Main application window inheriting from QMainWindow, orchestrating
                    all UI components, tabs, and analysis functionality.

Key Features:
    - Multi-tab interface with specialized analysis tools
    - AI-powered assistant for intelligent code analysis and guidance
    - Binary analysis engines (static, dynamic, symbolic execution)
    - Network protocol analysis and traffic interception
    - Exploitation framework with payload generation and testing
    - Plugin system for extensibility
    - Comprehensive logging and reporting capabilities

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

import contextlib
import logging
import os
import traceback
from collections.abc import Callable, Sized
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from intellicrack.ai.model_manager_module import ModelManager
from intellicrack.core.analysis.automated_patch_agent import run_automated_patch_agent
from intellicrack.core.analysis.concolic_executor import run_concolic_execution
from intellicrack.core.analysis.dynamic_instrumentation import run_dynamic_instrumentation
from intellicrack.core.analysis.frida_analyzer import run_frida_analysis
from intellicrack.core.analysis.ghidra_analyzer import run_advanced_ghidra_analysis
from intellicrack.core.analysis.incremental_analyzer import run_incremental_analysis
from intellicrack.core.analysis.multi_format_analyzer import run_multi_format_analysis
from intellicrack.core.analysis.protection_scanner import run_enhanced_protection_scan
from intellicrack.core.analysis.rop_generator import ROPChainGenerator, run_rop_chain_generator
from intellicrack.core.analysis.taint_analyzer import TaintAnalysisEngine, run_taint_analysis
from intellicrack.core.app_context import get_app_context
from intellicrack.core.config_manager import get_config
from intellicrack.core.network.cloud_license_hooker import run_cloud_license_hooker
from intellicrack.core.network.protocol_tool import launch_protocol_tool, update_protocol_tool_description
from intellicrack.core.patching.memory_patcher import setup_memory_patching
from intellicrack.core.processing.gpu_accelerator import GPUAccelerator
from intellicrack.core.processing.memory_loader import MemoryOptimizedBinaryLoader, run_memory_optimized_analysis
from intellicrack.core.processing.parallel_processing_manager import ParallelProcessingManager
from intellicrack.core.reporting.pdf_generator import PDFReportGenerator
from intellicrack.core.reporting.report_generator import generate_report, view_report
from intellicrack.core.task_manager import get_task_manager
from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QIcon,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    Qt,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.hexview.integration import TOOL_REGISTRY
from intellicrack.plugins.custom_modules.license_server_emulator import run_network_license_emulator
from intellicrack.plugins.plugin_system import run_frida_plugin_from_file, run_ghidra_plugin_from_file
from intellicrack.ui.cfg_explorer_inner import CfgExplorerInner
from intellicrack.ui.dashboard_manager import DashboardManager
from intellicrack.ui.distributed_processing import DistributedProcessing
from intellicrack.ui.gpu_analysis import GpuAnalysis
from intellicrack.ui.icon_manager import IconManager
from intellicrack.ui.symbolic_execution import SymbolicExecution
from intellicrack.ui.tabs.ai_assistant_tab import AIAssistantTab
from intellicrack.ui.tabs.analysis_tab import AnalysisTab
from intellicrack.ui.tabs.dashboard_tab import DashboardTab
from intellicrack.ui.tabs.exploitation_tab import ExploitationTab
from intellicrack.ui.tabs.settings_tab import SettingsTab
from intellicrack.ui.tabs.terminal_tab import TerminalTab
from intellicrack.ui.tabs.tools_tab import ToolsTab
from intellicrack.ui.tabs.workspace_tab import WorkspaceTab
from intellicrack.ui.theme_manager import get_theme_manager
from intellicrack.ui.traffic_analyzer import TrafficAnalyzer, clear_network_capture, start_network_capture, stop_network_capture
from intellicrack.utils.core.plugin_paths import get_frida_scripts_dir, get_ghidra_scripts_dir
from intellicrack.utils.logger import log_all_methods
from intellicrack.utils.protection_utils import inject_comprehensive_api_hooks
from intellicrack.utils.resource_helper import get_resource_path
from intellicrack.utils.runtime.runner_functions import run_frida_script, run_qemu_analysis, run_selected_analysis, run_ssl_tls_interceptor
from intellicrack.utils.type_safety import get_typed_item, validate_type


if TYPE_CHECKING:
    from intellicrack.ai.coordination_layer import AICoordinationLayer
    from intellicrack.ai.orchestrator import AIOrchestrator
    from intellicrack.ai.script_generation_agent import AIAgent
    from intellicrack.core.network.license_server_emulator import NetworkLicenseServerEmulator
    from intellicrack.core.network.protocol_fingerprinter import ProtocolFingerprinter
    from intellicrack.core.network.ssl_interceptor import SSLTLSInterceptor
    from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer


CONFIG = get_config()

logger = logging.getLogger(__name__)


@log_all_methods
class IntellicrackApp(QMainWindow):
    """Run application window for Intellicrack, a comprehensive binary analysis and security research toolkit.

    This class serves as the central orchestrator for the entire Intellicrack application, managing
    multiple analysis engines, UI components, tabs, plugins, and external tool integrations.
    It provides a professional-grade interface for reverse engineering, vulnerability research,
    and security testing with AI-powered assistance.

    The application supports modular architecture with specialized tabs for different analysis
    types, real-time progress tracking, comprehensive logging, and extensible plugin system.
    It integrates multiple analysis engines including static/dynamic analysis, symbolic execution,
    taint analysis, and network protocol analysis.

    Attributes:
        Main UI Components:
            tabs: QTabWidget containing all analysis tabs
            main_splitter: QSplitter dividing tabs and output panel
            output: QTextEdit for main output display
            raw_console_output: QPlainTextEdit for raw console messages
            statusBar: Application status bar

        Core Managers and Engines:
            app_context: Application context for state management
            task_manager: Task management and coordination
            model_manager: AI/ML model management
            ai_orchestrator: AI-powered analysis orchestration
            ai_agent: AI-powered autonomous analysis agent
            theme_manager: UI theming and styling
            icon_manager: Icon management system
            dashboard_manager: Dashboard monitoring and metrics

        Analysis Engines:
            dynamic_analyzer: Dynamic binary analysis engine
            ml_predictor: Machine learning prediction engine
            symbolic_execution_engine: Symbolic execution engine
            concolic_execution_engine: Concolic execution engine
            taint_analysis_engine: Taint analysis engine
            rop_chain_generator: Return-oriented programming chain generator
            parallel_processing_manager: Parallel processing manager
            gpu_accelerator: GPU-accelerated analysis engine

        Network Components:
            network_traffic_analyzer: Network traffic analysis
            ssl_interceptor: SSL/TLS traffic interception
            protocol_fingerprinter: Protocol fingerprinting engine
            network_license_server: License server emulator

        UI State and Configuration:
            binary_path: Currently loaded binary file path
            selected_model_path: Selected AI model path
            chat_history: AI assistant conversation history
            frida_sessions: Active Frida instrumentation sessions
            recent_files: Recently accessed files
            reports: Generated analysis reports
            binary_info: Information about loaded binary

        PyQt Signals:
            update_output: Signal for updating main output display
            update_status: Signal for status bar updates
            update_analysis_results: Signal for analysis result updates
            update_progress: Signal for progress bar updates
            update_assistant_status: Signal for AI assistant status
            update_chat_display: Signal for chat display updates
            log_user_question: Signal for user question logging
            set_keygen_name/version: Signals for key generator configuration
            switch_tab: Signal for tab switching
            generate_key_signal: Signal for key generation

    """

    # PyQt signals for UI communication
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    update_analysis_results = pyqtSignal(str)
    update_progress = pyqtSignal(int)
    update_assistant_status = pyqtSignal(str)
    update_chat_display = pyqtSignal(str)
    replace_chat_display_last = pyqtSignal(str)
    log_user_question = pyqtSignal(str)
    set_keygen_name = pyqtSignal(str)
    set_keygen_version = pyqtSignal(str)
    switch_tab = pyqtSignal(int)
    generate_key_signal = pyqtSignal()
    analysis_completed = pyqtSignal(str)

    PLUGIN_TYPE_CUSTOM = "custom"
    PLUGIN_TYPE_FRIDA = "frida"
    PLUGIN_TYPE_GHIDRA = "ghidra"

    def __init__(self) -> None:
        """Initialize the main Intellicrack application window.

        Sets up the logger, model manager, and other core components.
        """
        # Initialize UI attributes first
        self._initialize_ui_attributes()

        super().__init__()

        # Flag to track if UI is initialized
        self._ui_initialized = False

        # Initialize core components and managers
        self._initialize_core_components()
        self._initialize_ai_orchestrator()

        # Set up connections and properties
        self._connect_signals()
        self._setup_main_window_properties()
        self._initialize_application_properties()

        # Bind external functions and handlers
        self._bind_external_functions()
        self._bind_exploitation_handlers()
        self._bind_class_methods()

        # Initialize engines and components
        self._initialize_analyzer_engines()
        self._initialize_network_components()

        # Create UI layout and components
        self._create_main_ui_layout()
        self._setup_tabs_and_themes()
        self._create_output_panel()
        self._create_modular_tabs()
        self._setup_individual_tabs()

        # Finalize initialization
        self._finalize_ui_initialization()

    def _initialize_ui_attributes(self) -> None:
        """Initialize all UI-related attributes to None."""
        self.activity_log: QTextEdit | None = None
        self.assistant_status: QLabel | None = None
        self.binary_info_group: QWidget | None = None
        self.capture_thread: object | None = None
        self.chat_display: QTextEdit | None = None
        self.disasm_text: QTextEdit | None = None
        self.log_filter: QWidget | None = None
        self.log_output: QTextEdit | None = None
        self.program_info: QWidget | None = None
        self.recent_files_list: QWidget | None = None
        self.report_viewer: QTextEdit | None = None
        self.traffic_analyzer: TrafficAnalyzer | None = None

        self._hex_viewer_dialogs: list[QWidget] = []
        self.ai_conversation_history: list[dict[str, str]] = []
        self.log_access_history: list[str] = []
        self.reports: list[dict[str, Any]] = []

    def _initialize_core_components(self) -> None:
        """Initialize core application components and managers."""
        self.logger = logging.getLogger("IntellicrackLogger.Main")
        self.logger.info("IntellicrackApp constructor called. Initializing main application window.")

        self.app_context = get_app_context()
        self.task_manager = get_task_manager()
        self.logger.info("Initialized AppContext and TaskManager for state management")

        config_dict = validate_type(CONFIG, dict)
        model_repos = config_dict.get("model_repositories", {})
        local_config = model_repos.get("local", {}) if isinstance(model_repos, dict) else {}
        models_dir = local_config.get("models_directory", "models") if isinstance(local_config, dict) else "models"
        self.model_manager: ModelManager | None = ModelManager(str(models_dir))

    def _initialize_ai_orchestrator(self) -> None:
        """Initialize AI orchestration and coordination components."""
        self.ai_orchestrator: AIOrchestrator | None = None
        self.ai_coordinator: AICoordinationLayer | None = None
        try:
            self.logger.info("Initializing AI Orchestrator for agentic environment...")
            from ..ai.orchestrator import get_orchestrator

            self.ai_orchestrator = get_orchestrator()
            self.logger.info("AI Orchestrator initialized successfully - agentic environment ready")

            from ..ai.coordination_layer import AICoordinationLayer as AICoordLayer

            self.ai_coordinator = AICoordLayer(
                shared_context=self.ai_orchestrator.shared_context,
                event_bus=self.ai_orchestrator.event_bus,
            )
            self.logger.info("AI Coordination Layer initialized successfully")

            self.ai_orchestrator.event_bus.subscribe("task_complete", self._on_ai_task_complete_wrapper, "main_ui")
            self.ai_orchestrator.event_bus.subscribe(
                "coordinated_analysis_complete", self._on_coordinated_analysis_complete_wrapper, "main_ui"
            )

            self.logger.info("Exploitation Orchestrator initialized successfully")
            self.logger.info("IntellicrackApp initialization complete with agentic AI system.")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to initialize AI Orchestrator: %s", e)
            self.ai_orchestrator = None
            self.ai_coordinator = None
            self.logger.warning("Continuing without agentic AI system")

    def _connect_signals(self) -> None:
        """Connect all Qt signals to their respective slots."""
        # Connect internal signals
        self.update_output.connect(self.append_output)
        self.update_status.connect(self.set_status_message)
        self.update_analysis_results.connect(self.append_analysis_results)
        self.update_progress.connect(self.set_progress_value)
        self.update_assistant_status.connect(self.set_assistant_status)
        self.update_chat_display.connect(self.append_chat_display)
        self.replace_chat_display_last.connect(self.replace_last_chat_message)
        self.log_user_question.connect(self.handle_log_user_question)
        self.set_keygen_name.connect(self.handle_set_keygen_name)
        self.set_keygen_version.connect(self.handle_set_keygen_version)
        self.switch_tab.connect(self.handle_switch_tab)
        self.generate_key_signal.connect(self.handle_generate_key)

        # Connect AppContext signals
        self.app_context.binary_loaded.connect(self._on_binary_loaded)
        self.app_context.analysis_completed.connect(self._on_analysis_completed)
        self.app_context.task_started.connect(self._on_task_started)
        self.app_context.task_progress.connect(self._on_task_progress)
        self.app_context.task_completed.connect(self._on_task_completed)
        self.app_context.task_failed.connect(self._on_task_failed)

    def _setup_main_window_properties(self) -> None:
        """Set up main window properties, geometry, and icon."""
        # Set up main window
        self.setWindowTitle("Intellicrack")
        # Set default geometry (will be overridden by restore_window_state if config exists)
        self.setGeometry(100, 100, 1200, 800)
        # Restore window state from config
        self.restore_window_state()

        # Initialize and load custom fonts
        self._initialize_font_manager()

        # Try to load icon with multiple fallback paths
        icon_paths = [
            get_resource_path("assets/icon.ico"),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "icon.ico"),
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "intellicrack",
                "assets",
                "icon.ico",
            ),
        ]

        icon_loaded = False
        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                try:
                    icon = QIcon(icon_path)
                    if not icon.isNull():
                        self.setWindowIcon(icon)
                        app = QApplication.instance()
                        if app is not None and hasattr(app, "setWindowIcon"):
                            app.setWindowIcon(icon)
                        icon_loaded = True
                        break
                except Exception as e:
                    logger.debug("Failed to load icon from %s: %s", icon_path, e)

        if not icon_loaded:
            logger.debug("Failed to load application icon from any path")

    def _initialize_application_properties(self) -> None:
        """Initialize important application properties and variables."""
        self.binary_path: str | None = None
        self.current_binary: str = ""
        self.ghidra_analysis_result: Any = None
        self.ghidra_scripts_used: list[dict[str, Any]] = []
        config_dict = validate_type(CONFIG, dict)
        selected_path = config_dict.get("selected_model_path", None)
        self.selected_model_path: str | None = str(selected_path) if selected_path is not None else None

        if self.selected_model_path is not None and os.path.exists(self.selected_model_path):
            if hasattr(self, "custom_model_path_label"):
                self.custom_model_path_label.setText(os.path.basename(self.selected_model_path))
            self.update_output.emit(f"[AI Model] Loaded saved model path from config: {self.selected_model_path}")
        else:
            self.selected_model_path = None
            if hasattr(self, "custom_model_path_label"):
                self.custom_model_path_label.setText("None")
            self.update_output.emit("[AI Model] No saved model path found or path is invalid.")

        self.chat_history: list[dict[str, str]] = []
        self.frida_sessions: dict[str, Any] = {}
        self.auto_patch_attempted: bool = False
        self.potential_patches: list[dict[str, Any]] = []
        self.recent_files: list[str] = []

        self.dynamic_analyzer: object | None = None
        self.ml_predictor: object | None = None
        self.analyze_results: list[dict[str, Any]] = []
        self.patches: list[dict[str, Any]] = []
        self.binary_info: dict[str, Any] | None = None

    def _bind_external_functions(self) -> None:
        """Bind external function wrappers as instance methods using partial."""
        self.inject_comprehensive_api_hooks: Callable[..., Any] = partial(inject_comprehensive_api_hooks, self)

        def run_frida_plugin_wrapper(*args: Any, **kwargs: Any) -> Any:
            if self.binary_path is None:
                raise ValueError("No binary loaded - binary_path is required for Frida plugin execution")
            from intellicrack.plugins.plugin_system import AppProtocol as FridaAppProtocol

            app_for_frida = cast("FridaAppProtocol", self)
            return run_frida_plugin_from_file(app_for_frida, *args, **kwargs)

        def run_ghidra_plugin_wrapper(*args: Any, **kwargs: Any) -> Any:
            if self.binary_path is None:
                raise ValueError("No binary loaded - binary_path is required for Ghidra plugin execution")
            from intellicrack.plugins.plugin_system import AppProtocol as GhidraAppProtocol

            app_for_ghidra = cast("GhidraAppProtocol", self)
            return run_ghidra_plugin_from_file(app_for_ghidra, *args, **kwargs)

        self.run_frida_plugin_from_file_bound: Callable[..., Any] = run_frida_plugin_wrapper
        self.run_ghidra_plugin_from_file_bound: Callable[..., Any] = run_ghidra_plugin_wrapper
        self.setup_memory_patching_ref: Callable[..., Any] = setup_memory_patching
        self.run_rop_chain_generator_bound: Callable[..., Any] = partial(run_rop_chain_generator, self)
        self.run_automated_patch_agent_ref: Callable[..., Any] = run_automated_patch_agent

        self.run_ssl_tls_interceptor_bound: Callable[..., dict[str, object]] = partial(run_ssl_tls_interceptor, self)
        self.run_cloud_license_hooker_bound: Callable[..., Any] = partial(run_cloud_license_hooker, self)
        self.run_cfg_explorer: Callable[..., Any] = partial(CfgExplorerInner().run_cfg_explorer_inner, self)
        self.run_concolic_execution_bound: Callable[..., Any] = partial(run_concolic_execution, self)
        self.run_enhanced_protection_scan_bound: Callable[..., Any] = partial(run_enhanced_protection_scan, self)
        self.run_visual_network_traffic_analyzer: Callable[..., Any] = partial(TrafficAnalyzer().run_visual_network_traffic_analyzer, self)
        self.run_multi_format_analysis_bound: Callable[..., Any] = partial(run_multi_format_analysis, self)
        self.run_distributed_processing: Callable[..., Any] = partial(DistributedProcessing().run_distributed_processing, self)
        self.run_gpu_accelerated_analysis: Callable[..., Any] = partial(GpuAnalysis().run_gpu_accelerated_analysis, self)

        def run_advanced_ghidra_analysis_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not self.current_binary:
                raise ValueError("No binary loaded - current_binary is required for Ghidra analysis")
            from intellicrack.core.analysis.ghidra_analyzer import MainAppProtocol as GhidraMainAppProtocol

            app_for_ghidra_analysis = cast("GhidraMainAppProtocol", self)
            return run_advanced_ghidra_analysis(app_for_ghidra_analysis, *args, **kwargs)

        def run_dynamic_instrumentation_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not self.current_binary:
                raise ValueError("No binary loaded - current_binary is required for dynamic instrumentation")
            from intellicrack.core.analysis.dynamic_instrumentation import MainAppProtocol as DynInstrMainAppProtocol

            app_for_dyn_instr = cast("DynInstrMainAppProtocol", self)
            return run_dynamic_instrumentation(app_for_dyn_instr, *args, **kwargs)

        self.run_advanced_ghidra_analysis_bound: Callable[..., Any] = run_advanced_ghidra_analysis_wrapper
        self.run_symbolic_execution: Callable[..., Any] = partial(SymbolicExecution().run_symbolic_execution, self)
        self_any: Any = self
        self.run_incremental_analysis_bound: Callable[..., Any] = partial(run_incremental_analysis, self_any)
        self.run_memory_optimized_analysis_ref: Callable[..., Any] = run_memory_optimized_analysis
        self.run_taint_analysis_bound: Callable[..., Any] = partial(run_taint_analysis, self)
        self.run_qemu_analysis_bound: Callable[..., dict[str, object]] = partial(run_qemu_analysis, self)
        self.run_selected_analysis_partial: Callable[..., dict[str, object]] = partial(run_selected_analysis, self)
        self.run_network_license_emulator_ref: Callable[..., Any] = run_network_license_emulator
        self.run_frida_analysis_bound: Callable[..., Any] = partial(run_frida_analysis, self)
        self.run_dynamic_instrumentation_bound: Callable[..., Any] = run_dynamic_instrumentation_wrapper
        self.run_frida_script_bound: Callable[..., dict[str, object]] = partial(run_frida_script, self)

    def _bind_exploitation_handlers(self) -> None:
        """Bind exploitation handler methods from separate module."""
        from . import exploitation_handlers

        self.cleanup_exploitation: Callable[..., Any] = partial(exploitation_handlers.cleanup_exploitation, self)
        self.save_exploitation_output: Callable[..., Any] = partial(exploitation_handlers.save_exploitation_output, self)

    def _bind_class_methods(self) -> None:
        """Bind standalone method definitions to the instance."""
        self.start_network_capture = start_network_capture.__get__(self, type(self))
        self.stop_network_capture = stop_network_capture.__get__(self, type(self))
        self.clear_network_capture = clear_network_capture.__get__(self, type(self))
        self.launch_protocol_tool = launch_protocol_tool.__get__(self, type(self))
        self.update_protocol_tool_description = update_protocol_tool_description.__get__(self, type(self))
        self.generate_report = generate_report.__get__(self, type(self))
        self.view_report = view_report.__get__(self, type(self))

    def _initialize_analyzer_engines(self) -> None:
        """Initialize various analyzer engines with graceful fallbacks."""
        self.ai_agent: AIAgent | None = None
        try:
            from ..ai.script_generation_agent import AIAgent as AIAgentClass

            self.ai_agent = AIAgentClass()
            logger.info("AIAgent initialized successfully")
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize AIAgent: %s", e)

        self.memory_optimized_loader: MemoryOptimizedBinaryLoader | None = None
        try:
            self.memory_optimized_loader = MemoryOptimizedBinaryLoader()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize MemoryOptimizedBinaryLoader: %s", e)

        self.symbolic_execution_engine: object | None = None
        logger.info("SymbolicExecutionEngine will be initialized when binary is loaded")

        self.taint_analysis_engine: TaintAnalysisEngine | None = None
        try:
            self.taint_analysis_engine = TaintAnalysisEngine()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize TaintAnalysisEngine: %s", e)

        self.concolic_execution_engine: object | None = None
        logger.info("ConcolicExecutionEngine will be initialized when binary is loaded")

        self.rop_chain_generator: ROPChainGenerator | None = None
        try:
            self.rop_chain_generator = ROPChainGenerator()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize ROPChainGenerator: %s", e)

        self.parallel_processing_manager: ParallelProcessingManager | None = None
        try:
            self.parallel_processing_manager = ParallelProcessingManager()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize ParallelProcessingManager: %s", e)

        self.gpu_accelerator: GPUAccelerator | None = None
        try:
            self.gpu_accelerator = GPUAccelerator()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize GPUAccelerator: %s", e)

    def _initialize_network_components(self) -> None:
        """Initialize network analysis and traffic components."""
        self.network_traffic_analyzer: NetworkTrafficAnalyzer | None = None
        try:
            from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer

            self.network_traffic_analyzer = NetworkTrafficAnalyzer()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize NetworkTrafficAnalyzer: %s", e)

        self.ssl_interceptor: SSLTLSInterceptor | None = None
        try:
            from ..core.network.ssl_interceptor import SSLTLSInterceptor as SSLInt

            self.ssl_interceptor = SSLInt()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize SSLTLSInterceptor: %s", e)

        self.protocol_fingerprinter: ProtocolFingerprinter | None = None
        try:
            from ..core.network.protocol_fingerprinter import ProtocolFingerprinter

            self.protocol_fingerprinter = ProtocolFingerprinter()
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Failed to initialize ProtocolFingerprinter: %s", e)

        self.network_license_server: NetworkLicenseServerEmulator | None = None
        try:
            from ..core.network.license_server_emulator import NetworkLicenseServerEmulator

            self.network_license_server = NetworkLicenseServerEmulator()
        except (OSError, ValueError, RuntimeError, ImportError) as e:
            logger.warning("Failed to initialize NetworkLicenseServerEmulator: %s", e)

    def _create_main_ui_layout(self) -> None:
        """Create the main UI layout with central widget, tabs, and output panel."""
        self.TOOL_REGISTRY: dict[str, Any] = TOOL_REGISTRY.copy()

        self.ghidra_path_edit: QWidget | None = None

        self.pdf_report_generator: PDFReportGenerator | None = PDFReportGenerator()

        # Create central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout(self.central_widget)

        self.create_toolbar()

        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.main_splitter)

    def _setup_tabs_and_themes(self) -> None:
        """Set up tab widget and apply themes."""
        self.tabs = QTabWidget()

        # Style main tabs differently from sub-tabs to avoid visual confusion
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setTabsClosable(False)

        try:
            # Initialize and apply theme using ThemeManager
            self.theme_manager = get_theme_manager()
            self.theme_manager.set_theme(self.theme_manager.get_current_theme())

            # Initialize icon manager for consistent iconography
            self.icon_manager = IconManager()
        except Exception as e:
            # Continue initialization even if theme application fails
            logger.debug("Theme application failed: %s", e)

        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setTabsClosable(False)

        self.main_splitter.addWidget(self.tabs)

    def _create_output_panel(self) -> None:
        """Create the output panel with console and clear functionality."""
        self.output_panel = QWidget()

        self.output_layout = QVBoxLayout(self.output_panel)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.raw_console_output = QPlainTextEdit()
        self.raw_console_output.setReadOnly(True)
        self.raw_console_output.setMaximumBlockCount(1000)

        self.clear_output_btn = QPushButton("Clear Output")
        self.clear_output_btn.clicked.connect(self.clear_output)

        self.output_layout.addWidget(QLabel("<b>Output</b>"))
        self.output_layout.addWidget(self.output)
        self.output_layout.addWidget(QLabel("<b>Raw Console</b>"))
        self.output_layout.addWidget(self.raw_console_output)
        self.output_layout.addWidget(self.clear_output_btn)

        self.main_splitter.addWidget(self.output_panel)
        self.main_splitter.setSizes([700, 500])

    def _create_modular_tabs(self) -> None:
        """Create all modular tab instances with shared context."""
        shared_context: dict[str, Any] = {
            "main_window": self,
            "log_message": self.log_message,
            "app_context": self.app_context,
            "task_manager": self.task_manager,
        }

        self.dashboard_tab: DashboardTab | QWidget = DashboardTab(shared_context, self)
        self.analysis_tab: AnalysisTab | QWidget = AnalysisTab(shared_context, self)
        self.exploitation_tab: ExploitationTab | QWidget = ExploitationTab(shared_context, self)
        self.ai_assistant_tab: AIAssistantTab | QWidget = AIAssistantTab(shared_context, self)
        self.tools_tab: ToolsTab | QWidget = ToolsTab(shared_context, self)
        self.terminal_tab: TerminalTab | QWidget = TerminalTab(shared_context, self)
        self.settings_tab: SettingsTab | QWidget = SettingsTab(shared_context, self)
        self.workspace_tab: WorkspaceTab | QWidget = WorkspaceTab(shared_context, self)

        # Connect theme change signal to handler
        if hasattr(self.settings_tab, "theme_changed"):
            self.settings_tab.theme_changed.connect(self.on_theme_changed)

        # Add new modular tabs to the tab widget
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.workspace_tab, "Workspace")
        self.tabs.addTab(self.analysis_tab, "Analysis")
        self.tabs.addTab(self.exploitation_tab, "Exploitation")
        self.tabs.addTab(self.ai_assistant_tab, "AI Assistant")
        self.tabs.addTab(self.tools_tab, "Tools")
        self.tabs.addTab(self.terminal_tab, "Terminal")
        self.tabs.addTab(self.settings_tab, "Settings")

        # Set comprehensive tooltips for main tabs
        self.tabs.setTabToolTip(0, "Overview of current project status, recent files, and system health monitoring")
        self.tabs.setTabToolTip(1, "Manage projects, loaded binaries, and activity logs for your analysis sessions")
        self.tabs.setTabToolTip(
            2,
            "Comprehensive binary analysis suite with static, dynamic, and AI-powered analysis tools",
        )
        self.tabs.setTabToolTip(3, "Advanced exploitation toolkit for vulnerability research and security testing")
        self.tabs.setTabToolTip(4, "AI-powered assistant for code analysis, script generation, and intelligent guidance")
        self.tabs.setTabToolTip(5, "Collection of specialized security research and binary manipulation tools")
        self.tabs.setTabToolTip(6, "Interactive terminal for running scripts and commands with full I/O support")
        self.tabs.setTabToolTip(7, "Configure application preferences, model settings, and advanced options")

        # Initialize dashboard manager
        self.dashboard_manager = DashboardManager(self)

    def _setup_individual_tabs(self) -> None:
        """Set up each individual tab with error handling.

        Raises:
            OSError: If file system operations fail during tab setup.
            ValueError: If configuration values are invalid.
            RuntimeError: If required components fail to initialize.

        """
        # Initialize the binary_path variable before setting up tabs
        self.binary_path = None

        # Setup each tab with appropriate UI components
        try:
            self.setup_project_dashboard_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to setup project dashboard tab: %s", e)
            self.logger.exception(traceback.format_exc())
            raise

        try:
            self.setup_analysis_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to setup analysis tab: %s", e)
            self.logger.exception(traceback.format_exc())
            raise

        try:
            self.setup_patching_exploitation_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to setup patching exploitation tab: %s", e)
            self.logger.exception(traceback.format_exc())
            raise

        try:
            self.setup_ai_assistant_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to setup AI assistant tab: %s", e)
            self.logger.exception(traceback.format_exc())
            raise

        try:
            self.setup_netanalysis_emulation_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to setup network analysis emulation tab: %s", e)
            self.logger.exception(traceback.format_exc())
            raise

        try:
            self.setup_tools_plugins_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to setup tools plugins tab: %s", e)
            self.logger.exception(traceback.format_exc())
            raise

        try:
            self.setup_settings_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Failed to setup settings tab: %s", e)
            self.logger.exception(traceback.format_exc())
            raise

    def _finalize_ui_initialization(self) -> None:
        """Finalize UI initialization with tooltips, plugins, and final configuration."""
        # Register terminal manager with main app
        from intellicrack.core.terminal_manager import get_terminal_manager

        terminal_mgr = get_terminal_manager()
        terminal_mgr.set_main_app(self)

        # Mark UI as initialized
        self._ui_initialized = True

        # Apply comprehensive tooltips to all buttons
        try:
            self.apply_comprehensive_tooltips()
        except (AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError) as e:
            self.logger.warning("Could not apply tooltips: %s", e)

        # Ensure window is properly configured
        self.setGeometry(100, 100, 1200, 800)
        self.setWindowTitle("Intellicrack")
        self.setMinimumSize(800, 600)

        # Initialize plugins
        try:
            from ..plugins.plugin_system import create_sample_plugins

            create_sample_plugins()
            self.available_plugins = self.load_available_plugins()
            self.logger.info(
                "Loaded %d custom plugins, %d Frida scripts, %d Ghidra scripts",
                len(self.available_plugins.get("custom", [])),
                len(self.available_plugins.get("frida", [])),
                len(self.available_plugins.get("ghidra", [])),
            )
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Failed to initialize plugins: %s", e)
            self.available_plugins = {
                self.PLUGIN_TYPE_CUSTOM: [],
                self.PLUGIN_TYPE_FRIDA: [],
                self.PLUGIN_TYPE_GHIDRA: [],
            }

    def _on_ai_task_complete_wrapper(self, event_data: dict[str, Any], source_component: str) -> None:
        """Wrapper for AI task completion that accepts source_component parameter.

        Args:
            event_data: Dictionary containing task completion information.
            source_component: Name of the component that emitted the event.

        """
        self._on_ai_task_complete(event_data)

    def _on_ai_task_complete(self, event_data: dict[str, Any]) -> None:
        """Handle AI task completion events from the orchestrator.

        Args:
            event_data: Dictionary containing task completion information.

        """
        try:
            task_id = event_data.get("task_id", "unknown")
            task_type = event_data.get("task_type", "unknown")
            status = event_data.get("status", "unknown")
            results = event_data.get("results", {})

            self.logger.info("AI task completed - ID: %s, Type: %s, Status: %s", task_id, task_type, status)

            if hasattr(self, "update_output") and self.update_output:
                message = f"[AI] Task {task_id} ({task_type}) completed with status: {status}"
                self.update_output.emit(message)

                if results and isinstance(results, Sized):
                    result_summary = f"[AI] Results: {len(results)} items processed"
                    self.update_output.emit(result_summary)

        except Exception as e:
            self.logger.exception("Error handling AI task completion: %s", e)

    def _on_coordinated_analysis_complete_wrapper(self, event_data: dict[str, Any], source_component: str) -> None:
        """Wrapper for coordinated analysis completion that accepts source_component parameter.

        Args:
            event_data: Dictionary containing coordinated analysis results.
            source_component: Name of the component that emitted the event.

        """
        self._on_coordinated_analysis_complete(event_data)

    def _on_coordinated_analysis_complete(self, event_data: dict[str, Any]) -> None:
        """Handle coordinated analysis completion events from AI coordinator.

        Args:
            event_data: Dictionary containing coordinated analysis results.

        """
        try:
            analysis_id = event_data.get("analysis_id", "unknown")
            analysis_type = event_data.get("analysis_type", "unknown")
            findings = event_data.get("findings", [])
            recommendations = event_data.get("recommendations", [])

            self.logger.info("Coordinated analysis completed - ID: %s, Type: %s", analysis_id, analysis_type)

            if hasattr(self, "update_output") and self.update_output:
                message = f"[AI-COORD] Analysis {analysis_id} ({analysis_type}) completed"
                self.update_output.emit(message)

                if findings and isinstance(findings, Sized):
                    findings_msg = f"[AI-COORD] Found {len(findings)} security findings"
                    self.update_output.emit(findings_msg)

                if recommendations and isinstance(recommendations, Sized):
                    rec_msg = f"[AI-COORD] Generated {len(recommendations)} recommendations"
                    self.update_output.emit(rec_msg)

        except Exception as e:
            self.logger.exception("Error handling coordinated analysis completion: %s", e)

    def append_output(self, text: str) -> None:
        """Append text to the main output widget.

        Args:
            text: Text to append to the output displays.

        """
        if hasattr(self, "output") and self.output:
            self.output.append(text)
        if hasattr(self, "raw_console_output") and self.raw_console_output:
            self.raw_console_output.appendPlainText(text)

    def set_status_message(self, message: str) -> None:
        """Set status message in the application.

        Args:
            message: Status message to display in the status bar.

        """
        status_bar = self.statusBar()
        if status_bar is not None:
            status_bar.showMessage(message, 5000)
        self.logger.info("Status: %s", message)

    def append_analysis_results(self, results: str) -> None:
        """Append analysis results to appropriate display.

        Args:
            results: Analysis results to display.

        """
        if hasattr(self, "output") and self.output:
            formatted_results = f"[ANALYSIS] {results}"
            self.output.append(formatted_results)
        self.logger.info("Analysis results: %s", results)

    def set_progress_value(self, value: int) -> None:
        """Set progress value for any active progress indicators.

        Args:
            value: Progress value as a percentage (0-100).

        """
        self.logger.debug("Progress updated: %s%%", value)

    def set_assistant_status(self, status: str) -> None:
        """Set AI assistant status.

        Args:
            status: Status message for the AI assistant.

        """
        if self.assistant_status is not None:
            self.assistant_status.setText(status)
        self.logger.info("Assistant status: %s", status)

    def append_chat_display(self, message: str) -> None:
        """Append message to chat display.

        Args:
            message: Chat message to append.

        """
        if self.chat_display is not None:
            self.chat_display.append(message)
        self.logger.info("Chat: %s", message)

    def replace_last_chat_message(self, message: str) -> None:
        """Replace the last message in chat display.

        Args:
            message: Message to replace the last one with.

        """
        if self.chat_display is not None:
            cursor = self.chat_display.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            cursor.select(cursor.SelectionType.BlockUnderCursor)
            cursor.insertText(message)
        self.logger.info("Chat replaced: %s", message)

    def handle_log_user_question(self, question: str) -> None:
        """Handle user question logging.

        Args:
            question: User question to log.

        """
        if hasattr(self, "ai_conversation_history"):
            self.ai_conversation_history.append({"type": "question", "content": question})
        self.logger.info("User question logged: %s", question)

    def handle_set_keygen_name(self, name: str) -> None:
        """Handle setting keygen name.

        Args:
            name: Name to set for the key generator.

        """
        self.logger.info("Keygen name set: %s", name)

    def handle_set_keygen_version(self, version: str) -> None:
        """Handle setting keygen version.

        Args:
            version: Version to set for the key generator.

        """
        self.logger.info("Keygen version set: %s", version)

    def handle_switch_tab(self, tab_index: int) -> None:
        """Handle tab switching.

        Args:
            tab_index: Index of the tab to switch to.

        """
        if hasattr(self, "tabs") and self.tabs is not None:
            self.tabs.setCurrentIndex(tab_index)
        self.logger.info("Switched to tab index: %s", tab_index)

    def handle_generate_key(self) -> None:
        """Handle key generation request."""
        self.logger.info("Key generation requested")

    def clear_output(self) -> None:
        """Clear all output displays."""
        if hasattr(self, "output") and self.output:
            self.output.clear()
        if hasattr(self, "raw_console_output") and self.raw_console_output:
            self.raw_console_output.clear()
        self.logger.info("Output displays cleared")

    def log_message(self, message: str) -> str:
        """Format and return log message with timestamp.

        Args:
            message: Message to format with timestamp.

        Returns:
            Formatted message with timestamp prefix.

        """
        import datetime

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        return f"[{timestamp}] {message}"

    def _on_binary_loaded(self, binary_info: dict[str, Any]) -> None:
        """Handle binary loaded event from app context.

        Args:
            binary_info: Dictionary containing binary information.

        """
        if isinstance(binary_info, dict) and "path" in binary_info:
            path_val = binary_info["path"]
            self.binary_path = str(path_val) if path_val is not None else None
            self.current_binary = str(path_val) if path_val is not None else ""
            binary_name = binary_info.get("name", os.path.basename(str(path_val)))
            self.update_output.emit(self.log_message(f"Binary loaded: {binary_name}"))
            self.logger.info("Binary loaded: %s", binary_info["path"])

            if hasattr(self, "analysis_tab") and self.analysis_tab is not None and hasattr(self.analysis_tab, "set_binary_path"):
                self.analysis_tab.set_binary_path(str(path_val))
        else:
            self.binary_path = str(binary_info) if binary_info else None
            self.current_binary = str(binary_info) if binary_info else ""
            self.update_output.emit(self.log_message(f"Binary loaded: {binary_info}"))
            self.logger.info("Binary loaded: %s", binary_info)

    def _on_analysis_completed(self, results: list[Any]) -> None:
        """Handle analysis completion event from app context.

        Args:
            results: Analysis results list.

        """
        self.update_analysis_results.emit(f"Analysis completed with {len(results)} results")
        self.logger.info("Analysis completed")

    def _on_task_started(self, task_name: str) -> None:
        """Handle task started event from app context.

        Args:
            task_name: Name of the task that started.

        """
        self.update_status.emit(f"Task started: {task_name}")
        self.logger.info("Task started: %s", task_name)

    def _on_task_progress(self, progress: int) -> None:
        """Handle task progress event from app context.

        Args:
            progress: Progress percentage (0-100).

        """
        self.update_progress.emit(progress)
        self.logger.debug("Task progress: %s%%", progress)

    def _on_task_completed(self, task_name: str) -> None:
        """Handle task completed event from app context.

        Args:
            task_name: Name of the task that completed.

        """
        self.update_status.emit(f"Task completed: {task_name}")
        self.logger.info("Task completed: %s", task_name)

    def _on_task_failed(self, task_name: str, error: str) -> None:
        """Handle task failed event from app context.

        Args:
            task_name: Name of the task that failed.
            error: Error message describing the failure.

        """
        self.update_status.emit(f"Task failed: {task_name} - {error}")
        self.logger.exception("Task failed: %s - %s", task_name, error)

    def apply_comprehensive_tooltips(self) -> None:
        """Apply comprehensive tooltips to UI elements."""
        try:
            from intellicrack.ui.tooltip_helper import apply_tooltips_to_all_elements

            # Apply tooltips to the main window and all its children
            apply_tooltips_to_all_elements(self)

            # Apply tooltips to each tab specifically
            if hasattr(self, "tab_widget") and self.tab_widget is not None:
                for i in range(self.tab_widget.count()):
                    tab = self.tab_widget.widget(i)
                    if tab is not None:
                        apply_tooltips_to_all_elements(tab)

            self.logger.debug("Applied tooltips to UI elements")
        except Exception as e:
            self.logger.warning("Failed to apply tooltips: %s", e)

    def restore_window_state(self) -> None:
        """Restore window state from configuration."""
        try:
            from ..core.config_manager import get_config

            config = get_config()
            config_dict = validate_type(config, dict)
            ui_config = config_dict.get("ui", {})
            if isinstance(ui_config, dict):
                geometry = ui_config.get("window_geometry")
                if geometry is not None and isinstance(geometry, (list, tuple)) and len(geometry) >= 4:
                    self.setGeometry(int(geometry[0]), int(geometry[1]), int(geometry[2]), int(geometry[3]))
        except Exception as e:
            self.logger.debug("Could not restore window state: %s", e)

    def _initialize_font_manager(self) -> None:
        """Initialize custom fonts."""
        self.logger.debug("Font manager initialized")

    def create_toolbar(self) -> None:
        """Create application toolbar."""
        from PyQt6.QtWidgets import QToolBar

        toolbar = QToolBar("Main Toolbar", self)
        self.addToolBar(toolbar)
        self.logger.debug("Toolbar created")

    def on_theme_changed(self, theme_name: str) -> None:
        """Handle theme change event.

        Args:
            theme_name: Name of the theme to apply.

        """
        if hasattr(self, "theme_manager") and self.theme_manager:
            self.theme_manager.set_theme(theme_name)
        self.logger.info("Theme changed to: %s", theme_name)

    def _load_cache_data(self, cache_file: Path) -> dict[str, Any] | None:
        """Load and parse cache data from file.

        Args:
            cache_file: Path to cache file.

        Returns:
            Parsed cache data, or None if loading fails.

        """
        import json

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, encoding="utf-8") as f:
                result = json.load(f)
                return validate_type(result, dict) if isinstance(result, dict) else None
        except (json.JSONDecodeError, OSError) as e:
            self.logger.debug("Failed to load cache data: %s", e)
            return None

    def _check_file_modifications(self, plugin_dir: Path, cached_filenames: dict[str, float]) -> tuple[bool, dict[str, float]]:
        """Check if files in directory have been modified compared to cache.

        Args:
            plugin_dir: Path to plugin directory.
            cached_filenames: Dict mapping filenames to cached modification times.

        Returns:
            Tuple of (is_valid, remaining_cached_files) where is_valid indicates if
            all files match cache, and remaining_cached_files contains files
            that were in cache but not found in directory.

        """
        remaining: dict[str, float] = dict(cached_filenames)

        try:
            for entry in plugin_dir.iterdir():
                if entry.is_file():
                    current_mtime = entry.stat().st_mtime
                    file_name = entry.name
                    if file_name not in remaining or remaining[file_name] != current_mtime:
                        return False, {}
                    del remaining[file_name]
        except OSError as e:
            self.logger.debug("Error checking file modifications: %s", e)
            return False, {}

        return True, remaining

    def _validate_plugin_directory_cache(self, plugin_type: str, plugin_dir: Path, cached_data: dict[str, Any]) -> bool:
        """Validate cache for a specific plugin directory.

        Args:
            plugin_type: Type of plugin (custom, frida, ghidra).
            plugin_dir: Path to plugin directory.
            cached_data: Complete cached data dictionary.

        Returns:
            True if cache is valid for this directory, False otherwise.

        """
        plugins_data = cached_data.get("plugins", {})
        cached_plugins: list[dict[str, Any]] = plugins_data.get(plugin_type, []) if isinstance(plugins_data, dict) else []

        if not plugin_dir.exists():
            return not cached_plugins

        cached_filenames: dict[str, float] = {
            str(p["filename"]): float(p["modified"]) for p in cached_plugins if "filename" in p and "modified" in p
        }
        is_valid, remaining = self._check_file_modifications(plugin_dir, cached_filenames)

        return len(remaining) == 0 if is_valid else False

    def _is_plugin_cache_valid(self, cache_file: Path, plugin_directories: dict[str, Path]) -> tuple[bool, dict[str, Any] | None]:
        """Check if plugin cache exists and is still valid.

        Args:
            cache_file: Path to cache file.
            plugin_directories: Dict mapping plugin types to their directories.

        Returns:
            Tuple of (is_valid, cached_data) where is_valid is True if cache is valid,
            and cached_data contains the loaded cache or None if invalid.

        """
        cached_data = self._load_cache_data(cache_file)
        if cached_data is None:
            return False, None

        for plugin_type, plugin_dir in plugin_directories.items():
            if not self._validate_plugin_directory_cache(plugin_type, plugin_dir, cached_data):
                return False, None

        return True, cached_data

    def load_available_plugins(self) -> dict[str, list[dict[str, Any]]]:
        """Load available plugins from plugin directory with caching for performance.

        Uses a cache file to avoid rescanning the filesystem on every startup. Cache is
        invalidated when plugin files are added, removed, or modified.

        Returns:
            Dictionary containing lists of plugins by type (custom, frida, ghidra).

        """
        import json

        from filelock import FileLock

        cache_dir = Path.home() / ".intellicrack"
        cache_file = cache_dir / "plugin_cache.json"
        cache_lock_file = cache_dir / "plugin_cache.json.lock"

        plugin_base_dir = Path(__file__).parent.parent / "plugins"
        plugin_directories: dict[str, Path] = {
            self.PLUGIN_TYPE_CUSTOM: plugin_base_dir / "custom_modules",
            self.PLUGIN_TYPE_FRIDA: Path(get_frida_scripts_dir()),
            self.PLUGIN_TYPE_GHIDRA: Path(get_ghidra_scripts_dir()),
        }

        def is_path_safe(file_path: Path, plugin_dir_param: Path) -> bool:
            try:
                real_plugin_dir = plugin_dir_param.resolve()
                real_file_path = file_path.resolve()
                return real_file_path.is_relative_to(real_plugin_dir)
            except (ValueError, OSError):
                return False

        lock = FileLock(str(cache_lock_file), timeout=10)

        cache_is_valid, cached_data = self._is_plugin_cache_valid(cache_file, plugin_directories)
        if cache_is_valid and cached_data is not None:
            try:
                cached_plugins = cached_data.get(
                    "plugins",
                    {
                        self.PLUGIN_TYPE_CUSTOM: [],
                        self.PLUGIN_TYPE_FRIDA: [],
                        self.PLUGIN_TYPE_GHIDRA: [],
                    },
                )

                plugins: dict[str, list[dict[str, Any]]] = {
                    self.PLUGIN_TYPE_CUSTOM: [],
                    self.PLUGIN_TYPE_FRIDA: [],
                    self.PLUGIN_TYPE_GHIDRA: [],
                }
                if isinstance(cached_plugins, dict):
                    for plugin_type, plugin_list in cached_plugins.items():
                        if plugin_type not in plugin_directories:
                            continue

                        plugin_dir = plugin_directories[plugin_type]
                        if not isinstance(plugin_list, list):
                            continue
                        for plugin_info in plugin_list:
                            if not isinstance(plugin_info, dict):
                                continue
                            filename = plugin_info.get("filename")
                            if not filename:
                                continue

                            reconstructed_path = plugin_dir / str(filename)

                            if not is_path_safe(reconstructed_path, plugin_dir):
                                self.logger.warning("Rejecting potentially malicious plugin path: %s", filename)
                                continue

                            if not reconstructed_path.exists():
                                continue

                            plugin_info_with_path = dict(plugin_info)
                            plugin_info_with_path["path"] = str(reconstructed_path)
                            plugins[str(plugin_type)].append(plugin_info_with_path)

                self.logger.info("Loaded %s plugins from cache", sum(len(p) for p in plugins.values()))
                return plugins
            except (KeyError, OSError) as e:
                self.logger.warning("Failed to load plugin cache, rescanning: %s", e)

        plugins = {
            self.PLUGIN_TYPE_CUSTOM: [],
            self.PLUGIN_TYPE_FRIDA: [],
            self.PLUGIN_TYPE_GHIDRA: [],
        }

        BINARY_EXTENSIONS = {".pyd", ".dll", ".jar"}

        try:
            for plugin_type, plugin_dir in plugin_directories.items():
                try:
                    if not plugin_dir.exists():
                        self.logger.info("Plugin directory not found, creating: %s", plugin_dir)
                        plugin_dir.mkdir(parents=True, exist_ok=True)
                        continue

                    plugin_extensions: dict[str, list[str]] = {
                        self.PLUGIN_TYPE_CUSTOM: [".py", ".pyd", ".dll"],
                        self.PLUGIN_TYPE_FRIDA: [".js", ".ts"],
                        self.PLUGIN_TYPE_GHIDRA: [".py", ".java", ".jar"],
                    }

                    for entry in plugin_dir.iterdir():
                        if entry.is_file():
                            file_ext = entry.suffix.lower()
                            if file_ext in plugin_extensions.get(plugin_type, []):
                                try:
                                    if file_ext in BINARY_EXTENSIONS:
                                        with open(entry, "rb") as bf:
                                            bf.read(512)
                                    else:
                                        with open(entry, encoding="utf-8") as tf:
                                            tf.read(512)

                                    plugin_info_item: dict[str, Any] = {
                                        "name": entry.stem,
                                        "filename": entry.name,
                                        "path": str(entry),
                                        "type": plugin_type,
                                        "extension": file_ext,
                                        "size": entry.stat().st_size,
                                        "modified": entry.stat().st_mtime,
                                        "valid": True,
                                    }
                                    plugins[plugin_type].append(plugin_info_item)

                                except (OSError, UnicodeDecodeError) as file_error:
                                    self.logger.warning("Failed to validate plugin %s: %s", entry.name, file_error)
                                    plugins[plugin_type].append(
                                        {
                                            "name": entry.stem,
                                            "filename": entry.name,
                                            "path": str(entry),
                                            "type": plugin_type,
                                            "valid": False,
                                            "error": str(file_error),
                                        },
                                    )

                except OSError as dir_error:
                    self.logger.exception("Error accessing plugin directory %s: %s", plugin_dir, dir_error)

            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                with lock, open(cache_file, "w", encoding="utf-8") as wf:
                    json.dump({"plugins": plugins, "cache_version": "1.0"}, wf, indent=2)
                self.logger.debug("Plugin cache saved to %s", cache_file)
            except OSError as cache_error:
                self.logger.warning("Failed to save plugin cache: %s", cache_error)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Critical error loading plugins: %s", e)
            return {
                self.PLUGIN_TYPE_CUSTOM: [],
                self.PLUGIN_TYPE_FRIDA: [],
                self.PLUGIN_TYPE_GHIDRA: [],
            }

        self.logger.info("Loaded %s plugins across %s categories", sum(len(p) for p in plugins.values()), len(plugins))
        return plugins

    def setup_project_dashboard_tab(self) -> None:
        """Set up project dashboard tab with real-time monitoring."""
        try:
            if hasattr(self, "dashboard_tab") and self.dashboard_tab:
                self.dashboard_tab.setVisible(True)
                self.logger.info("Dashboard tab initialized successfully")
        except Exception as e:
            self.logger.exception("Failed to setup dashboard tab: %s", e)
            if hasattr(self, "dashboard_tab"):
                self.dashboard_tab.setVisible(True)

    def setup_analysis_tab(self) -> None:
        """Set up analysis tab with licensing protection analysis capabilities."""
        try:
            if hasattr(self, "analysis_tab") and self.analysis_tab:
                self.analysis_tab.setVisible(True)
                self.logger.info("Analysis tab initialized successfully")

            if hasattr(self, "symbolic_execution_engine"):
                self.symbolic_execution_engine = None
        except Exception as e:
            self.logger.exception("Failed to setup analysis tab: %s", e)
            if hasattr(self, "analysis_tab"):
                self.analysis_tab.setVisible(True)

    def setup_patching_exploitation_tab(self) -> None:
        """Set up patching exploitation tab with advanced license bypass capabilities."""
        try:
            if hasattr(self, "exploitation_tab") and self.exploitation_tab:
                self.exploitation_tab.setVisible(True)
                self.logger.info("Exploitation tab initialized successfully")
        except Exception as e:
            self.logger.exception("Failed to setup patching exploitation tab: %s", e)
            if hasattr(self, "exploitation_tab"):
                self.exploitation_tab.setVisible(True)

    def setup_ai_assistant_tab(self) -> None:
        """Set up AI assistant tab with license protection research capabilities."""
        try:
            if hasattr(self, "ai_assistant_tab") and self.ai_assistant_tab:
                self.ai_assistant_tab.setVisible(True)
                self.logger.info("AI assistant tab initialized successfully")
        except Exception as e:
            self.logger.exception("Failed to setup AI assistant tab: %s", e)
            if hasattr(self, "ai_assistant_tab"):
                self.ai_assistant_tab.setVisible(True)

    def setup_netanalysis_emulation_tab(self) -> None:
        """Set up network analysis emulation tab with license server bypass capabilities."""
        try:
            self.logger.info("Network analysis emulation tab initialized successfully")
        except Exception as e:
            self.logger.exception("Failed to setup network analysis emulation tab: %s", e)

    def setup_tools_plugins_tab(self) -> None:
        """Set up tools plugins tab with license protection research tool integration."""
        try:
            if hasattr(self, "tools_tab") and self.tools_tab:
                self.tools_tab.setVisible(True)
                self.logger.info("Tools tab initialized successfully")
        except Exception as e:
            self.logger.exception("Failed to setup tools plugins tab: %s", e)
            if hasattr(self, "tools_tab"):
                self.tools_tab.setVisible(True)

    def setup_settings_tab(self) -> None:
        """Set up settings tab with license protection research configuration."""
        try:
            if hasattr(self, "settings_tab") and self.settings_tab:
                self.settings_tab.setVisible(True)
                self.logger.info("Settings tab initialized successfully")
        except Exception as e:
            self.logger.exception("Failed to setup settings tab: %s", e)
            if hasattr(self, "settings_tab"):
                self.settings_tab.setVisible(True)


def launch() -> int:
    """Launch the Intellicrack application.

    Creates QApplication instance, instantiates IntellicrackApp,
    shows the main window, and runs the Qt event loop.

    Returns:
        Application exit code.

    """
    try:
        import os
        import sys

        from intellicrack.handlers.pyqt6_handler import QApplication, QIcon, QPixmap, QSplashScreen, Qt
        from intellicrack.utils.resource_helper import get_resource_path

        # Fix Windows taskbar icon grouping by setting explicit App User Model ID BEFORE creating QApplication
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ZacharyFlint.Intellicrack.BinaryAnalysis.2.0")
        except Exception as e:
            logger.debug("Could not set App User Model ID (expected on non-Windows): %s", e)

        # Create QApplication instance if it doesn't exist
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)

            # Set application metadata for better OS integration
            app.setApplicationName("Intellicrack")
            app.setOrganizationName("Zachary Flint")
            app.setApplicationDisplayName("Intellicrack")

            # Set application icon for taskbar/dock with multiple fallback paths
            icon_paths = [
                get_resource_path("assets/icon.ico"),
                os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                    "assets",
                    "icon.ico",
                ),
                os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
                    "intellicrack",
                    "assets",
                    "icon.ico",
                ),
            ]

            for icon_path in icon_paths:
                if os.path.exists(icon_path):
                    try:
                        icon = QIcon(icon_path)
                        if not icon.isNull():
                            app.setWindowIcon(icon)
                            break
                    except Exception as e:
                        logger.debug("Failed to load icon from %s: %s", icon_path, e)
                        continue

        # Create and show splash screen
        splash_path = get_resource_path("assets/splash.png")
        splash = None
        if os.path.exists(splash_path):
            splash_pixmap = QPixmap(splash_path)
            splash = QSplashScreen(splash_pixmap, Qt.WindowType.WindowStaysOnTopHint)
            splash.show()
            app.processEvents()  # Process events to ensure splash is shown

        # Create and show main application window
        main_window = IntellicrackApp()

        # Close splash screen when main window is ready
        if splash:
            main_window.show()
            splash.finish(main_window)
        else:
            main_window.show()

        # Run the Qt event loop
        return app.exec()

    except Exception as e:
        logger.exception("Failed to launch Intellicrack application: %s", e)
        return 1
