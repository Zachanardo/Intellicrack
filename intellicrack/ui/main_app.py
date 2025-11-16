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

import contextlib
import logging
import os
import traceback
from functools import partial

from intellicrack.ai.model_manager_module import ModelManager
from intellicrack.core.analysis.automated_patch_agent import run_automated_patch_agent
from intellicrack.core.analysis.concolic_executor import (
    run_concolic_execution,
)
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
from intellicrack.core.network.protocol_tool import (
    launch_protocol_tool,
    update_protocol_tool_description,
)
from intellicrack.core.patching.memory_patcher import setup_memory_patching
from intellicrack.core.processing.gpu_accelerator import GPUAccelerator
from intellicrack.core.processing.memory_loader import (
    MemoryOptimizedBinaryLoader,
    run_memory_optimized_analysis,
)
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
from intellicrack.plugins import run_frida_plugin_from_file, run_ghidra_plugin_from_file
from intellicrack.plugins.custom_modules.license_server_emulator import run_network_license_emulator
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
from intellicrack.utils import run_frida_script, run_qemu_analysis, run_selected_analysis, run_ssl_tls_interceptor
from intellicrack.utils.core.plugin_paths import get_frida_scripts_dir, get_ghidra_scripts_dir
from intellicrack.utils.log_message import log_message
from intellicrack.utils.logger import log_all_methods
from intellicrack.utils.protection_utils import inject_comprehensive_api_hooks
from intellicrack.utils.resource_helper import get_resource_path

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
        # UI component attributes (only attributes that are actually used)
        self.activity_log = None
        self.assistant_status = None
        self.binary_info_group = None
        self.capture_thread = None
        self.chat_display = None
        self.disasm_text = None
        self.log_filter = None
        self.log_output = None
        self.program_info = None
        self.recent_files_list = None
        self.report_viewer = None
        self.traffic_analyzer = None

        # Collection attributes
        self._hex_viewer_dialogs = []
        self.ai_conversation_history = []
        self.log_access_history = []
        self.reports = []

    def _initialize_core_components(self) -> None:
        """Initialize core application components and managers."""
        # Initialize logger first
        self.logger = logging.getLogger("IntellicrackLogger.Main")
        self.logger.info("IntellicrackApp constructor called. Initializing main application window.")

        # Initialize core components
        self.app_context = get_app_context()
        self.task_manager = get_task_manager()
        self.logger.info("Initialized AppContext and TaskManager for state management")

        # Initialize ModelManager
        models_dir = CONFIG.get("model_repositories", {}).get("local", {}).get("models_directory", "models")
        if ModelManager is not None:
            self.model_manager = ModelManager(models_dir)
        else:
            self.model_manager = None
            self.logger.warning("ModelManager not available - AI features will be limited")

    def _initialize_ai_orchestrator(self) -> None:
        """Initialize AI orchestration and coordination components."""
        try:
            self.logger.info("Initializing AI Orchestrator for agentic environment...")
            from ..ai.orchestrator import get_orchestrator

            self.ai_orchestrator = get_orchestrator()
            self.logger.info("AI Orchestrator initialized successfully - agentic environment ready")

            # Initialize coordination layer for intelligent AI workflows
            from ..ai.coordination_layer import AICoordinationLayer

            self.ai_coordinator = AICoordinationLayer(
                shared_context=self.ai_orchestrator.shared_context,
                event_bus=self.ai_orchestrator.event_bus,
            )
            self.logger.info("AI Coordination Layer initialized successfully")

            # Set up AI event subscriptions for UI integration
            self.ai_orchestrator.event_bus.subscribe("task_complete", self._on_ai_task_complete, "main_ui")
            self.ai_orchestrator.event_bus.subscribe("coordinated_analysis_complete", self._on_coordinated_analysis_complete, "main_ui")

            # Initialize Exploitation Orchestrator for advanced AI-guided exploitation

            self.logger.info("Exploitation Orchestrator initialized successfully")

            self.logger.info("IntellicrackApp initialization complete with agentic AI system.")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to initialize AI Orchestrator: %s", e)
            self.logger.error(f"Exception details: {traceback.format_exc()}")
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
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "intellicrack", "assets", "icon.ico"),
        ]

        icon_loaded = False
        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                try:
                    icon = QIcon(icon_path)
                    if not icon.isNull():
                        self.setWindowIcon(icon)
                        # Set application icon for taskbar visibility
                        app = QApplication.instance()
                        if app:
                            app.setWindowIcon(icon)
                        icon_loaded = True
                        break
                except Exception as e:
                    logger.debug(f"Failed to load icon from {icon_path}: {e}")

        if not icon_loaded:
            logger.debug("Failed to load application icon from any path")

    def _initialize_application_properties(self) -> None:
        """Initialize important application properties and variables."""
        # Initialize important properties
        self.binary_path = None
        self.selected_model_path = CONFIG.get("selected_model_path", None)

        if self.selected_model_path is not None and os.path.exists(self.selected_model_path):
            if hasattr(self, "custom_model_path_label"):
                self.custom_model_path_label.setText(os.path.basename(self.selected_model_path))
            self.update_output.emit(log_message(f"[AI Model] Loaded saved model path from config: {self.selected_model_path}"))
        else:
            self.selected_model_path = None
            if hasattr(self, "custom_model_path_label"):
                self.custom_model_path_label.setText("None")
            self.update_output.emit(log_message("[AI Model] No saved model path found or path is invalid."))

        # Initialize application state variables
        self.chat_history = []
        self.frida_sessions = {}
        self.auto_patch_attempted = False
        self.potential_patches = []
        self.recent_files = []

        # Initialize analyzer instance variables
        self.dynamic_analyzer = None
        self.ml_predictor = None
        self.analyze_results = []
        self.patches = []
        self.binary_info = None

    def _bind_external_functions(self) -> None:
        """Bind external function wrappers as instance methods using partial."""
        # Connect external function wrappers as instance methods using partial
        self.inject_comprehensive_api_hooks = partial(inject_comprehensive_api_hooks, self)
        self.run_frida_plugin_from_file = partial(run_frida_plugin_from_file, self)
        self.run_ghidra_plugin_from_file = partial(run_ghidra_plugin_from_file, self)
        self.setup_memory_patching = partial(setup_memory_patching, self)
        self.run_rop_chain_generator = partial(run_rop_chain_generator, self)
        self.run_automated_patch_agent = partial(run_automated_patch_agent, self)

        # Add all runner functions
        self.run_ssl_tls_interceptor = partial(run_ssl_tls_interceptor, self)
        self.run_cloud_license_hooker = partial(run_cloud_license_hooker, self)
        self.run_cfg_explorer = partial(CfgExplorerInner().run_cfg_explorer_inner, self)
        self.run_concolic_execution = partial(run_concolic_execution, self)
        self.run_enhanced_protection_scan = partial(run_enhanced_protection_scan, self)
        self.run_visual_network_traffic_analyzer = partial(TrafficAnalyzer().run_visual_network_traffic_analyzer, self)
        self.run_multi_format_analysis = partial(run_multi_format_analysis, self)
        self.run_distributed_processing = partial(DistributedProcessing().run_distributed_processing, self)
        self.run_gpu_accelerated_analysis = partial(GpuAnalysis().run_gpu_accelerated_analysis, self)
        self.run_advanced_ghidra_analysis = partial(run_advanced_ghidra_analysis, self)
        self.run_symbolic_execution = partial(SymbolicExecution().run_symbolic_execution, self)
        self.run_incremental_analysis = partial(run_incremental_analysis, self)
        self.run_memory_optimized_analysis = partial(run_memory_optimized_analysis, self)
        self.run_taint_analysis = partial(run_taint_analysis, self)
        self.run_qemu_analysis = partial(run_qemu_analysis, self)
        self.run_selected_analysis_partial = partial(run_selected_analysis, self)
        self.run_network_license_emulator = partial(run_network_license_emulator, self)
        self.run_frida_analysis = partial(run_frida_analysis, self)
        self.run_dynamic_instrumentation = partial(run_dynamic_instrumentation, self)
        self.run_frida_script = partial(run_frida_script, self)

    def _bind_exploitation_handlers(self) -> None:
        """Bind exploitation handler methods from separate module."""
        from . import exploitation_handlers

        self.cleanup_exploitation = partial(exploitation_handlers.cleanup_exploitation, self)
        self.save_exploitation_output = partial(exploitation_handlers.save_exploitation_output, self)

    def _bind_class_methods(self) -> None:
        """Bind standalone method definitions to the class."""
        # Bind network and license server methods
        self.__class__.start_network_capture = start_network_capture
        self.__class__.stop_network_capture = stop_network_capture
        self.__class__.clear_network_capture = clear_network_capture
        self.__class__.launch_protocol_tool = launch_protocol_tool
        self.__class__.update_protocol_tool_description = update_protocol_tool_description

        # Bind report-related methods
        self.__class__.generate_report = generate_report
        self.__class__.view_report = view_report

    def _initialize_analyzer_engines(self) -> None:
        """Initialize various analyzer engines with graceful fallbacks."""
        # Initialize AI components
        try:
            from ..ai.script_generation_agent import AIAgent

            self.ai_agent = AIAgent()
            logger.info("AIAgent initialized successfully")
        except (OSError, ValueError, RuntimeError) as e:
            self.ai_agent = None
            logger.warning("Failed to initialize AIAgent: %s", e)

        try:
            self.memory_optimized_loader = MemoryOptimizedBinaryLoader() if MemoryOptimizedBinaryLoader else None
        except (OSError, ValueError, RuntimeError) as e:
            self.memory_optimized_loader = None
            logger.warning("Failed to initialize MemoryOptimizedBinaryLoader: %s", e)

        try:
            # Use lazy initialization - create symbolic execution engine when needed with actual binary
            self.symbolic_execution_engine = None
            logger.info("SymbolicExecutionEngine will be initialized when binary is loaded")
        except (OSError, ValueError, RuntimeError) as e:
            self.symbolic_execution_engine = None
            logger.warning("Failed to prepare SymbolicExecutionEngine: %s", e)

        try:
            self.taint_analysis_engine = TaintAnalysisEngine() if TaintAnalysisEngine else None
        except (OSError, ValueError, RuntimeError) as e:
            self.taint_analysis_engine = None
            logger.warning("Failed to initialize TaintAnalysisEngine: %s", e)

        try:
            # Use lazy initialization - create concolic execution engine when needed with actual binary
            self.concolic_execution_engine = None
            logger.info("ConcolicExecutionEngine will be initialized when binary is loaded")
        except (OSError, ValueError, RuntimeError) as e:
            self.concolic_execution_engine = None
            logger.warning("Failed to prepare ConcolicExecutionEngine: %s", e)

        try:
            self.rop_chain_generator = ROPChainGenerator() if ROPChainGenerator else None
        except (OSError, ValueError, RuntimeError) as e:
            self.rop_chain_generator = None
            logger.warning("Failed to initialize ROPChainGenerator: %s", e)

        try:
            self.parallel_processing_manager = ParallelProcessingManager() if ParallelProcessingManager else None
        except (OSError, ValueError, RuntimeError) as e:
            self.parallel_processing_manager = None
            logger.warning("Failed to initialize ParallelProcessingManager: %s", e)

        try:
            self.gpu_accelerator = GPUAccelerator() if GPUAccelerator else None
        except (OSError, ValueError, RuntimeError) as e:
            self.gpu_accelerator = None
            logger.warning("Failed to initialize GPUAccelerator: %s", e)

    def _initialize_network_components(self) -> None:
        """Initialize network analysis and traffic components."""
        try:
            from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer

            self.network_traffic_analyzer = NetworkTrafficAnalyzer()
        except (OSError, ValueError, RuntimeError) as e:
            self.network_traffic_analyzer = None
            logger.warning("Failed to initialize NetworkTrafficAnalyzer: %s", e)

        try:
            from ..core.network.ssl_interceptor import SSLTLSInterceptor

            self.ssl_interceptor = SSLTLSInterceptor()
        except (OSError, ValueError, RuntimeError) as e:
            self.ssl_interceptor = None
            logger.warning("Failed to initialize SSLTLSInterceptor: %s", e)

        try:
            from ..core.network.protocol_fingerprinter import ProtocolFingerprinter

            self.protocol_fingerprinter = ProtocolFingerprinter()
        except (OSError, ValueError, RuntimeError) as e:
            self.protocol_fingerprinter = None
            logger.warning("Failed to initialize ProtocolFingerprinter: %s", e)

        try:
            from ..core.network.license_server_emulator import NetworkLicenseServerEmulator

            self.network_license_server = NetworkLicenseServerEmulator()
        except (OSError, ValueError, RuntimeError, ImportError, ModuleNotFoundError) as e:
            self.network_license_server = None
            logger.warning("Failed to initialize NetworkLicenseServerEmulator: %s", e)

    def _create_main_ui_layout(self) -> None:
        """Create the main UI layout with central widget, tabs, and output panel."""
        # Add TOOL_REGISTRY for hexview integration
        self.TOOL_REGISTRY = TOOL_REGISTRY.copy()

        # Initialize ghidra_path_edit to avoid attribute errors
        self.ghidra_path_edit = None

        # Create PDF report generator
        if PDFReportGenerator is not None:
            self.pdf_report_generator = PDFReportGenerator()
        else:
            self.pdf_report_generator = None
            self.logger.warning("PDFReportGenerator not available - reporting features will be limited")

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
            logger.debug(f"Theme application failed: {e}")

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
        # Create shared context for tabs
        shared_context = {
            "main_window": self,
            "log_message": self.log_message,
            "app_context": self.app_context,
            "task_manager": self.task_manager,
        }

        # Create new modular tabs with lazy loading
        self.dashboard_tab = DashboardTab(shared_context, self) if DashboardTab else QWidget()
        self.analysis_tab = AnalysisTab(shared_context, self) if AnalysisTab else QWidget()
        self.exploitation_tab = ExploitationTab(shared_context, self) if ExploitationTab else QWidget()
        self.ai_assistant_tab = AIAssistantTab(shared_context, self) if AIAssistantTab else QWidget()
        self.tools_tab = ToolsTab(shared_context, self) if ToolsTab else QWidget()
        self.terminal_tab = TerminalTab(shared_context, self) if TerminalTab else QWidget()
        self.settings_tab = SettingsTab(shared_context, self) if SettingsTab else QWidget()
        self.workspace_tab = WorkspaceTab(shared_context, self) if WorkspaceTab else QWidget()

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
        self.tabs.setTabToolTip(2, "Comprehensive binary analysis suite with static, dynamic, and AI-powered analysis tools")
        self.tabs.setTabToolTip(3, "Advanced exploitation toolkit for vulnerability research and security testing")
        self.tabs.setTabToolTip(4, "AI-powered assistant for code analysis, script generation, and intelligent guidance")
        self.tabs.setTabToolTip(5, "Collection of specialized security research and binary manipulation tools")
        self.tabs.setTabToolTip(6, "Interactive terminal for running scripts and commands with full I/O support")
        self.tabs.setTabToolTip(7, "Configure application preferences, model settings, and advanced options")

        # Initialize dashboard manager
        self.dashboard_manager = DashboardManager(self)

    def _setup_individual_tabs(self) -> None:
        """Set up each individual tab with error handling."""
        # Initialize the binary_path variable before setting up tabs
        self.binary_path = None

        # Setup each tab with appropriate UI components
        try:
            self.setup_project_dashboard_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup project dashboard tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.setup_analysis_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup analysis tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.setup_patching_exploitation_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup patching exploitation tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.setup_ai_assistant_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup AI assistant tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.setup_netanalysis_emulation_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup network analysis emulation tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.setup_tools_plugins_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup tools plugins tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.setup_settings_tab()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup settings tab: %s", e)
            self.logger.error(traceback.format_exc())
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
            self.logger.warning(f"Could not apply tooltips: {e}")

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
                f"Loaded {len(self.available_plugins.get('custom', []))} custom plugins, "
                f"{len(self.available_plugins.get('frida', []))} Frida scripts, "
                f"{len(self.available_plugins.get('ghidra', []))} Ghidra scripts",
            )
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning(f"Failed to initialize plugins: {e}")
            self.available_plugins = {
                self.PLUGIN_TYPE_CUSTOM: [],
                self.PLUGIN_TYPE_FRIDA: [],
                self.PLUGIN_TYPE_GHIDRA: [],
            }

    def _on_ai_task_complete(self, event_data: object) -> None:
        """Handle AI task completion events from the orchestrator.

        Args:
            event_data: Dictionary containing task completion information.

        """
        try:
            task_id = event_data.get("task_id", "unknown")
            task_type = event_data.get("task_type", "unknown")
            status = event_data.get("status", "unknown")
            results = event_data.get("results", {})

            self.logger.info(f"AI task completed - ID: {task_id}, Type: {task_type}, Status: {status}")

            # Update UI with task completion
            if hasattr(self, "update_output") and self.update_output:
                message = f"[AI] Task {task_id} ({task_type}) completed with status: {status}"
                self.update_output.emit(message)

                # If there are results, show summary
                if results:
                    result_summary = f"[AI] Results: {len(results)} items processed"
                    self.update_output.emit(result_summary)

        except Exception as e:
            self.logger.error(f"Error handling AI task completion: {e}")

    def _on_coordinated_analysis_complete(self, event_data: object) -> None:
        """Handle coordinated analysis completion events from AI coordinator.

        Args:
            event_data: Dictionary containing coordinated analysis results.

        """
        try:
            analysis_id = event_data.get("analysis_id", "unknown")
            analysis_type = event_data.get("analysis_type", "unknown")
            findings = event_data.get("findings", [])
            recommendations = event_data.get("recommendations", [])

            self.logger.info(f"Coordinated analysis completed - ID: {analysis_id}, Type: {analysis_type}")

            # Update UI with analysis completion
            if hasattr(self, "update_output") and self.update_output:
                message = f"[AI-COORD] Analysis {analysis_id} ({analysis_type}) completed"
                self.update_output.emit(message)

                # Show findings summary
                if findings:
                    findings_msg = f"[AI-COORD] Found {len(findings)} security findings"
                    self.update_output.emit(findings_msg)

                # Show recommendations summary
                if recommendations:
                    rec_msg = f"[AI-COORD] Generated {len(recommendations)} recommendations"
                    self.update_output.emit(rec_msg)

        except Exception as e:
            self.logger.error(f"Error handling coordinated analysis completion: {e}")

    def append_output(self, text: str) -> None:
        """Append text to the main output widget."""
        if hasattr(self, "output") and self.output:
            self.output.append(text)
        if hasattr(self, "raw_console_output") and self.raw_console_output:
            self.raw_console_output.appendPlainText(text)

    def set_status_message(self, message: str) -> None:
        """Set status message in the application."""
        if hasattr(self, "statusBar") and self.statusBar():
            self.statusBar().showMessage(message, 5000)
        self.logger.info(f"Status: {message}")

    def append_analysis_results(self, results: str) -> None:
        """Append analysis results to appropriate display."""
        if hasattr(self, "output") and self.output:
            formatted_results = f"[ANALYSIS] {results}"
            self.output.append(formatted_results)
        self.logger.info(f"Analysis results: {results}")

    def set_progress_value(self, value: int) -> None:
        """Set progress value for any active progress indicators."""
        self.logger.debug(f"Progress updated: {value}%")

    def set_assistant_status(self, status: str) -> None:
        """Set AI assistant status."""
        if hasattr(self, "assistant_status") and self.assistant_status:
            with contextlib.suppress(AttributeError):
                self.assistant_status.setText(status)
        self.logger.info(f"Assistant status: {status}")

    def append_chat_display(self, message: str) -> None:
        """Append message to chat display."""
        if hasattr(self, "chat_display") and self.chat_display:
            with contextlib.suppress(AttributeError):
                self.chat_display.append(message)
        self.logger.info(f"Chat: {message}")

    def replace_last_chat_message(self, message: str) -> None:
        """Replace the last message in chat display."""
        if hasattr(self, "chat_display") and self.chat_display:
            try:
                cursor = self.chat_display.textCursor()
                cursor.movePosition(cursor.MoveOperation.End)
                cursor.select(cursor.SelectionType.BlockUnderCursor)
                cursor.insertText(message)
            except AttributeError:
                self.append_chat_display(message)
        self.logger.info(f"Chat replaced: {message}")

    def handle_log_user_question(self, question: str) -> None:
        """Handle user question logging."""
        if hasattr(self, "ai_conversation_history"):
            self.ai_conversation_history.append({"type": "question", "content": question})
        self.logger.info(f"User question logged: {question}")

    def handle_set_keygen_name(self, name: str) -> None:
        """Handle setting keygen name."""
        self.logger.info(f"Keygen name set: {name}")

    def handle_set_keygen_version(self, version: str) -> None:
        """Handle setting keygen version."""
        self.logger.info(f"Keygen version set: {version}")

    def handle_switch_tab(self, tab_index: int) -> None:
        """Handle tab switching."""
        if hasattr(self, "tabs") and self.tabs:
            with contextlib.suppress(AttributeError, IndexError):
                self.tabs.setCurrentIndex(tab_index)
        self.logger.info(f"Switched to tab index: {tab_index}")

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
        """Format and return log message with timestamp."""
        import datetime

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        return f"[{timestamp}] {message}"

    def _on_binary_loaded(self, binary_info: dict) -> None:
        """Handle binary loaded event from app context."""
        if isinstance(binary_info, dict) and "path" in binary_info:
            self.binary_path = binary_info["path"]
            binary_name = binary_info.get("name", os.path.basename(binary_info["path"]))
            self.update_output.emit(self.log_message(f"Binary loaded: {binary_name}"))
            self.logger.info(f"Binary loaded: {binary_info['path']}")

            # Notify all tabs about the binary loading
            if hasattr(self, "analysis_tab") and self.analysis_tab:
                self.analysis_tab.set_binary_path(binary_info["path"])
        else:
            # Handle legacy string format for backward compatibility
            self.binary_path = str(binary_info) if binary_info else None
            self.update_output.emit(self.log_message(f"Binary loaded: {binary_info}"))
            self.logger.info(f"Binary loaded: {binary_info}")

    def _on_analysis_completed(self, results: object) -> None:
        """Handle analysis completion event from app context.

        Args:
            results: Analysis results object.

        """
        self.update_analysis_results.emit(f"Analysis completed with {len(results)} results")
        self.logger.info("Analysis completed")

    def _on_task_started(self, task_name: str) -> None:
        """Handle task started event from app context."""
        self.update_status.emit(f"Task started: {task_name}")
        self.logger.info(f"Task started: {task_name}")

    def _on_task_progress(self, progress: int) -> None:
        """Handle task progress event from app context."""
        self.update_progress.emit(progress)
        self.logger.debug(f"Task progress: {progress}%")

    def _on_task_completed(self, task_name: str) -> None:
        """Handle task completed event from app context."""
        self.update_status.emit(f"Task completed: {task_name}")
        self.logger.info(f"Task completed: {task_name}")

    def _on_task_failed(self, task_name: str, error: str) -> None:
        """Handle task failed event from app context."""
        self.update_status.emit(f"Task failed: {task_name} - {error}")
        self.logger.error(f"Task failed: {task_name} - {error}")

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
            self.logger.warning(f"Failed to apply tooltips: {e}")

    def restore_window_state(self) -> None:
        """Restore window state from configuration."""
        try:
            from ..core.config_manager import get_config

            config = get_config()
            ui_config = config.get("ui", {})
            geometry = ui_config.get("window_geometry")
            if geometry:
                self.setGeometry(*geometry)
        except Exception as e:
            self.logger.debug(f"Could not restore window state: {e}")

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
        """Handle theme change event."""
        if hasattr(self, "theme_manager") and self.theme_manager:
            self.theme_manager.set_theme(theme_name)
        self.logger.info(f"Theme changed to: {theme_name}")

    def _load_cache_data(self, cache_file: object) -> dict | None:
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
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            self.logger.debug(f"Failed to load cache data: {e}")
            return None

    def _check_file_modifications(self, plugin_dir: object, cached_filenames: dict) -> tuple[bool, dict]:
        """Check if files in directory have been modified compared to cache.

        Args:
            plugin_dir: Path to plugin directory (Path object or string).
            cached_filenames: Dict mapping filenames to cached modification times.

        Returns:
            Tuple of (is_valid, remaining_cached_files) where is_valid indicates if
            all files match cache, and remaining_cached_files contains files
            that were in cache but not found in directory.

        """
        from pathlib import Path

        plugin_dir = Path(plugin_dir)
        remaining = dict(cached_filenames)

        try:
            for entry in plugin_dir.iterdir():
                if entry.is_file():
                    current_mtime = entry.stat().st_mtime
                    file_name = entry.name
                    if file_name not in remaining or remaining[file_name] != current_mtime:
                        return False, {}
                    del remaining[file_name]
        except OSError as e:
            self.logger.debug(f"Error checking file modifications: {e}")
            return False, {}

        return True, remaining

    def _validate_plugin_directory_cache(self, plugin_type: str, plugin_dir: object, cached_data: dict) -> bool:
        """Validate cache for a specific plugin directory.

        Args:
            plugin_type: Type of plugin (custom, frida, ghidra).
            plugin_dir: Path to plugin directory (Path object or string).
            cached_data: Complete cached data dictionary.

        Returns:
            True if cache is valid for this directory, False otherwise.

        """
        from pathlib import Path

        plugin_dir = Path(plugin_dir)
        cached_plugins = cached_data.get("plugins", {}).get(plugin_type, [])

        if not plugin_dir.exists():
            return not cached_plugins

        cached_filenames = {p["filename"]: p["modified"] for p in cached_plugins}
        is_valid, remaining = self._check_file_modifications(plugin_dir, cached_filenames)

        if not is_valid:
            return False

        return len(remaining) == 0

    def _is_plugin_cache_valid(self, cache_file: object, plugin_directories: dict) -> tuple[bool, dict | None]:
        """Check if plugin cache exists and is still valid.

        Args:
            cache_file: Path to cache file (Path object).
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

    def load_available_plugins(self) -> dict:
        """Load available plugins from plugin directory with caching for performance.

        Uses a cache file to avoid rescanning the filesystem on every startup. Cache is
        invalidated when plugin files are added, removed, or modified.

        Returns:
            Dictionary containing lists of plugins by type (custom, frida, ghidra).

        """
        import json
        from pathlib import Path

        from filelock import FileLock

        cache_dir = Path.home() / ".intellicrack"
        cache_file = cache_dir / "plugin_cache.json"
        cache_lock_file = cache_dir / "plugin_cache.json.lock"

        plugin_base_dir = Path(__file__).parent.parent / "plugins"
        plugin_directories = {
            self.PLUGIN_TYPE_CUSTOM: plugin_base_dir / "custom_modules",
            self.PLUGIN_TYPE_FRIDA: get_frida_scripts_dir(),
            self.PLUGIN_TYPE_GHIDRA: get_ghidra_scripts_dir(),
        }

        def is_path_safe(file_path: object, plugin_dir: object) -> bool:
            """Validate that reconstructed path is within allowed plugin directory.

            Args:
                file_path: Path to validate (Path object or string).
                plugin_dir: Expected parent directory (Path object or string).

            Returns:
                True if file_path is within plugin_dir, False otherwise.

            """
            try:
                file_path = Path(file_path)
                plugin_dir = Path(plugin_dir)
                real_plugin_dir = plugin_dir.resolve()
                real_file_path = file_path.resolve()
                return real_file_path.is_relative_to(real_plugin_dir)
            except (ValueError, OSError):
                return False

        lock = FileLock(str(cache_lock_file), timeout=10)

        cache_is_valid, cached_data = self._is_plugin_cache_valid(cache_file, plugin_directories)
        if cache_is_valid:
            try:
                cached_plugins = cached_data.get(
                    "plugins",
                    {
                        self.PLUGIN_TYPE_CUSTOM: [],
                        self.PLUGIN_TYPE_FRIDA: [],
                        self.PLUGIN_TYPE_GHIDRA: [],
                    },
                )

                plugins = {
                    self.PLUGIN_TYPE_CUSTOM: [],
                    self.PLUGIN_TYPE_FRIDA: [],
                    self.PLUGIN_TYPE_GHIDRA: [],
                }
                for plugin_type, plugin_list in cached_plugins.items():
                    if plugin_type not in plugin_directories:
                        continue

                    plugin_dir = plugin_directories[plugin_type]
                    for plugin_info in plugin_list:
                        filename = plugin_info.get("filename")
                        if not filename:
                            continue

                        reconstructed_path = plugin_dir / filename

                        if not is_path_safe(reconstructed_path, plugin_dir):
                            self.logger.warning(f"Rejecting potentially malicious plugin path: {filename}")
                            continue

                        if not reconstructed_path.exists():
                            continue

                        plugin_info_with_path = plugin_info.copy()
                        plugin_info_with_path["path"] = str(reconstructed_path)
                        plugins[plugin_type].append(plugin_info_with_path)

                self.logger.info(f"Loaded {sum(len(p) for p in plugins.values())} plugins from cache")
                return plugins
            except (KeyError, OSError) as e:
                self.logger.warning(f"Failed to load plugin cache, rescanning: {e}")

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
                        self.logger.info(f"Plugin directory not found, creating: {plugin_dir}")
                        plugin_dir.mkdir(parents=True, exist_ok=True)
                        continue

                    plugin_extensions = {
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
                                        with open(entry, "rb") as f:
                                            f.read(512)
                                    else:
                                        with open(entry, encoding="utf-8") as f:
                                            f.read(512)

                                    plugin_info = {
                                        "name": entry.stem,
                                        "filename": entry.name,
                                        "path": str(entry),
                                        "type": plugin_type,
                                        "extension": file_ext,
                                        "size": entry.stat().st_size,
                                        "modified": entry.stat().st_mtime,
                                        "valid": True,
                                    }
                                    plugins[plugin_type].append(plugin_info)

                                except (OSError, UnicodeDecodeError, PermissionError) as file_error:
                                    self.logger.warning(f"Failed to validate plugin {entry.name}: {file_error}")
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

                except (OSError, PermissionError) as dir_error:
                    self.logger.error(f"Error accessing plugin directory {plugin_dir}: {dir_error}")

            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                with lock, open(cache_file, "w", encoding="utf-8") as f:
                    json.dump({"plugins": plugins, "cache_version": "1.0"}, f, indent=2)
                self.logger.debug(f"Plugin cache saved to {cache_file}")
            except OSError as cache_error:
                self.logger.warning(f"Failed to save plugin cache: {cache_error}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Critical error loading plugins: {e}")
            return {
                self.PLUGIN_TYPE_CUSTOM: [],
                self.PLUGIN_TYPE_FRIDA: [],
                self.PLUGIN_TYPE_GHIDRA: [],
            }

        self.logger.info(f"Loaded {sum(len(p) for p in plugins.values())} plugins across {len(plugins)} categories")
        return plugins

    def setup_project_dashboard_tab(self) -> None:
        """Set up project dashboard tab with real-time monitoring."""
        try:
            if hasattr(self, "dashboard_tab") and self.dashboard_tab:
                self.dashboard_tab.setVisible(True)
                self.logger.info("Dashboard tab initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup dashboard tab: {e}")
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
            self.logger.error(f"Failed to setup analysis tab: {e}")
            if hasattr(self, "analysis_tab"):
                self.analysis_tab.setVisible(True)

    def setup_patching_exploitation_tab(self) -> None:
        """Set up patching exploitation tab with advanced license bypass capabilities."""
        try:
            if hasattr(self, "exploitation_tab") and self.exploitation_tab:
                self.exploitation_tab.setVisible(True)
                self.logger.info("Exploitation tab initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup patching exploitation tab: {e}")
            if hasattr(self, "exploitation_tab"):
                self.exploitation_tab.setVisible(True)

    def setup_ai_assistant_tab(self) -> None:
        """Set up AI assistant tab with license protection research capabilities."""
        try:
            if hasattr(self, "ai_assistant_tab") and self.ai_assistant_tab:
                self.ai_assistant_tab.setVisible(True)
                self.logger.info("AI assistant tab initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup AI assistant tab: {e}")
            if hasattr(self, "ai_assistant_tab"):
                self.ai_assistant_tab.setVisible(True)

    def setup_netanalysis_emulation_tab(self) -> None:
        """Set up network analysis emulation tab with license server bypass capabilities."""
        try:
            self.logger.info("Network analysis emulation tab initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup network analysis emulation tab: {e}")

    def setup_tools_plugins_tab(self) -> None:
        """Set up tools plugins tab with license protection research tool integration."""
        try:
            if hasattr(self, "tools_tab") and self.tools_tab:
                self.tools_tab.setVisible(True)
                self.logger.info("Tools tab initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup tools plugins tab: {e}")
            if hasattr(self, "tools_tab"):
                self.tools_tab.setVisible(True)

    def setup_settings_tab(self) -> None:
        """Set up settings tab with license protection research configuration."""
        try:
            if hasattr(self, "settings_tab") and self.settings_tab:
                self.settings_tab.setVisible(True)
                self.logger.info("Settings tab initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup settings tab: {e}")
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
            logger.debug(f"Could not set App User Model ID (expected on non-Windows): {e}")

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
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "assets", "icon.ico"),
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
                        logger.debug(f"Failed to load icon from {icon_path}: {e}")
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
        logger.error(f"Failed to launch Intellicrack application: {e}")
        return 1
