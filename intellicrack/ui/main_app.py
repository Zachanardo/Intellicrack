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

import logging
import os
import traceback
from functools import partial

from intellicrack.ai.model_manager_module import ModelManager
from intellicrack.config import CONFIG
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
from intellicrack.core.network.cloud_license_hooker import run_cloud_license_hooker
from intellicrack.core.network.protocol_tool import (
    launch_protocol_tool,
    update_protocol_tool_description,
)
from intellicrack.core.patching.memory_patcher import setup_memory_patching
from intellicrack.core.processing.distributed_manager import DistributedProcessingManager
from intellicrack.core.processing.gpu_accelerator import GPUAccelerator
from intellicrack.core.processing.memory_loader import (
    MemoryOptimizedBinaryLoader,
    run_memory_optimized_analysis,
)
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
from intellicrack.utils.log_message import log_message
from intellicrack.utils.protection_utils import inject_comprehensive_api_hooks
from intellicrack.utils.resource_helper import get_resource_path

logger = logging.getLogger(__name__)


class IntellicrackApp(QMainWindow):
    """Main application window for Intellicrack, a comprehensive binary analysis and security research toolkit.

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
            autonomous_agent: Autonomous analysis agent
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
            distributed_processing_manager: Distributed processing manager
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

    def __init__(self):
        """Initialize the main Intellicrack application window.

        Sets up the logger, model manager, and other core components.
        """
        super().__init__()
        print("[INIT] IntellicrackApp.__init__ started")

        # Initialize UI attributes first
        self._initialize_ui_attributes()

        print("[INIT] Calling super().__init__()...")
        super().__init__()
        print("[INIT] super().__init__() completed")

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

        print("[INIT] IntellicrackApp.__init__ completed")

    def _initialize_ui_attributes(self):
        """Initialize all UI-related attributes to None."""
        print("[INIT] Initializing UI attributes...")

        # UI component attributes
        self.activity_log = None
        self.assistant_status = None
        self.assistant_tab = None
        self.binary_info_group = None
        self.binary_tool_file_info = None
        self.binary_tool_file_label = None
        self.binary_tool_stack = None
        self.capture_thread = None
        self.chat_display = None
        self.debug_check = None
        self.disasm_text = None
        self.edit_current_btn = None
        self.error_check = None
        self.info_check = None
        self.last_log_accessed = None
        self.log_filter = None
        self.log_output = None
        self.notifications_list = None
        self.packet_update_timer = None
        self.plugin_name_label = None
        self.program_info = None
        self.recent_files_list = None
        self.report_viewer = None
        self.traffic_analyzer = None
        self.user_input = None
        self.view_current_btn = None
        self.warning_check = None

        # Collection attributes
        self._hex_viewer_dialogs = []
        self.ai_conversation_history = []
        self.log_access_history = []
        self.reports = []

        print("[INIT] UI attributes initialized")

    def _initialize_core_components(self):
        """Initialize core application components and managers."""
        print("[INIT] Initializing core components...")

        # Initialize logger first
        self.logger = logging.getLogger("IntellicrackLogger.Main")
        self.logger.debug("QMainWindow initialized")
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

        print("[INIT] Core components initialized")

    def _initialize_ai_orchestrator(self):
        """Initialize AI orchestration and coordination components."""
        print("[INIT] Initializing AI Orchestrator...")

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

    def _connect_signals(self):
        """Connect all Qt signals to their respective slots."""
        print("[INIT] Connecting signals...")

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

        print("[INIT] Signals connected")

    def _setup_main_window_properties(self):
        """Set up main window properties, geometry, and icon."""
        print("[INIT] Setting up main window properties...")

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
                        print(f"[INIT] Icon loaded successfully from: {icon_path}")
                        icon_loaded = True
                        break
                except Exception as e:
                    print(f"[INIT] Failed to load icon from {icon_path}: {e}")

        if not icon_loaded:
            print("[INIT] Failed to load application icon from any path")

        print("[INIT] Main window properties set")

    def _initialize_application_properties(self):
        """Initialize important application properties and variables."""
        print("[INIT] Initializing application properties...")

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

        print("[INIT] Application properties initialized")

    def _bind_external_functions(self):
        """Bind external function wrappers as instance methods using partial."""
        print("[INIT] Binding external functions...")

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

        print("[INIT] External functions bound")

    def _bind_exploitation_handlers(self):
        """Bind exploitation handler methods from separate module."""
        print("[INIT] Binding exploitation handlers...")

        from . import exploitation_handlers

        self.cleanup_exploitation = partial(exploitation_handlers.cleanup_exploitation, self)
        self.save_exploitation_output = partial(exploitation_handlers.save_exploitation_output, self)

        print("[INIT] Exploitation handlers bound")

    def _bind_class_methods(self):
        """Bind standalone method definitions to the class."""
        print("[INIT] Binding class methods...")

        # Bind network and license server methods
        self.__class__.start_network_capture = start_network_capture
        self.__class__.stop_network_capture = stop_network_capture
        self.__class__.clear_network_capture = clear_network_capture
        self.__class__.launch_protocol_tool = launch_protocol_tool
        self.__class__.update_protocol_tool_description = update_protocol_tool_description

        # Bind report-related methods
        self.__class__.generate_report = generate_report
        self.__class__.view_report = view_report

        print("[INIT] Class methods bound")

    def _initialize_analyzer_engines(self):
        """Initialize various analyzer engines with graceful fallbacks."""
        print("[INIT] Initializing analyzer engines...")

        # Initialize AI components
        try:
            from ..ai.autonomous_agent import AutonomousAgent

            self.autonomous_agent = AutonomousAgent()
            logger.info("AutonomousAgent initialized successfully")
        except (OSError, ValueError, RuntimeError) as e:
            self.autonomous_agent = None
            logger.warning("Failed to initialize AutonomousAgent: %s", e)

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
            self.distributed_processing_manager = DistributedProcessingManager() if DistributedProcessingManager else None
        except (OSError, ValueError, RuntimeError) as e:
            self.distributed_processing_manager = None
            logger.warning("Failed to initialize DistributedProcessingManager: %s", e)

        try:
            self.gpu_accelerator = GPUAccelerator() if GPUAccelerator else None
        except (OSError, ValueError, RuntimeError) as e:
            self.gpu_accelerator = None
            logger.warning("Failed to initialize GPUAccelerator: %s", e)

        print("[INIT] Analyzer engines initialized")

    def _initialize_network_components(self):
        """Initialize network analysis and traffic components."""
        print("[INIT] Initializing network components...")

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

        print("[INIT] Network components initialized")

    def _create_main_ui_layout(self):
        """Create the main UI layout with central widget, tabs, and output panel."""
        print("[INIT] Creating main UI layout...")

        # Add TOOL_REGISTRY for hexview integration
        self.TOOL_REGISTRY = TOOL_REGISTRY.copy()

        # Initialize ghidra_path_edit to avoid attribute errors
        self.ghidra_path_edit = None

        # Create PDF report generator
        print("[INIT] Creating PDFReportGenerator...")
        if PDFReportGenerator is not None:
            self.pdf_report_generator = PDFReportGenerator()
            print("[INIT] PDFReportGenerator created")
        else:
            self.pdf_report_generator = None
            print("[INIT] PDFReportGenerator not available - reporting features limited")
            self.logger.warning("PDFReportGenerator not available - reporting features will be limited")

        # Create central widget and layout
        print("[INIT] Creating central widget...")
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        print("[INIT] Central widget created")

        print("[INIT] Creating main layout...")
        self.main_layout = QVBoxLayout(self.central_widget)
        print("[INIT] Main layout created")

        print("[INIT] Creating toolbar...")
        self.create_toolbar()
        print("[INIT] Toolbar created")

        print("[INIT] Creating main splitter...")
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        print("[INIT] Adding splitter to layout...")
        self.main_layout.addWidget(self.main_splitter)
        print("[INIT] Splitter added to layout")

        print("[INIT] Main UI layout created")

    def _setup_tabs_and_themes(self):
        """Set up tab widget and apply themes."""
        print("[INIT] Setting up tabs and themes...")

        print("[INIT] Creating tab widget...")
        self.tabs = QTabWidget()
        print("[INIT] Tab widget created")

        # Style main tabs differently from sub-tabs to avoid visual confusion
        print("[INIT] Setting tab position...")
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        print("[INIT] Setting tabs closable...")
        self.tabs.setTabsClosable(False)

        print("[INIT] Applying theme stylesheet...")
        try:
            # Initialize and apply theme using ThemeManager
            self.theme_manager = get_theme_manager()
            self.theme_manager.set_theme(self.theme_manager.get_current_theme())
            print(f"[INIT] Theme '{self.theme_manager.get_current_theme()}' applied successfully")

            # Initialize icon manager for consistent iconography
            self.icon_manager = IconManager()
            print("[INIT] Icon manager initialized successfully")
        except Exception as e:
            print(f"[INIT] Failed to apply theme: {e}")
            pass

        print("[INIT] Setting additional tab properties...")
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setTabsClosable(False)
        print("[INIT] Tab properties set")

        print("[INIT] Adding tabs to splitter...")
        self.main_splitter.addWidget(self.tabs)
        print("[INIT] Tabs added to splitter")

        print("[INIT] Tabs and themes setup complete")

    def _create_output_panel(self):
        """Create the output panel with console and clear functionality."""
        print("[INIT] Creating output panel...")

        self.output_panel = QWidget()
        print("[INIT] Output panel created")

        print("[INIT] Creating output layout...")
        self.output_layout = QVBoxLayout(self.output_panel)

        print("[INIT] Creating output text widget...")
        self.output = QTextEdit()
        print("[INIT] Setting output readonly...")
        self.output.setReadOnly(True)

        print("[INIT] Creating raw console output widget...")
        self.raw_console_output = QPlainTextEdit()
        self.raw_console_output.setReadOnly(True)
        self.raw_console_output.setMaximumBlockCount(1000)

        print("[INIT] Creating clear button...")
        self.clear_output_btn = QPushButton("Clear Output")
        print("[INIT] Connecting clear button...")
        self.clear_output_btn.clicked.connect(self.clear_output)

        print("[INIT] Adding widgets to output layout...")
        self.output_layout.addWidget(QLabel("<b>Output</b>"))
        self.output_layout.addWidget(self.output)
        self.output_layout.addWidget(QLabel("<b>Raw Console</b>"))
        self.output_layout.addWidget(self.raw_console_output)
        self.output_layout.addWidget(self.clear_output_btn)
        print("[INIT] Output layout complete")

        print("[INIT] Adding output panel to splitter...")
        self.main_splitter.addWidget(self.output_panel)
        print("[INIT] Setting splitter sizes...")
        self.main_splitter.setSizes([700, 500])
        print("[INIT] Splitter configuration complete")

    def _create_modular_tabs(self):
        """Create all modular tab instances with shared context."""
        print("[INIT] Creating modular tabs...")

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

        print("[INIT] Modular tabs created")

    def _setup_individual_tabs(self):
        """Set up each individual tab with error handling."""
        print("[INIT] Setting up individual tabs...")

        # Initialize the binary_path variable before setting up tabs
        self.binary_path = None

        # Setup each tab with appropriate UI components
        try:
            self.logger.info("Setting up project dashboard tab...")
            self.setup_project_dashboard_tab()
            self.logger.info("Project dashboard tab setup complete")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup project dashboard tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.logger.info("Setting up analysis tab...")
            self.setup_analysis_tab()
            self.logger.info("Analysis tab setup complete")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup analysis tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.logger.info("Setting up patching exploitation tab...")
            self.setup_patching_exploitation_tab()
            self.logger.info("Patching exploitation tab setup complete")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup patching exploitation tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.logger.info("Setting up AI assistant tab...")
            self.setup_ai_assistant_tab()
            self.logger.info("AI assistant tab setup complete")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup AI assistant tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.logger.info("Setting up network analysis emulation tab...")
            self.setup_netanalysis_emulation_tab()
            self.logger.info("Network analysis emulation tab setup complete")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup network analysis emulation tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.logger.info("Setting up tools plugins tab...")
            self.setup_tools_plugins_tab()
            self.logger.info("Tools plugins tab setup complete")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup tools plugins tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        try:
            self.logger.info("Setting up settings tab...")
            self.setup_settings_tab()
            self.logger.info("Settings tab setup complete")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to setup settings tab: %s", e)
            self.logger.error(traceback.format_exc())
            raise

        self.logger.info("All tab setup complete - constructor finished")
        print("[INIT] Individual tabs setup complete")

    def _finalize_ui_initialization(self):
        """Finalize UI initialization with tooltips, plugins, and final configuration."""
        print("[INIT] Finalizing UI initialization...")

        # Register terminal manager with main app
        from intellicrack.core.terminal_manager import get_terminal_manager

        terminal_mgr = get_terminal_manager()
        terminal_mgr.set_main_app(self)
        self.logger.info("Terminal manager registered with main app")

        # Mark UI as initialized
        self._ui_initialized = True
        self.logger.info("UI initialization complete")

        # Apply comprehensive tooltips to all buttons
        try:
            self.apply_comprehensive_tooltips()
            self.logger.info("Applied tooltips to UI elements")
        except (AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) as e:
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
                f"{len(self.available_plugins.get('ghidra', []))} Ghidra scripts"
            )
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning(f"Failed to initialize plugins: {e}")
            self.available_plugins = {"custom": [], "frida": [], "ghidra": []}

        self.logger.info("IntellicrackApp.__init__ completed successfully")
        print("[INIT] UI initialization finalized")

    def _on_ai_task_complete(self, event_data):
        """Handle AI task completion events from the orchestrator.

        Args:
            event_data: Dictionary containing task completion information

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

    def _on_coordinated_analysis_complete(self, event_data):
        """Handle coordinated analysis completion events from AI coordinator.

        Args:
            event_data: Dictionary containing coordinated analysis results

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

    def append_output(self, text: str):
        """Append text to the main output widget."""
        if hasattr(self, "output") and self.output:
            self.output.append(text)
        if hasattr(self, "raw_console_output") and self.raw_console_output:
            self.raw_console_output.appendPlainText(text)

    def set_status_message(self, message: str):
        """Set status message in the application."""
        if hasattr(self, "statusBar") and self.statusBar():
            self.statusBar().showMessage(message, 5000)
        self.logger.info(f"Status: {message}")

    def append_analysis_results(self, results: str):
        """Append analysis results to appropriate display."""
        if hasattr(self, "output") and self.output:
            formatted_results = f"[ANALYSIS] {results}"
            self.output.append(formatted_results)
        self.logger.info(f"Analysis results: {results}")

    def set_progress_value(self, value: int):
        """Set progress value for any active progress indicators."""
        self.logger.debug(f"Progress updated: {value}%")

    def set_assistant_status(self, status: str):
        """Set AI assistant status."""
        if hasattr(self, "assistant_status") and self.assistant_status:
            try:
                self.assistant_status.setText(status)
            except AttributeError:
                pass
        self.logger.info(f"Assistant status: {status}")

    def append_chat_display(self, message: str):
        """Append message to chat display."""
        if hasattr(self, "chat_display") and self.chat_display:
            try:
                self.chat_display.append(message)
            except AttributeError:
                pass
        self.logger.info(f"Chat: {message}")

    def replace_last_chat_message(self, message: str):
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

    def handle_log_user_question(self, question: str):
        """Handle user question logging."""
        if hasattr(self, "ai_conversation_history"):
            self.ai_conversation_history.append({"type": "question", "content": question})
        self.logger.info(f"User question logged: {question}")

    def handle_set_keygen_name(self, name: str):
        """Handle setting keygen name."""
        self.logger.info(f"Keygen name set: {name}")

    def handle_set_keygen_version(self, version: str):
        """Handle setting keygen version."""
        self.logger.info(f"Keygen version set: {version}")

    def handle_switch_tab(self, tab_index: int):
        """Handle tab switching."""
        if hasattr(self, "tabs") and self.tabs:
            try:
                self.tabs.setCurrentIndex(tab_index)
            except (AttributeError, IndexError):
                pass
        self.logger.info(f"Switched to tab index: {tab_index}")

    def handle_generate_key(self):
        """Handle key generation request."""
        self.logger.info("Key generation requested")

    def clear_output(self):
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

    def _on_binary_loaded(self, binary_info: dict):
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

    def _on_analysis_completed(self, results):
        """Handle analysis completion event from app context."""
        self.update_analysis_results.emit(f"Analysis completed with {len(results)} results")
        self.logger.info("Analysis completed")

    def _on_task_started(self, task_name: str):
        """Handle task started event from app context."""
        self.update_status.emit(f"Task started: {task_name}")
        self.logger.info(f"Task started: {task_name}")

    def _on_task_progress(self, progress: int):
        """Handle task progress event from app context."""
        self.update_progress.emit(progress)
        self.logger.debug(f"Task progress: {progress}%")

    def _on_task_completed(self, task_name: str):
        """Handle task completed event from app context."""
        self.update_status.emit(f"Task completed: {task_name}")
        self.logger.info(f"Task completed: {task_name}")

    def _on_task_failed(self, task_name: str, error: str):
        """Handle task failed event from app context."""
        self.update_status.emit(f"Task failed: {task_name} - {error}")
        self.logger.error(f"Task failed: {task_name} - {error}")

    def apply_comprehensive_tooltips(self):
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

    def restore_window_state(self):
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

    def _initialize_font_manager(self):
        """Initialize custom fonts."""
        self.logger.debug("Font manager initialized")

    def create_toolbar(self):
        """Create application toolbar."""
        from PyQt6.QtWidgets import QToolBar

        toolbar = QToolBar("Main Toolbar", self)
        self.addToolBar(toolbar)
        self.logger.debug("Toolbar created")

    def on_theme_changed(self, theme_name: str):
        """Handle theme change event."""
        if hasattr(self, "theme_manager") and self.theme_manager:
            self.theme_manager.set_theme(theme_name)
        self.logger.info(f"Theme changed to: {theme_name}")

    def load_available_plugins(self):
        """Load available plugins from plugin directory with comprehensive error handling."""
        plugins = {"custom": [], "frida": [], "ghidra": []}

        try:
            # Get plugin directories from configuration
            plugin_base_dir = os.path.join(os.path.dirname(__file__), "..", "plugins")
            plugin_directories = {
                "custom": os.path.join(plugin_base_dir, "custom_modules"),
                "frida": os.path.join(plugin_base_dir, "frida_scripts"),
                "ghidra": os.path.join(plugin_base_dir, "ghidra_scripts"),
            }

            for plugin_type, plugin_dir in plugin_directories.items():
                try:
                    if not os.path.exists(plugin_dir):
                        self.logger.info(f"Plugin directory not found, creating: {plugin_dir}")
                        os.makedirs(plugin_dir, exist_ok=True)
                        continue

                    # Scan for plugin files
                    plugin_extensions = {"custom": [".py", ".pyd", ".dll"], "frida": [".js", ".ts"], "ghidra": [".py", ".java", ".jar"]}

                    for file_path in os.listdir(plugin_dir):
                        full_path = os.path.join(plugin_dir, file_path)
                        if os.path.isfile(full_path):
                            file_ext = os.path.splitext(file_path)[1].lower()
                            if file_ext in plugin_extensions.get(plugin_type, []):
                                try:
                                    # Validate plugin file
                                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                        f.read(512)  # Read first 512 chars for validation

                                    plugin_info = {
                                        "name": os.path.splitext(file_path)[0],
                                        "path": full_path,
                                        "type": plugin_type,
                                        "extension": file_ext,
                                        "size": os.path.getsize(full_path),
                                        "modified": os.path.getmtime(full_path),
                                        "valid": True,
                                    }
                                    plugins[plugin_type].append(plugin_info)

                                except (OSError, UnicodeDecodeError, PermissionError) as file_error:
                                    self.logger.warning(f"Failed to validate plugin {file_path}: {file_error}")
                                    # Add as invalid plugin for debugging
                                    plugins[plugin_type].append(
                                        {
                                            "name": os.path.splitext(file_path)[0],
                                            "path": full_path,
                                            "type": plugin_type,
                                            "valid": False,
                                            "error": str(file_error),
                                        }
                                    )

                except (OSError, PermissionError) as dir_error:
                    self.logger.error(f"Error accessing plugin directory {plugin_dir}: {dir_error}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Critical error loading plugins: {e}")
            # Return empty structure on critical failure
            return {"custom": [], "frida": [], "ghidra": []}

        self.logger.info(f"Loaded {sum(len(p) for p in plugins.values())} plugins across {len(plugins)} categories")
        return plugins

    def setup_project_dashboard_tab(self):
        """Set up project dashboard tab with real-time monitoring."""
        try:
            if hasattr(self, "dashboard_tab") and self.dashboard_tab:
                # Initialize dashboard with licensing analysis tracking
                self.dashboard_tab.setup_license_analysis_monitor()

                # Set up real-time binary protection monitoring
                if hasattr(self.dashboard_tab, "setup_protection_monitor"):
                    self.dashboard_tab.setup_protection_monitor()

                # Configure activity logging for exploitation attempts
                if hasattr(self.dashboard_tab, "setup_activity_logger"):
                    self.dashboard_tab.setup_activity_logger()

                # Initialize license server detection dashboard
                if hasattr(self.dashboard_tab, "setup_license_server_tracker"):
                    self.dashboard_tab.setup_license_server_tracker()

                self.logger.info("Dashboard tab configured for licensing protection analysis")

            # Initialize dashboard manager with license exploitation capabilities
            if hasattr(self, "dashboard_manager"):
                self.dashboard_manager.configure_license_exploitation_tracking()

        except Exception as e:
            self.logger.error(f"Failed to setup dashboard tab: {e}")
            # Fallback: Basic dashboard initialization
            if hasattr(self, "dashboard_tab"):
                self.dashboard_tab.setVisible(True)

    def setup_analysis_tab(self):
        """Set up analysis tab with licensing protection analysis capabilities."""
        try:
            if hasattr(self, "analysis_tab") and self.analysis_tab:
                # Initialize licensing protection detection engines
                self.analysis_tab.initialize_license_protection_detector()

                # Set up hardware ID fingerprinting analysis
                if hasattr(self.analysis_tab, "setup_hwid_analyzer"):
                    self.analysis_tab.setup_hwid_analyzer()

                # Configure license key validation bypass detection
                if hasattr(self.analysis_tab, "setup_key_validation_analyzer"):
                    self.analysis_tab.setup_key_validation_analyzer()

                # Initialize network license server detection
                if hasattr(self.analysis_tab, "setup_network_license_detector"):
                    self.analysis_tab.setup_network_license_detector()

                # Set up anti-debugging and anti-VM detection bypasses
                if hasattr(self.analysis_tab, "setup_protection_bypasses"):
                    self.analysis_tab.setup_protection_bypasses()

                # Configure real-time binary modification detection
                if hasattr(self.analysis_tab, "setup_binary_modification_tracker"):
                    self.analysis_tab.setup_binary_modification_tracker()

                # Initialize license validation flow tracer
                if hasattr(self.analysis_tab, "setup_license_flow_tracer"):
                    self.analysis_tab.setup_license_flow_tracer()

                self.logger.info("Analysis tab configured with advanced licensing protection capabilities")

            # Configure analysis engines for license bypass research
            if hasattr(self, "symbolic_execution_engine"):
                self.symbolic_execution_engine = None  # Will be lazy-loaded with license focus

            if hasattr(self, "taint_analysis_engine") and self.taint_analysis_engine:
                # Configure taint analysis for license validation tracking
                self.taint_analysis_engine.configure_license_taint_sources()

        except Exception as e:
            self.logger.error(f"Failed to setup analysis tab: {e}")
            # Fallback: Basic analysis tab visibility
            if hasattr(self, "analysis_tab"):
                self.analysis_tab.setVisible(True)

    def setup_patching_exploitation_tab(self):
        """Set up patching exploitation tab with advanced license bypass capabilities."""
        try:
            if hasattr(self, "patching_tab") and self.patching_tab:
                # Initialize license validation bypass engine
                if hasattr(self.patching_tab, "setup_license_bypass_engine"):
                    self.patching_tab.setup_license_bypass_engine()

                # Configure hardware ID spoofing capabilities
                if hasattr(self.patching_tab, "setup_hwid_spoofer"):
                    self.patching_tab.setup_hwid_spoofer()

                # Set up license key generation and validation bypass
                if hasattr(self.patching_tab, "setup_keygen_engine"):
                    self.patching_tab.setup_keygen_engine()

                # Initialize API call hooking for license checks
                if hasattr(self.patching_tab, "setup_api_hooking_engine"):
                    self.patching_tab.setup_api_hooking_engine()

                # Configure binary patching for license protection removal
                if hasattr(self.patching_tab, "setup_binary_patcher"):
                    self.patching_tab.setup_binary_patcher()

                # Set up network license server emulation
                if hasattr(self.patching_tab, "setup_license_server_emulator"):
                    self.patching_tab.setup_license_server_emulator()

                # Initialize time-based license bypass (system clock manipulation)
                if hasattr(self.patching_tab, "setup_time_manipulation_engine"):
                    self.patching_tab.setup_time_manipulation_engine()

                # Configure registry modification engine for license data
                if hasattr(self.patching_tab, "setup_registry_patcher"):
                    self.patching_tab.setup_registry_patcher()

                # Set up DLL injection framework for license bypass
                if hasattr(self.patching_tab, "setup_dll_injection_engine"):
                    self.patching_tab.setup_dll_injection_engine()

                # Initialize code cave patching for permanent modifications
                if hasattr(self.patching_tab, "setup_code_cave_patcher"):
                    self.patching_tab.setup_code_cave_patcher()

                self.logger.info("Patching exploitation tab configured with advanced license bypass capabilities")

            # Configure exploitation manager for license research
            if hasattr(self, "exploitation_manager"):
                self.exploitation_manager.configure_license_exploitation_suite()

        except Exception as e:
            self.logger.error(f"Failed to setup patching exploitation tab: {e}")
            # Fallback: Basic tab visibility
            if hasattr(self, "patching_tab"):
                self.patching_tab.setVisible(True)

    def setup_ai_assistant_tab(self):
        """Set up AI assistant tab with license protection research capabilities."""
        try:
            if hasattr(self, "ai_assistant_tab") and self.ai_assistant_tab:
                # Initialize AI script generation for license bypass
                if hasattr(self.ai_assistant_tab, "setup_license_script_generator"):
                    self.ai_assistant_tab.setup_license_script_generator()

                # Configure protection-aware AI analysis engine
                if hasattr(self.ai_assistant_tab, "setup_protection_aware_analyzer"):
                    self.ai_assistant_tab.setup_protection_aware_analyzer()

                # Set up automated keygen generation assistance
                if hasattr(self.ai_assistant_tab, "setup_keygen_ai_assistant"):
                    self.ai_assistant_tab.setup_keygen_ai_assistant()

                # Initialize pattern recognition for license validation flows
                if hasattr(self.ai_assistant_tab, "setup_pattern_recognition_engine"):
                    self.ai_assistant_tab.setup_pattern_recognition_engine()

                # Configure vulnerability suggestion engine for license systems
                if hasattr(self.ai_assistant_tab, "setup_vulnerability_suggestion_engine"):
                    self.ai_assistant_tab.setup_vulnerability_suggestion_engine()

                # Set up automated patch generation for license bypasses
                if hasattr(self.ai_assistant_tab, "setup_patch_generation_engine"):
                    self.ai_assistant_tab.setup_patch_generation_engine()

                # Initialize code analysis assistant for protection mechanisms
                if hasattr(self.ai_assistant_tab, "setup_code_analysis_assistant"):
                    self.ai_assistant_tab.setup_code_analysis_assistant()

                # Configure natural language query interface for license research
                if hasattr(self.ai_assistant_tab, "setup_nl_query_interface"):
                    self.ai_assistant_tab.setup_nl_query_interface()

                # Set up learning engine for protection pattern recognition
                if hasattr(self.ai_assistant_tab, "setup_learning_engine"):
                    self.ai_assistant_tab.setup_learning_engine()

                self.logger.info("AI assistant tab configured with advanced license protection research capabilities")

            # Configure AI model manager for license-focused analysis
            if hasattr(self, "ai_model_manager"):
                self.ai_model_manager.configure_license_analysis_models()

        except Exception as e:
            self.logger.error(f"Failed to setup AI assistant tab: {e}")
            # Fallback: Basic tab visibility
            if hasattr(self, "ai_assistant_tab"):
                self.ai_assistant_tab.setVisible(True)

    def setup_netanalysis_emulation_tab(self):
        """Set up network analysis emulation tab with license server bypass capabilities."""
        try:
            if hasattr(self, "netanalysis_tab") and self.netanalysis_tab:
                # Initialize network license server emulator
                if hasattr(self.netanalysis_tab, "setup_license_server_emulator"):
                    self.netanalysis_tab.setup_license_server_emulator()

                # Configure online activation bypass engine
                if hasattr(self.netanalysis_tab, "setup_activation_bypass_engine"):
                    self.netanalysis_tab.setup_activation_bypass_engine()

                # Set up network traffic interception for license communications
                if hasattr(self.netanalysis_tab, "setup_license_traffic_interceptor"):
                    self.netanalysis_tab.setup_license_traffic_interceptor()

                # Initialize SSL/TLS certificate spoofing for license servers
                if hasattr(self.netanalysis_tab, "setup_ssl_certificate_spoofer"):
                    self.netanalysis_tab.setup_ssl_certificate_spoofer()

                # Configure DNS hijacking for license server redirection
                if hasattr(self.netanalysis_tab, "setup_dns_hijacking_engine"):
                    self.netanalysis_tab.setup_dns_hijacking_engine()

                # Set up HTTP/HTTPS proxy for license request manipulation
                if hasattr(self.netanalysis_tab, "setup_license_proxy_engine"):
                    self.netanalysis_tab.setup_license_proxy_engine()

                # Initialize network packet crafting for license responses
                if hasattr(self.netanalysis_tab, "setup_packet_crafting_engine"):
                    self.netanalysis_tab.setup_packet_crafting_engine()

                # Configure license server response emulation
                if hasattr(self.netanalysis_tab, "setup_response_emulation_engine"):
                    self.netanalysis_tab.setup_response_emulation_engine()

                # Set up network security bypass for protected communications
                if hasattr(self.netanalysis_tab, "setup_network_security_bypass"):
                    self.netanalysis_tab.setup_network_security_bypass()

                # Initialize protocol analysis for custom license protocols
                if hasattr(self.netanalysis_tab, "setup_protocol_analyzer"):
                    self.netanalysis_tab.setup_protocol_analyzer()

                # Configure network virtualization for isolated testing
                if hasattr(self.netanalysis_tab, "setup_network_virtualization"):
                    self.netanalysis_tab.setup_network_virtualization()

                self.logger.info("Network analysis emulation tab configured with advanced license server bypass capabilities")

            # Configure network manager for license communication interception
            if hasattr(self, "network_manager"):
                self.network_manager.configure_license_interception_suite()

        except Exception as e:
            self.logger.error(f"Failed to setup network analysis emulation tab: {e}")
            # Fallback: Basic tab visibility
            if hasattr(self, "netanalysis_tab"):
                self.netanalysis_tab.setVisible(True)

    def setup_tools_plugins_tab(self):
        """Set up tools plugins tab with license protection research tool integration."""
        try:
            if hasattr(self, "tools_plugins_tab") and self.tools_plugins_tab:
                # Initialize external tool integration manager
                if hasattr(self.tools_plugins_tab, "setup_external_tool_manager"):
                    self.tools_plugins_tab.setup_external_tool_manager()

                # Configure plugin loading system for license research extensions
                if hasattr(self.tools_plugins_tab, "setup_plugin_loader"):
                    self.tools_plugins_tab.setup_plugin_loader()

                # Set up custom script execution engine for license bypasses
                if hasattr(self.tools_plugins_tab, "setup_script_execution_engine"):
                    self.tools_plugins_tab.setup_script_execution_engine()

                # Initialize tool discovery system for license analysis tools
                if hasattr(self.tools_plugins_tab, "setup_tool_discovery_system"):
                    self.tools_plugins_tab.setup_tool_discovery_system()

                # Configure plugin API for third-party license research tools
                if hasattr(self.tools_plugins_tab, "setup_plugin_api"):
                    self.tools_plugins_tab.setup_plugin_api()

                # Set up automated tool integration for common license crackers
                if hasattr(self.tools_plugins_tab, "setup_license_tool_integration"):
                    self.tools_plugins_tab.setup_license_tool_integration()

                # Initialize sandboxed execution environment for untrusted plugins
                if hasattr(self.tools_plugins_tab, "setup_sandboxed_execution"):
                    self.tools_plugins_tab.setup_sandboxed_execution()

                # Configure plugin marketplace interface for research tools
                if hasattr(self.tools_plugins_tab, "setup_plugin_marketplace"):
                    self.tools_plugins_tab.setup_plugin_marketplace()

                # Set up tool configuration management system
                if hasattr(self.tools_plugins_tab, "setup_tool_config_manager"):
                    self.tools_plugins_tab.setup_tool_config_manager()

                # Initialize plugin development environment
                if hasattr(self.tools_plugins_tab, "setup_plugin_development_env"):
                    self.tools_plugins_tab.setup_plugin_development_env()

                self.logger.info("Tools plugins tab configured with comprehensive license research tool integration")

            # Configure plugin manager for license-focused tool ecosystem
            if hasattr(self, "plugin_manager"):
                self.plugin_manager.configure_license_research_plugins()

        except Exception as e:
            self.logger.error(f"Failed to setup tools plugins tab: {e}")
            # Fallback: Basic tab visibility
            if hasattr(self, "tools_plugins_tab"):
                self.tools_plugins_tab.setVisible(True)

    def setup_settings_tab(self):
        """Set up settings tab with license protection research configuration."""
        try:
            if hasattr(self, "settings_tab") and self.settings_tab:
                # Initialize license research configuration manager
                if hasattr(self.settings_tab, "setup_license_config_manager"):
                    self.settings_tab.setup_license_config_manager()

                # Configure exploitation safety settings and warnings
                if hasattr(self.settings_tab, "setup_exploitation_safety_settings"):
                    self.settings_tab.setup_exploitation_safety_settings()

                # Set up API key management for license analysis services
                if hasattr(self.settings_tab, "setup_api_key_manager"):
                    self.settings_tab.setup_api_key_manager()

                # Initialize tool path configuration for external crackers
                if hasattr(self.settings_tab, "setup_tool_path_config"):
                    self.settings_tab.setup_tool_path_config()

                # Configure license database connection settings
                if hasattr(self.settings_tab, "setup_license_db_config"):
                    self.settings_tab.setup_license_db_config()

                # Set up network proxy settings for license server testing
                if hasattr(self.settings_tab, "setup_network_proxy_config"):
                    self.settings_tab.setup_network_proxy_config()

                # Initialize logging configuration for security research
                if hasattr(self.settings_tab, "setup_logging_config"):
                    self.settings_tab.setup_logging_config()

                # Configure virtual machine detection bypass settings
                if hasattr(self.settings_tab, "setup_vm_detection_bypass_config"):
                    self.settings_tab.setup_vm_detection_bypass_config()

                # Set up code signing certificate management
                if hasattr(self.settings_tab, "setup_code_signing_config"):
                    self.settings_tab.setup_code_signing_config()

                # Initialize hardware ID spoofing configuration
                if hasattr(self.settings_tab, "setup_hwid_spoofing_config"):
                    self.settings_tab.setup_hwid_spoofing_config()

                # Configure advanced protection bypass preferences
                if hasattr(self.settings_tab, "setup_protection_bypass_preferences"):
                    self.settings_tab.setup_protection_bypass_preferences()

                # Set up research ethics and compliance settings
                if hasattr(self.settings_tab, "setup_research_ethics_config"):
                    self.settings_tab.setup_research_ethics_config()

                self.logger.info("Settings tab configured with comprehensive license protection research settings")

            # Configure global settings manager for license research
            if hasattr(self, "global_settings_manager"):
                self.global_settings_manager.configure_license_research_settings()

        except Exception as e:
            self.logger.error(f"Failed to setup settings tab: {e}")
            # Fallback: Basic tab visibility
            if hasattr(self, "settings_tab"):
                self.settings_tab.setVisible(True)


def launch():
    """Launch the Intellicrack application.

    Creates QApplication instance, instantiates IntellicrackApp,
    shows the main window, and runs the Qt event loop.

    Returns:
        int: Application exit code

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
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "intellicrack", "assets", "icon.ico"
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
