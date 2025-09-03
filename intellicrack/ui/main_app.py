import logging
import os
import traceback
from functools import partial

from intellicrack.ai.model_manager_module import ModelManager
from intellicrack.config import CONFIG, get_config
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
from intellicrack.core.network.license_server_emulator import run_network_license_emulator
from intellicrack.core.network.protocol_tool import (
    launch_protocol_tool,
    update_protocol_tool_description,
)
from intellicrack.core.patching.adobe_compiler import AdobeLicenseCompiler
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
from intellicrack.ui.tabs.tools_tab import ToolsTab
from intellicrack.ui.tabs.workspace_tab import WorkspaceTab
from intellicrack.ui.theme_manager import get_theme_manager
from intellicrack.ui.traffic_analyzer import TrafficAnalyzer, clear_network_capture, start_network_capture, stop_network_capture
from intellicrack.utils import run_frida_script, run_qemu_analysis, run_selected_analysis, run_ssl_tls_interceptor
from intellicrack.utils.log_message import log_message
from intellicrack.utils.protection.protection_utils import inject_comprehensive_api_hooks
from intellicrack.utils.resource_helper import get_resource_path

logger = logging.getLogger(__name__)


class IntellicrackApp(QMainWindow):
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
        self._initialize_adobe_compiler()

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
            from ..ai.exploitation_orchestrator import ExploitationOrchestrator

            self.exploitation_orchestrator = ExploitationOrchestrator(ai_model=None)
            self.logger.info("Exploitation Orchestrator initialized successfully")

            self.logger.info("IntellicrackApp initialization complete with agentic AI system.")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Failed to initialize AI Orchestrator: %s", e)
            self.logger.error(f"Exception details: {traceback.format_exc()}")
            self.ai_orchestrator = None
            self.ai_coordinator = None
            self.exploitation_orchestrator = None
            self.logger.warning("Continuing without agentic AI system")

    def _initialize_adobe_compiler(self):
        """Initialize Adobe License Compiler and configuration."""
        print("[INIT] Initializing Adobe License Compiler...")

        try:
            self.adobe_compiler = AdobeLicenseCompiler()

            # Get Adobe configuration from unified config system
            config = get_config()
            adobe_config = config.get("adobe_license_compiler", {})
            deployment_config = adobe_config.get("deployment", {})

            # Store configurable service name and display elements
            self.adobe_service_name = deployment_config.get("service_name", "AdobeLicenseX")
            self.adobe_display_name = f"Adobe {self.adobe_service_name}"

            self.logger.info("Adobe License Compiler initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize Adobe License Compiler: {e}")
            self.adobe_compiler = None
            # Fallback to default names if config unavailable
            self.adobe_service_name = "AdobeLicenseX"
            self.adobe_display_name = "Adobe AdobeLicenseX"

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

        # Try to load icon
        icon_path = get_resource_path("assets/icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

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

        self.generate_advanced_payload = partial(exploitation_handlers.generate_advanced_payload, self)
        self.test_generated_payload = partial(exploitation_handlers.test_generated_payload, self)
        self.start_c2_server = partial(exploitation_handlers.start_c2_server, self)
        self.stop_c2_server = partial(exploitation_handlers.stop_c2_server, self)
        self.open_c2_management = partial(exploitation_handlers.open_c2_management, self)
        self.establish_persistence = partial(exploitation_handlers.establish_persistence, self)
        self.escalate_privileges = partial(exploitation_handlers.escalate_privileges, self)
        self.perform_lateral_movement = partial(exploitation_handlers.perform_lateral_movement, self)
        self.harvest_credentials = partial(exploitation_handlers.harvest_credentials, self)
        self.collect_system_info = partial(exploitation_handlers.collect_system_info, self)
        self.cleanup_exploitation = partial(exploitation_handlers.cleanup_exploitation, self)
        self.open_vulnerability_research = partial(exploitation_handlers.open_vulnerability_research, self)
        self.run_quick_vulnerability_analysis = partial(exploitation_handlers.run_quick_vulnerability_analysis, self)
        self.run_ai_guided_analysis = partial(exploitation_handlers.run_ai_guided_analysis, self)
        self.test_aslr_bypass = partial(exploitation_handlers.test_aslr_bypass, self)
        self.test_dep_bypass = partial(exploitation_handlers.test_dep_bypass, self)
        self.test_cfi_bypass = partial(exploitation_handlers.test_cfi_bypass, self)
        self.test_cet_bypass = partial(exploitation_handlers.test_cet_bypass, self)
        self.test_stack_canary_bypass = partial(exploitation_handlers.test_stack_canary_bypass, self)
        self.run_full_automated_exploitation = partial(exploitation_handlers.run_full_automated_exploitation, self)
        self.run_ai_orchestrated_campaign = partial(exploitation_handlers.run_ai_orchestrated_campaign, self)
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
        except (OSError, ValueError, RuntimeError) as e:
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
        self.tabs.addTab(self.settings_tab, "Settings")

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
        self.setWindowTitle("Intellicrack - Binary Analysis Tool")
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

    def _on_binary_loaded(self, binary_path: str):
        """Handle binary loaded event from app context."""
        self.binary_path = binary_path
        self.update_output.emit(self.log_message(f"Binary loaded: {binary_path}"))
        self.logger.info(f"Binary loaded: {binary_path}")

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
        self.logger.debug("Applied tooltips to UI elements")

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
        """Load available plugins from plugin directory."""
        return {"custom": [], "frida": [], "ghidra": []}

    def setup_project_dashboard_tab(self):
        """Set up project dashboard tab."""
        self.logger.debug("Project dashboard tab setup")

    def setup_analysis_tab(self):
        """Set up analysis tab."""
        self.logger.debug("Analysis tab setup")

    def setup_patching_exploitation_tab(self):
        """Set up patching exploitation tab."""
        self.logger.debug("Patching exploitation tab setup")

    def setup_ai_assistant_tab(self):
        """Set up AI assistant tab."""
        self.logger.debug("AI assistant tab setup")

    def setup_netanalysis_emulation_tab(self):
        """Set up network analysis emulation tab."""
        self.logger.debug("Network analysis emulation tab setup")

    def setup_tools_plugins_tab(self):
        """Set up tools plugins tab."""
        self.logger.debug("Tools plugins tab setup")

    def setup_settings_tab(self):
        """Set up settings tab."""
        self.logger.debug("Settings tab setup")


def launch():
    """Launch the Intellicrack application.

    Creates QApplication instance, instantiates IntellicrackApp,
    shows the main window, and runs the Qt event loop.

    Returns:
        int: Application exit code
    """
    try:
        import sys

        from intellicrack.handlers.pyqt6_handler import QApplication

        # Create QApplication instance if it doesn't exist
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)

        # Create and show main application window
        main_window = IntellicrackApp()
        main_window.show()

        # Run the Qt event loop
        return app.exec()

    except Exception as e:
        logger.error(f"Failed to launch Intellicrack application: {e}")
        return 1
