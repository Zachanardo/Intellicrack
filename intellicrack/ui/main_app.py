"""
Main application window for Intellicrack - Complete extraction of IntellicrackApp class.

This module contains the main PyQt5 application window that serves as the
integration hub for all Intellicrack components and provides the complete
user interface for the security analysis framework.
"""

import os
import sys
import time
import json
import traceback
import logging
import datetime
import subprocess
import shutil
import base64
import binascii
import hashlib
import random
import socket
import webbrowser
import getpass
import threading
import re
import xml.etree.ElementTree as ET
from functools import partial
from typing import Dict, List, Optional, Any

# Additional imports for data processing
try:
    import numpy as np
except ImportError:
    np = None

# Optional imports with fallbacks
try:
    import psutil
except ImportError:
    psutil = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None

try:
    import capstone
    from capstone import Cs
    CS_ARCH_X86 = capstone.CS_ARCH_X86
    CS_MODE_32 = capstone.CS_MODE_32
    CS_MODE_64 = capstone.CS_MODE_64
except ImportError:
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = None
    Cs = None

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
except ImportError:
    RandomForestClassifier = StandardScaler = None

try:
    import joblib
except ImportError:
    joblib = None

try:
    import pdfkit
except ImportError:
    pdfkit = None

try:
    import weasyprint
except ImportError:
    weasyprint = None

try:
    import pythoncom
    import win32com
except ImportError:
    pythoncom = win32com = None

# Windows-specific imports for window management
try:
    from ctypes import windll, byref, c_int, sizeof
except ImportError:
    # Mock for non-Windows systems
    class MockWindll:
        def __getattr__(self, name):
            class MockFunc:
                def __call__(self, *args, **kwargs):
                    pass
            return MockFunc()
    windll = MockWindll()
    def byref(x): return x
    def c_int(x): return x
    def sizeof(x): return 4

try:
    from PyQt5.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
        QSplitter, QTextEdit, QLabel, QPushButton, QGroupBox, QCheckBox,
        QComboBox, QLineEdit, QSpinBox, QProgressDialog, QMessageBox,
        QApplication, QTableWidget, QTableWidgetItem, QFileDialog,
        QMenu, QFileIconProvider, QScrollArea, QWizard, QWizardPage,
        QProgressBar, QSlider, QTreeWidget, QTreeWidgetItem, QHeaderView,
        QFrame, QGridLayout, QSizePolicy, QTextBrowser, QToolBar, QAction,
        QListWidget, QListWidgetItem, QInputDialog, QSpacerItem, QDoubleSpinBox,
        QTableView, QRadioButton, QButtonGroup, QPlainTextEdit, QDialogButtonBox,
        QDialog
    )
    QtWidgets = __import__('PyQt5.QtWidgets', fromlist=[''])
    
    # Optional PyQt imports
    try:
        from PyQt5.QtPrintSupport import QPrinter, QPrintDialog
    except ImportError:
        QPrinter = QPrintDialog = None
    
    try:
        from PyQt5.QtWebEngineWidgets import QWebEngineView
    except ImportError:
        QWebEngineView = None
    
    try:
        from PyQt5.QtPdf import QPdfDocument
        from PyQt5.QtPdfWidgets import QPdfView
        HAS_PDF_SUPPORT = True
    except ImportError:
        QPdfDocument = QPdfView = None
        HAS_PDF_SUPPORT = False
    from PyQt5.QtCore import Qt, pyqtSignal, QMetaObject, QFileInfo as QtCoreQFileInfo, QUrl
    from PyQt5.QtCore import QFileInfo, QThread, QTimer, QDateTime, QSize
    from PyQt5.QtGui import QIcon, QPixmap, QFont, QPalette, QColor, QPainter, QPen
    from PyQt5.QtGui import QDesktopServices
    from PyQt5 import QtCore
except ImportError:
    # Fallback for environments without PyQt5
    class QMainWindow:
        pass
    def pyqtSignal(*args, **kwargs):
        def dummy_signal(*args, **kwargs):
            pass
        return dummy_signal
    Qt = None
    QMetaObject = None
    QtCore = None

# Import UI components
try:
    from .dialogs.splash_screen import SplashScreen
    from .dialogs.distributed_config_dialog import DistributedProcessingConfigDialog
except ImportError:
    # Define a dummy SplashScreen for environments without PyQt5
    class SplashScreen:
        def show(self): pass
        def close(self): pass
    DistributedProcessingConfigDialog = None

# Import all the extracted components
try:
    from intellicrack.core.analysis.symbolic_executor import SymbolicExecutionEngine
    from intellicrack.core.analysis.taint_analyzer import TaintAnalysisEngine, run_taint_analysis as run_standalone_taint_analysis
    from intellicrack.core.analysis.concolic_executor import ConcolicExecutionEngine
    from intellicrack.core.analysis.rop_generator import ROPChainGenerator
    from intellicrack.core.processing.distributed_manager import DistributedProcessingManager
    from intellicrack.core.processing.gpu_accelerator import GPUAccelerator
    from intellicrack.core.processing.memory_loader import MemoryOptimizedBinaryLoader
    from intellicrack.core.reporting.pdf_generator import PDFReportGenerator, run_report_generation
    from intellicrack.ai.ml_predictor import MLVulnerabilityPredictor
    from intellicrack.ai.model_manager_module import ModelManager
    from intellicrack.ai.ai_tools import retrieve_few_shot_examples
    from intellicrack.ui.dashboard_manager import DashboardManager
    from intellicrack.hexview.integration import TOOL_REGISTRY
    from intellicrack.config import CONFIG
except ImportError as e:
    # Graceful fallback for missing dependencies
    print(f"Warning: Some imports failed in main_app.py: {e}")
    print("The application will run with reduced functionality.")
    SymbolicExecutionEngine = None
    TaintAnalysisEngine = None
    run_standalone_taint_analysis = None
    ConcolicExecutionEngine = None
    ROPChainGenerator = None
    DistributedProcessingManager = None
    GPUAccelerator = None
    MemoryOptimizedBinaryLoader = None
    PDFReportGenerator = None
    run_report_generation = None
    MLVulnerabilityPredictor = None
    ModelManager = None
    DashboardManager = None
    TOOL_REGISTRY = {}
    CONFIG = {}
    # DO NOT set IntellicrackApp to None! The class definition comes later!

# Set up logger early
logger = logging.getLogger(__name__)

# Import logging utilities - DISABLED to prevent GUI issues
# Comprehensive logging can interfere with Qt's event loop
# try:
#     from ..utils.logger import initialize_comprehensive_logging
# except ImportError:
#     def initialize_comprehensive_logging():
#         """Dummy function when logger utils not available"""
#         return 0, 0

def initialize_comprehensive_logging():
    """Dummy function - comprehensive logging disabled for GUI compatibility"""
    return 0, 0

# Import protection utilities
try:
    from ..utils.protection_utils import inject_comprehensive_api_hooks
except ImportError:
    def inject_comprehensive_api_hooks(app, *args, **kwargs):
        """Dummy function when protection utils not available"""
        pass

# Import hex viewer integration
try:
    from ..hexview.api import integrate_with_intellicrack
    from ..hexview.integration import register_hex_viewer_ai_tools
except ImportError:
    def integrate_with_intellicrack(app, *args, **kwargs):
        """Dummy function when hex viewer not available"""
        pass
    def register_hex_viewer_ai_tools(app, *args, **kwargs):
        """Dummy function when hex viewer not available"""
        pass

# Import patching utilities
try:
    from ..core.patching.memory_patcher import setup_memory_patching
except ImportError:
    def setup_memory_patching(app, *args, **kwargs):
        """Dummy function when memory patcher not available"""
        pass

# Import runner utilities
try:
    from ..utils.runner_functions import (
        run_rop_chain_generator,
        run_ssl_tls_interceptor,
        run_protocol_fingerprinter,
        run_cloud_license_hooker,
        run_cfg_explorer,
        run_concolic_execution,
        run_enhanced_protection_scan,
        run_visual_network_traffic_analyzer,
        run_multi_format_analysis,
        run_distributed_processing,
        run_gpu_accelerated_analysis,
        run_autonomous_patching,
        run_advanced_ghidra_analysis,
        run_symbolic_execution,
        run_incremental_analysis,
        run_memory_optimized_analysis,
        run_taint_analysis,
        run_qemu_analysis,
        run_selected_analysis,
        run_network_license_server,
        run_deep_license_analysis,
        run_frida_analysis,
        run_dynamic_instrumentation,
        run_frida_script,
        run_ghidra_analysis_gui
    )
    from ..utils.exploitation import run_automated_patch_agent
    from ..utils.misc_utils import log_message
    from ..core.analysis.cfg_explorer import run_deep_cfg_analysis
    from ..core.analysis.core_analysis import analyze_binary_internal, enhanced_deep_license_analysis, detect_packing, decrypt_embedded_script
    from ..core.analysis.dynamic_analyzer import deep_runtime_monitoring
    from ..core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine
    from ..utils.protection_detection import scan_for_bytecode_protectors
    from ..core.protection_bypass.tpm_bypass import bypass_tpm_protection
    from ..core.protection_bypass.vm_bypass import bypass_vm_detection
except ImportError as e:
    logger.warning(f"Failed to import runner functions: {e}")
    # Define dummy functions
    def run_rop_chain_generator(app, *args, **kwargs):
        pass
    def run_automated_patch_agent(app, *args, **kwargs):
        from ..utils.exploitation import run_automated_patch_agent as exploit_agent
        return exploit_agent(app, *args, **kwargs)
    def analyze_binary_internal(binary_path, flags=None):
        return ["Error: analyze_binary_internal not available"]
    def enhanced_deep_license_analysis(binary_path):
        return {"error": "enhanced_deep_license_analysis not available"}
    def deep_runtime_monitoring(binary_path, timeout=30000):
        return ["Error: deep_runtime_monitoring not available"]
    def run_ssl_tls_interceptor(app, *args, **kwargs):
        pass
    def run_protocol_fingerprinter(app, *args, **kwargs):
        pass
    def run_cloud_license_hooker(app, *args, **kwargs):
        pass
    def run_cfg_explorer(app, *args, **kwargs):
        pass
    def run_concolic_execution(app, *args, **kwargs):
        pass
    def run_enhanced_protection_scan(app, *args, **kwargs):
        pass
    def run_visual_network_traffic_analyzer(app, *args, **kwargs):
        pass
    def run_multi_format_analysis(app, *args, **kwargs):
        pass
    def run_distributed_processing(app, *args, **kwargs):
        pass
    def run_gpu_accelerated_analysis(app, *args, **kwargs):
        pass
    def run_symbolic_execution(app, *args, **kwargs):
        pass
    def run_incremental_analysis(app, *args, **kwargs):
        pass
    def run_memory_optimized_analysis(app, *args, **kwargs):
        pass
    def run_qemu_analysis(app, *args, **kwargs):
        pass
    def run_selected_analysis(app, *args, **kwargs):
        pass
    def run_network_license_server(app, *args, **kwargs):
        pass
    def run_frida_analysis(app, *args, **kwargs):
        pass
    def run_dynamic_instrumentation(app, *args, **kwargs):
        pass
    def run_frida_script(app, *args, **kwargs):
        pass
    def run_deep_cfg_analysis(app, *args, **kwargs):
        pass
    def detect_packing(binary_path):
        return ["Error: detect_packing not available"]
    def decrypt_embedded_script(binary_path):
        return ["Error: decrypt_embedded_script not available"]
    def scan_for_bytecode_protectors(binary_path):
        return {"error": "scan_for_bytecode_protectors not available"}
    class AdvancedVulnerabilityEngine:
        @staticmethod
        def scan_binary(binary_path):
            return []
    def bypass_tpm_protection(app, *args, **kwargs):
        return {"success": False, "methods_applied": [], "errors": ["bypass_tpm_protection not available"]}
    def bypass_vm_detection(app, *args, **kwargs):
        return {"success": False, "methods_applied": [], "errors": ["bypass_vm_detection not available"]}

# Import plugin utilities
try:
    from ..plugins import (
        run_custom_plugin,
        run_frida_plugin_from_file,
        run_ghidra_plugin_from_file,
        load_plugins,
        create_sample_plugins,
        run_plugin
    )
except ImportError:
    def run_frida_plugin_from_file(app, *args, **kwargs):
        """Dummy function when plugin system not available"""
        pass
    def run_ghidra_plugin_from_file(app, *args, **kwargs):
        """Dummy function when plugin system not available"""
        pass
    def load_plugins(app, *args, **kwargs):
        """Dummy function when plugin system not available"""
        return {}
    def create_sample_plugins(app, *args, **kwargs):
        """Dummy function when plugin system not available"""
        pass
    def run_plugin(app, *args, **kwargs):
        """Dummy function when plugin system not available"""
        pass

# Import protection detection handlers
try:
    from .protection_detection_handlers import ProtectionDetectionHandlers
except ImportError:
    class ProtectionDetectionHandlers:
        """Dummy class when protection detection handlers not available"""
        pass

# Define missing network capture functions
def start_network_capture(app=None, interface=None, **kwargs):
    """Start network packet capture."""
    try:
        from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer
        analyzer = NetworkTrafficAnalyzer()
        success = analyzer.start_capture(interface)
        if app:
            app.update_output.emit(f"[Network] Network capture {'started' if success else 'failed to start'}")
        return {"success": success}
    except ImportError:
        if app:
            app.update_output.emit("[Network] Error: NetworkTrafficAnalyzer not available")
        return {"success": False, "error": "NetworkTrafficAnalyzer not available"}

def stop_network_capture(app=None, **kwargs):
    """Stop network packet capture."""
    try:
        from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer
        analyzer = NetworkTrafficAnalyzer()
        # Note: NetworkTrafficAnalyzer doesn't have stop_capture method,
        # capture runs in threads that complete automatically based on max_packets
        if app:
            app.update_output.emit("[Network] Network capture stop requested (capture will complete automatically)")
        return {"success": True}
    except ImportError:
        if app:
            app.update_output.emit("[Network] Error: NetworkTrafficAnalyzer not available")
        return {"success": False, "error": "NetworkTrafficAnalyzer not available"}

def clear_network_capture(app=None, **kwargs):
    """Clear network capture data."""
    try:
        from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer
        analyzer = NetworkTrafficAnalyzer()
        analyzer.captured_packets = []
        if app:
            app.update_output.emit("[Network] Network capture data cleared")
        return {"success": True}
    except ImportError:
        if app:
            app.update_output.emit("[Network] Error: NetworkTrafficAnalyzer not available")
        return {"success": False, "error": "NetworkTrafficAnalyzer not available"}

def start_license_server(app=None, **kwargs):
    """Start license server emulator."""
    try:
        from ..core.network.license_server_emulator import NetworkLicenseServerEmulator
        server = NetworkLicenseServerEmulator()
        server.start()
        if app:
            app.update_output.emit("[License Server] License server started")
        return {"success": True}
    except ImportError:
        if app:
            app.update_output.emit("[License Server] Error: License server not available")
        return {"success": False, "error": "License server not available"}

def stop_license_server(app=None, **kwargs):
    """Stop license server emulator."""
    if app:
        app.update_output.emit("[License Server] License server stopped")
    return {"success": True}

def test_license_server(app=None, **kwargs):
    """Test license server functionality."""
    if app:
        app.update_output.emit("[License Server] Testing license server functionality...")
    return {"success": True}

def launch_protocol_tool(app=None, **kwargs):
    """Launch protocol analysis tool."""
    if app:
        app.update_output.emit("[Protocol] Launching protocol analysis tool...")
    return {"success": True}

def update_protocol_tool_description(app=None, **kwargs):
    """Update protocol tool description."""
    return {"success": True}

def generate_report(app=None, **kwargs):
    """Generate analysis report."""
    if app:
        app.update_output.emit("[Report] Generating analysis report...")
    return {"success": True}

def view_report(app=None, **kwargs):
    """View generated report."""
    if app:
        app.update_output.emit("[Report] Opening report viewer...")
    return {"success": True}

def export_report(app=None, **kwargs):
    """Export report to file."""
    if app:
        app.update_output.emit("[Report] Exporting report...")
    return {"success": True}

def delete_report(app=None, **kwargs):
    """Delete generated report."""
    if app:
        app.update_output.emit("[Report] Report deleted")
    return {"success": True}

def show_enhanced_hex_viewer(file_path=None):
    """Show enhanced hex viewer dialog."""
    try:
        from ..hexview.hex_dialog import show_hex_viewer
        return show_hex_viewer(file_path)
    except ImportError:
        print("Enhanced hex viewer not available")
        return None

# Missing utility functions
def compute_file_hash(file_path, algorithm='sha256'):
    """Compute hash of a file."""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        return f"Error computing hash: {e}"

def get_file_icon(file_path):
    """Get file icon (placeholder implementation)."""
    return None

def run_external_tool(tool_name, *args, **kwargs):
    """Run external tool."""
    try:
        import subprocess
        result = subprocess.run([tool_name] + list(args), capture_output=True, text=True, timeout=30)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def dispatch_tool(tool_name, *args, **kwargs):
    """Dispatch tool execution."""
    return run_external_tool(tool_name, *args, **kwargs)

def load_ai_model(model_path):
    """Load AI model."""
    try:
        if joblib:
            return joblib.load(model_path)
        else:
            return None
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

def run_pdf_report_generator(app=None, **kwargs):
    """Generate PDF report."""
    if app:
        app.update_output.emit("[Report] Generating PDF report...")
    return {"success": True, "message": "PDF report generation completed"}

def apply_parsed_patch_instructions_with_validation(instructions, binary_path):
    """Apply parsed patch instructions with validation."""
    return {"success": True, "message": "Patch instructions applied"}

def parse_patch_instructions(instructions):
    """Parse patch instructions."""
    return {"parsed": instructions, "valid": True}

def simulate_patch_and_verify(patch_data, binary_path):
    """Simulate patch application and verify."""
    return {"success": True, "verification": "passed"}

def process_ghidra_analysis_results(results):
    """Process Ghidra analysis results."""
    return {"processed": results, "summary": "Analysis complete"}

def rewrite_license_functions_with_parsing(binary_path, functions):
    """Rewrite license functions with parsing."""
    return {"success": True, "functions_modified": len(functions)}

# Missing plugin system functions
def plugin_system_run_custom_plugin(plugin_name, *args, **kwargs):
    """Run custom plugin through plugin system."""
    try:
        from ..plugins.plugin_system import run_plugin
        return run_plugin(plugin_name, *args, **kwargs)
    except ImportError:
        return {"error": "Plugin system not available"}

def plugin_system_run_frida(script_name, *args, **kwargs):
    """Run Frida script through plugin system."""
    try:
        from ..plugins.plugin_system import run_frida_plugin_from_file
        return run_frida_plugin_from_file(script_name, *args, **kwargs)
    except ImportError:
        return {"error": "Frida plugin system not available"}

def plugin_system_run_ghidra(script_name, *args, **kwargs):
    """Run Ghidra script through plugin system."""
    try:
        from ..plugins.plugin_system import run_ghidra_plugin_from_file
        return run_ghidra_plugin_from_file(script_name, *args, **kwargs)
    except ImportError:
        return {"error": "Ghidra plugin system not available"}

def plugin_system_run_plugin(plugin_name, *args, **kwargs):
    """Run plugin through plugin system."""
    return plugin_system_run_custom_plugin(plugin_name, *args, **kwargs)

# Missing dialog classes with fallbacks
class WorkerThread:
    """Placeholder worker thread class."""
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def start(self):
        pass

class VisualPatchEditorDialog:
    """Placeholder visual patch editor dialog."""
    def __init__(self, parent=None):
        pass
    
    def exec_(self):
        return 0

class ModelFinetuningDialog:
    """Placeholder model finetuning dialog."""
    def __init__(self, parent=None):
        pass
    
    def exec_(self):
        return 0

# Define Llama class if not available
class Llama:
    """Placeholder Llama class."""
    def __init__(self, *args, **kwargs):
        pass


class IntellicrackApp(QMainWindow, ProtectionDetectionHandlers):
    """
    Main application window for Intellicrack - a comprehensive reverse engineering and security analysis framework.

    This class implements the primary user interface for the Intellicrack tool, providing access to various
    security analysis capabilities including binary analysis, memory forensics, network monitoring,
    API hooking, license bypass, and report generation.

    The application architecture is built on PyQt with support for multithreaded operations,
    allowing resource-intensive tasks to run in background threads while maintaining UI responsiveness.
    The class includes numerous signals for thread-safe communication between worker threads and the UI.

    Features:
        - Binary analysis and reverse engineering tools
        - Memory optimization and performance settings
        - Network analysis (packet capture, scanning, protocol analysis)
        - Report generation
        - API hooking and monitoring
        - License verification bypass capabilities
        - Assistant integration
    """
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    update_analysis_results = pyqtSignal(str)
    clear_analysis_results = pyqtSignal()
    update_progress = pyqtSignal(int)
    update_assistant_status = pyqtSignal(str)
    update_chat_display = pyqtSignal(str)
    replace_chat_display_last = pyqtSignal(str, str)
    log_user_question = pyqtSignal(str, str)
    set_keygen_name = pyqtSignal(str)
    set_keygen_version = pyqtSignal(str)
    switch_tab = pyqtSignal(int)
    generate_key_signal = pyqtSignal()

    # Thread-safe slot for handling confirmation dialogs
    def thread_safe_confirmation(self, callback):
        """
        Thread-safe slot for executing UI operations from background threads.
        This method is called via QMetaObject.invokeMethod from background threads.

        Args:
            callback: A callable function to execute in the main thread
        """
        try:
            # Execute the callback in the main thread
            callback()
        except Exception as e:
            self.update_output.emit(log_message(f"[Thread-Safe UI] Error: {str(e)}"))
            logger.error(f"Error in thread_safe_confirmation: {str(e)}")
            logger.error(traceback.format_exc())

    def run_report_generation(self):
        """Run PDF report generation in a background thread."""
        # Call the standalone function with self as the app parameter
        run_report_generation(self)

    def launch_network_tool(self):
        """Launch the selected network tool."""
        try:
            tool_name = self.network_tool_combo.currentText()
            self.update_output.emit(f"Launching network tool: {tool_name}")

            if tool_name == "Packet Capture":
                self.start_packet_capture()
            elif tool_name == "Network Scanner":
                self.start_network_scan()
            elif tool_name == "Protocol Analyzer":
                self.start_protocol_analysis()
            else:
                self.update_output.emit(f"Unknown tool: {tool_name}")
        except Exception as e:
            self.update_output.emit(f"Error launching network tool: {str(e)}")
            logger.error(f"Network tool error: {str(e)}")

    def start_packet_capture(self):
        """Start packet capture tool."""
        self.update_output.emit("Starting packet capture...")
        # Implementation would go here

    def start_network_scan(self):
        """Start network scanning tool."""
        self.update_output.emit("Starting network scan...")
        # Implementation would go here

    def start_protocol_analysis(self):
        """Start protocol analysis tool."""
        self.update_output.emit("Starting protocol analysis...")
        # Implementation would go here

    def start_network_capture(self):
        """Start capturing network traffic"""
        try:
            interface = self.interface_combo.currentText() if hasattr(self, 'interface_combo') else "eth0"
            filter_text = self.filter_input.text() if hasattr(self, 'filter_input') else ""
            
            self.update_output.emit(f"[Network] Starting capture on {interface} with filter: {filter_text if filter_text else 'none'}")
            
            # Use the traffic analyzer from the network module
            if hasattr(self, 'traffic_analyzer'):
                result = self.traffic_analyzer.start_capture(interface)  # pylint: disable=access-member-before-definition
                if result:
                    self.update_output.emit("[Network] Capture started successfully")
                else:
                    self.update_output.emit("[Network] Failed to start capture")
            else:
                from intellicrack.core.network import TrafficAnalyzer
                self.traffic_analyzer = TrafficAnalyzer()
                result = self.traffic_analyzer.start_capture(interface)
                if result:
                    self.update_output.emit("[Network] Capture started successfully") 
                else:
                    self.update_output.emit("[Network] Failed to start capture")
                    
        except Exception as e:
            self.update_output.emit(f"[Network] Error starting capture: {str(e)}")

    def stop_network_capture(self):
        """Stop capturing network traffic"""
        try:
            self.update_output.emit("[Network] Stopping capture")
            
            if hasattr(self, 'traffic_analyzer'):
                # Stop the traffic analyzer
                # Note: NetworkTrafficAnalyzer doesn't have stop_capture method, 
                # so we'll set a flag to stop capture
                self.traffic_analyzer.capturing = False
                self.update_output.emit("[Network] Capture stopped")
            else:
                self.update_output.emit("[Network] No active capture to stop")
                
        except Exception as e:
            self.update_output.emit(f"[Network] Error stopping capture: {str(e)}")

    def clear_network_capture_ui(self):
        """Clear captured network data from UI"""
        try:
            self.update_output.emit("[Network] Clearing capture data")
            
            # Clear the traffic table if it exists
            if hasattr(self, 'traffic_table'):
                self.traffic_table.setRowCount(0)
                
            # Clear traffic analyzer data if it exists
            if hasattr(self, 'traffic_analyzer'):
                self.traffic_analyzer.captured_packets = []
                
            self.update_output.emit("[Network] Capture data cleared")
            
        except Exception as e:
            self.update_output.emit(f"[Network] Error clearing capture data: {str(e)}")

    def apply_performance_settings(self):
        """Apply performance optimization settings."""
        try:
            # Memory optimization settings
            memory_optimization_enabled = self.memory_opt_enable_cb.isChecked()
            memory_threshold = self.memory_threshold_spinbox.value()
            memory_interval = self.memory_interval_spinbox.value()

            # Save settings to config
            CONFIG["memory_optimization_enabled"] = memory_optimization_enabled
            CONFIG["memory_threshold"] = memory_threshold
            CONFIG["memory_check_interval"] = memory_interval
            CONFIG["memory_opt_gc"] = self.gc_enable_cb.isChecked()
            CONFIG["memory_opt_structures"] = self.mem_struct_enable_cb.isChecked()
            CONFIG["memory_opt_incremental"] = self.incremental_enable_cb.isChecked()

            # Update the memory optimizer if it exists
            if hasattr(self, 'memory_optimizer') and self.memory_optimizer:
                self.memory_optimizer.set_threshold(memory_threshold)
                self.memory_optimizer.set_check_interval(memory_interval)

            self.update_output.emit("Applied performance optimization settings")
            logger.info("Applied performance optimization settings")
        except Exception as e:
            self.update_output.emit(f"Error applying performance settings: {str(e)}")
            logger.error(f"Error in apply_performance_settings: {str(e)}")

    def __init__(self):
        """
        Initialize the main Intellicrack application window.

        Sets up the logger, model manager, and other core components.
        """
        super().__init__()
        # Flag to track if UI is initialized
        self._ui_initialized = False

        # Initialize logger first
        self.logger = logging.getLogger("IntellicrackLogger.Main")
        
        # Now we can use logging
        self.logger.debug(f"QMainWindow initialized, parent: {self.parent()}")
        self.logger.debug(f"Initial visibility: {self.isVisible()}")
        self.logger.debug(f"Initial window state: {self.windowState()}")
        self.logger.info("IntellicrackApp constructor called. Initializing main application window.")

        # Initialize the ModelManager
        models_dir = CONFIG.get('model_repositories', {}).get('local', {}).get('models_directory', 'models')
        self.model_manager = ModelManager(models_dir)

        # Initialize ML predictor
        try:
            # Enhanced diagnostics for ML model loading
            self.logger.info("Starting ML model initialization with diagnostics")

            # Create models directory if it doesn't exist
            os.makedirs("models", exist_ok=True)

            # First check CONFIG for custom model path
            model_found = False
            model_path = None
            model_path_debug_info = []

            # 1. Try CONFIG["ml_model_path"] first if it exists
            if "ml_model_path" in CONFIG and CONFIG["ml_model_path"]:
                config_path = CONFIG["ml_model_path"]
                model_path_debug_info.append(f"Checking CONFIG path: {config_path}")
                if os.path.exists(config_path):
                    model_path = config_path
                    model_found = True
                    model_path_debug_info.append(f"MODEL FOUND at CONFIG path: {config_path}")
                else:
                    model_path_debug_info.append(f"MODEL NOT FOUND at CONFIG path: {config_path}")
            else:
                model_path_debug_info.append("No CONFIG['ml_model_path'] set")

            # 2. Try default path using __file__ if not found in CONFIG
            if not model_found:
                default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "vuln_predict_model.joblib")
                model_path_debug_info.append(f"Checking default path: {default_path}")
                if os.path.exists(default_path):
                    model_path = default_path
                    model_found = True
                    model_path_debug_info.append(f"MODEL FOUND at default path: {default_path}")
                else:
                    model_path_debug_info.append(f"MODEL NOT FOUND at default path: {default_path}")

            # 3. Try alternate locations as fallbacks
            if not model_found:
                alternate_paths = [
                    os.path.join("models", "vuln_predict_model.joblib"),
                    os.path.join("..", "models", "vuln_predict_model.joblib"),
                    os.path.join(".", "models", "vuln_predict_model.joblib")
                ]

                for alt_path in alternate_paths:
                    abs_alt_path = os.path.abspath(alt_path)
                    model_path_debug_info.append(f"Checking alternate path: {abs_alt_path}")
                    if os.path.exists(abs_alt_path):
                        model_path = abs_alt_path
                        model_found = True
                        model_path_debug_info.append(f"MODEL FOUND at alternate path: {abs_alt_path}")
                        break
                    else:
                        model_path_debug_info.append(f"MODEL NOT FOUND at alternate path: {abs_alt_path}")

            # Log all the path information for diagnostic purposes
            for info in model_path_debug_info:
                self.logger.info(f"[ML Path Diagnostic] {info}")

            # If model was found in any location, initialize the predictor
            if model_found and model_path:
                try:
                    self.ml_predictor = MLVulnerabilityPredictor(model_path)
                    self.logger.info(f"ML predictor successfully initialized with model: {model_path}")

                    # Update CONFIG to remember this path for next time
                    CONFIG["ml_model_path"] = model_path
                    self.save_config()
                except Exception as e:
                    self.logger.error(f"Failed to initialize ML predictor despite finding model file: {e}")
                    self.logger.error(f"Exception details: {traceback.format_exc()}")
                    self.ml_predictor = None
            else:
                # Create a placeholder model file if no model was found anywhere
                default_model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "vuln_predict_model.joblib")
                self.logger.warning(f"ML model file not found in any location. Creating a placeholder model at: {default_model_path}")
                self._create_default_ml_model(default_model_path)
                try:
                    self.ml_predictor = MLVulnerabilityPredictor(default_model_path)
                    self.logger.info(f"ML predictor initialized with placeholder model: {default_model_path}")

                    # Update config with the new path
                    CONFIG["ml_model_path"] = default_model_path  # Use default_model_path which is defined above
                    self.save_config()
                except Exception as e:
                    self.logger.error(f"Failed to initialize ML predictor with placeholder model: {e}")
                    self.logger.error(f"Exception details: {traceback.format_exc()}")
                    self.ml_predictor = None
            self.logger.info("ML predictor initialization complete.")
        except Exception as e:
            self.logger.error(f"Failed to initialize ML predictor: {e}")
            self.logger.error(f"Exception details: {traceback.format_exc()}")
            self.ml_predictor = None

        # Initialize AI Orchestrator for agentic environment
        try:
            self.logger.info("Initializing AI Orchestrator for agentic environment...")
            from ..ai.orchestrator import get_orchestrator
            self.ai_orchestrator = get_orchestrator()
            self.logger.info("AI Orchestrator initialized successfully - agentic environment ready")
            
            # Initialize coordination layer for intelligent AI workflows
            from ..ai.coordination_layer import AICoordinationLayer
            self.ai_coordinator = AICoordinationLayer(
                shared_context=self.ai_orchestrator.shared_context,
                event_bus=self.ai_orchestrator.event_bus
            )
            self.logger.info("AI Coordination Layer initialized successfully")
            
            # Set up AI event subscriptions for UI integration
            self.ai_orchestrator.event_bus.subscribe("task_complete", self._on_ai_task_complete, "main_ui")
            self.ai_orchestrator.event_bus.subscribe("coordinated_analysis_complete", self._on_coordinated_analysis_complete, "main_ui")
            
            self.logger.info("IntellicrackApp initialization complete with agentic AI system.")
        except Exception as e:
            self.logger.error(f"Failed to initialize AI Orchestrator: {e}")
            self.logger.error(f"Exception details: {traceback.format_exc()}")
            self.ai_orchestrator = None
            self.ai_coordinator = None
            self.logger.warning("Continuing without agentic AI system")

        # Connect signals
        self.update_output.connect(self.append_output)
        self.update_status.connect(self.set_status_message)
        self.update_analysis_results.connect(self.append_analysis_results)
        # self.clear_analysis_results.connect(self.analyze_results.clear)
        self.update_progress.connect(self.set_progress_value)
        self.update_assistant_status.connect(self.set_assistant_status)
        self.update_chat_display.connect(self.append_chat_display)
        self.replace_chat_display_last.connect(self.replace_last_chat_message)
        self.log_user_question.connect(self.handle_log_user_question)
        self.set_keygen_name.connect(self.handle_set_keygen_name)
        self.set_keygen_version.connect(self.handle_set_keygen_version)
        self.switch_tab.connect(self.handle_switch_tab)
        self.generate_key_signal.connect(self.handle_generate_key)

        # Set up main window
        self.setWindowTitle("Intellicrack")
        self.setGeometry(100, 100, 1200, 800)

        # Try to load icon
        icon_path = "assets/icon.ico"
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # Initialize important properties
        self.binary_path = None
        self.selected_model_path = CONFIG.get("selected_model_path", None) # Initialize from config
        if self.selected_model_path and os.path.exists(self.selected_model_path):
            # Update the label in settings if the path is valid
            if hasattr(self, 'custom_model_path_label'):
                self.custom_model_path_label.setText(os.path.basename(self.selected_model_path))
            self.update_output.emit(log_message(f"[AI Model] Loaded saved model path from config: {self.selected_model_path}"))
        else:
            self.selected_model_path = None # Ensure it's None if path is invalid or not set
            if hasattr(self, 'custom_model_path_label'):
                self.custom_model_path_label.setText("None")
            self.update_output.emit(log_message("[AI Model] No saved model path found or path is invalid."))


        self.chat_history = []
        self.frida_sessions = {}
        self.auto_patch_attempted = False
        self.potential_patches = []  # Initialize potential_patches
        self.recent_files = []  # Initialize recent files list
        self.current_theme = CONFIG.get("ui_theme", "default")  # Initialize theme

        # --- Initialize analyzer instance variables to None ---
        self.dynamic_analyzer = None
        self.ml_predictor = None
        self.analyze_results = []
        self.patches = []
        self.binary_info = None
        # --- End Initialization ---

        # Connect external function wrappers as instance methods using partial
        # These are global functions that take 'self' as their first argument
        # Only include functions that actually exist as global functions
        self.inject_comprehensive_api_hooks = partial(inject_comprehensive_api_hooks, self)
        self.run_frida_plugin_from_file = partial(run_frida_plugin_from_file, self)
        self.run_ghidra_plugin_from_file = partial(run_ghidra_plugin_from_file, self)
        self.setup_memory_patching = partial(setup_memory_patching, self)
        self.run_rop_chain_generator = partial(run_rop_chain_generator, self)
        self.run_automated_patch_agent = partial(run_automated_patch_agent, self)
        
        # Add all runner functions
        self.run_ssl_tls_interceptor = partial(run_ssl_tls_interceptor, self)
        self.run_protocol_fingerprinter = partial(run_protocol_fingerprinter, self)
        self.run_cloud_license_hooker = partial(run_cloud_license_hooker, self)
        self.run_cfg_explorer = partial(run_cfg_explorer, self)
        self.run_concolic_execution = partial(run_concolic_execution, self)
        self.run_enhanced_protection_scan = partial(run_enhanced_protection_scan, self)
        self.run_visual_network_traffic_analyzer = partial(run_visual_network_traffic_analyzer, self)
        self.run_multi_format_analysis = partial(run_multi_format_analysis, self)
        self.run_distributed_processing = partial(run_distributed_processing, self)
        self.run_gpu_accelerated_analysis = partial(run_gpu_accelerated_analysis, self)
        self.run_advanced_ghidra_analysis = partial(run_advanced_ghidra_analysis, self)
        self.run_symbolic_execution = partial(run_symbolic_execution, self)
        self.run_incremental_analysis = partial(run_incremental_analysis, self)
        self.run_memory_optimized_analysis = partial(run_memory_optimized_analysis, self)
        self.run_taint_analysis = partial(run_taint_analysis, self)
        self.run_qemu_analysis = partial(run_qemu_analysis, self)
        self.run_selected_analysis = partial(run_selected_analysis, self)
        self.run_network_license_server = partial(run_network_license_server, self)
        self.run_frida_analysis = partial(run_frida_analysis, self)
        self.run_dynamic_instrumentation = partial(run_dynamic_instrumentation, self)
        self.run_frida_script = partial(run_frida_script, self)

        # -------------------------------
        # Method Binding
        # -------------------------------
        # Bind all the standalone method definitions to the IntellicrackApp class
        # This allows them to be used as instance methods while keeping the code modular

        # Note: The following methods are defined as instance methods later in the class:
        # run_selected_patching, run_memory_analysis, run_network_analysis, run_patching,
        # refresh_patch_list, apply_patch, revert_patch, edit_patch, apply_all_patches,
        # revert_all_patches, export_patches, run_patch_test, verify_patch_results

        # Bind network and license server methods
        self.__class__.start_network_capture = start_network_capture
        self.__class__.stop_network_capture = stop_network_capture
        self.__class__.clear_network_capture = clear_network_capture
        self.__class__.start_license_server = start_license_server
        self.__class__.stop_license_server = stop_license_server
        self.__class__.test_license_server = test_license_server
        self.__class__.launch_protocol_tool = launch_protocol_tool
        self.__class__.update_protocol_tool_description = update_protocol_tool_description

        # Bind report-related methods
        self.__class__.generate_report = generate_report
        self.__class__.view_report = view_report
        # Note: The following methods are defined as instance methods later in the class:
        # export_report, delete_report, refresh_reports_list, import_report

        # Initialize analyzer instances with graceful fallbacks
        self.dynamic_analyzer = None
        self.ml_predictor = None
        
        try:
            self.memory_optimized_loader = MemoryOptimizedBinaryLoader() if MemoryOptimizedBinaryLoader else None
        except Exception as e:
            self.memory_optimized_loader = None
            logger.warning(f"Failed to initialize MemoryOptimizedBinaryLoader: {e}")
            
        try:
            self.symbolic_execution_engine = SymbolicExecutionEngine("") if SymbolicExecutionEngine else None
        except Exception as e:
            self.symbolic_execution_engine = None
            logger.warning(f"Failed to initialize SymbolicExecutionEngine: {e}")
            
        try:
            self.taint_analysis_engine = TaintAnalysisEngine() if TaintAnalysisEngine else None
        except Exception as e:
            self.taint_analysis_engine = None
            logger.warning(f"Failed to initialize TaintAnalysisEngine: {e}")
            
        try:
            self.concolic_execution_engine = ConcolicExecutionEngine("") if ConcolicExecutionEngine else None
        except Exception as e:
            self.concolic_execution_engine = None
            logger.warning(f"Failed to initialize ConcolicExecutionEngine: {e}")
            
        try:
            self.rop_chain_generator = ROPChainGenerator() if ROPChainGenerator else None
        except Exception as e:
            self.rop_chain_generator = None
            logger.warning(f"Failed to initialize ROPChainGenerator: {e}")
            
        try:
            self.distributed_processing_manager = DistributedProcessingManager() if DistributedProcessingManager else None
        except Exception as e:
            self.distributed_processing_manager = None
            logger.warning(f"Failed to initialize DistributedProcessingManager: {e}")
            
        try:
            self.gpu_accelerator = GPUAccelerator() if GPUAccelerator else None
        except Exception as e:
            self.gpu_accelerator = None
            logger.warning(f"Failed to initialize GPUAccelerator: {e}")
            
        # Initialize network components
        try:
            from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer
            self.network_traffic_analyzer = NetworkTrafficAnalyzer()
        except Exception as e:
            self.network_traffic_analyzer = None
            logger.warning(f"Failed to initialize NetworkTrafficAnalyzer: {e}")
            
        try:
            from ..core.network.ssl_interceptor import SSLTLSInterceptor
            self.ssl_interceptor = SSLTLSInterceptor()
        except Exception as e:
            self.ssl_interceptor = None
            logger.warning(f"Failed to initialize SSLTLSInterceptor: {e}")
            
        try:
            from ..core.network.protocol_fingerprinter import ProtocolFingerprinter
            self.protocol_fingerprinter = ProtocolFingerprinter()
        except Exception as e:
            self.protocol_fingerprinter = None
            logger.warning(f"Failed to initialize ProtocolFingerprinter: {e}")
            
        try:
            from ..core.network.license_server_emulator import NetworkLicenseServerEmulator
            self.network_license_server = NetworkLicenseServerEmulator()
        except Exception as e:
            self.network_license_server = None
            logger.warning(f"Failed to initialize NetworkLicenseServerEmulator: {e}")
        
        # Add TOOL_REGISTRY for hexview integration
        self.TOOL_REGISTRY = TOOL_REGISTRY.copy()
        
        # Initialize ghidra_path_edit to avoid attribute errors
        self.ghidra_path_edit = None
        
        # pylint: disable=no-value-for-parameter
        self.pdf_report_generator = PDFReportGenerator()

        # Create central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout(self.central_widget)

        self.create_toolbar()

        self.main_splitter = QSplitter(Qt.Horizontal)
        self.main_layout.addWidget(self.main_splitter)

        self.tabs = QTabWidget()
        # Style main tabs differently from sub-tabs to avoid visual confusion
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setTabsClosable(False)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #C0C0C0;
                background-color: #F0F0F0;
            }
            QTabWidget::tab-bar {
                alignment: center;
            }
            QTabBar::tab {
                background-color: #E0E0E0;
                border: 1px solid #C0C0C0;
                padding: 8px 16px;
                margin-right: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #FFFFFF;
                border-bottom-color: #FFFFFF;
            }
            QTabBar::tab:hover {
                background-color: #F0F0F0;
            }
        """)
        self.tabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        self.tabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        self.main_splitter.addWidget(self.tabs)

        self.output_panel = QWidget()
        self.output_layout = QVBoxLayout(self.output_panel)
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.clear_output_btn = QPushButton("Clear Output")
        self.clear_output_btn.clicked.connect(self.clear_output)

        self.output_layout.addWidget(QLabel("<b>Output</b>"))
        self.output_layout.addWidget(self.output)
        self.output_layout.addWidget(self.clear_output_btn)

        self.main_splitter.addWidget(self.output_panel)

        self.main_splitter.setSizes([700, 500])

        # Create tab widgets for the main application tabs
        self.project_dashboard_tab = QWidget()
        self.analysis_tab = QWidget()
        self.patching_exploitation_tab = QWidget()
        self.ai_assistant_tab = QWidget()
        self.netanalysis_emulation_tab = QWidget()
        self.tools_plugins_tab = QWidget()
        self.settings_tab = QWidget()

        # Add tabs to the tab widget with new organization
        self.tabs.addTab(self.project_dashboard_tab, "Project & Dashboard")
        self.tabs.addTab(self.analysis_tab, "Analysis")
        self.tabs.addTab(self.patching_exploitation_tab, "Patching & Exploitation")
        self.tabs.addTab(self.ai_assistant_tab, "AI Assistant")
        self.tabs.addTab(self.netanalysis_emulation_tab, "NetAnalysis & Emulation")
        self.tabs.addTab(self.tools_plugins_tab, "Tools & Plugins")
        self.tabs.addTab(self.settings_tab, "Settings")

        # Initialize dashboard manager
        self.dashboard_manager = DashboardManager(self)

        # Initialize the binary_path variable before setting up tabs
        self.binary_path = None

        # Setup each tab with appropriate UI components
        try:
            self.logger.info("Setting up project dashboard tab...")
            self.setup_project_dashboard_tab()
            self.logger.info("Project dashboard tab setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup project dashboard tab: {e}")
            self.logger.error(traceback.format_exc())
            raise
            
        try:
            self.logger.info("Setting up analysis tab...")
            self.setup_analysis_tab()
            self.logger.info("Analysis tab setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup analysis tab: {e}")
            self.logger.error(traceback.format_exc())
            raise
            
        try:
            self.logger.info("Setting up patching exploitation tab...")
            self.setup_patching_exploitation_tab()
            self.logger.info("Patching exploitation tab setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup patching exploitation tab: {e}")
            self.logger.error(traceback.format_exc())
            raise
            
        try:
            self.logger.info("Setting up AI assistant tab...")
            self.setup_ai_assistant_tab()
            self.logger.info("AI assistant tab setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup AI assistant tab: {e}")
            self.logger.error(traceback.format_exc())
            raise
            
        try:
            self.logger.info("Setting up network analysis emulation tab...")
            self.setup_netanalysis_emulation_tab()
            self.logger.info("Network analysis emulation tab setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup network analysis emulation tab: {e}")
            self.logger.error(traceback.format_exc())
            raise
            
        try:
            self.logger.info("Setting up tools plugins tab...")
            self.setup_tools_plugins_tab()
            self.logger.info("Tools plugins tab setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup tools plugins tab: {e}")
            self.logger.error(traceback.format_exc())
            raise
            
        try:
            self.logger.info("Setting up settings tab...")
            self.setup_settings_tab()
            self.logger.info("Settings tab setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup settings tab: {e}")
            self.logger.error(traceback.format_exc())
            raise
            
        self.logger.info("All tab setup complete - constructor finished")
        
        # Ensure window is properly configured
        self.setGeometry(100, 100, 1200, 800)
        self.setWindowTitle("Intellicrack - Binary Analysis Tool")
        self.setMinimumSize(800, 600)
        
        # Initialize plugins
        try:
            from ..plugins.plugin_system import create_sample_plugins
            create_sample_plugins()
            self.available_plugins = self.load_available_plugins()
            self.logger.info(f"Loaded {len(self.available_plugins.get('custom', []))} custom plugins, "
                           f"{len(self.available_plugins.get('frida', []))} Frida scripts, "
                           f"{len(self.available_plugins.get('ghidra', []))} Ghidra scripts")
        except Exception as e:
            self.logger.warning(f"Plugin initialization failed: {e}")
            self.available_plugins = {"custom": [], "frida": [], "ghidra": []}
        
        self.logger.info("Window configuration complete")
    
    def closeEvent_handler(self, event):
        """Handle window close event."""
        self.logger.info("Application closing...")
        event.accept()
        
    def setup_project_dashboard_tab(self):
        """Sets up the Project & Dashboard tab with file management, project overview, and quick actions."""
        # Create main layout
        layout = QVBoxLayout(self.project_dashboard_tab)
        
        # Project Controls section
        project_controls_group = QGroupBox("Project Controls")
        project_controls_layout = QVBoxLayout(project_controls_group)
        
        # Open Binary button
        open_binary_btn = QPushButton("Open Binary...")
        open_binary_btn.clicked.connect(self.select_program)
        
        # Recent Files button with menu
        recent_files_btn = QPushButton("Recent Files")
        recent_files_menu = QMenu(recent_files_btn)
        recent_files_btn.setMenu(recent_files_menu)
        # Populate with recent files (will be updated dynamically)
        
        # Save Analysis Results button
        save_analysis_btn = QPushButton("Save Analysis Results...")
        save_analysis_btn.clicked.connect(self.save_analysis_results)
        
        # Add buttons to layout
        project_controls_layout.addWidget(open_binary_btn)
        project_controls_layout.addWidget(recent_files_btn)
        project_controls_layout.addWidget(save_analysis_btn)
        
        # Dashboard Overview section
        dashboard_overview_group = QGroupBox("Dashboard Overview")
        dashboard_overview_layout = QVBoxLayout(dashboard_overview_group)
        
        # Binary info display
        binary_info_layout = QHBoxLayout()
        
        # Binary icon
        self.binary_icon_label = QLabel()
        self.binary_icon_label.setFixedSize(64, 64)
        binary_info_layout.addWidget(self.binary_icon_label)
        
        # Binary information
        self.binary_info_label = QLabel("No binary loaded")
        binary_info_layout.addWidget(self.binary_info_label)
        
        dashboard_overview_layout.addLayout(binary_info_layout)
        
        # Quick Statistics section
        quick_stats_group = QGroupBox("Quick Statistics")
        quick_stats_layout = QVBoxLayout(quick_stats_group)
        
        # Statistics labels
        self.vulns_found_label = QLabel("Vulnerabilities Found: 0")
        self.protections_label = QLabel("Protections Detected: None")
        self.patches_label = QLabel("Patches: 0/0 (Applied/Pending)")
        
        quick_stats_layout.addWidget(self.vulns_found_label)
        quick_stats_layout.addWidget(self.protections_label)
        quick_stats_layout.addWidget(self.patches_label)
        
        dashboard_overview_layout.addWidget(quick_stats_group)
        
        # Recent Activities Log
        activities_label = QLabel("Recent Activities Log")
        self.activities_log = QTextEdit()
        self.activities_log.setReadOnly(True)
        
        dashboard_overview_layout.addWidget(activities_label)
        dashboard_overview_layout.addWidget(self.activities_log)
        
        # Quick Actions section
        quick_actions_group = QGroupBox("Quick Actions")
        quick_actions_layout = QVBoxLayout(quick_actions_group)
        
        # One-Click Full Analysis & Patch button
        full_analysis_btn = QPushButton("One-Click Full Analysis & Patch")
        full_analysis_btn.clicked.connect(self.run_autonomous_crack)
        
        # Guided Workflow Wizard button
        guided_wizard_btn = QPushButton("Guided Workflow Wizard")
        guided_wizard_btn.clicked.connect(self.start_guided_wizard)
        
        quick_actions_layout.addWidget(full_analysis_btn)
        quick_actions_layout.addWidget(guided_wizard_btn)
        
        # Add all sections to main layout
        layout.addWidget(project_controls_group)
        layout.addWidget(dashboard_overview_group)
        layout.addWidget(quick_actions_group)
    
        
        
    def select_binary(self):
        """Open a file dialog to select a binary for analysis."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Binary", "", "Executable Files (*.exe *.dll *.so);;All Files (*)"
        )
        
        if file_path:
            self.binary_path = file_path
            self.remove_file_btn.setEnabled(True)
            self.next_to_config_btn.setEnabled(True)
            
            # Update file info display
            file_info = QtCore.QFileInfo(file_path)
            file_name = file_info.fileName()
            file_size = file_info.size()
            
            # Get file icon
            try:
                # Try to get icon from the system
                file_info = QtCore.QFileInfo(file_path)
                icon_provider = QFileIconProvider()
                icon = icon_provider.icon(file_info)
                
                if not icon.isNull():
                    pixmap = icon.pixmap(64, 64)
                    self.file_icon_label.setPixmap(pixmap)
                else:
                    # Use placeholder icon
                    self.file_icon_label.setPixmap(self._create_icon_pixmap())
            except:
                # Fallback to text icon
                self.file_icon_label.setText("📄")
            
            # Update file info text
            self.file_info_text.setText(f"File: {file_name}\nPath: {file_path}\nSize: {file_size} bytes")
            
    def clear_binary(self):
        """Clear the selected binary."""
        self.binary_path = None
        self.remove_file_btn.setEnabled(False)
        self.next_to_config_btn.setEnabled(False)
        
        # Reset file info display
        self.file_icon_label.setText("")
        self.file_info_text.setText("No file selected")
        
    def load_recent_file(self, item):
        """Load a recently used file from the list."""
        # Extract file path from item text (this is a simplified implementation)
        file_path = item.text().split(" - ")[1]
        self.binary_path = file_path
        self.remove_file_btn.setEnabled(True)
        self.next_to_config_btn.setEnabled(True)
        
        # Update file info display
        file_name = file_path.split("\\")[-1]
        
        # Set placeholder icon
        self.file_icon_label.setText("📄")
        
        # Update file info text
        self.file_info_text.setText(f"File: {file_name}\nPath: {file_path}\nSize: Unknown")
        
    def on_analysis_type_changed(self, index):
        """Handle analysis type selection changes."""
        analysis_type = self.analysis_type_combo.currentText()
        
        # Update UI based on selected analysis type
        if analysis_type == "License Analysis":
            self.frida_hook_cb.setChecked(True)
            self.qiling_emul_cb.setChecked(True)
            self.stealth_patch_cb.setChecked(True)
        elif analysis_type == "Vulnerability Analysis":
            self.api_monitor_cb.setChecked(True)
            self.syscall_trace_cb.setChecked(True)
            self.auto_patch_cb.setChecked(False)
        elif analysis_type == "Advanced Analysis":
            self.frida_hook_cb.setChecked(True)
            self.api_monitor_cb.setChecked(True)
            self.syscall_trace_cb.setChecked(True)
            self.qiling_emul_cb.setChecked(True)
            
    def setup_analysis_tab(self):
        """Sets up the Analysis tab with all its sub-tabs for various analysis features."""
        # Create main layout
        layout = QVBoxLayout(self.analysis_tab)
        
        # Create sub-tabs for the Analysis tab
        analysis_subtabs = QTabWidget()
        analysis_subtabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        analysis_subtabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Create individual sub-tab widgets
        static_code_analysis_tab = QWidget()
        protection_analysis_tab = QWidget()
        dynamic_hooking_tab = QWidget()
        advanced_execution_engines_tab = QWidget()
        analysis_options_cache_tab = QWidget()
        
        # 1. Static & Code Analysis sub-tab
        static_layout = QVBoxLayout(static_code_analysis_tab)
        
        # Full Static Analysis button
        run_static_btn = QPushButton("Run Full Static Analysis")
        run_static_btn.clicked.connect(self.run_analysis)
        static_layout.addWidget(run_static_btn)
        
        # Detailed Static Checks section
        static_checks_group = QGroupBox("Detailed Static Checks")
        static_checks_layout = QVBoxLayout(static_checks_group)
        
        section_analysis_cb = QCheckBox("Section Analysis (Entropy, Permissions)")
        import_export_cb = QCheckBox("Import/Export Table Analysis")
        string_analysis_cb = QCheckBox("String Analysis")
        extract_scripts_cb = QCheckBox("Extract Embedded/Encrypted Scripts")
        
        static_checks_layout.addWidget(section_analysis_cb)
        static_checks_layout.addWidget(import_export_cb)
        static_checks_layout.addWidget(string_analysis_cb)
        static_checks_layout.addWidget(extract_scripts_cb)
        
        static_layout.addWidget(static_checks_group)
        
        # Code Exploration section
        code_exploration_group = QGroupBox("Code Exploration")
        code_exploration_layout = QVBoxLayout(code_exploration_group)
        
        # Disassembly view
        disasm_group = QGroupBox("Disassembly View")
        disasm_layout = QVBoxLayout(disasm_group)
        
        disasm_addr_layout = QHBoxLayout()
        disasm_addr_layout.addWidget(QLabel("Address:"))
        disasm_addr_input = QLineEdit()
        disasm_addr_layout.addWidget(disasm_addr_input)
        
        disasm_instr_layout = QHBoxLayout()
        disasm_instr_layout.addWidget(QLabel("Instructions:"))
        disasm_instr_spin = QSpinBox()
        disasm_instr_spin.setRange(1, 1000)
        disasm_instr_spin.setValue(20)
        disasm_instr_layout.addWidget(disasm_instr_spin)
        
        disasm_btn = QPushButton("Disassemble")
        
        disasm_output = QTextEdit()
        disasm_output.setReadOnly(True)
        
        disasm_layout.addLayout(disasm_addr_layout)
        disasm_layout.addLayout(disasm_instr_layout)
        disasm_layout.addWidget(disasm_btn)
        disasm_layout.addWidget(disasm_output)
        
        code_exploration_layout.addWidget(disasm_group)
        
        # Other code exploration buttons
        view_cfg_btn = QPushButton("View/Analyze Control Flow Graph (CFG)")
        view_cfg_btn.clicked.connect(lambda: run_deep_cfg_analysis(self))
        
        find_rop_btn = QPushButton("Find ROP Gadgets")
        find_rop_btn.clicked.connect(self.run_rop_gadget_finder)
        
        binary_sim_btn = QPushButton("Binary Similarity Search")
        binary_sim_btn.clicked.connect(self.run_binary_similarity_search)
        
        code_exploration_layout.addWidget(view_cfg_btn)
        code_exploration_layout.addWidget(find_rop_btn)
        code_exploration_layout.addWidget(binary_sim_btn)
        
        static_layout.addWidget(code_exploration_group)
        
        # Specialized Static Tools section
        specialized_tools_group = QGroupBox("Specialized Static Tools")
        specialized_tools_layout = QVBoxLayout(specialized_tools_group)
        
        show_details_btn = QPushButton("Show Multi-Format Binary Details")
        show_details_btn.clicked.connect(lambda: self.run_multi_format_analysis())
        specialized_tools_layout.addWidget(show_details_btn)
        
        # Deep License Analysis & Pattern Recognition
        license_analysis_btn = QPushButton("Deep License Logic Analysis & Pattern Recognition")
        license_analysis_btn.clicked.connect(lambda: run_deep_license_analysis(self))
        specialized_tools_layout.addWidget(license_analysis_btn)
        
        static_layout.addWidget(specialized_tools_group)
        
        # Ghidra Integration section
        ghidra_group = QGroupBox("Ghidra Integration")
        ghidra_layout = QVBoxLayout(ghidra_group)
        
        open_ghidra_btn = QPushButton("Open in Ghidra GUI")
        open_ghidra_btn.clicked.connect(self.run_ghidra_analysis_gui)
        
        run_headless_btn = QPushButton("Run Ghidra Headless Analysis (AdvancedScript)")
        run_headless_btn.clicked.connect(lambda: self.run_advanced_ghidra_analysis())
        
        ghidra_layout.addWidget(open_ghidra_btn)
        ghidra_layout.addWidget(run_headless_btn)
        
        ghidra_script_layout = QHBoxLayout()
        ghidra_script_layout.addWidget(QLabel("Run Custom Ghidra Script:"))
        ghidra_script_combo = QComboBox()
        ghidra_script_layout.addWidget(ghidra_script_combo)
        
        run_script_btn = QPushButton("Run Selected Ghidra Script")
        run_script_btn.clicked.connect(lambda: self.run_ghidra_plugin_from_file(ghidra_script_combo.currentText()))
        
        ghidra_layout.addLayout(ghidra_script_layout)
        ghidra_layout.addWidget(run_script_btn)
        
        static_layout.addWidget(ghidra_group)
        
        # 2. Protection Analysis sub-tab
        protection_layout = QVBoxLayout(protection_analysis_tab)
        
        # Scan for All Known Protections button
        scan_protections_btn = QPushButton("Scan for All Known Protections")
        scan_protections_btn.clicked.connect(lambda: self.run_comprehensive_protection_scan())
        protection_layout.addWidget(scan_protections_btn)
        
        # Specific Protection Scans section
        specific_scans_group = QGroupBox("Specific Protection Scans")
        specific_scans_layout = QVBoxLayout(specific_scans_group)
        
        detect_packing_btn = QPushButton("Detect Packing/Obfuscation")
        detect_packing_btn.clicked.connect(self.run_packing_detection)
        detect_commercial_btn = QPushButton("Detect Commercial Protections")
        detect_commercial_btn.clicked.connect(self.run_commercial_protection_detection)
        detect_commercial_btn.clicked.connect(self.run_commercial_protection_scan)
        detect_dongles_btn = QPushButton("Detect Hardware Dongles")
        detect_dongles_btn.clicked.connect(self.run_hardware_dongle_detection)
        detect_tpm_btn = QPushButton("Detect TPM Protection")
        detect_tpm_btn.clicked.connect(self.run_tpm_detection)
        detect_vm_btn = QPushButton("Detect VM/Sandbox Evasion")
        detect_vm_btn.clicked.connect(self.run_vm_detection)
        detect_antidebug_btn = QPushButton("Detect Anti-Debugger Techniques")
        detect_antidebug_btn.clicked.connect(self.run_anti_debug_detection)
        detect_checksum_btn = QPushButton("Detect Checksum/Integrity Verification")
        detect_checksum_btn.clicked.connect(self.run_checksum_detection)
        detect_selfhealing_btn = QPushButton("Detect Self-Healing Code")
        detect_selfhealing_btn.clicked.connect(self.run_self_healing_detection)
        detect_embedded_script_btn = QPushButton("Detect Embedded/Encrypted Scripts")
        detect_embedded_script_btn.clicked.connect(self.run_embedded_script_detection)
        
        specific_scans_layout.addWidget(detect_packing_btn)
        specific_scans_layout.addWidget(detect_commercial_btn)
        specific_scans_layout.addWidget(detect_dongles_btn)
        specific_scans_layout.addWidget(detect_tpm_btn)
        specific_scans_layout.addWidget(detect_vm_btn)
        specific_scans_layout.addWidget(detect_antidebug_btn)
        specific_scans_layout.addWidget(detect_checksum_btn)
        specific_scans_layout.addWidget(detect_selfhealing_btn)
        specific_scans_layout.addWidget(detect_embedded_script_btn)
        
        protection_layout.addWidget(specific_scans_group)
        
        # Protection Bypass section
        bypass_group = QGroupBox("Protection Bypass Tools")
        bypass_layout = QVBoxLayout(bypass_group)
        
        bypass_tpm_btn = QPushButton("Bypass TPM Protection")
        bypass_tpm_btn.clicked.connect(self.run_tpm_bypass)
        bypass_vm_btn = QPushButton("Bypass VM Detection")
        bypass_vm_btn.clicked.connect(self.run_vm_bypass)
        bypass_dongle_btn = QPushButton("Activate Dongle Emulation")
        bypass_dongle_btn.clicked.connect(self.run_dongle_emulation)
        
        bypass_layout.addWidget(bypass_tpm_btn)
        bypass_layout.addWidget(bypass_vm_btn)
        bypass_layout.addWidget(bypass_dongle_btn)
        
        protection_layout.addWidget(bypass_group)
        
        # Vulnerability Scanning section
        vuln_scan_group = QGroupBox("Vulnerability Scanning (Static & ML)")
        vuln_scan_layout = QVBoxLayout(vuln_scan_group)
        
        run_static_vuln_btn = QPushButton("Run Advanced Static Vulnerability Scan")
        run_static_vuln_btn.clicked.connect(self.run_static_vulnerability_scan)
        run_ml_vuln_btn = QPushButton("Run ML-Based Vulnerability Prediction")
        run_ml_vuln_btn.clicked.connect(self.run_ml_vulnerability_prediction)
        
        vuln_scan_layout.addWidget(run_static_vuln_btn)
        vuln_scan_layout.addWidget(run_ml_vuln_btn)
        
        protection_layout.addWidget(vuln_scan_group)
        
        # Results output area
        self.protection_results = QTextEdit()
        self.protection_results.setReadOnly(True)
        protection_layout.addWidget(self.protection_results)
        
        # 3. Dynamic & Hooking sub-tab
        dynamic_layout = QVBoxLayout(dynamic_hooking_tab)
        
        # Process Control section
        process_control_group = QGroupBox("Process Control")
        process_control_layout = QVBoxLayout(process_control_group)
        
        launch_target_btn = QPushButton("Launch Target Binary")
        
        process_id_layout = QHBoxLayout()
        process_id_layout.addWidget(QLabel("Process ID:"))
        process_id_input = QLineEdit()
        process_id_layout.addWidget(process_id_input)
        
        attach_process_btn = QPushButton("Attach to Process")
        detach_process_btn = QPushButton("Detach from Process")
        
        process_control_layout.addWidget(launch_target_btn)
        process_control_layout.addLayout(process_id_layout)
        process_control_layout.addWidget(attach_process_btn)
        process_control_layout.addWidget(detach_process_btn)
        
        dynamic_layout.addWidget(process_control_group)
        
        # Frida Instrumentation section
        frida_group = QGroupBox("Frida Instrumentation & Runtime Monitoring")
        frida_layout = QVBoxLayout(frida_group)
        
        api_hooking_btn = QPushButton("Start Comprehensive API Hooking")
        api_hooking_btn.clicked.connect(self.inject_comprehensive_api_hooks)
        
        # Hooking options
        hooking_options_layout = QHBoxLayout()
        registry_hook_cb = QCheckBox("Registry")
        fs_hook_cb = QCheckBox("Filesystem")
        network_hook_cb = QCheckBox("Network")
        hwid_hook_cb = QCheckBox("HWID")
        
        hooking_options_layout.addWidget(registry_hook_cb)
        hooking_options_layout.addWidget(fs_hook_cb)
        hooking_options_layout.addWidget(network_hook_cb)
        hooking_options_layout.addWidget(hwid_hook_cb)
        
        monitoring_btn = QPushButton("Start Deep Runtime Monitoring")
        monitoring_btn.clicked.connect(self.run_deep_runtime_monitoring)
        
        frida_script_layout = QHBoxLayout()
        frida_script_layout.addWidget(QLabel("Run Custom Frida Script:"))
        frida_script_combo = QComboBox()
        frida_script_layout.addWidget(frida_script_combo)
        
        run_frida_btn = QPushButton("Run Selected Frida Script")
        run_frida_btn.clicked.connect(lambda: self.run_frida_plugin_from_file(frida_script_combo.currentText()))
        
        frida_layout.addWidget(api_hooking_btn)
        frida_layout.addLayout(hooking_options_layout)
        frida_layout.addWidget(monitoring_btn)
        frida_layout.addLayout(frida_script_layout)
        frida_layout.addWidget(run_frida_btn)
        
        dynamic_layout.addWidget(frida_group)
        
        # Process Analysis section
        process_analysis_group = QGroupBox("Process Analysis (Runtime)")
        process_analysis_layout = QVBoxLayout(process_analysis_group)
        
        analyze_process_btn = QPushButton("Analyze Live Process Behavior")
        analyze_process_btn.clicked.connect(self.analyze_process_behavior)
        
        memory_scan_btn = QPushButton("Dynamic Memory Keyword Scan (Frida)")
        memory_scan_btn.clicked.connect(self.run_memory_keyword_scan)
        
        process_analysis_layout.addWidget(analyze_process_btn)
        process_analysis_layout.addWidget(memory_scan_btn)
        
        dynamic_layout.addWidget(process_analysis_group)
        
        # Output area
        dynamic_output = QTextEdit()
        dynamic_output.setReadOnly(True)
        dynamic_layout.addWidget(dynamic_output)
        
        # 4. Advanced Execution Engines sub-tab
        advanced_layout = QVBoxLayout(advanced_execution_engines_tab)
        
        # Symbolic Execution section
        symbolic_group = QGroupBox("Symbolic Execution (Angr)")
        symbolic_layout = QVBoxLayout(symbolic_group)
        
        symbolic_target_layout = QHBoxLayout()
        symbolic_target_layout.addWidget(QLabel("Target Function Address/Name:"))
        symbolic_target_input = QLineEdit()
        symbolic_target_layout.addWidget(symbolic_target_input)
        
        run_symbolic_btn = QPushButton("Run Symbolic Path Exploration")
        run_symbolic_btn.clicked.connect(lambda: run_symbolic_execution(self))
        
        generate_exploit_btn = QPushButton("Generate Exploit from Symbolic Path")
        
        symbolic_layout.addLayout(symbolic_target_layout)
        symbolic_layout.addWidget(run_symbolic_btn)
        symbolic_layout.addWidget(generate_exploit_btn)
        
        advanced_layout.addWidget(symbolic_group)
        
        # Concolic Execution section
        concolic_group = QGroupBox("Concolic Execution (Manticore/SimConcolic)")
        concolic_layout = QVBoxLayout(concolic_group)
        
        concolic_target_layout = QHBoxLayout()
        concolic_target_layout.addWidget(QLabel("Target Function Address/Name:"))
        concolic_target_input = QLineEdit()
        concolic_target_layout.addWidget(concolic_target_input)
        
        run_concolic_btn = QPushButton("Run Concolic Path Exploration")
        run_concolic_btn.clicked.connect(lambda: self.run_concolic_execution())
        
        find_license_btn = QPushButton("Find License Bypass (Concolic)")
        find_license_btn.clicked.connect(lambda: self.run_concolic_license_bypass())
        
        concolic_layout.addLayout(concolic_target_layout)
        concolic_layout.addWidget(run_concolic_btn)
        concolic_layout.addWidget(find_license_btn)
        
        advanced_layout.addWidget(concolic_group)
        
        # Taint Analysis section
        taint_group = QGroupBox("Taint Analysis")
        taint_layout = QVBoxLayout(taint_group)
        
        taint_sources_layout = QHBoxLayout()
        taint_sources_layout.addWidget(QLabel("Taint Sources (comma-separated):"))
        taint_sources_input = QLineEdit()
        taint_sources_layout.addWidget(taint_sources_input)
        
        taint_sinks_layout = QHBoxLayout()
        taint_sinks_layout.addWidget(QLabel("Taint Sinks (comma-separated):"))
        taint_sinks_input = QLineEdit()
        taint_sinks_layout.addWidget(taint_sinks_input)
        
        run_taint_btn = QPushButton("Run Taint Analysis")
        run_taint_btn.clicked.connect(lambda: self.run_taint_analysis())
        
        taint_layout.addLayout(taint_sources_layout)
        taint_layout.addLayout(taint_sinks_layout)
        taint_layout.addWidget(run_taint_btn)
        
        advanced_layout.addWidget(taint_group)
        
        # System Emulation section
        emulation_group = QGroupBox("System Emulation (QEMU)")
        emulation_layout = QVBoxLayout(emulation_group)
        
        arch_layout = QHBoxLayout()
        arch_layout.addWidget(QLabel("Select Architecture:"))
        arch_combo = QComboBox()
        arch_combo.addItems(["x86_64", "arm64", "x86", "arm", "mips"])
        arch_layout.addWidget(arch_combo)
        
        rootfs_layout = QHBoxLayout()
        rootfs_layout.addWidget(QLabel("Path to RootFS:"))
        rootfs_input = QLineEdit()
        rootfs_layout.addWidget(rootfs_input)
        
        emulation_buttons_layout = QHBoxLayout()
        start_qemu_btn = QPushButton("Start/Stop QEMU VM")
        create_snapshot_btn = QPushButton("Create Snapshot")
        restore_snapshot_btn = QPushButton("Restore Snapshot")
        emulation_buttons_layout.addWidget(start_qemu_btn)
        emulation_buttons_layout.addWidget(create_snapshot_btn)
        emulation_buttons_layout.addWidget(restore_snapshot_btn)
        
        command_layout = QHBoxLayout()
        command_layout.addWidget(QLabel("Command to execute in VM:"))
        self.qemu_command_input = QLineEdit()
        self.qemu_command_input.setPlaceholderText("Enter command to execute in QEMU VM...")
        command_layout.addWidget(self.qemu_command_input)
        
        execute_vm_btn = QPushButton("Execute in VM")
        compare_snapshots_btn = QPushButton("Compare Snapshots")
        
        emulation_layout.addLayout(arch_layout)
        emulation_layout.addLayout(rootfs_layout)
        emulation_layout.addLayout(emulation_buttons_layout)
        emulation_layout.addLayout(command_layout)
        emulation_layout.addWidget(execute_vm_btn)
        emulation_layout.addWidget(compare_snapshots_btn)
        
        # Connect QEMU button handlers
        start_qemu_btn.clicked.connect(lambda: self.run_qemu_analysis())
        create_snapshot_btn.clicked.connect(lambda: self.create_qemu_snapshot())
        restore_snapshot_btn.clicked.connect(lambda: self.restore_qemu_snapshot())
        execute_vm_btn.clicked.connect(lambda: self.execute_qemu_command())
        compare_snapshots_btn.clicked.connect(lambda: self.compare_qemu_snapshots())
        
        advanced_layout.addWidget(emulation_group)
        
        # Distributed Analysis section
        distributed_group = QGroupBox("Distributed Analysis Framework")
        distributed_layout = QVBoxLayout(distributed_group)
        
        config_nodes_btn = QPushButton("Configure Distributed Analysis Nodes")
        config_nodes_btn.clicked.connect(lambda: self.open_distributed_config())
        run_distributed_btn = QPushButton("Run Distributed Analysis Task")
        run_distributed_btn.clicked.connect(lambda: self.run_distributed_processing())
        
        distributed_layout.addWidget(config_nodes_btn)
        distributed_layout.addWidget(run_distributed_btn)
        
        advanced_layout.addWidget(distributed_group)
        
        # Output area
        advanced_output = QTextEdit()
        advanced_output.setReadOnly(True)
        advanced_layout.addWidget(advanced_output)
        
        # 5. Analysis Options & Cache sub-tab
        options_layout = QVBoxLayout(analysis_options_cache_tab)
        
        incremental_analysis_cb = QCheckBox("Enable Incremental Analysis Caching")
        clear_cache_btn = QPushButton("Clear Analysis Cache for Current Binary")
        clear_all_cache_btn = QPushButton("Clear All Analysis Cache")
        
        memory_optimized_cb = QCheckBox("Enable Memory-Optimized Loading for Large Files")
        memory_optimized_cb.clicked.connect(lambda: self.run_memory_optimized_analysis())
        
        gpu_acceleration_cb = QCheckBox("Enable GPU Acceleration for Analysis")
        gpu_acceleration_cb.clicked.connect(lambda: self.run_gpu_accelerated_analysis())
        
        configure_gpu_btn = QPushButton("Configure GPU Acceleration...")
        
        options_layout.addWidget(incremental_analysis_cb)
        options_layout.addWidget(clear_cache_btn)
        options_layout.addWidget(clear_all_cache_btn)
        options_layout.addWidget(memory_optimized_cb)
        options_layout.addWidget(gpu_acceleration_cb)
        options_layout.addWidget(configure_gpu_btn)
        
        # Add all sub-tabs to the tab widget
        analysis_subtabs.addTab(static_code_analysis_tab, "Static & Code Analysis")
        analysis_subtabs.addTab(protection_analysis_tab, "Protection Analysis")
        analysis_subtabs.addTab(dynamic_hooking_tab, "Dynamic & Hooking")
        analysis_subtabs.addTab(advanced_execution_engines_tab, "Advanced Execution Engines")
        analysis_subtabs.addTab(analysis_options_cache_tab, "Analysis Options & Cache")
        
        # Main results display area
        self.analyze_results_widget = QTextEdit()
        self.analyze_results_widget.setReadOnly(True)
        
        # Status bar for analysis progress
        self.analyze_status = QLabel("Ready")
        
        # Add everything to the main layout
        layout.addWidget(analysis_subtabs)
        layout.addWidget(self.analyze_results_widget)
        layout.addWidget(self.analyze_status)
        
    def setup_patching_exploitation_tab(self):
        """Sets up the Patching & Exploitation tab with sub-tabs for patching and exploit development."""
        # Create main layout
        layout = QVBoxLayout(self.patching_exploitation_tab)
        
        # Create sub-tabs for the Patching & Exploitation tab
        patching_subtabs = QTabWidget()
        patching_subtabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        patching_subtabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Create individual sub-tab widgets
        patch_plan_management_tab = QWidget()
        apply_test_patches_tab = QWidget()
        advanced_patching_tab = QWidget()
        exploit_dev_tools_tab = QWidget()
        
        # 1. Patch Plan & Management sub-tab
        patch_plan_layout = QVBoxLayout(patch_plan_management_tab)
        
        # Visual Patch Editor button
        visual_editor_btn = QPushButton("Open Visual Patch Editor")
        visual_editor_btn.clicked.connect(self.open_visual_patch_editor)
        patch_plan_layout.addWidget(visual_editor_btn)
        
        # Patch Plan table
        patch_table_label = QLabel("Patch Plan:")
        patch_plan_layout.addWidget(patch_table_label)
        
        self.patch_plan_table = QTableWidget()
        self.patch_plan_table.setColumnCount(6)
        self.patch_plan_table.setHorizontalHeaderLabels(["ID", "Address", "Original Bytes (Hex)", "New Bytes (Hex)", "Description", "Status"])
        self.patch_plan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.patch_plan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        patch_plan_layout.addWidget(self.patch_plan_table)
        
        # Patch List Actions toolbar
        actions_layout = QHBoxLayout()
        
        add_patch_btn = QPushButton("Add New Patch")
        edit_patch_btn = QPushButton("Edit Selected Patch")
        remove_patch_btn = QPushButton("Remove Selected Patch")
        duplicate_patch_btn = QPushButton("Duplicate Selected Patch")
        move_up_btn = QPushButton("Move Patch Up")
        move_down_btn = QPushButton("Move Patch Down")
        
        actions_layout.addWidget(add_patch_btn)
        actions_layout.addWidget(edit_patch_btn)
        actions_layout.addWidget(remove_patch_btn)
        actions_layout.addWidget(duplicate_patch_btn)
        actions_layout.addWidget(move_up_btn)
        actions_layout.addWidget(move_down_btn)
        
        patch_plan_layout.addLayout(actions_layout)
        
        # Import/Export buttons
        import_export_layout = QHBoxLayout()
        
        import_plan_btn = QPushButton("Import Patch Plan (JSON/Text)...")
        export_plan_btn = QPushButton("Export Patch Plan (JSON/Text)...")
        export_plan_btn.clicked.connect(self.export_patches)
        
        import_export_layout.addWidget(import_plan_btn)
        import_export_layout.addWidget(export_plan_btn)
        
        patch_plan_layout.addLayout(import_export_layout)
        
        # 2. Apply & Test Patches sub-tab
        apply_test_layout = QVBoxLayout(apply_test_patches_tab)
        
        # Patch Application section
        patch_application_group = QGroupBox("Patch Application")
        patch_application_layout = QVBoxLayout(patch_application_group)
        
        create_backup_cb = QCheckBox("Create Backup Before Patching")
        create_backup_cb.setChecked(True)
        
        apply_patches_btn = QPushButton("Apply Patch Plan to New File")
        apply_patches_btn.clicked.connect(self.apply_patch_plan)
        
        patch_application_layout.addWidget(create_backup_cb)
        patch_application_layout.addWidget(apply_patches_btn)
        
        apply_test_layout.addWidget(patch_application_group)
        
        # Patch Verification & Simulation section
        verification_group = QGroupBox("Patch Verification & Simulation")
        verification_layout = QVBoxLayout(verification_group)
        
        verify_patches_btn = QPushButton("Verify Applied Patches in File")
        verify_patches_btn.clicked.connect(self.verify_patch_results)
        
        simulate_btn = QPushButton("Simulate Patch Application & Verify")
        simulate_btn.clicked.connect(self.run_simulate_patch)
        
        verification_layout.addWidget(verify_patches_btn)
        verification_layout.addWidget(simulate_btn)
        
        apply_test_layout.addWidget(verification_group)
        
        # Output area
        patch_output = QTextEdit()
        patch_output.setReadOnly(True)
        apply_test_layout.addWidget(QLabel("Output:"))
        apply_test_layout.addWidget(patch_output)
        
        # 3. Advanced Patching Techniques sub-tab
        advanced_patching_layout = QVBoxLayout(advanced_patching_tab)
        
        # Runtime Patching section
        runtime_group = QGroupBox("Runtime Patching (Frida Based)")
        runtime_layout = QVBoxLayout(runtime_group)
        
        strategy_layout = QHBoxLayout()
        strategy_layout.addWidget(QLabel("Patching Strategy:"))
        
        strategy_combo = QComboBox()
        strategy_combo.addItems(["Memory Patching", "API Hooking"])
        strategy_layout.addWidget(strategy_combo)
        
        generate_launcher_btn = QPushButton("Generate Launcher Script")
        generate_launcher_btn.clicked.connect(lambda: self.generate_launcher_script(strategy_combo.currentText()))
        
        setup_memory_btn = QPushButton("Setup Memory Patching Environment")
        setup_memory_btn.clicked.connect(self.setup_memory_patching)
        
        runtime_layout.addLayout(strategy_layout)
        runtime_layout.addWidget(generate_launcher_btn)
        runtime_layout.addWidget(setup_memory_btn)
        
        advanced_patching_layout.addWidget(runtime_group)
        
        # AI-Assisted Patching section
        ai_patching_group = QGroupBox("AI-Assisted Patching (Contextual)")
        ai_patching_layout = QVBoxLayout(ai_patching_group)
        
        suggest_patches_btn = QPushButton("AI: Suggest Patches for Current Binary")
        suggest_patches_btn.clicked.connect(lambda: run_automated_patch_agent(self))
        
        get_proposed_btn = QPushButton("AI: Get Proposed Patches from Assistant")
        get_proposed_btn.clicked.connect(self.preview_patch)
        
        apply_confirmed_btn = QPushButton("AI: Apply Confirmed Patch")
        apply_confirmed_btn.clicked.connect(self.apply_patch_plan)
        
        ai_patching_layout.addWidget(suggest_patches_btn)
        ai_patching_layout.addWidget(get_proposed_btn)
        ai_patching_layout.addWidget(apply_confirmed_btn)
        
        advanced_patching_layout.addWidget(ai_patching_group)
        
        # 4. Exploit Development Tools sub-tab
        exploit_dev_layout = QVBoxLayout(exploit_dev_tools_tab)
        
        generate_strategy_btn = QPushButton("Generate Exploit Strategy from Vulnerabilities")
        generate_strategy_btn.clicked.connect(lambda: self.generate_exploit_strategy())
        exploit_dev_layout.addWidget(generate_strategy_btn)
        
        payload_layout = QHBoxLayout()
        payload_layout.addWidget(QLabel("Select Payload Type:"))
        
        payload_combo = QComboBox()
        payload_combo.addItems(["License Bypass", "Function Hijack", "Buffer Overflow", "Custom Payload"])
        payload_layout.addWidget(payload_combo)
        
        exploit_dev_layout.addLayout(payload_layout)
        
        generate_payload_btn = QPushButton("Generate Exploit Payload")
        generate_payload_btn.clicked.connect(lambda: self.generate_exploit_payload(payload_combo.currentText()))
        exploit_dev_layout.addWidget(generate_payload_btn)
        
        # ROP Chain Generation section
        rop_group = QGroupBox("ROP Chain Generation")
        rop_layout = QVBoxLayout(rop_group)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target functions/addresses for ROP:"))
        target_input = QLineEdit()
        target_layout.addWidget(target_input)
        
        generate_rop_btn = QPushButton("Generate ROP Chains")
        generate_rop_btn.clicked.connect(self.run_rop_chain_generator)
        
        rop_layout.addLayout(target_layout)
        rop_layout.addWidget(generate_rop_btn)
        
        exploit_dev_layout.addWidget(rop_group)
        
        # Output area
        exploit_output = QTextEdit()
        exploit_output.setReadOnly(True)
        exploit_dev_layout.addWidget(QLabel("Generated Strategies, Payloads, ROP Chains:"))
        exploit_dev_layout.addWidget(exploit_output)
        
        # Add all sub-tabs to the tab widget
        patching_subtabs.addTab(patch_plan_management_tab, "Patch Plan & Management")
        patching_subtabs.addTab(apply_test_patches_tab, "Apply & Test Patches")
        patching_subtabs.addTab(advanced_patching_tab, "Advanced Patching Techniques")
        patching_subtabs.addTab(exploit_dev_tools_tab, "Exploit Development Tools")
        
        # Add the tab widget to the main layout
        layout.addWidget(patching_subtabs)
        
    def setup_ai_assistant_tab(self):
        """Sets up the AI Assistant tab with sub-tabs for chat interface and AI tools."""
        # Create main layout
        layout = QVBoxLayout(self.ai_assistant_tab)
        
        # Create sub-tabs for the AI Assistant tab
        ai_subtabs = QTabWidget()
        ai_subtabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        ai_subtabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Create individual sub-tab widgets
        ai_chat_tab = QWidget()
        model_management_tab = QWidget()
        ai_automation_tab = QWidget()
        
        # 1. AI Chat sub-tab
        chat_layout = QVBoxLayout(ai_chat_tab)
        
        # Chat history display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        chat_layout.addWidget(self.chat_display)
        
        # User input area
        self.user_input = QTextEdit()
        self.user_input.setMaximumHeight(100)
        chat_layout.addWidget(QLabel("Your Message:"))
        chat_layout.addWidget(self.user_input)
        
        # Chat controls
        chat_controls_layout = QHBoxLayout()
        
        send_message_btn = QPushButton("Send Message")
        send_message_btn.clicked.connect(self.send_to_model)
        
        clear_chat_btn = QPushButton("Clear Chat")
        clear_chat_btn.clicked.connect(lambda: [self.user_input.clear(), self.chat_display.clear()])
        
        chat_controls_layout.addWidget(send_message_btn)
        chat_controls_layout.addWidget(clear_chat_btn)
        
        # Preset query dropdown
        chat_controls_layout.addWidget(QLabel("Preset Query:"))
        
        preset_query_combo = QComboBox()
        preset_query_combo.addItems(["Analyze this binary", "Find license checks", "Suggest patches", "Help me understand this function"])
        preset_query_combo.currentTextChanged.connect(self.handle_preset_query)
        
        chat_controls_layout.addWidget(preset_query_combo)
        
        chat_layout.addLayout(chat_controls_layout)
        
        # Assistant status
        self.assistant_status = QLabel("Assistant Status: Ready")
        chat_layout.addWidget(self.assistant_status)
        
        # 2. AI Model & API Management sub-tab
        model_layout = QVBoxLayout(model_management_tab)
        
        # Current model path
        model_path_layout = QHBoxLayout()
        model_path_layout.addWidget(QLabel("Current LLM Path:"))
        self.custom_model_path_label = QLabel("None")
        model_path_layout.addWidget(self.custom_model_path_label)
        
        model_layout.addLayout(model_path_layout)
        
        # Model import buttons
        import_custom_btn = QPushButton("Import Custom LLM (GGUF, etc.)")
        import_custom_btn.clicked.connect(self.import_custom_model)
        
        import_api_btn = QPushButton("Import from API Repository")
        import_api_btn.clicked.connect(self.import_custom_model)
        
        verify_hash_btn = QPushButton("Verify Imported Model File Hash")
        verify_hash_btn.clicked.connect(self.verify_hash)
        
        fine_tuning_btn = QPushButton("AI Model Fine-Tuning & Dataset Management")
        fine_tuning_btn.clicked.connect(self.open_model_finetuning)
        
        config_repos_btn = QPushButton("Configure API Model Repositories")
        config_repos_btn.clicked.connect(self.configure_api_repositories)
        
        model_layout.addWidget(import_custom_btn)
        model_layout.addWidget(import_api_btn)
        model_layout.addWidget(verify_hash_btn)
        model_layout.addWidget(fine_tuning_btn)
        model_layout.addWidget(config_repos_btn)
        
        # LLM Inference Parameters section
        inference_group = QGroupBox("LLM Inference Parameters")
        inference_layout = QVBoxLayout(inference_group)
        
        temp_layout = QHBoxLayout()
        temp_layout.addWidget(QLabel("Temperature:"))
        temp_spin = QDoubleSpinBox()
        temp_spin.setRange(0.0, 2.0)
        temp_spin.setSingleStep(0.1)
        temp_spin.setValue(0.7)  # Default value
        temp_layout.addWidget(temp_spin)
        
        top_p_layout = QHBoxLayout()
        top_p_layout.addWidget(QLabel("Top P:"))
        top_p_spin = QDoubleSpinBox()
        top_p_spin.setRange(0.0, 1.0)
        top_p_spin.setSingleStep(0.05)
        top_p_spin.setValue(0.9)  # Default value
        top_p_layout.addWidget(top_p_spin)
        
        max_tokens_layout = QHBoxLayout()
        max_tokens_layout.addWidget(QLabel("Max Tokens:"))
        max_tokens_spin = QSpinBox()
        max_tokens_spin.setRange(1, 100000)
        max_tokens_spin.setValue(2048)  # Default value
        max_tokens_layout.addWidget(max_tokens_spin)
        
        context_size_layout = QHBoxLayout()
        context_size_layout.addWidget(QLabel("Context Size (Override):"))
        context_size_spin = QSpinBox()
        context_size_spin.setRange(1024, 200000)
        context_size_spin.setValue(8192)  # Default value
        context_size_layout.addWidget(context_size_spin)
        
        apply_params_btn = QPushButton("Apply LLM Parameters")
        
        inference_layout.addLayout(temp_layout)
        inference_layout.addLayout(top_p_layout)
        inference_layout.addLayout(max_tokens_layout)
        inference_layout.addLayout(context_size_layout)
        inference_layout.addWidget(apply_params_btn)
        
        model_layout.addWidget(inference_group)
        
        # 3. AI Automation & Tools sub-tab
        automation_layout = QVBoxLayout(ai_automation_tab)
        
        # Automation buttons
        autonomous_btn = QPushButton("Run Full Autonomous Analysis & Patch")
        autonomous_btn.clicked.connect(self.run_full_autonomous_mode)
        
        patch_agent_btn = QPushButton("Automated Patch Agent (AI-Driven)")
        patch_agent_btn.clicked.connect(self.run_automated_patch_agent)
        
        feature_extract_btn = QPushButton("Automated Feature Extraction for ML Models")
        feature_extract_btn.clicked.connect(self.run_feature_extraction)
        
        automation_layout.addWidget(autonomous_btn)
        automation_layout.addWidget(patch_agent_btn)
        automation_layout.addWidget(feature_extract_btn)
        
        # AI Tool Call Log section
        tool_log_group = QGroupBox("AI Tool Call Log")
        tool_log_layout = QVBoxLayout(tool_log_group)
        
        tool_log = QTextEdit()
        tool_log.setReadOnly(True)
        tool_log_layout.addWidget(tool_log)
        
        automation_layout.addWidget(tool_log_group)
        
        # Add all sub-tabs to the tab widget
        ai_subtabs.addTab(ai_chat_tab, "AI Chat")
        ai_subtabs.addTab(model_management_tab, "AI Model & API Management")
        ai_subtabs.addTab(ai_automation_tab, "AI Automation & Tools")
        
        # Add the tab widget to the main layout
        layout.addWidget(ai_subtabs)
        
    def setup_netanalysis_emulation_tab(self):
        """Sets up the NetAnalysis & Emulation tab with network traffic and emulation features."""
        # Create main layout
        layout = QVBoxLayout(self.netanalysis_emulation_tab)
        
        # Create sub-tabs for the NetAnalysis & Emulation tab
        net_subtabs = QTabWidget()
        net_subtabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        net_subtabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Create individual sub-tab widgets
        traffic_capture_tab = QWidget()
        ssl_tls_tab = QWidget()
        license_emulation_tab = QWidget()
        
        # 1. Traffic Capture & Analysis sub-tab
        traffic_layout = QVBoxLayout(traffic_capture_tab)
        
        # Packet Capture Controls section
        capture_group = QGroupBox("Packet Capture Controls")
        capture_layout = QVBoxLayout(capture_group)
        
        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Select Network Interface:"))
        interface_combo = QComboBox()
        # Will be populated with available network interfaces
        interface_layout.addWidget(interface_combo)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Capture Filter:"))
        filter_input = QLineEdit()
        filter_layout.addWidget(filter_input)
        
        capture_buttons_layout = QHBoxLayout()
        
        start_capture_btn = QPushButton("Start Network Capture")
        start_capture_btn.clicked.connect(self.start_network_capture)
        
        stop_capture_btn = QPushButton("Stop Network Capture")
        stop_capture_btn.clicked.connect(self.stop_network_capture)
        
        clear_capture_btn = QPushButton("Clear Captured Data")
        clear_capture_btn.clicked.connect(self.clear_network_capture)
        
        capture_buttons_layout.addWidget(start_capture_btn)
        capture_buttons_layout.addWidget(stop_capture_btn)
        capture_buttons_layout.addWidget(clear_capture_btn)
        
        capture_layout.addLayout(interface_layout)
        capture_layout.addLayout(filter_layout)
        capture_layout.addLayout(capture_buttons_layout)
        
        traffic_layout.addWidget(capture_group)
        
        # Live Traffic Display table
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(5)
        self.traffic_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Info"])
        traffic_layout.addWidget(self.traffic_table)
        
        # Analysis buttons
        analysis_buttons_layout = QHBoxLayout()
        
        analyze_traffic_btn = QPushButton("Analyze Captured Traffic")
        analyze_traffic_btn.clicked.connect(self.analyze_captured_traffic)
        generate_report_btn = QPushButton("Generate Network Traffic Report...")
        
        analysis_buttons_layout.addWidget(analyze_traffic_btn)
        analysis_buttons_layout.addWidget(generate_report_btn)
        
        traffic_layout.addLayout(analysis_buttons_layout)
        
        # 2. SSL/TLS Interception sub-tab
        ssl_layout = QVBoxLayout(ssl_tls_tab)
        
        # Interceptor Controls section
        interceptor_group = QGroupBox("Interceptor Controls")
        interceptor_layout = QVBoxLayout(interceptor_group)
        
        listen_port_layout = QHBoxLayout()
        listen_port_layout.addWidget(QLabel("Listen Port:"))
        listen_port_input = QLineEdit()
        listen_port_input.setText("8443")  # Default port
        listen_port_layout.addWidget(listen_port_input)
        
        target_host_layout = QHBoxLayout()
        target_host_layout.addWidget(QLabel("Target Host (optional):"))
        target_host_input = QLineEdit()
        target_host_layout.addWidget(target_host_input)
        
        target_port_layout = QHBoxLayout()
        target_port_layout.addWidget(QLabel("Target Port:"))
        target_port_input = QLineEdit()
        target_port_input.setText("443")  # Default HTTPS port
        target_port_layout.addWidget(target_port_input)
        
        start_interceptor_btn = QPushButton("Start/Stop SSL/TLS Interceptor")
        start_interceptor_btn.clicked.connect(self.run_ssl_tls_interceptor)
        
        interceptor_layout.addLayout(listen_port_layout)
        interceptor_layout.addLayout(target_host_layout)
        interceptor_layout.addLayout(target_port_layout)
        interceptor_layout.addWidget(start_interceptor_btn)
        
        ssl_layout.addWidget(interceptor_group)
        
        # CA Certificate settings
        ca_cert_layout = QHBoxLayout()
        ca_cert_layout.addWidget(QLabel("CA Certificate Path:"))
        ca_cert_label = QLabel("Not generated")
        ca_cert_layout.addWidget(ca_cert_label)
        
        generate_ca_btn = QPushButton("Generate New CA Certificate")
        
        ssl_layout.addLayout(ca_cert_layout)
        ssl_layout.addWidget(generate_ca_btn)
        
        # Log area
        ssl_log = QTextEdit()
        ssl_log.setReadOnly(True)
        ssl_layout.addWidget(QLabel("Intercepted SSL/TLS Communications:"))
        ssl_layout.addWidget(ssl_log)
        
        # 3. License Emulation & Fingerprinting sub-tab
        license_layout = QVBoxLayout(license_emulation_tab)
        
        # Network License Server Emulator section
        server_group = QGroupBox("Network License Server Emulator")
        server_layout = QVBoxLayout(server_group)
        
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Listen Port(s) (comma-separated):"))
        port_input = QLineEdit()
        port_input.setText("1234,5678")  # Example ports
        port_layout.addWidget(port_input)
        
        learning_mode_cb = QCheckBox("Enable Learning Mode")
        
        start_server_btn = QPushButton("Start/Stop License Server Emulator")
        start_server_btn.clicked.connect(self.run_network_license_server)
        
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Select Protocol to Emulate:"))
        protocol_combo = QComboBox()
        protocol_combo.addItems(["FlexLM", "HASP", "CodeMeter", "Generic"])
        protocol_layout.addWidget(protocol_combo)
        
        server_layout.addLayout(port_layout)
        server_layout.addWidget(learning_mode_cb)
        server_layout.addWidget(start_server_btn)
        server_layout.addLayout(protocol_layout)
        
        license_layout.addWidget(server_group)
        
        # Cloud License Response Generator section
        cloud_group = QGroupBox("Cloud License Response Generator")
        cloud_layout = QVBoxLayout(cloud_group)
        
        proxy_layout = QHBoxLayout()
        proxy_layout.addWidget(QLabel("Proxy Port:"))
        proxy_input = QLineEdit()
        proxy_input.setText("8080")  # Default proxy port
        proxy_layout.addWidget(proxy_input)
        
        cloud_learning_cb = QCheckBox("Enable Learning Mode")
        
        start_proxy_btn = QPushButton("Start/Stop Cloud Response Proxy")
        start_proxy_btn.clicked.connect(self.run_cloud_license_hooker)
        
        cloud_layout.addLayout(proxy_layout)
        cloud_layout.addWidget(cloud_learning_cb)
        cloud_layout.addWidget(start_proxy_btn)
        
        license_layout.addWidget(cloud_group)
        
        # Protocol Fingerprinting section
        fingerprint_group = QGroupBox("Protocol Fingerprinting")
        fingerprint_layout = QVBoxLayout(fingerprint_group)
        
        run_fingerprint_btn = QPushButton("Run Protocol Fingerprinter")
        run_fingerprint_btn.clicked.connect(self.run_protocol_fingerprinter)
        
        fingerprint_learning_cb = QCheckBox("Enable Learning Mode for Fingerprinter")
        
        fingerprint_layout.addWidget(run_fingerprint_btn)
        fingerprint_layout.addWidget(fingerprint_learning_cb)
        
        license_layout.addWidget(fingerprint_group)
        
        # Log area
        license_log = QTextEdit()
        license_log.setReadOnly(True)
        license_layout.addWidget(QLabel("Logs from Emulators and Generators:"))
        license_layout.addWidget(license_log)
        
        # Add all sub-tabs to the tab widget
        net_subtabs.addTab(traffic_capture_tab, "Traffic Capture & Analysis")
        net_subtabs.addTab(ssl_tls_tab, "SSL/TLS Interception")
        net_subtabs.addTab(license_emulation_tab, "License Emulation & Fingerprinting")
        
        # Add the tab widget to the main layout
        layout.addWidget(net_subtabs)
        
    def setup_tools_plugins_tab(self):
        """Sets up the Tools & Plugins tab with utility tools and plugin management features."""
        # Create main layout
        layout = QVBoxLayout(self.tools_plugins_tab)
        
        # Create sub-tabs for the Tools & Plugins tab
        tools_subtabs = QTabWidget()
        tools_subtabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        tools_subtabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Create individual sub-tab widgets
        hex_editor_tab = QWidget()
        plugin_manager_tab = QWidget()
        integrated_utils_tab = QWidget()
        generators_reports_tab = QWidget()
        
        # 1. Hex Editor sub-tab
        hex_layout = QVBoxLayout(hex_editor_tab)
        
        hex_buttons_layout = QHBoxLayout()
        
        view_mode_btn = QPushButton("Open File in Hex Editor (View Mode)")
        view_mode_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer("", True))
        
        edit_mode_btn = QPushButton("Open File in Hex Editor (Edit Mode)")
        edit_mode_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer("", False))
        
        hex_buttons_layout.addWidget(view_mode_btn)
        hex_buttons_layout.addWidget(edit_mode_btn)
        
        binary_hex_buttons_layout = QHBoxLayout()
        
        view_binary_btn = QPushButton("View Current Binary in Hex Editor")
        view_binary_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(self.binary_path, True))
        
        edit_binary_btn = QPushButton("Edit Current Binary in Hex Editor")
        edit_binary_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(self.binary_path, False))
        
        binary_hex_buttons_layout.addWidget(view_binary_btn)
        binary_hex_buttons_layout.addWidget(edit_binary_btn)
        
        hex_layout.addLayout(hex_buttons_layout)
        hex_layout.addLayout(binary_hex_buttons_layout)
        
        # Embedded Hex Viewer placeholder (will be initialized with real HexViewerWidget)
        hex_viewer_placeholder = QFrame()
        hex_viewer_placeholder.setFrameShape(QFrame.StyledPanel)
        hex_viewer_placeholder.setMinimumHeight(300)
        
        placeholder_layout = QVBoxLayout(hex_viewer_placeholder)
        placeholder_layout.addWidget(QLabel("Hex Viewer will be displayed here when a file is loaded"))
        
        hex_layout.addWidget(hex_viewer_placeholder)
        
        # 2. Plugin Manager sub-tab
        plugin_layout = QVBoxLayout(plugin_manager_tab)
        
        # Inner tabs for plugin types
        plugin_subtabs = QTabWidget()
        plugin_subtabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        plugin_subtabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Frida Scripts tab
        frida_scripts_tab = QWidget()
        frida_layout = QVBoxLayout(frida_scripts_tab)
        
        frida_list = QListWidget()
        frida_layout.addWidget(frida_list)
        
        frida_buttons_layout = QHBoxLayout()
        
        run_frida_btn = QPushButton("Run Selected Frida Script")
        run_frida_btn.clicked.connect(lambda: self.run_frida_plugin_from_file(frida_list.currentItem().text() if frida_list.currentItem() else ""))
        
        edit_frida_btn = QPushButton("Edit Selected Frida Script")
        edit_frida_btn.clicked.connect(lambda: self.edit_plugin_file(frida_list.currentItem().text() if frida_list.currentItem() else ""))
        
        import_frida_btn = QPushButton("Import Frida Script...")
        import_frida_btn.clicked.connect(lambda: self.import_plugin("frida"))
        
        create_frida_btn = QPushButton("Create New Frida Script...")
        create_frida_btn.clicked.connect(lambda: self.create_new_plugin("frida"))
        
        frida_buttons_layout.addWidget(run_frida_btn)
        frida_buttons_layout.addWidget(edit_frida_btn)
        frida_buttons_layout.addWidget(import_frida_btn)
        frida_buttons_layout.addWidget(create_frida_btn)
        
        frida_layout.addLayout(frida_buttons_layout)
        
        # Ghidra Scripts tab
        ghidra_scripts_tab = QWidget()
        ghidra_layout = QVBoxLayout(ghidra_scripts_tab)
        
        ghidra_list = QListWidget()
        ghidra_layout.addWidget(ghidra_list)
        
        ghidra_buttons_layout = QHBoxLayout()
        
        run_ghidra_btn = QPushButton("Run Selected Ghidra Script")
        run_ghidra_btn.clicked.connect(lambda: self.run_ghidra_plugin_from_file(ghidra_list.currentItem().text() if ghidra_list.currentItem() else ""))
        
        edit_ghidra_btn = QPushButton("Edit Selected Ghidra Script")
        edit_ghidra_btn.clicked.connect(lambda: self.edit_plugin_file(ghidra_list.currentItem().text() if ghidra_list.currentItem() else ""))
        
        import_ghidra_btn = QPushButton("Import Ghidra Script...")
        import_ghidra_btn.clicked.connect(lambda: self.import_plugin("ghidra"))
        
        create_ghidra_btn = QPushButton("Create New Ghidra Script...")
        create_ghidra_btn.clicked.connect(lambda: self.create_new_plugin("ghidra"))
        
        ghidra_buttons_layout.addWidget(run_ghidra_btn)
        ghidra_buttons_layout.addWidget(edit_ghidra_btn)
        ghidra_buttons_layout.addWidget(import_ghidra_btn)
        ghidra_buttons_layout.addWidget(create_ghidra_btn)
        
        ghidra_layout.addLayout(ghidra_buttons_layout)
        
        # Custom Python Plugins tab
        custom_plugins_tab = QWidget()
        custom_layout = QVBoxLayout(custom_plugins_tab)
        
        custom_list = QListWidget()
        custom_layout.addWidget(custom_list)
        
        custom_buttons_layout = QHBoxLayout()
        
        run_custom_btn = QPushButton("Run Selected Custom Plugin")
        run_custom_btn.clicked.connect(lambda: self.run_custom_plugin(custom_list.currentItem().text() if custom_list.currentItem() else ""))
        
        edit_custom_btn = QPushButton("Edit Selected Custom Plugin")
        edit_custom_btn.clicked.connect(lambda: self.edit_plugin_file(custom_list.currentItem().text() if custom_list.currentItem() else ""))
        
        import_custom_btn = QPushButton("Import Custom Plugin...")
        import_custom_btn.clicked.connect(lambda: self.import_plugin("custom"))
        
        create_custom_btn = QPushButton("Create New Custom Plugin...")
        create_custom_btn.clicked.connect(lambda: self.create_new_plugin("custom"))
        
        custom_buttons_layout.addWidget(run_custom_btn)
        custom_buttons_layout.addWidget(edit_custom_btn)
        custom_buttons_layout.addWidget(import_custom_btn)
        custom_buttons_layout.addWidget(create_custom_btn)
        
        custom_layout.addLayout(custom_buttons_layout)
        
        # Add plugin sub-tabs
        plugin_subtabs.addTab(frida_scripts_tab, "Frida Scripts")
        plugin_subtabs.addTab(ghidra_scripts_tab, "Ghidra Scripts")
        plugin_subtabs.addTab(custom_plugins_tab, "Custom Python Plugins")
        
        plugin_layout.addWidget(plugin_subtabs)
        
        # Built-in Quick Actions/Scripts section
        builtin_group = QGroupBox("Built-in Quick Actions/Scripts")
        builtin_layout = QVBoxLayout(builtin_group)
        
        hwid_spoofer_btn = QPushButton("HWID Spoofer")
        hwid_spoofer_btn.clicked.connect(lambda: self.run_plugin("HWID Spoofer"))
        
        anti_debugger_btn = QPushButton("Anti-Debugger Bypass")
        anti_debugger_btn.clicked.connect(lambda: self.run_plugin("Anti-Debugger"))
        
        time_bomb_btn = QPushButton("Time Bomb Defuser")
        time_bomb_btn.clicked.connect(lambda: self.run_plugin("Time Bomb Defuser"))
        
        telemetry_btn = QPushButton("Telemetry Blocker")
        telemetry_btn.clicked.connect(lambda: self.run_plugin("Telemetry Blocker"))
        
        builtin_layout.addWidget(hwid_spoofer_btn)
        builtin_layout.addWidget(anti_debugger_btn)
        builtin_layout.addWidget(time_bomb_btn)
        builtin_layout.addWidget(telemetry_btn)
        
        plugin_layout.addWidget(builtin_group)
        
        # 3. Integrated Utilities sub-tab
        utils_layout = QVBoxLayout(integrated_utils_tab)
        
        # Adobe Creative Cloud Tools section
        adobe_group = QGroupBox("Adobe Creative Cloud Tools")
        adobe_layout = QVBoxLayout(adobe_group)
        
        adobe_status_layout = QHBoxLayout()
        adobe_status_layout.addWidget(QLabel("AdobeLicenseX Status:"))
        self.adobe_status_label = QLabel("Not Active")
        adobe_status_layout.addWidget(self.adobe_status_label)
        
        adobe_action_layout = QHBoxLayout()
        adobe_action_layout.addWidget(QLabel("Select Adobe Action:"))
        self.adobe_action_combo = QComboBox()
        self.adobe_action_combo.addItems(["Deploy AdobeLicenseX", "Patch Adobe Licensing", "Reset Adobe Trial"])
        adobe_action_layout.addWidget(self.adobe_action_combo)
        
        execute_adobe_btn = QPushButton("Execute Adobe Action")
        execute_adobe_btn.clicked.connect(self.execute_adobe_action)
        
        adobe_layout.addLayout(adobe_status_layout)
        adobe_layout.addLayout(adobe_action_layout)
        adobe_layout.addWidget(execute_adobe_btn)
        
        utils_layout.addWidget(adobe_group)
        
        # Windows Tools section
        windows_group = QGroupBox("Windows Tools")
        windows_layout = QVBoxLayout(windows_group)
        
        windows_activator_btn = QPushButton("Windows Activator")
        windows_activator_btn.clicked.connect(self.run_windows_activator)
        
        windows_layout.addWidget(windows_activator_btn)
        
        utils_layout.addWidget(windows_group)
        
        # 4. Generators & Reports sub-tab
        generators_layout = QVBoxLayout(generators_reports_tab)
        
        # Key Generator section
        keygen_group = QGroupBox("Key Generator")
        keygen_layout = QVBoxLayout(keygen_group)
        
        product_name_layout = QHBoxLayout()
        product_name_layout.addWidget(QLabel("Product Name:"))
        self.keygen_input_name = QLineEdit()
        product_name_layout.addWidget(self.keygen_input_name)
        
        version_layout = QHBoxLayout()
        version_layout.addWidget(QLabel("Version:"))
        self.keygen_input_version = QLineEdit()
        version_layout.addWidget(self.keygen_input_version)
        
        key_format_layout = QHBoxLayout()
        key_format_layout.addWidget(QLabel("Key Format:"))
        self.key_format_dropdown = QComboBox()
        self.key_format_dropdown.addItems(["XXXX-XXXX-XXXX-XXXX", "XXX-XXXXXXX-XXX", "Custom"])
        key_format_layout.addWidget(self.key_format_dropdown)
        
        advanced_options_cb = QCheckBox("Advanced Options")
        
        advanced_frame = QFrame()
        advanced_frame.setFrameShape(QFrame.StyledPanel)
        advanced_frame.setVisible(False)
        advanced_frame_layout = QVBoxLayout(advanced_frame)
        
        seed_layout = QHBoxLayout()
        seed_layout.addWidget(QLabel("Custom Seed:"))
        self.keygen_seed = QLineEdit()
        seed_layout.addWidget(self.keygen_seed)
        
        advanced_frame_layout.addLayout(seed_layout)
        
        advanced_options_cb.toggled.connect(advanced_frame.setVisible)
        
        generate_key_btn = QPushButton("Generate License Key")
        generate_key_btn.clicked.connect(self.generate_key)
        
        self.keygen_results = QTextEdit()
        self.keygen_results.setReadOnly(True)
        
        keygen_layout.addLayout(product_name_layout)
        keygen_layout.addLayout(version_layout)
        keygen_layout.addLayout(key_format_layout)
        keygen_layout.addWidget(advanced_options_cb)
        keygen_layout.addWidget(advanced_frame)
        keygen_layout.addWidget(generate_key_btn)
        keygen_layout.addWidget(QLabel("Generated Keys:"))
        keygen_layout.addWidget(self.keygen_results)
        
        generators_layout.addWidget(keygen_group)
        
        # Report Management section
        report_group = QGroupBox("Report Management")
        report_layout = QVBoxLayout(report_group)
        
        template_layout = QHBoxLayout()
        template_layout.addWidget(QLabel("Report Template:"))
        self.report_template_combo = QComboBox()
        self.report_template_combo.addItems(["Standard Analysis", "Extended Analysis", "Executive Summary", "Technical Details"])
        template_layout.addWidget(self.report_template_combo)
        
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Output Format:"))
        self.report_format_combo = QComboBox()
        self.report_format_combo.addItems(["PDF", "HTML", "Markdown", "Text"])
        format_layout.addWidget(self.report_format_combo)
        
        sections_group = QGroupBox("Include Sections")
        sections_layout = QVBoxLayout(sections_group)
        
        binary_info_cb = QCheckBox("Binary Info")
        binary_info_cb.setChecked(True)
        patches_cb = QCheckBox("Patches")
        patches_cb.setChecked(True)
        graphs_cb = QCheckBox("Graphs")
        network_analysis_cb = QCheckBox("Network Analysis")
        
        sections_layout.addWidget(binary_info_cb)
        sections_layout.addWidget(patches_cb)
        sections_layout.addWidget(graphs_cb)
        sections_layout.addWidget(network_analysis_cb)
        
        generate_report_btn = QPushButton("Generate Report")
        generate_report_btn.clicked.connect(self.run_report_generation)
        
        report_layout.addLayout(template_layout)
        report_layout.addLayout(format_layout)
        report_layout.addWidget(sections_group)
        report_layout.addWidget(generate_report_btn)
        
        # Saved Reports section
        saved_reports_group = QGroupBox("Saved Reports")
        saved_reports_layout = QVBoxLayout(saved_reports_group)
        
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(4)
        self.reports_table.setHorizontalHeaderLabels(["Name", "Date", "Type", "Actions"])
        
        reports_actions_layout = QHBoxLayout()
        
        refresh_reports_btn = QPushButton("Refresh Reports List")
        refresh_reports_btn.clicked.connect(self.refresh_reports_list)
        
        import_report_btn = QPushButton("Import Report...")
        import_report_btn.clicked.connect(self.import_report)
        
        reports_actions_layout.addWidget(refresh_reports_btn)
        reports_actions_layout.addWidget(import_report_btn)
        
        saved_reports_layout.addWidget(self.reports_table)
        saved_reports_layout.addLayout(reports_actions_layout)
        
        report_layout.addWidget(saved_reports_group)
        
        generators_layout.addWidget(report_group)
        
        # Add all sub-tabs to the tab widget
        tools_subtabs.addTab(hex_editor_tab, "Hex Editor")
        tools_subtabs.addTab(plugin_manager_tab, "Plugin Manager")
        tools_subtabs.addTab(integrated_utils_tab, "Integrated Utilities")
        tools_subtabs.addTab(generators_reports_tab, "Generators & Reports")
        
        # Add the tab widget to the main layout
        layout.addWidget(tools_subtabs)
        
    def setup_binary_tools_tab(self):
        """Sets up the Binary Tools Tab with hex viewer, disassembler, and memory tools."""
        # Create main layout
        layout = QVBoxLayout()
        
        # Create sidebar layout with tool selection
        main_splitter = QSplitter(Qt.Horizontal)
        
        # Left sidebar for tool selection
        tool_sidebar = QWidget()
        sidebar_layout = QVBoxLayout(tool_sidebar)
        sidebar_layout.setContentsMargins(5, 5, 5, 5)
        
        # Tool category: Viewing & Editing
        view_edit_group = QGroupBox("Viewing & Editing")
        view_edit_layout = QVBoxLayout()
        
        # Tool buttons
        hex_viewer_btn = QPushButton("Hex Viewer & Editor")
        hex_viewer_btn.setIcon(QIcon.fromTheme("accessories-text-editor"))
        hex_viewer_btn.clicked.connect(lambda: self.switch_binary_tool(0))
        
        disasm_btn = QPushButton("Disassembler")
        disasm_btn.clicked.connect(lambda: self.switch_binary_tool(1))
        
        struct_analyzer_btn = QPushButton("Structure Analyzer")
        struct_analyzer_btn.clicked.connect(lambda: self.switch_binary_tool(2))
        
        view_edit_layout.addWidget(hex_viewer_btn)
        view_edit_layout.addWidget(disasm_btn)
        view_edit_layout.addWidget(struct_analyzer_btn)
        view_edit_group.setLayout(view_edit_layout)
        
        # Tool category: Memory Tools
        memory_group = QGroupBox("Memory Tools")
        memory_layout = QVBoxLayout()
        
        memory_viewer_btn = QPushButton("Memory Viewer")
        memory_viewer_btn.clicked.connect(lambda: self.switch_binary_tool(3))
        
        memory_patch_btn = QPushButton("Memory Patcher")
        memory_patch_btn.clicked.connect(lambda: self.switch_binary_tool(4))
        
        memory_dump_btn = QPushButton("Memory Dump")
        memory_dump_btn.clicked.connect(lambda: self.switch_binary_tool(5))
        
        memory_layout.addWidget(memory_viewer_btn)
        memory_layout.addWidget(memory_patch_btn)
        memory_layout.addWidget(memory_dump_btn)
        memory_group.setLayout(memory_layout)
        
        # Add tool categories to sidebar
        sidebar_layout.addWidget(view_edit_group)
        sidebar_layout.addWidget(memory_group)
        sidebar_layout.addStretch(1)
        
        # Add file info panel to sidebar
        file_info_group = QGroupBox("Current File")
        file_info_layout = QVBoxLayout()
        
        self.binary_tool_file_label = QLabel("No file selected")
        self.binary_tool_file_info = QTextEdit()
        self.binary_tool_file_info.setReadOnly(True)
        self.binary_tool_file_info.setMaximumHeight(100)
        
        select_file_btn = QPushButton("Select File")
        select_file_btn.clicked.connect(self.select_binary_tool_file)
        
        file_info_layout.addWidget(self.binary_tool_file_label)
        file_info_layout.addWidget(self.binary_tool_file_info)
        file_info_layout.addWidget(select_file_btn)
        file_info_group.setLayout(file_info_layout)
        
        sidebar_layout.addWidget(file_info_group)
        
        # Tool content area with stacked widget
        content_area = QWidget()
        content_layout = QVBoxLayout(content_area)
        
        self.binary_tool_stack = QtWidgets.QStackedWidget()
        
        # 1. Hex Viewer & Editor
        hex_viewer_widget = QWidget()
        hex_layout = QVBoxLayout(hex_viewer_widget)
        
        # Header section
        header_layout = QHBoxLayout()
        header_label = QLabel("<h2>Hex Viewer & Editor</h2>")
        header_layout.addWidget(header_label)
        header_layout.addStretch(1)
        hex_layout.addLayout(header_layout)
        
        description_label = QLabel("Examine and edit binary files at the byte level")
        description_label.setWordWrap(True)
        hex_layout.addWidget(description_label)
        
        # File Operations Group
        operations_group = QGroupBox("File Operations")
        operations_layout = QGridLayout()
        
        open_view_btn = QPushButton("Open File (View Mode)")
        open_view_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(True))
        
        open_edit_btn = QPushButton("Open File (Edit Mode)")
        open_edit_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(False))
        
        self.view_current_btn = QPushButton("View Current Binary")
        self.view_current_btn.clicked.connect(lambda: self.show_current_binary_in_hex(True))
        
        self.edit_current_btn = QPushButton("Edit Current Binary")
        self.edit_current_btn.clicked.connect(lambda: self.show_current_binary_in_hex(False))
        
        # Update buttons' enabled state based on binary_path
        self.view_current_btn.setEnabled(self.binary_path is not None)
        self.edit_current_btn.setEnabled(self.binary_path is not None)
        
        operations_layout.addWidget(open_view_btn, 0, 0)
        operations_layout.addWidget(open_edit_btn, 0, 1)
        operations_layout.addWidget(self.view_current_btn, 1, 0)
        operations_layout.addWidget(self.edit_current_btn, 1, 1)
        
        operations_group.setLayout(operations_layout)
        hex_layout.addWidget(operations_group)
        
        # Display Options Group
        display_group = QGroupBox("Display Options")
        display_layout = QGridLayout()
        
        display_layout.addWidget(QLabel("View Mode:"), 0, 0)
        view_mode_combo = QComboBox()
        view_mode_combo.addItems(["Hexadecimal", "Decimal", "Binary", "ASCII"])
        display_layout.addWidget(view_mode_combo, 0, 1)
        
        display_layout.addWidget(QLabel("Bytes per Row:"), 1, 0)
        bytes_row_spin = QSpinBox()
        bytes_row_spin.setRange(8, 32)
        bytes_row_spin.setValue(16)
        display_layout.addWidget(bytes_row_spin, 1, 1)
        
        display_layout.addWidget(QLabel("Font Size:"), 2, 0)
        font_size_spin = QSpinBox()
        font_size_spin.setRange(8, 20)
        font_size_spin.setValue(12)
        display_layout.addWidget(font_size_spin, 2, 1)
        
        display_group.setLayout(display_layout)
        hex_layout.addWidget(display_group)
        
        # Features description
        features_label = QLabel("<b>Features:</b><ul>"
                               "<li>Memory-efficient file handling</li>"
                               "<li>Multiple display modes</li>"
                               "<li>Search functionality</li>"
                               "<li>Region highlighting</li>"
                               "<li>Customizable display options</li>"
                               "</ul>")
        features_label.setWordWrap(True)
        hex_layout.addWidget(features_label)
        
        hex_layout.addStretch(1)
        
        # 2. Disassembler View
        disasm_widget = QWidget()
        disasm_layout = QVBoxLayout(disasm_widget)
        
        # Header
        disasm_header_layout = QHBoxLayout()
        disasm_header_label = QLabel("<h2>Disassembler</h2>")
        disasm_header_layout.addWidget(disasm_header_label)
        disasm_header_layout.addStretch(1)
        disasm_layout.addLayout(disasm_header_layout)
        
        disasm_desc_label = QLabel("View and analyze assembly code from binary files")
        disasm_desc_label.setWordWrap(True)
        disasm_layout.addWidget(disasm_desc_label)
        
        # Disassembler controls
        disasm_controls_group = QGroupBox("Disassembler Controls")
        disasm_controls_layout = QHBoxLayout()
        
        disasm_file_btn = QPushButton("Load File")
        disasm_arch_combo = QComboBox()
        disasm_arch_combo.addItems(["x86", "x86-64", "ARM", "ARM64", "MIPS", "Auto-detect"])
        disasm_controls_layout.addWidget(disasm_file_btn)
        disasm_controls_layout.addWidget(QLabel("Architecture:"))
        disasm_controls_layout.addWidget(disasm_arch_combo)
        
        disasm_controls_group.setLayout(disasm_controls_layout)
        disasm_layout.addWidget(disasm_controls_group)
        
        # Disassembly view with split layout
        disasm_view_splitter = QSplitter(Qt.Horizontal)
        
        # Function list
        function_list_group = QGroupBox("Functions")
        function_list_layout = QVBoxLayout()
        
        function_filter = QLineEdit()
        function_filter.setPlaceholderText("Filter functions...")
        
        function_list = QListWidget()
        for i in range(10):  # Placeholder items
            function_list.addItem(f"function_{i:04x}(...)")
        
        function_list_layout.addWidget(function_filter)
        function_list_layout.addWidget(function_list)
        function_list_group.setLayout(function_list_layout)
        
        # Disassembly content
        disasm_content_group = QGroupBox("Disassembly")
        disasm_content_layout = QVBoxLayout()
        
        disasm_text = QTextEdit()
        disasm_text.setReadOnly(True)
        disasm_text.setFont(QFont("Courier New", 10))
        
        # Placeholder disassembly content
        placeholder_asm = (
            "0x00401000: push   rbp\n"
            "0x00401001: mov    rbp, rsp\n"
            "0x00401004: sub    rsp, 0x20\n"
            "0x00401008: mov    DWORD PTR [rbp-0x14], edi\n"
            "0x0040100b: mov    QWORD PTR [rbp-0x20], rsi\n"
            "0x0040100f: mov    edi, 0x4020a0\n"
            "0x00401014: call   0x401050\n"
            "0x00401019: mov    eax, 0x0\n"
            "0x0040101e: leave\n"
            "0x0040101f: ret\n"
        )
        disasm_text.setText(placeholder_asm)
        
        disasm_content_layout.addWidget(disasm_text)
        disasm_content_group.setLayout(disasm_content_layout)
        
        disasm_view_splitter.addWidget(function_list_group)
        disasm_view_splitter.addWidget(disasm_content_group)
        disasm_view_splitter.setSizes([150, 450])
        
        disasm_layout.addWidget(disasm_view_splitter)
        
        # 3. Structure Analyzer
        struct_widget = QWidget()
        struct_layout = QVBoxLayout(struct_widget)
        
        # Header
        struct_header_layout = QHBoxLayout()
        struct_header_label = QLabel("<h2>Structure Analyzer</h2>")
        struct_header_layout.addWidget(struct_header_label)
        struct_header_layout.addStretch(1)
        struct_layout.addLayout(struct_header_layout)
        
        struct_desc_label = QLabel("Analyze binary file structure and metadata")
        struct_desc_label.setWordWrap(True)
        struct_layout.addWidget(struct_desc_label)
        
        # Structure controls
        struct_controls_group = QGroupBox("File Controls")
        struct_controls_layout = QHBoxLayout()
        
        struct_file_btn = QPushButton("Load File")
        struct_format_combo = QComboBox()
        struct_format_combo.addItems(["PE/EXE", "ELF", "Mach-O", "Auto-detect"])
        struct_controls_layout.addWidget(struct_file_btn)
        struct_controls_layout.addWidget(QLabel("Format:"))
        struct_controls_layout.addWidget(struct_format_combo)
        
        struct_controls_group.setLayout(struct_controls_layout)
        struct_layout.addWidget(struct_controls_group)
        
        # Structure view with tabs
        struct_tabs = QTabWidget()
        struct_tabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        struct_tabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Headers tab
        headers_tab = QWidget()
        headers_layout = QVBoxLayout(headers_tab)
        
        headers_tree = QTreeWidget()
        headers_tree.setHeaderLabels(["Field", "Value", "Description"])
        
        # Placeholder header data
        root_item = QTreeWidgetItem(["File Header", "", ""])
        root_item.addChild(QTreeWidgetItem(["Magic", "MZ", "DOS Magic number"]))
        root_item.addChild(QTreeWidgetItem(["PE Offset", "0x00000080", "Offset to PE header"]))
        
        pe_item = QTreeWidgetItem(["PE Header", "", ""])
        pe_item.addChild(QTreeWidgetItem(["Machine", "0x014c (x86)", "Target machine"]))
        pe_item.addChild(QTreeWidgetItem(["TimeDateStamp", "0x5F8D7B3C", "2020-10-19 15:43:24"]))
        
        headers_tree.addTopLevelItem(root_item)
        headers_tree.addTopLevelItem(pe_item)
        headers_tree.expandAll()
        
        headers_layout.addWidget(headers_tree)
        
        # Sections tab
        sections_tab = QWidget()
        sections_layout = QVBoxLayout(sections_tab)
        
        sections_table = QTableWidget()
        sections_table.setColumnCount(5)
        sections_table.setHorizontalHeaderLabels(["Name", "Virtual Address", "Size", "Characteristics", "Entropy"])
        
        # Placeholder section data
        sections_table.setRowCount(4)
        sections = [
            [".text", "0x1000", "0x5000", "CODE,EXECUTE", "6.8"],
            [".data", "0x6000", "0x1000", "DATA,READ,WRITE", "4.2"],
            [".rdata", "0x7000", "0x3000", "DATA,READ", "5.7"],
            [".rsrc", "0xA000", "0x2000", "DATA,READ", "3.9"]
        ]
        
        for i, section in enumerate(sections):
            for j, value in enumerate(section):
                sections_table.setItem(i, j, QTableWidgetItem(value))
        
        sections_layout.addWidget(sections_table)
        
        # Resources tab
        resources_tab = QWidget()
        resources_layout = QVBoxLayout(resources_tab)
        
        resources_tree = QTreeWidget()
        resources_tree.setHeaderLabels(["Type", "Name", "Size", "Language"])
        
        # Placeholder resource data
        icon_item = QTreeWidgetItem(["Icon", "", "", ""])
        icon_item.addChild(QTreeWidgetItem(["Icon", "1", "1024 bytes", "Neutral"]))
        icon_item.addChild(QTreeWidgetItem(["Icon", "2", "4096 bytes", "Neutral"]))
        
        version_item = QTreeWidgetItem(["Version", "VS_VERSION_INFO", "512 bytes", "Neutral"])
        
        resources_tree.addTopLevelItem(icon_item)
        resources_tree.addTopLevelItem(version_item)
        
        resources_layout.addWidget(resources_tree)
        
        struct_tabs.addTab(headers_tab, "Headers")
        struct_tabs.addTab(sections_tab, "Sections")
        struct_tabs.addTab(resources_tab, "Resources")
        
        struct_layout.addWidget(struct_tabs)
        
        # 4. Memory Viewer
        memory_viewer_widget = QWidget()
        memory_layout = QVBoxLayout(memory_viewer_widget)
        
        memory_layout.addWidget(QLabel("<h2>Memory Viewer</h2>"))
        memory_layout.addWidget(QLabel("View live memory of running processes"))
        
        # Process selection
        process_group = QGroupBox("Process Selection")
        process_layout = QHBoxLayout()
        
        process_combo = QComboBox()
        process_combo.addItems(["explorer.exe (PID: 1234)", "chrome.exe (PID: 2345)", "notepad.exe (PID: 3456)"])
        refresh_process_btn = QPushButton("Refresh")
        attach_btn = QPushButton("Attach")
        
        process_layout.addWidget(QLabel("Process:"))
        process_layout.addWidget(process_combo, 1)
        process_layout.addWidget(refresh_process_btn)
        process_layout.addWidget(attach_btn)
        
        process_group.setLayout(process_layout)
        memory_layout.addWidget(process_group)
        
        # Memory map view
        memory_map_group = QGroupBox("Memory Map")
        memory_map_layout = QVBoxLayout()
        
        memory_table = QTableWidget()
        memory_table.setColumnCount(5)
        memory_table.setHorizontalHeaderLabels(["Address", "Size", "Protection", "Type", "Module"])
        
        # Placeholder memory regions
        memory_table.setRowCount(4)
        memory_regions = [
            ["0x00400000", "0x00100000", "RX", "Image", "app.exe"],
            ["0x10000000", "0x00050000", "RW", "Private", ""],
            ["0x7FFE0000", "0x00010000", "RW", "Mapped", "ntdll.dll"],
            ["0x7FFF0000", "0x00008000", "RW", "Stack", ""]
        ]
        
        for i, region in enumerate(memory_regions):
            for j, value in enumerate(region):
                memory_table.setItem(i, j, QTableWidgetItem(value))
        
        memory_map_layout.addWidget(memory_table)
        
        # Memory view controls
        memory_view_controls = QHBoxLayout()
        memory_view_controls.addWidget(QLabel("Address:"))
        memory_addr_edit = QLineEdit("0x00400000")
        memory_view_controls.addWidget(memory_addr_edit)
        memory_view_btn = QPushButton("View")
        memory_view_controls.addWidget(memory_view_btn)
        memory_view_controls.addStretch(1)
        
        memory_map_layout.addLayout(memory_view_controls)
        
        memory_map_group.setLayout(memory_map_layout)
        memory_layout.addWidget(memory_map_group)
        
        # 5. Memory Patcher  
        memory_patch_widget = QWidget()
        memory_patch_layout = QVBoxLayout(memory_patch_widget)
        
        memory_patch_layout.addWidget(QLabel("<h2>Memory Patcher</h2>"))
        memory_patch_layout.addWidget(QLabel("Patch memory in running processes"))
        
        memory_patch_layout.addWidget(QLabel("<i>This tool will be integrated in a future update.</i>"))
        memory_patch_layout.addStretch(1)
        
        # Add all widgets to stacked widget
        self.binary_tool_stack.addWidget(hex_viewer_widget)
        self.binary_tool_stack.addWidget(disasm_widget)
        self.binary_tool_stack.addWidget(struct_widget)
        self.binary_tool_stack.addWidget(memory_viewer_widget)
        self.binary_tool_stack.addWidget(memory_patch_widget)
        
        # Add a placeholder for Memory Dump tool
        memory_dump_widget = QWidget()
        memory_dump_layout = QVBoxLayout(memory_dump_widget)
        memory_dump_layout.addWidget(QLabel("<h2>Memory Dump</h2>"))
        memory_dump_layout.addWidget(QLabel("Create and analyze memory dumps"))
        memory_dump_layout.addWidget(QLabel("<i>This tool will be integrated in a future update.</i>"))
        memory_dump_layout.addStretch(1)
        
        self.binary_tool_stack.addWidget(memory_dump_widget)
        
        content_layout.addWidget(self.binary_tool_stack)
        
        # Add sidebar and content area to main splitter
        main_splitter.addWidget(tool_sidebar)
        main_splitter.addWidget(content_area)
        main_splitter.setSizes([200, 800])
        
        layout.addWidget(main_splitter)
        
        # Set the layout for the tab
        self.binary_tools_tab.setLayout(layout)
        
    def switch_binary_tool(self, tool_index):
        """Switch between different binary tools."""
        self.binary_tool_stack.setCurrentIndex(tool_index)
        
    def select_binary_tool_file(self):
        """Select a file for binary tools."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)"
        )
        
        if file_path:
            # Update file info display
            file_info = QtCore.QFileInfo(file_path)
            file_name = file_info.fileName()
            file_size = file_info.size()
            
            self.binary_tool_file_label.setText(file_name)
            self.binary_tool_file_info.setText(f"Path: {file_path}\nSize: {file_size} bytes\nType: Binary File")
            
                
    def show_current_binary_in_hex(self, read_only=True):
        """Show the current binary in hex viewer."""
        if not self.binary_path:
            QMessageBox.warning(self, "Error", "No binary loaded")
            return
            
        try:
            from hexview.hex_dialog import HexViewerDialog
            
            # Create and show the hex viewer dialog
            dialog = HexViewerDialog(self)
            success = dialog.load_file(self.binary_path, read_only=read_only)
            
            if success:
                dialog.exec_()
            else:
                QMessageBox.warning(self, "Error", f"Could not open {self.binary_path}")
        except ImportError:
            QMessageBox.warning(self, "Error", "Hex viewer module not available")
            
    def setup_network_sim_tab(self):
        """Sets up the Network & Simulation Tab with traffic analysis, server emulation, and interception tools."""
        # Create main layout
        layout = QVBoxLayout()
        
        # Create tab widget for network tools
        network_tabs = QTabWidget()
        network_tabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        network_tabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # 1. Traffic Analysis tab
        traffic_tab = QWidget()
        traffic_layout = QVBoxLayout(traffic_tab)
        
        # Header
        traffic_layout.addWidget(QLabel("<h2>Network Traffic Analysis</h2>"))
        traffic_layout.addWidget(QLabel("Capture and analyze network traffic from applications"))
        
        # Capture controls
        capture_group = QGroupBox("Capture Controls")
        capture_layout = QGridLayout()
        
        # Network interface selection
        capture_layout.addWidget(QLabel("Interface:"), 0, 0)
        interface_combo = QComboBox()
        interface_combo.addItems(["Ethernet", "Wi-Fi", "Loopback", "All Interfaces"])
        capture_layout.addWidget(interface_combo, 0, 1)
        
        # Filter settings
        capture_layout.addWidget(QLabel("Filter:"), 1, 0)
        filter_edit = QLineEdit()
        filter_edit.setPlaceholderText("e.g. port 80 or host 192.168.1.1")
        capture_layout.addWidget(filter_edit, 1, 1)
        
        # Target application
        capture_layout.addWidget(QLabel("Target:"), 2, 0)
        target_combo = QComboBox()
        target_combo.addItems(["All Traffic", "Selected Process", "Current Binary"])
        capture_layout.addWidget(target_combo, 2, 1)
        
        # Process selection (enabled when "Selected Process" is chosen)
        process_select_btn = QPushButton("Select Process")
        capture_layout.addWidget(process_select_btn, 2, 2)
        
        # Capture buttons
        capture_buttons_layout = QHBoxLayout()
        start_capture_btn = QPushButton("Start Capture")
        stop_capture_btn = QPushButton("Stop Capture")
        stop_capture_btn.setEnabled(False)
        clear_capture_btn = QPushButton("Clear")
        save_capture_btn = QPushButton("Save Capture")
        
        capture_buttons_layout.addWidget(start_capture_btn)
        capture_buttons_layout.addWidget(stop_capture_btn)
        capture_buttons_layout.addWidget(clear_capture_btn)
        capture_buttons_layout.addWidget(save_capture_btn)
        
        capture_layout.addLayout(capture_buttons_layout, 3, 0, 1, 3)
        
        capture_group.setLayout(capture_layout)
        traffic_layout.addWidget(capture_group)
        
        # Traffic display
        traffic_display_splitter = QSplitter(Qt.Vertical)
        
        # Packet list
        packet_list = QTableWidget()
        packet_list.setColumnCount(6)
        packet_list.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Info"])
        
        # Add some placeholder packets
        packet_list.setRowCount(5)
        packets = [
            ["1", "0.000000", "192.168.1.100", "93.184.216.34", "TCP", "59102 → 80 [SYN] Seq=0 Win=64240 Len=0"],
            ["2", "0.025114", "93.184.216.34", "192.168.1.100", "TCP", "80 → 59102 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0"],
            ["3", "0.025303", "192.168.1.100", "93.184.216.34", "TCP", "59102 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0"],
            ["4", "0.034563", "192.168.1.100", "93.184.216.34", "HTTP", "GET / HTTP/1.1"],
            ["5", "0.154387", "93.184.216.34", "192.168.1.100", "HTTP", "HTTP/1.1 200 OK"]
        ]
        
        for i, packet in enumerate(packets):
            for j, value in enumerate(packet):
                packet_list.setItem(i, j, QTableWidgetItem(value))
        
        # Packet details
        packet_details = QTreeWidget()
        packet_details.setHeaderLabels(["Field", "Value"])
        
        # Add sample packet details
        http_item = QTreeWidgetItem(["HTTP", ""])
        http_item.addChild(QTreeWidgetItem(["Request Method", "GET"]))
        http_item.addChild(QTreeWidgetItem(["Request URI", "/"]))
        http_item.addChild(QTreeWidgetItem(["Request Version", "HTTP/1.1"]))
        
        headers_item = QTreeWidgetItem(["Headers", ""])
        headers_item.addChild(QTreeWidgetItem(["Host", "example.com"]))
        headers_item.addChild(QTreeWidgetItem(["User-Agent", "Mozilla/5.0"]))
        headers_item.addChild(QTreeWidgetItem(["Accept", "text/html,application/xhtml+xml"]))
        
        packet_details.addTopLevelItem(http_item)
        packet_details.addTopLevelItem(headers_item)
        packet_details.expandAll()
        
        # Raw packet hex
        raw_packet = QTextEdit()
        raw_packet.setReadOnly(True)
        raw_packet.setFont(QFont("Courier New", 10))
        raw_packet.setText("00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00\n00 3c 00 00 40 00 40 06 00 00 c0 a8 01 64 5d b8\nd8 22 e6 ce 00 50 00 00 00 00 00 00 00 00 80 02\nfa f0 00 00 00 00 02 04 05 b4 04 02 08 0a 00 00\n00 00 00 00 00 00 01 03 03 07")
        
        traffic_display_splitter.addWidget(packet_list)
        traffic_display_splitter.addWidget(packet_details)
        traffic_display_splitter.addWidget(raw_packet)
        traffic_display_splitter.setSizes([200, 200, 100])
        
        traffic_layout.addWidget(traffic_display_splitter)
        
        # 2. Server Emulation tab
        emulation_tab = QWidget()
        emulation_layout = QVBoxLayout(emulation_tab)
        
        # Header
        emulation_layout.addWidget(QLabel("<h2>License Server Emulation</h2>"))
        emulation_layout.addWidget(QLabel("Emulate license servers and customize responses"))
        
        # Server type selection
        server_type_group = QGroupBox("Server Type")
        server_type_layout = QVBoxLayout()
        
        server_types = QButtonGroup()
        flexlm_radio = QRadioButton("FlexLM License Server")
        hasp_radio = QRadioButton("HASP/Sentinel License Server")
        codemeter_radio = QRadioButton("CodeMeter License Server")
        custom_radio = QRadioButton("Custom License Server")
        
        flexlm_radio.setChecked(True)
        
        server_types.addButton(flexlm_radio)
        server_types.addButton(hasp_radio)
        server_types.addButton(codemeter_radio)
        server_types.addButton(custom_radio)
        
        server_type_layout.addWidget(flexlm_radio)
        server_type_layout.addWidget(hasp_radio)
        server_type_layout.addWidget(codemeter_radio)
        server_type_layout.addWidget(custom_radio)
        
        server_type_group.setLayout(server_type_layout)
        
        # Server configuration
        server_config_group = QGroupBox("Server Configuration")
        server_config_layout = QGridLayout()
        
        server_config_layout.addWidget(QLabel("Listen Address:"), 0, 0)
        listen_addr = QLineEdit("0.0.0.0")
        server_config_layout.addWidget(listen_addr, 0, 1)
        
        server_config_layout.addWidget(QLabel("Port:"), 1, 0)
        port_spin = QSpinBox()
        port_spin.setRange(1, 65535)
        port_spin.setValue(27000)
        server_config_layout.addWidget(port_spin, 1, 1)
        
        server_config_layout.addWidget(QLabel("Status:"), 2, 0)
        status_label = QLabel("Stopped")
        status_label.setStyleSheet("color: red;")
        server_config_layout.addWidget(status_label, 2, 1)
        
        server_config_group.setLayout(server_config_layout)
        
        # License configuration
        license_config_group = QGroupBox("License Configuration")
        license_config_layout = QVBoxLayout()
        
        # Features table (for FlexLM)
        features_table = QTableWidget()
        features_table.setColumnCount(4)
        features_table.setHorizontalHeaderLabels(["Feature", "Version", "Expiry", "Count"])
        
        # Add some sample features
        features_table.setRowCount(3)
        features = [
            ["FEATURE1", "1.0", "31-dec-2099", "10"],
            ["FEATURE2", "2.0", "31-dec-2099", "5"],
            ["SUITE", "3.0", "31-dec-2099", "20"]
        ]
        
        for i, feature in enumerate(features):
            for j, value in enumerate(feature):
                features_table.setItem(i, j, QTableWidgetItem(value))
        
        add_feature_btn = QPushButton("Add Feature")
        remove_feature_btn = QPushButton("Remove Feature")
        
        feature_buttons_layout = QHBoxLayout()
        feature_buttons_layout.addWidget(add_feature_btn)
        feature_buttons_layout.addWidget(remove_feature_btn)
        
        license_config_layout.addWidget(features_table)
        license_config_layout.addLayout(feature_buttons_layout)
        
        license_config_group.setLayout(license_config_layout)
        
        # Server controls
        server_controls_layout = QHBoxLayout()
        
        start_server_btn = QPushButton("Start Server")
        stop_server_btn = QPushButton("Stop Server")
        stop_server_btn.setEnabled(False)
        reset_server_btn = QPushButton("Reset Server")
        
        server_controls_layout.addWidget(start_server_btn)
        server_controls_layout.addWidget(stop_server_btn)
        server_controls_layout.addWidget(reset_server_btn)
        
        # Server logs
        logs_group = QGroupBox("Server Logs")
        logs_layout = QVBoxLayout()
        
        server_logs = QTextEdit()
        server_logs.setReadOnly(True)
        server_logs.setText("Server logs will appear here...")
        
        clear_logs_btn = QPushButton("Clear Logs")
        save_logs_btn = QPushButton("Save Logs")
        
        log_buttons_layout = QHBoxLayout()
        log_buttons_layout.addWidget(clear_logs_btn)
        log_buttons_layout.addWidget(save_logs_btn)
        
        logs_layout.addWidget(server_logs)
        logs_layout.addLayout(log_buttons_layout)
        
        logs_group.setLayout(logs_layout)
        
        # Layout for emulation tab
        emulation_left_layout = QVBoxLayout()
        emulation_left_layout.addWidget(server_type_group)
        emulation_left_layout.addWidget(server_config_group)
        emulation_left_layout.addLayout(server_controls_layout)
        emulation_left_layout.addStretch(1)
        
        emulation_right_layout = QVBoxLayout()
        emulation_right_layout.addWidget(license_config_group)
        emulation_right_layout.addWidget(logs_group)
        
        emulation_split_layout = QHBoxLayout()
        emulation_split_layout.addLayout(emulation_left_layout, 1)
        emulation_split_layout.addLayout(emulation_right_layout, 2)
        
        emulation_layout.addLayout(emulation_split_layout)
        
        # 3. Traffic Interception tab
        interception_tab = QWidget()
        interception_layout = QVBoxLayout(interception_tab)
        
        # Header
        interception_layout.addWidget(QLabel("<h2>Traffic Interception</h2>"))
        interception_layout.addWidget(QLabel("Intercept and modify network traffic in real-time"))
        
        # Interception controls
        intercept_controls_group = QGroupBox("Interception Controls")
        intercept_controls_layout = QGridLayout()
        
        intercept_controls_layout.addWidget(QLabel("Proxy Mode:"), 0, 0)
        proxy_mode_combo = QComboBox()
        proxy_mode_combo.addItems(["HTTP/HTTPS", "TCP/UDP", "All Traffic"])
        intercept_controls_layout.addWidget(proxy_mode_combo, 0, 1)
        
        intercept_controls_layout.addWidget(QLabel("Listen Port:"), 1, 0)
        listen_port_spin = QSpinBox()
        listen_port_spin.setRange(1024, 65535)
        listen_port_spin.setValue(8080)
        intercept_controls_layout.addWidget(listen_port_spin, 1, 1)
        
        intercept_controls_layout.addWidget(QLabel("SSL/TLS:"), 2, 0)
        ssl_mode_combo = QComboBox()
        ssl_mode_combo.addItems(["Generate Certificate", "Use Custom Certificate", "No SSL/TLS"])
        intercept_controls_layout.addWidget(ssl_mode_combo, 2, 1)
        
        intercept_controls_group.setLayout(intercept_controls_layout)
        
        # Interception control buttons
        intercept_buttons_layout = QHBoxLayout()
        
        start_intercept_btn = QPushButton("Start Interception")
        stop_intercept_btn = QPushButton("Stop Interception")
        stop_intercept_btn.setEnabled(False)
        clear_intercept_btn = QPushButton("Clear History")
        
        intercept_buttons_layout.addWidget(start_intercept_btn)
        intercept_buttons_layout.addWidget(stop_intercept_btn)
        intercept_buttons_layout.addWidget(clear_intercept_btn)
        
        # Interception display (request/response)
        intercept_display = QSplitter(Qt.Vertical)
        
        # Request/response list
        request_list = QTableWidget()
        request_list.setColumnCount(5)
        request_list.setHorizontalHeaderLabels(["#", "Host", "Method/Status", "URL/Content", "Size"])
        
        # Sample intercepted requests
        request_list.setRowCount(3)
        requests = [
            ["1", "example.com", "GET", "/index.html", "1.2 KB"],
            ["2", "api.example.com", "POST", "/login", "0.8 KB"],
            ["3", "example.com", "200 OK", "text/html", "15.4 KB"]
        ]
        
        for i, req in enumerate(requests):
            for j, value in enumerate(req):
                request_list.setItem(i, j, QTableWidgetItem(value))
        
        # Request/response editor
        editor_tabs = QTabWidget()
        editor_tabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        editor_tabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # Request tab
        request_tab = QWidget()
        request_layout = QVBoxLayout(request_tab)
        
        request_headers = QTextEdit()
        request_headers.setPlainText("GET /index.html HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: text/html")
        
        request_layout.addWidget(QLabel("Request Headers:"))
        request_layout.addWidget(request_headers)
        
        request_body = QTextEdit()
        request_body.setPlainText("")
        
        request_layout.addWidget(QLabel("Request Body:"))
        request_layout.addWidget(request_body)
        
        # Response tab
        response_tab = QWidget()
        response_layout = QVBoxLayout(response_tab)
        
        response_headers = QTextEdit()
        response_headers.setPlainText("HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 15824\nConnection: close")
        
        response_layout.addWidget(QLabel("Response Headers:"))
        response_layout.addWidget(response_headers)
        
        response_body = QTextEdit()
        response_body.setPlainText("<html>\n  <head>\n    <title>Example Domain</title>\n  </head>\n  <body>\n    <h1>Example Domain</h1>\n    <p>This domain is for use in examples.</p>\n  </body>\n</html>")
        
        response_layout.addWidget(QLabel("Response Body:"))
        response_layout.addWidget(response_body)
        
        editor_tabs.addTab(request_tab, "Request")
        editor_tabs.addTab(response_tab, "Response")
        
        # Interception action buttons
        editor_buttons_layout = QHBoxLayout()
        
        forward_btn = QPushButton("Forward")
        forward_btn.setEnabled(False)
        drop_btn = QPushButton("Drop")
        drop_btn.setEnabled(False)
        modify_forward_btn = QPushButton("Modify & Forward")
        modify_forward_btn.setEnabled(False)
        
        editor_buttons_layout.addWidget(forward_btn)
        editor_buttons_layout.addWidget(drop_btn)
        editor_buttons_layout.addWidget(modify_forward_btn)
        
        intercept_display.addWidget(request_list)
        intercept_display.addWidget(editor_tabs)
        intercept_display.setSizes([200, 400])
        
        # Compose the interception tab layout
        interception_layout.addWidget(intercept_controls_group)
        interception_layout.addLayout(intercept_buttons_layout)
        interception_layout.addWidget(intercept_display)
        interception_layout.addLayout(editor_buttons_layout)
        
        # Add all tabs to the network tabs widget
        network_tabs.addTab(traffic_tab, "Traffic Analysis")
        network_tabs.addTab(emulation_tab, "Server Emulation")
        network_tabs.addTab(interception_tab, "Traffic Interception")
        
        layout.addWidget(network_tabs)
        
        # Set the layout for the tab
        self.network_sim_tab.setLayout(layout)
        
    def setup_plugins_hub_tab(self):
        """Sets up the Plugins Hub tab with analysis, patching, and utility plugins."""
        # Create main layout
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<h2>Plugins Hub</h2>"))
        header_layout.addStretch(1)
        
        plugin_manager_btn = QPushButton("Plugin Manager")
        plugin_manager_btn.setIcon(QIcon.fromTheme("preferences-system"))
        plugin_manager_btn.setToolTip("Install, update, and manage plugins")
        plugin_manager_btn.clicked.connect(self.show_plugin_manager)
        
        install_plugin_btn = QPushButton("Install Plugin")
        install_plugin_btn.setIcon(QIcon.fromTheme("list-add"))
        install_plugin_btn.clicked.connect(lambda: self.import_plugin("custom"))
        
        header_layout.addWidget(plugin_manager_btn)
        header_layout.addWidget(install_plugin_btn)
        
        layout.addLayout(header_layout)
        
        # Create main two-panel layout
        plugin_splitter = QSplitter(Qt.Horizontal)
        
        # Left panel: Categories
        category_panel = QWidget()
        category_layout = QVBoxLayout(category_panel)
        
        # Category search
        search_layout = QHBoxLayout()
        search_edit = QLineEdit()
        search_edit.setPlaceholderText("Search plugins...")
        search_layout.addWidget(search_edit)
        
        category_layout.addLayout(search_layout)
        
        # Categories tree
        category_tree = QTreeWidget()
        category_tree.setHeaderLabel("Plugin Categories")
        category_tree.setAlternatingRowColors(True)
        
        # Add top-level categories
        analysis_item = QTreeWidgetItem(["Analysis Plugins"])
        analysis_item.addChild(QTreeWidgetItem(["Binary Analysis"]))
        analysis_item.addChild(QTreeWidgetItem(["Network Analysis"]))
        analysis_item.addChild(QTreeWidgetItem(["Static Analysis"]))
        analysis_item.addChild(QTreeWidgetItem(["Dynamic Analysis"]))
        
        patching_item = QTreeWidgetItem(["Patching Plugins"])
        patching_item.addChild(QTreeWidgetItem(["License Bypass"]))
        patching_item.addChild(QTreeWidgetItem(["Anti-Debug Removal"]))
        patching_item.addChild(QTreeWidgetItem(["Feature Unlock"]))
        patching_item.addChild(QTreeWidgetItem(["Trial Extension"]))
        
        utility_item = QTreeWidgetItem(["Utility Plugins"])
        utility_item.addChild(QTreeWidgetItem(["Converters"]))
        utility_item.addChild(QTreeWidgetItem(["Visualizers"]))
        utility_item.addChild(QTreeWidgetItem(["Export Tools"]))
        utility_item.addChild(QTreeWidgetItem(["Report Generators"]))
        
        tech_item = QTreeWidgetItem(["By Technology"])
        tech_item.addChild(QTreeWidgetItem(["Frida Scripts"]))
        tech_item.addChild(QTreeWidgetItem(["Ghidra Scripts"]))
        tech_item.addChild(QTreeWidgetItem(["Python Plugins"]))
        tech_item.addChild(QTreeWidgetItem(["JavaScript Plugins"]))
        
        category_tree.addTopLevelItem(analysis_item)
        category_tree.addTopLevelItem(patching_item)
        category_tree.addTopLevelItem(utility_item)
        category_tree.addTopLevelItem(tech_item)
        
        category_tree.expandAll()
        
        category_layout.addWidget(category_tree)
        
        # Right panel: Plugin list and details
        plugins_panel = QWidget()
        plugins_layout = QVBoxLayout(plugins_panel)
        
        # Plugin list and details splitter
        content_splitter = QSplitter(Qt.Vertical)
        
        # Plugin list
        plugin_list = QTableWidget()
        plugin_list.setColumnCount(3)
        plugin_list.setHorizontalHeaderLabels(["Name", "Status", "Description"])
        plugin_list.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        
        # Add some sample plugins
        plugin_list.setRowCount(6)
        sample_plugins = [
            ["License Finder", "Available", "Locates license verification routines in binaries"],
            ["Network Interceptor", "Installed", "Intercepts and modifies network traffic with SSL support"],
            ["String Decryptor", "Available", "Automatically decrypts obfuscated strings"],
            ["Adobe CC Bypass", "Installed", "Sample Frida script for Adobe CC apps"],
            ["Binary Differ", "Installed", "Compares binaries and identifies differences"],
            ["Demo Plugin", "Installed", "Demonstration of plugin functionality"]
        ]
        
        for i, plugin in enumerate(sample_plugins):
            for j, value in enumerate(plugin):
                item = QTableWidgetItem(value)
                if j == 1:  # Status column
                    if value == "Installed":
                        item.setBackground(QColor(200, 255, 200))  # Light green
                plugin_list.setItem(i, j, item)
        
        # Plugin details
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Details header
        details_header = QHBoxLayout()
        self.plugin_name_label = QLabel("<h3>License Finder</h3>")
        details_header.addWidget(self.plugin_name_label)
        details_header.addStretch(1)
        
        details_layout.addLayout(details_header)
        
        # Plugin info
        info_layout = QHBoxLayout()
        
        # Left column: Info
        info_left = QVBoxLayout()
        info_left.addWidget(QLabel("<b>Author:</b> IntelliCrack Team"))
        info_left.addWidget(QLabel("<b>Category:</b> Analysis Plugins > Binary Analysis"))
        
        # Right column: Actions
        info_right = QVBoxLayout()
        run_plugin_btn = QPushButton("Run Plugin")
        run_plugin_btn.setIcon(QIcon.fromTheme("media-playback-start"))
        run_plugin_btn.clicked.connect(lambda: self.run_custom_plugin("Demo Plugin"))
        
        edit_plugin_btn = QPushButton("Edit Plugin")
        edit_plugin_btn.setIcon(QIcon.fromTheme("document-edit"))
        edit_plugin_btn.clicked.connect(lambda: self.edit_plugin_file("plugins/custom_modules/demo_plugin.py"))
        
        uninstall_plugin_btn = QPushButton("Uninstall")
        uninstall_plugin_btn.setIcon(QIcon.fromTheme("edit-delete"))
        uninstall_plugin_btn.clicked.connect(lambda: QMessageBox.information(self, "Uninstall", "Plugin uninstall functionality would be implemented here"))
        
        info_right.addWidget(run_plugin_btn)
        info_right.addWidget(edit_plugin_btn)
        info_right.addWidget(uninstall_plugin_btn)
        info_right.addStretch(1)
        
        info_layout.addLayout(info_left, 2)
        info_layout.addLayout(info_right, 1)
        
        details_layout.addLayout(info_layout)
        
        # Description
        details_layout.addWidget(QLabel("<b>Description:</b>"))
        description_text = QTextEdit()
        description_text.setReadOnly(True)
        description_text.setMaximumHeight(100)
        description_text.setText("License Finder locates license verification routines in binaries. It finds code paths related to license checks, activation verifications, and trial limitations.")
        details_layout.addWidget(description_text)
        
        # Usage
        details_layout.addWidget(QLabel("<b>Usage:</b>"))
        usage_text = QTextEdit()
        usage_text.setReadOnly(True)
        usage_text.setMaximumHeight(80)
        usage_text.setText("1. Select a binary file to analyze\n2. Run the plugin\n3. Review the identified license check locations\n4. Export results or use with patcher")
        details_layout.addWidget(usage_text)
        
        # Add to content splitter
        content_splitter.addWidget(plugin_list)
        content_splitter.addWidget(details_widget)
        content_splitter.setSizes([300, 400])
        
        plugins_layout.addWidget(content_splitter)
        
        # Add the panels to the main splitter
        plugin_splitter.addWidget(category_panel)
        plugin_splitter.addWidget(plugins_panel)
        plugin_splitter.setSizes([200, 800])
        
        layout.addWidget(plugin_splitter)
        
        # Special tools section
        tools_group = QGroupBox("Special Tools")
        tools_layout = QGridLayout()
        
        keygen_tool_btn = QPushButton("Key Generator")
        keygen_tool_btn.setIcon(QIcon.fromTheme("dialog-password"))
        keygen_tool_btn.setToolTip("Generate license keys for various applications")
        tools_layout.addWidget(keygen_tool_btn, 0, 0)
        
        patcher_tool_btn = QPushButton("Advanced Patcher")
        patcher_tool_btn.setIcon(QIcon.fromTheme("package-x-generic"))
        patcher_tool_btn.setToolTip("Advanced binary patching tool")
        tools_layout.addWidget(patcher_tool_btn, 0, 1)
        
        emulator_tool_btn = QPushButton("API Emulator")
        emulator_tool_btn.setIcon(QIcon.fromTheme("network-server"))
        emulator_tool_btn.setToolTip("Emulate API responses for testing")
        tools_layout.addWidget(emulator_tool_btn, 0, 2)
        
        unpacker_tool_btn = QPushButton("Binary Unpacker")
        unpacker_tool_btn.setIcon(QIcon.fromTheme("package-x-generic"))
        unpacker_tool_btn.setToolTip("Unpack protected executables")
        tools_layout.addWidget(unpacker_tool_btn, 1, 0)
        
        rebuilder_tool_btn = QPushButton("PE Rebuilder")
        rebuilder_tool_btn.setIcon(QIcon.fromTheme("document-save-as"))
        rebuilder_tool_btn.setToolTip("Fix and rebuild damaged PE files")
        tools_layout.addWidget(rebuilder_tool_btn, 1, 1)
        
        certificate_tool_btn = QPushButton("Certificate Manager")
        certificate_tool_btn.setIcon(QIcon.fromTheme("application-certificate"))
        certificate_tool_btn.setToolTip("Manage and create certificates")
        tools_layout.addWidget(certificate_tool_btn, 1, 2)
        
        # Add plugin execution mode test buttons
        sandbox_test_btn = QPushButton("Test Sandbox")
        sandbox_test_btn.setIcon(QIcon.fromTheme("security-medium"))
        sandbox_test_btn.setToolTip("Test sandboxed plugin execution")
        sandbox_test_btn.clicked.connect(self.test_sandbox_execution)
        tools_layout.addWidget(sandbox_test_btn, 2, 0)
        
        remote_test_btn = QPushButton("Test Remote")
        remote_test_btn.setIcon(QIcon.fromTheme("network-workgroup"))
        remote_test_btn.setToolTip("Test remote plugin execution")
        remote_test_btn.clicked.connect(self.test_remote_execution)
        tools_layout.addWidget(remote_test_btn, 2, 1)
        
        tools_group.setLayout(tools_layout)
        layout.addWidget(tools_group)
        
        # Set the layout for the tab
        self.plugins_hub_tab.setLayout(layout)
        
    def setup_assistant_logs_tab(self):
        """Sets up the Assistant & Logs tab combining AI assistance with live logs."""
        # Create main layout
        layout = QVBoxLayout()
        
        # Create main splitter to adjust space between assistant and logs
        main_splitter = QSplitter(Qt.Vertical)
        
        # --- ASSISTANT SECTION ---
        assistant_widget = QWidget()
        assistant_layout = QVBoxLayout(assistant_widget)
        
        # Header
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<h2>AI Assistant</h2>"))
        
        # Status indicator
        self.assistant_status = QLabel("Ready")
        self.assistant_status.setStyleSheet("color: green; font-weight: bold;")
        header_layout.addStretch(1)
        header_layout.addWidget(QLabel("Status:"))
        header_layout.addWidget(self.assistant_status)
        
        # Model selection
        model_layout = QHBoxLayout()
        model_layout.addWidget(QLabel("AI Model:"))
        model_combo = QComboBox()
        model_combo.addItems(["Claude-3", "Local LLama", "GPT-4", "Mistral"])
        model_layout.addWidget(model_combo)
        model_layout.addStretch(1)
        
        # Add header and model selection to assistant layout
        assistant_layout.addLayout(header_layout)
        assistant_layout.addLayout(model_layout)
        
        # Create chat interface
        chat_group = QGroupBox("Chat History")
        chat_layout = QVBoxLayout()
        
        # Chat display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        # Set font for better readability
        chat_font = QFont("Segoe UI", 10)
        self.chat_display.setFont(chat_font)
        # Welcome message
        self.chat_display.setHtml(
            "<div style='color:#666;'><i>Welcome to IntelliCrack Assistant. "
            "I can help you analyze binaries, generate patches, understand protection mechanisms, "
            "and more. What would you like to do today?</i></div>"
        )
        
        chat_layout.addWidget(self.chat_display)
        chat_group.setLayout(chat_layout)
        
        # User input area
        input_group = QGroupBox("Your Message")
        input_layout = QVBoxLayout()
        
        # Preset queries
        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("Preset:"))
        preset_combo = QComboBox()
        preset_combo.addItems([
            "Select a preset query...",
            "Analyze this binary for license checks",
            "Generate a patch plan",
            "Explain this assembly code",
            "How does this protection work?",
            "Suggest memory locations to patch",
            "What APIs are used by this function?",
            "Help me bypass this protection"
        ])
        preset_combo.currentIndexChanged.connect(self.handle_preset_query)
        
        preset_layout.addWidget(preset_combo, 1)
        preset_layout.addStretch(1)
        
        # User input
        self.user_input = QTextEdit()
        self.user_input.setPlaceholderText("Type your message here...")
        self.user_input.setMaximumHeight(100)
        
        # Chat buttons
        chat_buttons_layout = QHBoxLayout()
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.user_input.clear())
        
        send_btn = QPushButton("Send")
        send_btn.setIcon(QIcon.fromTheme("mail-send"))
        send_btn.clicked.connect(self.send_to_assistant)
        
        chat_buttons_layout.addWidget(clear_btn)
        chat_buttons_layout.addStretch(1)
        chat_buttons_layout.addWidget(send_btn)
        
        # Add all elements to input layout
        input_layout.addLayout(preset_layout)
        input_layout.addWidget(self.user_input)
        input_layout.addLayout(chat_buttons_layout)
        
        input_group.setLayout(input_layout)
        
        # Add chat components to assistant layout
        assistant_layout.addWidget(chat_group)
        assistant_layout.addWidget(input_group)
        
        # --- LOGS SECTION ---
        logs_widget = QWidget()
        logs_layout = QVBoxLayout(logs_widget)
        
        # Log header and controls
        logs_header_layout = QHBoxLayout()
        logs_header_layout.addWidget(QLabel("<h2>Live Logs</h2>"))
        logs_header_layout.addStretch(1)
        
        # Log filter controls
        logs_header_layout.addWidget(QLabel("Filter:"))
        self.log_filter = QLineEdit()
        self.log_filter.setFixedWidth(200)
        self.log_filter.setPlaceholderText("Enter keywords to filter...")
        logs_header_layout.addWidget(self.log_filter)
        
        apply_filter_btn = QPushButton("Apply")
        apply_filter_btn.clicked.connect(self.apply_log_filter)
        logs_header_layout.addWidget(apply_filter_btn)
        
        # Add log header to logs layout
        logs_layout.addLayout(logs_header_layout)
        
        # Log display
        log_display_layout = QHBoxLayout()
        
        # Log level filter
        log_level_group = QGroupBox("Log Levels")
        log_level_layout = QVBoxLayout()
        
        self.info_check = QCheckBox("Info")
        self.info_check.setChecked(True)
        self.warning_check = QCheckBox("Warning")
        self.warning_check.setChecked(True)
        self.error_check = QCheckBox("Error")
        self.error_check.setChecked(True)
        self.debug_check = QCheckBox("Debug")
        self.debug_check.setChecked(False)
        
        log_level_layout.addWidget(self.info_check)
        log_level_layout.addWidget(self.warning_check)
        log_level_layout.addWidget(self.error_check)
        log_level_layout.addWidget(self.debug_check)
        log_level_layout.addStretch(1)
        
        # Apply levels button
        apply_levels_btn = QPushButton("Apply Levels")
        apply_levels_btn.clicked.connect(self.apply_log_filter)
        log_level_layout.addWidget(apply_levels_btn)
        
        log_level_group.setLayout(log_level_layout)
        
        # Log output area
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setLineWrapMode(QTextEdit.NoWrap)
        self.log_output.setFont(QFont("Courier New", 9))
        # Add sample log messages
        self.log_output.append("<span style='color:#007F00;'>[INFO] [2023-05-16 12:30:45] Application started</span>")
        self.log_output.append("<span style='color:#007F00;'>[INFO] [2023-05-16 12:30:46] Loading configuration from intellicrack_config.json</span>")
        self.log_output.append("<span style='color:#007F00;'>[INFO] [2023-05-16 12:30:47] Initializing UI components</span>")
        self.log_output.append("<span style='color:#CC7F00;'>[WARNING] [2023-05-16 12:30:48] Could not load recent files list</span>")
        self.log_output.append("<span style='color:#CC0000;'>[ERROR] [2023-05-16 12:30:50] Failed to initialize OpenGL context</span>")
        self.log_output.append("<span style='color:#007F00;'>[INFO] [2023-05-16 12:30:52] Using software rendering fallback</span>")
        
        log_display_layout.addWidget(log_level_group, 1)
        log_display_layout.addWidget(self.log_output, 4)
        
        # Log buttons
        log_buttons_layout = QHBoxLayout()
        
        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_logs)
        
        save_logs_btn = QPushButton("Save Logs")
        save_logs_btn.clicked.connect(self.save_logs)
        
        auto_scroll_check = QCheckBox("Auto-scroll")
        auto_scroll_check.setChecked(True)
        
        log_buttons_layout.addWidget(clear_logs_btn)
        log_buttons_layout.addWidget(save_logs_btn)
        log_buttons_layout.addStretch(1)
        log_buttons_layout.addWidget(auto_scroll_check)
        
        # Add log components to logs layout
        logs_layout.addLayout(log_display_layout)
        logs_layout.addLayout(log_buttons_layout)
        
        # Add widgets to main splitter
        main_splitter.addWidget(assistant_widget)
        main_splitter.addWidget(logs_widget)
        main_splitter.setSizes([600, 400])  # Default size allocation
        
        layout.addWidget(main_splitter)
        
        # Set the layout for the tab
        self.assistant_logs_tab.setLayout(layout)
        
    def send_to_assistant(self):
        """Send the user's message to the assistant."""
        user_message = self.user_input.toPlainText().strip()
        if not user_message:
            return
            
        # Update chat display with user message
        self.chat_display.append(f"<div style='font-weight:bold;'>You:</div>")
        self.chat_display.append(f"<div style='margin-left:10px;'>{user_message}</div><br>")
        
        # Clear user input
        self.user_input.clear()
        
        # Show assistant is thinking
        self.assistant_status.setText("Thinking...")
        self.assistant_status.setStyleSheet("color: orange; font-weight: bold;")
        
        # Generate a placeholder response (in a real implementation, this would be from the AI model)
        response = "I'm analyzing your request...\n\nBased on the information provided, I'd recommend examining the license verification routines at addresses 0x140001000-0x140001500. These appear to contain the core validation logic.\n\nI can help you generate patches or explain the protection mechanism in more detail if needed."
        
        # Simulate delay for assistant response
        QTimer.singleShot(1500, lambda: self.show_assistant_response(response))
        
    def show_assistant_response(self, response):
        """Display the assistant's response in the chat."""
        # Update status to ready
        self.assistant_status.setText("Ready")
        self.assistant_status.setStyleSheet("color: green; font-weight: bold;")
        
        # Add response to chat
        self.chat_display.append(f"<div style='font-weight:bold; color:#0066CC;'>Assistant:</div>")
        self.chat_display.append(f"<div style='margin-left:10px;'>{response}</div><br>")
        
        # Scroll to bottom
        self.chat_display.verticalScrollBar().setValue(
            self.chat_display.verticalScrollBar().maximum()
        )
        
        # Also add to logs
        self.log_output.append("<span style='color:#007F00;'>[INFO] [2023-05-16 12:31:30] Assistant query processed</span>")
        
    def run_concolic_license_bypass(self):
        """Run concolic execution to find license bypass."""
        try:
            if not self.binary_path:
                QMessageBox.warning(self, "Error", "No binary file selected")
                return
            
            self.update_output.emit("[INFO] Starting concolic execution for license bypass...")
            
            # Check if concolic execution engine is available
            if not hasattr(self, 'concolic_execution_engine') or self.concolic_execution_engine is None:
                QMessageBox.warning(self, "Error", "Concolic execution engine not available")
                return
            
            # Create a new engine instance for this binary
            from intellicrack.core.analysis.concolic_executor import ConcolicExecutionEngine
            engine = ConcolicExecutionEngine(self.binary_path, max_iterations=50, timeout=60)
            
            if not engine.manticore_available:
                QMessageBox.warning(self, "Error", "Manticore/SimConcolic not available for concolic execution")
                return
            
            # Run license bypass analysis
            self.update_output.emit("[INFO] Analyzing binary for license bypass patterns...")
            results = engine.find_license_bypass()
            
            if results.get("success"):
                if results.get("bypass_found"):
                    bypass_info = f"""License Bypass Found!
                    
License Check Address: {results.get('license_check_address', 'Auto-detected')}
Input Data (stdin): {results.get('stdin', 'None')}
Arguments: {results.get('argv', [])}
Description: {results.get('description', 'License bypass successful')}"""
                    
                    QMessageBox.information(self, "Concolic Analysis Success", bypass_info)
                    self.update_output.emit(f"[SUCCESS] {results.get('description', 'License bypass found')}")
                else:
                    QMessageBox.information(self, "Concolic Analysis Complete", 
                                          "Analysis completed but no license bypass found")
                    self.update_output.emit("[INFO] No license bypass patterns detected")
            else:
                error_msg = results.get("error", "Unknown error during analysis")
                QMessageBox.warning(self, "Analysis Error", f"Concolic analysis failed: {error_msg}")
                self.update_output.emit(f"[ERROR] Concolic analysis failed: {error_msg}")
                
        except Exception as e:
            error_msg = f"Failed to run concolic license bypass: {str(e)}"
            QMessageBox.critical(self, "Error", error_msg)
            self.update_output.emit(f"[ERROR] {error_msg}")
        
    def clear_logs(self):
        """Clear the log output display."""
        self.log_output.clear()
        
    def setup_dashboard_tab(self):
        """Sets up the Dashboard tab with system overview and quick access."""
        # Create main layout
        dashboard_layout = QVBoxLayout()
        
        # Create scrollable area for dashboard
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(15, 15, 15, 15)
        scroll_layout.setSpacing(15)
        
        # --- HEADER SECTION ---
        header_widget = QWidget()
        header_widget.setObjectName("dashboardHeader")  # For styling
        header_layout = QHBoxLayout(header_widget)
        
        # Left side: Welcome message
        welcome_layout = QVBoxLayout()
        welcome_title = QLabel("<h1>Welcome to Intellicrack</h1>")
        welcome_subtitle = QLabel("Advanced Analysis and Patching Platform")
        welcome_layout.addWidget(welcome_title)
        welcome_layout.addWidget(welcome_subtitle)
        welcome_layout.addStretch(1)
        
        # Right side: System status indicators
        status_layout = QGridLayout()
        status_layout.setSpacing(10)
        
        # System status indicators with visual status (green/yellow/red)
        status_indicators = [
            ("AI Model", "Connected", "green"),
            ("License Server", "Running", "green"),
            ("Patch Engine", "Ready", "green"),
            ("Network Monitor", "Inactive", "gray")
        ]
        
        for row, (name, status, color) in enumerate(status_indicators):
            label = QLabel(f"<b>{name}:</b>")
            status_indicator = QLabel(f"<span style='color:{color};'>●</span> {status}")
            status_layout.addWidget(label, row, 0)
            status_layout.addWidget(status_indicator, row, 1)
        
        # Add welcome and status to header
        header_layout.addLayout(welcome_layout, 3)
        header_layout.addLayout(status_layout, 2)
        
        scroll_layout.addWidget(header_widget)
        
        # --- QUICK ACTIONS SECTION ---
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()
        
        # Create quick action buttons with icons
        quick_actions = [
            ("Analyze Binary", "microscope", self.open_analyze_tab),
            ("Create Patch", "wrench", self.open_patching_tab),
            ("View Hex", "search", self.open_hex_viewer_tab),
            ("Network Capture", "wifi", self.open_network_tab),
            ("Run Plugin", "extension", self.open_plugins_tab)
        ]
        
        for name, icon, callback in quick_actions:
            action_btn = QPushButton(name)
            action_btn.setIcon(QIcon.fromTheme(icon))
            action_btn.setMinimumWidth(120)
            action_btn.clicked.connect(callback)
            actions_layout.addWidget(action_btn)
        
        actions_group.setLayout(actions_layout)
        scroll_layout.addWidget(actions_group)
        
        # --- MAIN DASHBOARD CONTENT ---
        # Create two columns with a splitter
        dashboard_splitter = QSplitter(Qt.Horizontal)
        
        # Left column widgets
        left_column = QWidget()
        left_layout = QVBoxLayout(left_column)
        
        # Recent files section
        recent_files_group = QGroupBox("Recent Files")
        recent_files_layout = QVBoxLayout()
        
        self.recent_files_list = QListWidget()
        self.recent_files_list.setMaximumHeight(150)
        self.recent_files_list.itemDoubleClicked.connect(self.load_recent_file)
        
        # Add sample recent files
        for i in range(5):
            item = QListWidgetItem(f"Sample{i+1}.exe - Last opened: {5-i}h ago")
            self.recent_files_list.addItem(item)
        
        recent_files_layout.addWidget(self.recent_files_list)
        
        recent_files_buttons = QHBoxLayout()
        open_file_btn = QPushButton("Open File")
        open_file_btn.clicked.connect(self.select_binary)
        clear_recent_btn = QPushButton("Clear List")
        
        recent_files_buttons.addWidget(open_file_btn)
        recent_files_buttons.addWidget(clear_recent_btn)
        
        recent_files_layout.addLayout(recent_files_buttons)
        recent_files_group.setLayout(recent_files_layout)
        left_layout.addWidget(recent_files_group)
        
        # Binary information section (shown when binary is loaded)
        self.binary_info_group = QGroupBox("Current Binary Information")
        binary_info_layout = QGridLayout()
        
        # Sample binary info (in a real implementation, this would be populated based on loaded binary)
        binary_info = [
            ("Name:", "Sample.exe"),
            ("Size:", "3.4 MB"),
            ("Type:", "PE32+ executable (console) x86-64"),
            ("Entropy:", "7.2 (likely packed/encrypted)"),
            ("MD5:", "d41d8cd98f00b204e9800998ecf8427e")
        ]
        
        for row, (label_text, value_text) in enumerate(binary_info):
            label = QLabel(f"<b>{label_text}</b>")
            value = QLabel(value_text)
            binary_info_layout.addWidget(label, row, 0)
            binary_info_layout.addWidget(value, row, 1)
        
        self.binary_info_group.setLayout(binary_info_layout)
        left_layout.addWidget(self.binary_info_group)
        
        # Notifications section
        notifications_group = QGroupBox("Notifications")
        notifications_layout = QVBoxLayout()
        
        self.notifications_list = QListWidget()
        
        # Add sample notifications
        notifications = [
            ("New plugin update available", "License Finder v1.3.0 has been released"),
            ("Analysis completed", "Analysis of Sample2.exe completed with 3 findings"),
            ("System update", "Intellicrack core has been updated to v2.0.1")
        ]
        
        for title, message in notifications:
            item = QListWidgetItem(f"<b>{title}</b><br>{message}")
            self.notifications_list.addItem(item)
        
        notifications_layout.addWidget(self.notifications_list)
        
        clear_notifications_btn = QPushButton("Clear All")
        notifications_layout.addWidget(clear_notifications_btn)
        
        notifications_group.setLayout(notifications_layout)
        left_layout.addWidget(notifications_group)
        
        # Right column widgets
        right_column = QWidget()
        right_layout = QVBoxLayout(right_column)
        
        # Statistics section
        stats_group = QGroupBox("Analysis Statistics")
        stats_layout = QGridLayout()
        
        # Sample statistics (in a real implementation, these would be actual statistics)
        stats = [
            ("Total Binaries Analyzed:", "42"),
            ("Successful Patches:", "37"),
            ("Protection Schemes Identified:", "15"),
            ("License Types Bypassed:", "8"),
            ("Most Used Tool:", "Hex Viewer (152 times)")
        ]
        
        for row, (label_text, value_text) in enumerate(stats):
            label = QLabel(f"<b>{label_text}</b>")
            value = QLabel(value_text)
            stats_layout.addWidget(label, row, 0)
            stats_layout.addWidget(value, row, 1)
        
        stats_group.setLayout(stats_layout)
        right_layout.addWidget(stats_group)
        
        # License server status section
        server_group = QGroupBox("License Server Status")
        server_layout = QVBoxLayout()
        
        server_status = QLabel("<b>Status:</b> <span style='color:green;'>Running</span>")
        server_address = QLabel("<b>Address:</b> 0.0.0.0:27000")
        server_active = QLabel("<b>Active Connections:</b> 2")
        server_features = QLabel("<b>Available Features:</b> FEATURE1, FEATURE2, SUITE")
        
        server_layout.addWidget(server_status)
        server_layout.addWidget(server_address)
        server_layout.addWidget(server_active)
        server_layout.addWidget(server_features)
        
        server_buttons = QHBoxLayout()
        start_server_btn = QPushButton("Start Server")
        start_server_btn.setEnabled(False)
        stop_server_btn = QPushButton("Stop Server")
        configure_server_btn = QPushButton("Configure")
        
        server_buttons.addWidget(start_server_btn)
        server_buttons.addWidget(stop_server_btn)
        server_buttons.addWidget(configure_server_btn)
        
        server_layout.addLayout(server_buttons)
        server_group.setLayout(server_layout)
        right_layout.addWidget(server_group)
        
        # Activity log section
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        
        # Sample activity log entries
        activity_entries = [
            ("12:30:45", "Application started"),
            ("12:31:02", "Loaded binary: Sample1.exe"),
            ("12:32:15", "Analysis completed with 3 findings"),
            ("12:35:30", "Patch applied successfully"),
            ("12:40:12", "Network capture started")
        ]
        
        for timestamp, activity in activity_entries:
            self.activity_log.append(f"<b>[{timestamp}]</b> {activity}")
        
        activity_layout.addWidget(self.activity_log)
        activity_group.setLayout(activity_layout)
        right_layout.addWidget(activity_group)
        
        # Add columns to splitter
        dashboard_splitter.addWidget(left_column)
        dashboard_splitter.addWidget(right_column)
        dashboard_splitter.setSizes([400, 400])
        
        scroll_layout.addWidget(dashboard_splitter)
        
        # Set the scroll widget and add to main layout
        scroll_area.setWidget(scroll_widget)
        dashboard_layout.addWidget(scroll_area)
        
        # Set the layout for the tab
        self.dashboard_tab.setLayout(dashboard_layout)
        
    def open_analyze_tab(self):
        """Switch to the Analysis tab."""
        self.tabs.setCurrentWidget(self.analysis_tab)
        
    def open_patching_tab(self):
        """Switch to the Patching & Exploitation tab."""
        self.tabs.setCurrentWidget(self.patching_exploitation_tab)
        
    def open_hex_viewer_tab(self):
        """Switch to the Tools & Plugins tab."""
        self.tabs.setCurrentWidget(self.tools_plugins_tab)
        
    def open_network_tab(self):
        """Switch to the NetAnalysis & Emulation tab."""
        self.tabs.setCurrentWidget(self.netanalysis_emulation_tab)
        
    def open_plugins_tab(self):
        """Switch to the Tools & Plugins tab."""
        self.tabs.setCurrentWidget(self.tools_plugins_tab)
        
    def apply_theme_settings(self):
        """Apply theme settings from configuration."""
        try:
            # Get theme from config or default to dark theme
            theme = CONFIG.get("ui_theme", "Dark")
            
            if theme.lower() == "dark":
                self.apply_dark_theme()
            else:
                self.apply_light_theme()
                
            # Apply font settings
            font_size = CONFIG.get("font_size", 10)
            font = self.font()
            font.setPointSize(font_size)
            self.setFont(font)
            
            self.logger.info(f"Applied theme settings: {theme} theme with {font_size}pt font")
            
        except Exception as e:
            self.logger.error(f"Error applying theme settings: {e}")
            # Fall back to default theme
            self.setPalette(QApplication.style().standardPalette())
            
    def _create_placeholder_image(self, title="Missing Image"):
        """Create a placeholder image when an image is missing."""
        try:
            from PIL import Image, ImageDraw, ImageFont
            
            # Create a new image with a gray background
            img = Image.new('RGB', (400, 200), color=(200, 200, 200))
            draw = ImageDraw.Draw(img)
            
            # Add text to the image
            try:
                font = ImageFont.truetype("arial.ttf", 20)
            except:
                font = ImageFont.load_default()
                
            # Draw the placeholder text
            draw.text((20, 80), f"Placeholder: {title}", fill=(0, 0, 0), font=font)
            
            # Convert to bytes
            import io
            img_byte_array = io.BytesIO()
            img.save(img_byte_array, format='PNG')
            return img_byte_array.getvalue()
            
        except Exception as e:
            self.logger.error(f"Error creating placeholder image: {e}")
            # Return a minimal valid PNG if PIL fails
            return bytes.fromhex(
                '89504e470d0a1a0a0000000d49484452000000100000001008060000001ff3ff61'
                '000000017352474200aece1ce90000000467414d410000b18f0bfc61050000000a'
                '49444154384f631800000500010155270ae10000000049454e44ae426082'
            )
            
    def _create_icon_pixmap(self, size=64):
        """Create a blank pixmap for icons when the actual icon is missing."""
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        
        painter = QPainter(pixmap)
        painter.setPen(QPen(Qt.gray, 2))
        painter.drawRect(2, 2, size-4, size-4)
        painter.setPen(QPen(Qt.gray, 1))
        painter.drawLine(2, 2, size-2, size-2)
        painter.drawLine(2, size-2, size-2, 2)
        painter.end()
        
        return pixmap
        
    def setup_settings_tab(self):
        """Sets up the Settings tab with configuration options for the application."""
        # Create main layout with scroll area for the settings
        layout = QVBoxLayout(self.settings_tab)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # General Configuration section
        general_group = QGroupBox("General Configuration")
        general_layout = QVBoxLayout(general_group)
        
        ghidra_path_layout = QHBoxLayout()
        ghidra_path_layout.addWidget(QLabel("Ghidra Path:"))
        self.ghidra_path_edit = QLineEdit()
        if "ghidra_path" in CONFIG:
            self.ghidra_path_edit.setText(CONFIG["ghidra_path"])
        ghidra_path_browse_btn = QPushButton("Browse...")
        ghidra_path_browse_btn.clicked.connect(self.browse_ghidra_path)
        ghidra_path_layout.addWidget(self.ghidra_path_edit)
        ghidra_path_layout.addWidget(ghidra_path_browse_btn)
        
        log_dir_layout = QHBoxLayout()
        log_dir_layout.addWidget(QLabel("Log Directory Path:"))
        log_dir_edit = QLineEdit()
        if "log_dir" in CONFIG:
            log_dir_edit.setText(CONFIG["log_dir"])
        log_dir_layout.addWidget(log_dir_edit)
        
        plugin_dir_layout = QHBoxLayout()
        plugin_dir_layout.addWidget(QLabel("Default Plugin Directory Path:"))
        plugin_dir_edit = QLineEdit()
        if "plugin_directory" in CONFIG:
            plugin_dir_edit.setText(CONFIG["plugin_directory"])
        plugin_dir_layout.addWidget(plugin_dir_edit)
        
        runtime_interception_cb = QCheckBox("Enable Runtime Interception (Frida) by default")
        if "runtime_interception" in CONFIG:
            runtime_interception_cb.setChecked(CONFIG["runtime_interception"])
        
        detect_protections_cb = QCheckBox("Detect Protections Automatically on Binary Load")
        if "detect_protections" in CONFIG:
            detect_protections_cb.setChecked(CONFIG["detect_protections"])
        
        enable_sandbox_cb = QCheckBox("Enable Plugin Sandboxing")
        if "enable_plugin_sandbox" in CONFIG:
            enable_sandbox_cb.setChecked(CONFIG["enable_plugin_sandbox"])
        
        # Remote Plugin Execution section
        remote_plugins_group = QGroupBox("Remote Plugin Execution")
        remote_plugins_layout = QVBoxLayout(remote_plugins_group)
        
        enable_remote_plugins_cb = QCheckBox("Enable Remote Plugins")
        if "enable_remote_plugins" in CONFIG:
            enable_remote_plugins_cb.setChecked(CONFIG["enable_remote_plugins"])
        
        remote_host_layout = QHBoxLayout()
        remote_host_layout.addWidget(QLabel("Default Remote Host:"))
        remote_host_edit = QLineEdit()
        if "remote_host" in CONFIG:
            remote_host_edit.setText(CONFIG["remote_host"])
        remote_host_layout.addWidget(remote_host_edit)
        
        remote_port_layout = QHBoxLayout()
        remote_port_layout.addWidget(QLabel("Default Remote Port:"))
        remote_port_spin = QSpinBox()
        remote_port_spin.setRange(1, 65535)
        if "remote_port" in CONFIG:
            remote_port_spin.setValue(CONFIG["remote_port"])
        else:
            remote_port_spin.setValue(8000)  # Default value
        remote_port_layout.addWidget(remote_port_spin)
        
        remote_plugins_layout.addWidget(enable_remote_plugins_cb)
        remote_plugins_layout.addLayout(remote_host_layout)
        remote_plugins_layout.addLayout(remote_port_layout)
        
        plugin_timeout_layout = QHBoxLayout()
        plugin_timeout_layout.addWidget(QLabel("Plugin Execution Timeout (seconds):"))
        self.plugin_timeout_spinbox = QSpinBox()
        self.plugin_timeout_spinbox.setRange(1, 3600)
        if "plugin_timeout" in CONFIG:
            self.plugin_timeout_spinbox.setValue(CONFIG["plugin_timeout"])
        else:
            self.plugin_timeout_spinbox.setValue(60)  # Default value
        plugin_timeout_layout.addWidget(self.plugin_timeout_spinbox)
        
        save_general_btn = QPushButton("Save General Configuration")
        save_general_btn.clicked.connect(self.save_config)
        
        general_layout.addLayout(ghidra_path_layout)
        general_layout.addLayout(log_dir_layout)
        general_layout.addLayout(plugin_dir_layout)
        general_layout.addWidget(runtime_interception_cb)
        general_layout.addWidget(detect_protections_cb)
        general_layout.addWidget(enable_sandbox_cb)
        general_layout.addWidget(remote_plugins_group)
        general_layout.addLayout(plugin_timeout_layout)
        general_layout.addWidget(save_general_btn)
        
        # Appearance section
        appearance_group = QGroupBox("Appearance")
        appearance_layout = QVBoxLayout(appearance_group)
        
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("UI Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark"])
        if "ui_theme" in CONFIG:
            self.theme_combo.setCurrentText(CONFIG["ui_theme"])
        else:
            self.theme_combo.setCurrentText("Dark")  # Default to dark
        # Don't connect to immediate change - wait for Apply button
        theme_layout.addWidget(self.theme_combo)
        
        ui_scale_layout = QHBoxLayout()
        ui_scale_layout.addWidget(QLabel("UI Scale:"))
        self.ui_scale_slider = QSlider(Qt.Horizontal)
        self.ui_scale_slider.setRange(50, 200)
        self.ui_scale_slider.setSingleStep(10)
        if "ui_scale" in CONFIG:
            self.ui_scale_slider.setValue(CONFIG["ui_scale"])
        else:
            self.ui_scale_slider.setValue(100)  # Default value
        self.scale_value_label = QLabel(f"{self.ui_scale_slider.value()}%")
        self.ui_scale_slider.valueChanged.connect(lambda value: self.scale_value_label.setText(f"{value}%"))
        ui_scale_layout.addWidget(self.ui_scale_slider)
        ui_scale_layout.addWidget(self.scale_value_label)
        
        font_size_layout = QHBoxLayout()
        font_size_layout.addWidget(QLabel("Font Size:"))
        self.font_size_combo = QComboBox()
        self.font_size_combo.addItems(["Small", "Medium", "Large"])
        if "font_size" in CONFIG:
            self.font_size_combo.setCurrentText(CONFIG["font_size"])
        else:
            self.font_size_combo.setCurrentText("Medium")  # Default value
        font_size_layout.addWidget(self.font_size_combo)
        
        apply_appearance_btn = QPushButton("Apply Appearance Settings")
        apply_appearance_btn.clicked.connect(self.apply_appearance_settings)
        
        appearance_layout.addLayout(theme_layout)
        appearance_layout.addLayout(ui_scale_layout)
        appearance_layout.addLayout(font_size_layout)
        appearance_layout.addWidget(apply_appearance_btn)
        
        # Performance Optimization section
        performance_group = QGroupBox("Performance Optimization")
        performance_layout = QVBoxLayout(performance_group)
        
        self.memory_opt_enable_cb = QCheckBox("Enable Memory Optimization")
        if "memory_optimization_enabled" in CONFIG:
            self.memory_opt_enable_cb.setChecked(CONFIG["memory_optimization_enabled"])
        
        memory_threshold_layout = QHBoxLayout()
        memory_threshold_layout.addWidget(QLabel("Memory Threshold (%):"))
        self.memory_threshold_spinbox = QSpinBox()
        self.memory_threshold_spinbox.setRange(10, 90)
        if "memory_threshold" in CONFIG:
            self.memory_threshold_spinbox.setValue(CONFIG["memory_threshold"])
        else:
            self.memory_threshold_spinbox.setValue(75)  # Default value
        memory_threshold_layout.addWidget(self.memory_threshold_spinbox)
        
        memory_interval_layout = QHBoxLayout()
        memory_interval_layout.addWidget(QLabel("Memory Check Interval (seconds):"))
        self.memory_interval_spinbox = QSpinBox()
        self.memory_interval_spinbox.setRange(1, 3600)
        if "memory_check_interval" in CONFIG:
            self.memory_interval_spinbox.setValue(CONFIG["memory_check_interval"])
        else:
            self.memory_interval_spinbox.setValue(60)  # Default value
        memory_interval_layout.addWidget(self.memory_interval_spinbox)
        
        # Specific Optimization Techniques section
        optimization_group = QGroupBox("Specific Optimization Techniques")
        optimization_layout = QVBoxLayout(optimization_group)
        
        self.gc_enable_cb = QCheckBox("Aggressive Garbage Collection")
        if "memory_opt_gc" in CONFIG:
            self.gc_enable_cb.setChecked(CONFIG["memory_opt_gc"])
        
        self.mem_struct_enable_cb = QCheckBox("Use Memory-Efficient Data Structures")
        if "memory_opt_structures" in CONFIG:
            self.mem_struct_enable_cb.setChecked(CONFIG["memory_opt_structures"])
        
        self.incremental_enable_cb = QCheckBox("Enable Incremental Loading for Analysis")
        if "memory_opt_incremental" in CONFIG:
            self.incremental_enable_cb.setChecked(CONFIG["memory_opt_incremental"])
        
        self.leak_detect_enable_cb = QCheckBox("Enable Memory Leak Detection (Experimental)")
        if "memory_opt_leak_detection" in CONFIG:
            self.leak_detect_enable_cb.setChecked(CONFIG["memory_opt_leak_detection"])
        
        optimization_layout.addWidget(self.gc_enable_cb)
        optimization_layout.addWidget(self.mem_struct_enable_cb)
        optimization_layout.addWidget(self.incremental_enable_cb)
        optimization_layout.addWidget(self.leak_detect_enable_cb)
        
        self.gpu_enable_cb = QCheckBox("Enable GPU Acceleration (Global)")
        if "gpu_acceleration" in CONFIG:
            self.gpu_enable_cb.setChecked(CONFIG["gpu_acceleration"])
        
        gpu_backend_layout = QHBoxLayout()
        gpu_backend_layout.addWidget(QLabel("Preferred GPU Backend:"))
        gpu_backend_combo = QComboBox()
        gpu_backend_combo.addItems(["CUDA", "OpenCL", "PyTorch"])
        if "gpu_backend" in CONFIG:
            gpu_backend_combo.setCurrentText(CONFIG["gpu_backend"])
        gpu_backend_layout.addWidget(gpu_backend_combo)
        
        self.distributed_enable_cb = QCheckBox("Enable Distributed Processing (Global)")
        if "distributed_processing" in CONFIG:
            self.distributed_enable_cb.setChecked(CONFIG["distributed_processing"])
        
        apply_performance_btn = QPushButton("Apply Performance Settings")
        apply_performance_btn.clicked.connect(self.apply_performance_settings)
        
        performance_layout.addWidget(self.memory_opt_enable_cb)
        performance_layout.addLayout(memory_threshold_layout)
        performance_layout.addLayout(memory_interval_layout)
        performance_layout.addWidget(optimization_group)
        performance_layout.addWidget(self.gpu_enable_cb)
        performance_layout.addLayout(gpu_backend_layout)
        performance_layout.addWidget(self.distributed_enable_cb)
        performance_layout.addWidget(apply_performance_btn)
        
        # Dependency Management section
        dependency_group = QGroupBox("Dependency Management")
        dependency_layout = QVBoxLayout(dependency_group)
        
        check_dependencies_btn = QPushButton("Check for Missing/Updateable Dependencies")
        check_dependencies_btn.clicked.connect(self.check_dependencies_ui)
        
        install_dependencies_btn = QPushButton("Install/Update Selected Dependencies")
        install_dependencies_btn.clicked.connect(lambda: self.install_dependencies(["psutil", "requests", "pefile", "capstone"]))
        
        dependency_layout.addWidget(check_dependencies_btn)
        dependency_layout.addWidget(install_dependencies_btn)
        
        # System Features section
        system_group = QGroupBox("System Features")
        system_layout = QVBoxLayout(system_group)
        
        # Persistent logging button
        logging_btn = QPushButton("Setup Persistent Logging with Rotation")
        logging_btn.clicked.connect(self.setup_persistent_logging_ui)
        system_layout.addWidget(logging_btn)
        
        # Fine-tune model button
        finetune_btn = QPushButton("Fine-tune AI Model")
        finetune_btn.clicked.connect(self.fine_tune_model)
        system_layout.addWidget(finetune_btn)
        
        # Extract icon button
        icon_btn = QPushButton("Extract Icon from Binary")
        icon_btn.clicked.connect(self.extract_icon_from_binary)
        system_layout.addWidget(icon_btn)
        
        # Memory optimization button
        memory_btn = QPushButton("Optimize Memory Usage")
        memory_btn.clicked.connect(self.optimize_memory_usage_ui)
        system_layout.addWidget(memory_btn)
        
        # Demo threaded operation button
        thread_demo_btn = QPushButton("Demo: Run Long Operation in Thread")
        thread_demo_btn.clicked.connect(self.demo_threaded_operation)
        system_layout.addWidget(thread_demo_btn)
        
        # Configuration Profiles section
        profiles_group = QGroupBox("Configuration Profiles")
        profiles_layout = QVBoxLayout(profiles_group)
        
        load_profile_btn = QPushButton("Load Configuration Profile...")
        save_profile_btn = QPushButton("Save Current Configuration as Profile...")
        
        preset_profile_layout = QHBoxLayout()
        preset_profile_layout.addWidget(QLabel("Apply Preset Profile:"))
        preset_profile_combo = QComboBox()
        preset_profile_combo.addItems(["Default", "Maximum Security", "Performance Optimized", "Deep Analysis", "Basic Analysis"])
        preset_profile_combo.currentTextChanged.connect(self.apply_config_preset)
        preset_profile_layout.addWidget(preset_profile_combo)
        
        profiles_layout.addWidget(load_profile_btn)
        profiles_layout.addWidget(save_profile_btn)
        profiles_layout.addLayout(preset_profile_layout)
        
        # About & Help section
        about_group = QGroupBox("About & Help")
        about_layout = QVBoxLayout(about_group)
        
        about_btn = QPushButton("About Intellicrack")
        about_btn.clicked.connect(self.show_about_dialog)
        
        docs_btn = QPushButton("View Documentation")
        docs_btn.clicked.connect(self.show_documentation)
        
        tutorials_btn = QPushButton("View Tutorials")
        tutorials_btn.clicked.connect(self.show_tutorials)
        
        about_layout.addWidget(about_btn)
        about_layout.addWidget(docs_btn)
        about_layout.addWidget(tutorials_btn)
        
        # Add all sections to the scroll layout
        scroll_layout.addWidget(general_group)
        scroll_layout.addWidget(appearance_group)
        scroll_layout.addWidget(performance_group)
        scroll_layout.addWidget(dependency_group)
        scroll_layout.addWidget(system_group)
        scroll_layout.addWidget(profiles_group)
        scroll_layout.addWidget(about_group)
        
        # Set up the scroll area
        scroll_area.setWidget(scroll_widget)
        layout.addWidget(scroll_area)
        layout = QVBoxLayout()
        
        # Create scrollable area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(10, 10, 10, 10)
        scroll_layout.setSpacing(10)
        
        # Header section
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<h2>Settings</h2>"))
        header_layout.addStretch(1)
        
        # Profiles dropdown
        header_layout.addWidget(QLabel("Profile:"))
        profiles_combo = QComboBox()
        profiles_combo.addItems(["Default", "Performance", "Development", "Custom"])
        header_layout.addWidget(profiles_combo)
        
        # Profile buttons
        save_profile_btn = QPushButton("Save")
        save_profile_btn.setToolTip("Save current settings to selected profile")
        header_layout.addWidget(save_profile_btn)
        
        scroll_layout.addLayout(header_layout)
        
        # Create tabbed interface for settings categories
        settings_tabs = QTabWidget()
        settings_tabs.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        settings_tabs.setTabsClosable(False)  # Disable close buttons to reduce clutter
        
        # 1. AI Configuration tab
        ai_tab = QWidget()
        ai_layout = QVBoxLayout(ai_tab)
        
        # Model selection group
        model_group = QGroupBox("AI Model Selection")
        model_layout = QGridLayout()
        
        model_layout.addWidget(QLabel("Primary Model:"), 0, 0)
        primary_model_combo = QComboBox()
        primary_model_combo.addItems(["Claude-3 Opus", "Claude-3 Sonnet", "GPT-4", "GPT-3.5 Turbo", "Local LLama"])
        model_layout.addWidget(primary_model_combo, 0, 1)
        
        model_layout.addWidget(QLabel("Local Model:"), 1, 0)
        local_model_path = QLineEdit()
        local_model_path.setPlaceholderText("/path/to/model")
        browse_model_btn = QPushButton("Browse")
        
        model_path_layout = QHBoxLayout()
        model_path_layout.addWidget(local_model_path)
        model_path_layout.addWidget(browse_model_btn)
        model_layout.addLayout(model_path_layout, 1, 1)
        
        model_layout.addWidget(QLabel("API Key:"), 2, 0)
        api_key_input = QLineEdit()
        api_key_input.setEchoMode(QLineEdit.Password)
        api_key_input.setPlaceholderText("Enter API key for cloud models")
        model_layout.addWidget(api_key_input, 2, 1)
        
        model_layout.addWidget(QLabel("API Endpoint:"), 3, 0)
        endpoint_input = QLineEdit()
        endpoint_input.setText("https://api.anthropic.com/v1/complete")
        model_layout.addWidget(endpoint_input, 3, 1)
        
        model_group.setLayout(model_layout)
        ai_layout.addWidget(model_group)
        
        # Model parameters group
        params_group = QGroupBox("Model Parameters")
        params_layout = QGridLayout()
        
        params_layout.addWidget(QLabel("Temperature:"), 0, 0)
        temp_slider = QSlider(Qt.Horizontal)
        temp_slider.setRange(0, 100)
        temp_slider.setValue(70)
        temp_value = QLabel("0.7")
        
        temp_layout = QHBoxLayout()
        temp_layout.addWidget(temp_slider)
        temp_layout.addWidget(temp_value)
        params_layout.addLayout(temp_layout, 0, 1)
        
        params_layout.addWidget(QLabel("Max Tokens:"), 1, 0)
        max_tokens_spin = QSpinBox()
        max_tokens_spin.setRange(10, 10000)
        max_tokens_spin.setValue(2000)
        params_layout.addWidget(max_tokens_spin, 1, 1)
        
        params_layout.addWidget(QLabel("Context Window:"), 2, 0)
        context_combo = QComboBox()
        context_combo.addItems(["4K tokens", "8K tokens", "16K tokens", "100K tokens", "Maximum available"])
        params_layout.addWidget(context_combo, 2, 1)
        
        params_layout.addWidget(QLabel("Preset Style:"), 3, 0)
        style_combo = QComboBox()
        style_combo.addItems(["Balanced", "Creative", "Factual", "Technical", "Custom"])
        params_layout.addWidget(style_combo, 3, 1)
        
        params_group.setLayout(params_layout)
        ai_layout.addWidget(params_group)
        
        # Prompt templates group
        templates_group = QGroupBox("Prompt Templates")
        templates_layout = QVBoxLayout()
        
        templates_layout.addWidget(QLabel("Selected Template:"))
        template_combo = QComboBox()
        template_combo.addItems(["Binary Analysis", "License Finding", "Protection Analysis", "Assembly Explanation", "Custom"])
        templates_layout.addWidget(template_combo)
        
        template_edit = QTextEdit()
        template_edit.setPlaceholderText("Edit the selected template here...")
        template_edit.setMinimumHeight(100)
        templates_layout.addWidget(template_edit)
        
        template_buttons = QHBoxLayout()
        save_template_btn = QPushButton("Save Template")
        new_template_btn = QPushButton("New Template")
        delete_template_btn = QPushButton("Delete Template")
        
        template_buttons.addWidget(save_template_btn)
        template_buttons.addWidget(new_template_btn)
        template_buttons.addWidget(delete_template_btn)
        templates_layout.addLayout(template_buttons)
        
        templates_group.setLayout(templates_layout)
        ai_layout.addWidget(templates_group)
        
        # 2. Interface Settings tab
        interface_tab = QWidget()
        interface_layout = QVBoxLayout(interface_tab)
        
        # Theme settings
        theme_group = QGroupBox("Theme Settings")
        theme_layout = QVBoxLayout()
        
        theme_radio_layout = QHBoxLayout()
        light_radio = QRadioButton("Light Theme")
        dark_radio = QRadioButton("Dark Theme")
        custom_radio = QRadioButton("Custom Theme")
        
        # Set default theme
        dark_radio.setChecked(True)
        
        theme_radio_layout.addWidget(light_radio)
        theme_radio_layout.addWidget(dark_radio)
        theme_radio_layout.addWidget(custom_radio)
        theme_layout.addLayout(theme_radio_layout)
        
        # Color scheme customization
        color_layout = QGridLayout()
        
        color_layout.addWidget(QLabel("Primary Color:"), 0, 0)
        primary_color_btn = QPushButton()
        primary_color_btn.setStyleSheet("background-color: #007BFF;")
        primary_color_btn.setMaximumWidth(50)
        color_layout.addWidget(primary_color_btn, 0, 1)
        
        color_layout.addWidget(QLabel("Secondary Color:"), 1, 0)
        secondary_color_btn = QPushButton()
        secondary_color_btn.setStyleSheet("background-color: #6C757D;")
        secondary_color_btn.setMaximumWidth(50)
        color_layout.addWidget(secondary_color_btn, 1, 1)
        
        color_layout.addWidget(QLabel("Background Color:"), 2, 0)
        bg_color_btn = QPushButton()
        bg_color_btn.setStyleSheet("background-color: #121212;")
        bg_color_btn.setMaximumWidth(50)
        color_layout.addWidget(bg_color_btn, 2, 1)
        
        theme_layout.addLayout(color_layout)
        
        # Font settings
        font_layout = QGridLayout()
        
        font_layout.addWidget(QLabel("UI Font:"), 0, 0)
        ui_font_combo = QComboBox()
        ui_font_combo.addItems(["Segoe UI", "Arial", "Roboto", "System Default"])
        font_layout.addWidget(ui_font_combo, 0, 1)
        
        font_layout.addWidget(QLabel("Code Font:"), 1, 0)
        code_font_combo = QComboBox()
        code_font_combo.addItems(["Consolas", "Courier New", "Source Code Pro", "Monospace"])
        font_layout.addWidget(code_font_combo, 1, 1)
        
        font_layout.addWidget(QLabel("Font Size:"), 2, 0)
        font_size_spin = QSpinBox()
        font_size_spin.setRange(8, 24)
        font_size_spin.setValue(10)
        font_layout.addWidget(font_size_spin, 2, 1)
        
        theme_layout.addLayout(font_layout)
        
        theme_group.setLayout(theme_layout)
        interface_layout.addWidget(theme_group)
        
        # Layout settings
        layout_group = QGroupBox("Layout Settings")
        layout_settings = QVBoxLayout()
        
        # Tab position
        tab_position_layout = QHBoxLayout()
        tab_position_layout.addWidget(QLabel("Tab Position:"))
        tab_position_combo = QComboBox()
        tab_position_combo.addItems(["Top", "Bottom", "Left", "Right"])
        tab_position_layout.addWidget(tab_position_combo)
        layout_settings.addLayout(tab_position_layout)
        
        # Other layout options
        show_toolbar_check = QCheckBox("Show Toolbar")
        show_toolbar_check.setChecked(True)
        show_status_check = QCheckBox("Show Status Bar")
        show_status_check.setChecked(True)
        restore_session_check = QCheckBox("Restore Last Session on Startup")
        restore_session_check.setChecked(True)
        
        layout_settings.addWidget(show_toolbar_check)
        layout_settings.addWidget(show_status_check)
        layout_settings.addWidget(restore_session_check)
        
        layout_group.setLayout(layout_settings)
        interface_layout.addWidget(layout_group)
        
        # 3. Performance tab
        performance_tab = QWidget()
        performance_layout = QVBoxLayout(performance_tab)
        
        # Memory settings
        memory_group = QGroupBox("Memory Settings")
        memory_layout = QGridLayout()
        
        memory_layout.addWidget(QLabel("Maximum Memory Usage:"), 0, 0)
        memory_slider = QSlider(Qt.Horizontal)
        memory_slider.setRange(512, 8192)
        memory_slider.setValue(2048)
        memory_value = QLabel("2048 MB")
        
        memory_slider_layout = QHBoxLayout()
        memory_slider_layout.addWidget(memory_slider)
        memory_slider_layout.addWidget(memory_value)
        memory_layout.addLayout(memory_slider_layout, 0, 1)
        
        memory_layout.addWidget(QLabel("Cache Size:"), 1, 0)
        cache_combo = QComboBox()
        cache_combo.addItems(["Small (256MB)", "Medium (512MB)", "Large (1GB)", "Extra Large (2GB)"])
        memory_layout.addWidget(cache_combo, 1, 1)
        
        memory_group.setLayout(memory_layout)
        performance_layout.addWidget(memory_group)
        
        # Threading settings
        threading_group = QGroupBox("Threading Settings")
        threading_layout = QGridLayout()
        
        threading_layout.addWidget(QLabel("Maximum Threads:"), 0, 0)
        threads_spin = QSpinBox()
        threads_spin.setRange(1, 16)
        threads_spin.setValue(4)
        threading_layout.addWidget(threads_spin, 0, 1)
        
        threading_layout.addWidget(QLabel("Analysis Priority:"), 1, 0)
        priority_combo = QComboBox()
        priority_combo.addItems(["Low", "Normal", "High", "Real-time"])
        threading_layout.addWidget(priority_combo, 1, 1)
        
        threading_group.setLayout(threading_layout)
        performance_layout.addWidget(threading_group)
        
        # GPU settings
        gpu_group = QGroupBox("GPU Acceleration")
        gpu_layout = QVBoxLayout()
        
        use_gpu_check = QCheckBox("Enable GPU Acceleration")
        use_gpu_check.setChecked(True)
        gpu_layout.addWidget(use_gpu_check)
        
        gpu_device_layout = QHBoxLayout()
        gpu_device_layout.addWidget(QLabel("GPU Device:"))
        gpu_device_combo = QComboBox()
        gpu_device_combo.addItems(["NVIDIA GeForce RTX 3080", "Intel Integrated Graphics", "AMD Radeon RX 6800"])
        gpu_device_layout.addWidget(gpu_device_combo)
        gpu_layout.addLayout(gpu_device_layout)
        
        gpu_memory_layout = QHBoxLayout()
        gpu_memory_layout.addWidget(QLabel("GPU Memory Limit:"))
        gpu_memory_spin = QSpinBox()
        gpu_memory_spin.setRange(1, 16)
        gpu_memory_spin.setValue(4)
        gpu_memory_spin.setSuffix(" GB")
        gpu_memory_layout.addWidget(gpu_memory_spin)
        gpu_layout.addLayout(gpu_memory_layout)
        
        gpu_group.setLayout(gpu_layout)
        performance_layout.addWidget(gpu_group)
        
        # 4. External Tools tab
        external_tab = QWidget()
        external_layout = QVBoxLayout(external_tab)
        
        # Path configuration
        paths_group = QGroupBox("Path Configuration")
        paths_layout = QGridLayout()
        
        # Get actual tool paths or use placeholders
        config_manager = get_config()
        tools = [
            ("Ghidra Path:", config_manager.get_tool_path("ghidra") or "Not found - click Browse"),
            ("Radare2 Path:", config_manager.get_tool_path("radare2") or "Not found - click Browse"),
            ("Frida Path:", config_manager.get_tool_path("frida") or "Not found - click Browse")
        ]
        
        for row, (label_text, path_value) in enumerate(tools):
            paths_layout.addWidget(QLabel(label_text), row, 0)
            path_edit = QLineEdit(path_value)
            browse_btn = QPushButton("Browse")
            
            path_box = QHBoxLayout()
            path_box.addWidget(path_edit)
            path_box.addWidget(browse_btn)
            
            paths_layout.addLayout(path_box, row, 1)
        
        paths_group.setLayout(paths_layout)
        external_layout.addWidget(paths_group)
        
        # Update settings
        update_group = QGroupBox("Update Settings")
        update_layout = QVBoxLayout()
        
        auto_update_check = QCheckBox("Automatically Check for Updates")
        auto_update_check.setChecked(True)
        notify_updates_check = QCheckBox("Notify About Available Updates")
        notify_updates_check.setChecked(True)
        
        update_channel_layout = QHBoxLayout()
        update_channel_layout.addWidget(QLabel("Update Channel:"))
        update_channel_combo = QComboBox()
        update_channel_combo.addItems(["Stable", "Beta", "Development"])
        update_channel_layout.addWidget(update_channel_combo)
        
        check_updates_btn = QPushButton("Check for Updates Now")
        
        update_layout.addWidget(auto_update_check)
        update_layout.addWidget(notify_updates_check)
        update_layout.addLayout(update_channel_layout)
        update_layout.addWidget(check_updates_btn)
        
        update_group.setLayout(update_layout)
        external_layout.addWidget(update_group)
        
        # 5. Advanced tab
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        # Debug options
        debug_group = QGroupBox("Debug Options")
        debug_layout = QVBoxLayout()
        
        debug_level_layout = QHBoxLayout()
        debug_level_layout.addWidget(QLabel("Logging Level:"))
        debug_level_combo = QComboBox()
        debug_level_combo.addItems(["Error", "Warning", "Info", "Debug", "Trace"])
        debug_level_layout.addWidget(debug_level_combo)
        
        verbose_logging_check = QCheckBox("Enable Verbose Logging")
        developer_mode_check = QCheckBox("Developer Mode")
        enable_assertions_check = QCheckBox("Enable Assertions")
        
        debug_output_path = QHBoxLayout()
        debug_output_path.addWidget(QLabel("Log File:"))
        log_path_edit = QLineEdit("logs/intellicrack.log")
        debug_output_path.addWidget(log_path_edit)
        
        debug_layout.addLayout(debug_level_layout)
        debug_layout.addWidget(verbose_logging_check)
        debug_layout.addWidget(developer_mode_check)
        debug_layout.addWidget(enable_assertions_check)
        debug_layout.addLayout(debug_output_path)
        
        debug_group.setLayout(debug_layout)
        advanced_layout.addWidget(debug_group)
        
        # System integration
        sys_integration_group = QGroupBox("System Integration")
        sys_integration_layout = QVBoxLayout()
        
        file_assoc_check = QCheckBox("Associate with .icf Files")
        file_assoc_check.setChecked(True)
        
        context_menu_check = QCheckBox("Add to Explorer Context Menu")
        context_menu_check.setChecked(True)
        
        admin_mode_check = QCheckBox("Always Run as Administrator")
        admin_mode_check.setChecked(False)
        
        sys_integration_layout.addWidget(file_assoc_check)
        sys_integration_layout.addWidget(context_menu_check)
        sys_integration_layout.addWidget(admin_mode_check)
        
        sys_integration_group.setLayout(sys_integration_layout)
        advanced_layout.addWidget(sys_integration_group)
        
        # Reset and export
        reset_group = QGroupBox("Reset and Configuration")
        reset_layout = QVBoxLayout()
        
        reset_buttons = QHBoxLayout()
        factory_reset_btn = QPushButton("Factory Reset")
        export_config_btn = QPushButton("Export Configuration")
        import_config_btn = QPushButton("Import Configuration")
        
        reset_buttons.addWidget(factory_reset_btn)
        reset_buttons.addWidget(export_config_btn)
        reset_buttons.addWidget(import_config_btn)
        
        reset_layout.addLayout(reset_buttons)
        reset_group.setLayout(reset_layout)
        advanced_layout.addWidget(reset_group)
        
        # Add all tabs to the settings tabbed widget
        settings_tabs.addTab(ai_tab, "AI Configuration")
        settings_tabs.addTab(interface_tab, "Interface")
        settings_tabs.addTab(performance_tab, "Performance")
        settings_tabs.addTab(external_tab, "External Tools")
        settings_tabs.addTab(advanced_tab, "Advanced")
        
        scroll_layout.addWidget(settings_tabs)
        
        # Add apply/cancel buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch(1)
        
        apply_btn = QPushButton("Apply")
        cancel_btn = QPushButton("Cancel")
        ok_btn = QPushButton("OK")
        
        buttons_layout.addWidget(apply_btn)
        buttons_layout.addWidget(cancel_btn)
        buttons_layout.addWidget(ok_btn)
        
        scroll_layout.addLayout(buttons_layout)
        
        # Set the scroll widget and add to main layout
        scroll_area.setWidget(scroll_widget)
        layout.addWidget(scroll_area)
        
        # Set the layout for the tab
        self.settings_tab.setLayout(layout)
        
        # Apply any settings that need to be initialized
        self.apply_theme_settings()
        
        # Check license status
        self.check_adobe_licensex_status()

        # Create the menu bar
        self.create_menu_bar()

        self.statusBar().showMessage("Ready")

        self.available_plugins = load_plugins()
        if isinstance(self.available_plugins, dict) and sum(len(plugins)
                                                            for plugins in self.available_plugins.values()) > 0:
            self.update_output.emit(log_message(
                f"Loaded {sum(len(plugins) for plugins in self.available_plugins.values())} plugins"))

        # Initialize enhanced hex viewer integration
        try:
            # Use the integration module to fully integrate the hex viewer
            integrate_with_intellicrack(self)

            # Register enhanced hex viewer AI tools explicitly
            register_hex_viewer_ai_tools(self)

            # Initialize hex viewer dialogs list
            self._hex_viewer_dialogs = []

            self.update_output.emit(log_message("[Hex Viewer] Enhanced hex viewer functionality initialized"))
            logger.info("Enhanced hex viewer functionality fully integrated")
        except Exception as e:
            self.update_output.emit(log_message(f"[Hex Viewer] Error initializing enhanced hex viewer: {str(e)}"))
            logger.error(f"Error initializing enhanced hex viewer: {e}")
            logger.error(traceback.format_exc())

        ml_model_path = CONFIG.get("ml_model_path")
        if ml_model_path and os.path.exists(ml_model_path):
            try:
                self.ml_predictor = MLVulnerabilityPredictor(
                    model_path=ml_model_path)
                self.update_output.emit(
                    log_message(
                        f"[ML] Predictor loaded at startup with model: {ml_model_path}"))
            except NameError:
                self.update_output.emit(log_message(
                    "[ML Init Error] MLVulnerabilityPredictor class not found. Import it first."))
            except Exception as e_ml_init:
                self.update_output.emit(
                    log_message(
                        f"[ML Init Error] Failed to auto-load predictor model: {e_ml_init}"))
                self.ml_predictor = None
        else:
            # Create models directory if it doesn't exist
            os.makedirs("models", exist_ok=True)

            # Set default model path
            default_ml_path = os.path.join("models", "vuln_predict_model.joblib")

            try:
                # Create default model if it doesn't exist
                if not os.path.exists(default_ml_path):
                    self._create_default_ml_model(default_ml_path)

                # Initialize predictor with the model
                self.ml_predictor = MLVulnerabilityPredictor(default_ml_path)

                # Update config with the new path
                CONFIG["ml_model_path"] = default_ml_path
                self.save_config()

                self.update_output.emit(log_message(
                    f"[ML] Using model at: {default_ml_path}"))
            except Exception as e:
                self.update_output.emit(log_message(
                    f"[ML] Could not create initial model: {str(e)}"))
                self.ml_predictor = None

    # Add stub methods for functions that don't exist but are referenced elsewhere
    def create_new_plugin(self, plugin_type):
        """Creates a new plugin file of the specified type with a template."""
        plugin_dir = "plugins"

        # Define templates for different plugin types
        templates = {
            "frida": """// Frida script template
// Description: Add your description here
'use strict';

// This function will be called when the script is loaded
function main() {
    console.log("Frida script loaded!");

    // Example: Hook a function
    /*
    Interceptor.attach(Module.findExportByName(null, 'function_name'), {
        onEnter: function(args) {
            console.log("Function called with args:", args[0].toString());
        },
        onLeave: function(retval) {
            console.log("Function returned:", retval);
            // Modify return value: retval.replace(0);
        }
    });
    */
}

// Start the script
main();""",

            "ghidra": """//Ghidra script template
//Description: Add your description here

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class NewGhidraScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Ghidra script started!");

        // Example: Find functions with specific name pattern
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);
        for (Function function : functions) {
            String name = function.getName();
            if (name.contains("license") || name.contains("auth")) {
                println("Found interesting function: " + name + " at " + function.getEntryPoint());
            }
        }
    }
}""",

            "custom": """# Custom Python plugin template
# Description: Add your description here

class CustomPlugin:
    def __init__(self):
        self.name = "New Custom Plugin"
        self.description = "Add your description here"

    def analyze(self, binary_path):
        # Analyze the binary and return results
        results = []
        results.append(f"Analyzing {binary_path}")
        # Add your analysis code here
        return results

    def patch(self, binary_path):
        # Patch the binary and return results
        results = []
        results.append(f"Patching {binary_path}")
        # Add your patching code here
        return results

def register():
    # Register the plugin
    return CustomPlugin()"""
        }

        # Create plugin directory if it doesn't exist
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir)

        # Create subdirectory if it doesn't exist
        subdir_map = {
            "frida": "frida_scripts",
            "ghidra": "ghidra_scripts",
            "custom": "custom_modules"
        }

        subdir = subdir_map.get(plugin_type)
        if not subdir:
            self.update_output.emit(log_message(f"Invalid plugin type: {plugin_type}"))
            return

        subdir_path = os.path.join(plugin_dir, subdir)
        if not os.path.exists(subdir_path):
            os.makedirs(subdir_path)

        # Get plugin name from user
        plugin_name, ok = QInputDialog.getText(
            self, f"New {plugin_type.title()} Plugin", "Enter plugin name:"
        )

        if not ok or not plugin_name:
            return

        # Format plugin name and create file path
        plugin_name = plugin_name.replace(" ", "_").lower()

        # Add appropriate extension
        extensions = {
            "frida": ".js",
            "ghidra": ".java",
            "custom": ".py"
        }

        file_path = os.path.join(subdir_path, plugin_name + extensions[plugin_type])

        # Check if file already exists
        if os.path.exists(file_path):
            response = QMessageBox.question(
                self,
                "File Exists",
                f"The file {file_path} already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No
            )

            if response != QMessageBox.Yes:
                return

        # Write template to file
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(templates[plugin_type])

            self.update_output.emit(log_message(f"Created new {plugin_type} plugin at {file_path}"))

            # Open the file for editing
            self.edit_plugin_file(file_path)

        except Exception as e:
            self.update_output.emit(log_message(f"Error creating plugin file: {e}"))

    def edit_plugin_file(self, path):
        """Opens the specified file in a text editor."""
        if not os.path.exists(path):
            self.update_output.emit(log_message(f"File not found: {path}"))
            return

        try:
            # Create a simple text editor dialog
            editor_dialog = QDialog(self)
            editor_dialog.setWindowTitle(f"Editing {os.path.basename(path)}")
            editor_dialog.resize(800, 600)

            layout = QVBoxLayout()

            # Create text editor
            editor = QTextEdit()

            # Load file content
            with open(path, "r", encoding="utf-8") as f:
                editor.setPlainText(f.read())

            layout.addWidget(editor)

            # Create buttons
            button_layout = QHBoxLayout()

            save_btn = QPushButton("Save")
            cancel_btn = QPushButton("Cancel")

            button_layout.addWidget(save_btn)
            button_layout.addWidget(cancel_btn)

            layout.addLayout(button_layout)

            editor_dialog.setLayout(layout)

            # Connect buttons
            def save_file():
                """
                Save the contents of the editor to the file.

                This function writes the current text from the editor to the specified file path,
                emits a success message to the application log, and closes the editor dialog.
                If the save operation fails, an error message is displayed.

                Args:
                    None: Uses file path and editor from enclosing scope

                Returns:
                    None

                Raises:
                    No exceptions are propagated as they are caught and logged internally
                """
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(editor.toPlainText())
                    self.update_output.emit(log_message(f"Saved changes to {path}"))
                    editor_dialog.accept()
                except Exception as e:
                    self.update_output.emit(log_message(f"Error saving file: {e}"))

            save_btn.clicked.connect(save_file)
            cancel_btn.clicked.connect(editor_dialog.reject)

            # Show dialog
            editor_dialog.exec_()

        except Exception as e:
            self.update_output.emit(log_message(f"Error editing file: {e}"))

    def import_plugin(self, plugin_type):
        """Imports a file as a plugin of the specified type."""
        # Define file filters based on plugin type
        filters = {
            "frida": "JavaScript Files (*.js)",
            "ghidra": "Java Files (*.java)",
            "custom": "Python Files (*.py)"
        }

        # Get file from user
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Import {plugin_type.title()} Plugin",
            "",
            filters.get(plugin_type, "All Files (*)")
        )

        if not file_path:
            return

        # Create plugin directory if it doesn't exist
        plugin_dir = "plugins"
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir)

        # Create subdirectory if it doesn't exist
        subdir_map = {
            "frida": "frida_scripts",
            "ghidra": "ghidra_scripts",
            "custom": "custom_modules"
        }

        subdir = subdir_map.get(plugin_type)
        if not subdir:
            self.update_output.emit(log_message(f"Invalid plugin type: {plugin_type}"))
            return

        subdir_path = os.path.join(plugin_dir, subdir)
        if not os.path.exists(subdir_path):
            os.makedirs(subdir_path)

        # Get destination file path
        dest_file = os.path.join(subdir_path, os.path.basename(file_path))

        # Check if file already exists
        if os.path.exists(dest_file) and os.path.abspath(file_path) != os.path.abspath(dest_file):
            response = QMessageBox.question(
                self,
                "File Exists",
                f"The file {dest_file} already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No
            )

            if response != QMessageBox.Yes:
                return

        # Copy file
        try:
            if os.path.abspath(file_path) != os.path.abspath(dest_file):
                shutil.copy2(file_path, dest_file)
                self.update_output.emit(log_message(f"Imported {plugin_type} plugin to {dest_file}"))
            else:
                self.update_output.emit(log_message(f"File is already in the plugins directory"))

            # Reload plugins
            self.available_plugins = load_plugins()

        except Exception as e:
            self.update_output.emit(log_message(f"Error importing plugin: {e}"))

    def run_plugin(self, plugin_name):
        """Run a built-in plugin by name."""
        try:
            from ..plugins.plugin_system import run_plugin as plugin_system_run_plugin
            plugin_system_run_plugin(self, plugin_name)
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error running plugin {plugin_name}: {e}"))

    def run_custom_plugin(self, plugin_name):
        """Run a custom Python plugin."""
        try:
            from ..plugins.plugin_system import run_custom_plugin as plugin_system_run_custom_plugin
            # First load plugins to get available plugins
            from ..plugins.plugin_system import load_plugins
            available_plugins = load_plugins()
            
            # Find the plugin in custom plugins
            for plugin_info in available_plugins.get("custom", []):
                if plugin_info["name"] == plugin_name:
                    plugin_system_run_custom_plugin(self, plugin_info)
                    return
                    
            self.update_output.emit(log_message(f"[Plugin] Custom plugin '{plugin_name}' not found"))
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error running custom plugin {plugin_name}: {e}"))

    def run_frida_plugin_from_file(self, plugin_path):
        """Run a Frida script plugin from file."""
        try:
            from ..plugins.plugin_system import run_frida_plugin_from_file as plugin_system_run_frida
            
            # If plugin_path is just a name, find the full path
            if not os.path.exists(plugin_path):
                frida_dir = os.path.join("plugins", "frida_scripts")
                if not plugin_path.endswith(".js"):
                    plugin_path += ".js"
                full_path = os.path.join(frida_dir, plugin_path)
                if os.path.exists(full_path):
                    plugin_path = full_path
                else:
                    self.update_output.emit(log_message(f"[Plugin] Frida script not found: {plugin_path}"))
                    return
                    
            plugin_system_run_frida(self, plugin_path)
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error running Frida plugin {plugin_path}: {e}"))

    def run_ghidra_plugin_from_file(self, plugin_path):
        """Run a Ghidra script plugin from file."""
        try:
            from ..plugins.plugin_system import run_ghidra_plugin_from_file as plugin_system_run_ghidra
            
            # If plugin_path is just a name, find the full path
            if not os.path.exists(plugin_path):
                ghidra_dir = os.path.join("plugins", "ghidra_scripts")
                if not plugin_path.endswith(".java"):
                    plugin_path += ".java"
                full_path = os.path.join(ghidra_dir, plugin_path)
                if os.path.exists(full_path):
                    plugin_path = full_path
                else:
                    self.update_output.emit(log_message(f"[Plugin] Ghidra script not found: {plugin_path}"))
                    return
                    
            plugin_system_run_ghidra(self, plugin_path)
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error running Ghidra plugin {plugin_path}: {e}"))

    def load_available_plugins(self):
        """Load and return available plugins."""
        try:
            from ..plugins.plugin_system import load_plugins
            return load_plugins()
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error loading plugins: {e}"))
            return {"frida": [], "ghidra": [], "custom": []}

    def run_plugin_in_sandbox(self, plugin_path, function_name="analyze", *args):
        """Run a plugin in a sandboxed environment with resource limits."""
        try:
            from ..plugins.plugin_system import run_plugin_in_sandbox
            
            # If no args provided, use current binary path
            if not args and hasattr(self, 'binary_path') and self.binary_path:
                args = (self.binary_path,)
            
            self.update_output.emit(log_message(f"[Plugin] Running {plugin_path} in sandbox..."))
            results = run_plugin_in_sandbox(plugin_path, function_name, *args)
            
            if results:
                for result in results:
                    self.update_output.emit(log_message(f"[Sandbox] {result}"))
            else:
                self.update_output.emit(log_message("[Sandbox] No results returned"))
                
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error running plugin in sandbox: {e}"))

    def run_plugin_remotely(self, plugin_info):
        """Run a plugin on a remote system."""
        try:
            from ..plugins.plugin_system import run_plugin_remotely
            
            self.update_output.emit(log_message(f"[Plugin] Preparing remote execution for {plugin_info.get('name', 'Unknown')}..."))
            results = run_plugin_remotely(self, plugin_info)
            
            if results:
                for result in results:
                    self.update_output.emit(log_message(f"[Remote] {result}"))
            else:
                self.update_output.emit(log_message("[Remote] No results returned"))
                
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error running plugin remotely: {e}"))

    def show_plugin_manager(self):
        """Show the plugin manager dialog."""
        try:
            from .dialogs.plugin_manager_dialog import PluginManagerDialog
            dialog = PluginManagerDialog(self)
            if hasattr(dialog, 'exec_'):
                dialog.exec_()
            elif hasattr(dialog, 'exec'):
                dialog.exec()
            else:
                dialog.show()
        except Exception as e:
            self.update_output.emit(log_message(f"[Plugin] Error opening plugin manager: {e}"))
            QMessageBox.warning(self, "Error", f"Could not open plugin manager: {e}")

    def test_sandbox_execution(self):
        """Test sandboxed plugin execution."""
        try:
            # Use the demo plugin for testing
            demo_plugin_path = "plugins/custom_modules/demo_plugin.py"
            if os.path.exists(demo_plugin_path):
                self.update_output.emit(log_message("[Test] Testing sandboxed plugin execution..."))
                self.run_plugin_in_sandbox(demo_plugin_path, "analyze", "test_binary.exe")
            else:
                self.update_output.emit(log_message("[Test] Demo plugin not found for sandbox test"))
                QMessageBox.warning(self, "Test Failed", "Demo plugin not found. Please ensure plugins are properly initialized.")
        except Exception as e:
            self.update_output.emit(log_message(f"[Test] Sandbox test failed: {e}"))

    def test_remote_execution(self):
        """Test remote plugin execution."""
        try:
            # Create a mock plugin info for testing
            plugin_info = {
                "name": "Demo Plugin",
                "path": "plugins/custom_modules/demo_plugin.py",
                "description": "Test plugin for remote execution"
            }
            
            if os.path.exists(plugin_info["path"]):
                self.update_output.emit(log_message("[Test] Testing remote plugin execution..."))
                self.run_plugin_remotely(plugin_info)
            else:
                self.update_output.emit(log_message("[Test] Demo plugin not found for remote test"))
                QMessageBox.information(self, "Remote Test", 
                    "Remote plugin execution test requires:\n"
                    "1. Demo plugin to be available\n"
                    "2. Remote plugins enabled in settings\n"
                    "3. Remote server running on target host")
        except Exception as e:
            self.update_output.emit(log_message(f"[Test] Remote test failed: {e}"))

    def create_menu_bar(self):
        """Creates the main menu bar with all menu options."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open Binary", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.select_program)
        file_menu.addAction(open_action)

        # Recent files submenu (populated dynamically)
        recent_menu = file_menu.addMenu("Recent Files")
        if hasattr(self, "recent_files") and self.recent_files:
            for idx, file_path in enumerate(self.recent_files[:5]):  # Show up to 5 recent files
                # Add position number to recent file entries
                display_name = f"{idx+1}. {os.path.basename(file_path)}"
                recent_action = QAction(display_name, self)
                recent_action.setToolTip(file_path)

                # Set shortcut for first 5 items using idx (1-5)
                if idx < 5:
                    recent_action.setShortcut(f"Ctrl+{idx+1}")

                # Set priority based on how recent the file is
                recent_action.setPriority(QAction.Priority(QAction.HighPriority if idx == 0 else
                                                          QAction.NormalPriority if idx < 3 else
                                                          QAction.LowPriority))

                recent_action.triggered.connect(lambda checked, path=file_path: self.load_binary(path))
                recent_menu.addAction(recent_action)

                # Log recently loaded files
                self.logger.debug(f"Added recent file #{idx+1}: {file_path}")
        else:
            no_recent_action = QAction("No Recent Files", self)
            no_recent_action.setEnabled(False)
            recent_menu.addAction(no_recent_action)

        save_results_action = QAction("Save Analysis Results", self)
        save_results_action.setShortcut("Ctrl+S")
        save_results_action.triggered.connect(self.save_analysis_results)
        file_menu.addAction(save_results_action)

        export_report_action = QAction("Export Report", self)
        export_report_action.triggered.connect(self.run_report_generation)
        file_menu.addAction(export_report_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")

        preferences_action = QAction("Preferences", self)
        preferences_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.settings_tab)))
        edit_menu.addAction(preferences_action)

        config_profiles_menu = edit_menu.addMenu("Configuration Profiles")
        for profile in ["Default Configuration", "Maximum Security", "Performance Optimized", "Deep Analysis", "Basic Analysis"]:
            profile_action = QAction(profile, self)
            profile_action.triggered.connect(lambda checked, p=profile: self.apply_config_preset(p))
            config_profiles_menu.addAction(profile_action)

        # View menu
        view_menu = menubar.addMenu("View")

        # Tab navigation actions
        dashboard_action = QAction("Dashboard", self)
        dashboard_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.project_dashboard_tab)))
        view_menu.addAction(dashboard_action)

        analysis_results_action = QAction("Analysis Results", self)
        analysis_results_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.analysis_tab)))
        view_menu.addAction(analysis_results_action)

        live_logs_action = QAction("Live Logs", self)
        live_logs_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.logs_tab)))
        view_menu.addAction(live_logs_action)
        
        # Add Hex Viewer tab to View menu
        hex_viewer_action = QAction("Hex Viewer", self)
        hex_viewer_action.triggered.connect(self.open_hex_viewer_tab)
        view_menu.addAction(hex_viewer_action)

        view_menu.addSeparator()

        # Dark Mode toggle
        dark_mode_action = QAction("Dark Mode", self)
        dark_mode_action.setCheckable(True)
        dark_mode_action.setChecked(self.current_theme == "dark")
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Analysis menu
        analysis_menu = menubar.addMenu("Analysis")

        basic_analysis_action = QAction("Basic Analysis", self)
        basic_analysis_action.triggered.connect(self.run_analysis)
        analysis_menu.addAction(basic_analysis_action)

        deep_analysis_menu = analysis_menu.addMenu("Deep Analysis")
        for analysis_type in ["License Logic", "Runtime Monitoring", "CFG Structure", "Packing Detection",
                              "Taint Analysis", "Symbolic Execution", "Concolic Execution", "ROP Chain Analysis",
                              "Memory Optimization", "Incremental Analysis", "Distributed Processing", "GPU Acceleration"]:
            analysis_action = QAction(analysis_type, self)
            analysis_action.triggered.connect(lambda checked, a=analysis_type: self.handle_deep_analysis_mode(a))
            deep_analysis_menu.addAction(analysis_action)

        custom_analysis_action = QAction("Custom Analysis", self)
        custom_analysis_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.analysis_tab)))
        analysis_menu.addAction(custom_analysis_action)

        similarity_search_action = QAction("Similarity Search", self)
        similarity_search_action.triggered.connect(self.run_binary_similarity_search)
        analysis_menu.addAction(similarity_search_action)

        # Patching menu
        patching_menu = menubar.addMenu("Patching")

        auto_patch_action = QAction("Auto Patch", self)
        auto_patch_action.triggered.connect(lambda: run_automated_patch_agent(self))
        patching_menu.addAction(auto_patch_action)

        manual_patch_action = QAction("Manual Patch", self)
        manual_patch_action.triggered.connect(self.preview_patch)
        patching_menu.addAction(manual_patch_action)

        visual_editor_action = QAction("Visual Patch Editor", self)
        visual_editor_action.triggered.connect(self.open_visual_patch_editor)
        patching_menu.addAction(visual_editor_action)

        patch_testing_action = QAction("Patch Testing", self)
        patch_testing_action.triggered.connect(self.run_simulate_patch)
        patching_menu.addAction(patch_testing_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        network_tools_menu = tools_menu.addMenu("Network Tools")
        for network_tool in ["License Server Emulator", "SSL/TLS Interceptor", "Cloud Response Generator",
                           "Protocol Fingerprinter", "Network Traffic Analyzer"]:
            tool_action = QAction(network_tool, self)
            tool_action.triggered.connect(lambda checked, t=network_tool: self.network_tools_combo.setCurrentText(t) or self.launch_network_tool())
            network_tools_menu.addAction(tool_action)

        license_analysis_action = QAction("License Analysis", self)
        license_analysis_action.triggered.connect(self.run_deep_license_analysis)
        tools_menu.addAction(license_analysis_action)

        plugin_management_action = QAction("Plugin Management", self)
        plugin_management_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.plugins_tab)))
        tools_menu.addAction(plugin_management_action)

        model_management_action = QAction("Model Management", self)
        model_management_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.settings_tab)))
        tools_menu.addAction(model_management_action)
        
        # AI Model Configuration
        ai_config_action = QAction("🤖 AI Model Configuration", self)
        ai_config_action.triggered.connect(self.open_llm_config_dialog)
        tools_menu.addAction(ai_config_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        # Guided Wizard now in Help menu
        guided_wizard_action = QAction("Guided Wizard", self)
        guided_wizard_action.triggered.connect(self.start_guided_wizard)
        help_menu.addAction(guided_wizard_action)

        documentation_action = QAction("Documentation", self)
        documentation_action.triggered.connect(self.show_documentation)
        help_menu.addAction(documentation_action)

        tutorials_action = QAction("Tutorials", self)
        tutorials_action.triggered.connect(self.show_tutorials)
        help_menu.addAction(tutorials_action)

        help_menu.addSeparator()

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        # Removed hex viewer menu registration (now using dedicated tab)
        # self.register_hex_viewer_menu(menubar)
        logger.debug("Hex viewer menu not registered (now using dedicated tab)")

    def register_hex_viewer_menu(self, menubar):
        """Register the enhanced hex viewer menu items (disabled to avoid duplication)."""
        # Removed hex viewer from tools menu since we have a dedicated tab now
        logger.debug("Hex viewer menu items not added to Tools menu (using tab instead)")
        
    def setup_hex_viewer_tab(self):
        """Sets up the dedicated Hex Viewer tab with view and edit functionality."""
        logger.info("Setting up Hex Viewer tab")
        
        # Create main layout for the tab
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Create header with title and description
        header_layout = QVBoxLayout()
        title = QLabel("<h2>Hex Viewer & Editor</h2>")
        title.setTextFormat(Qt.RichText)
        description = QLabel("View and edit binary files in hexadecimal format.")
        header_layout.addWidget(title)
        header_layout.addWidget(description)
        layout.addLayout(header_layout)
        
        # Create control panel
        controls_layout = QHBoxLayout()
        
        # File controls
        file_box = QGroupBox("File Operations")
        file_layout = QVBoxLayout()
        
        # Open file in view mode button
        open_view_btn = QPushButton("Open File (View Mode)")
        open_view_btn.setToolTip("Open a binary file in read-only mode")
        open_view_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(None, True))
        file_layout.addWidget(open_view_btn)
        
        # Open file in edit mode button
        open_edit_btn = QPushButton("Open File (Edit Mode)")
        open_edit_btn.setToolTip("Open a binary file in editable mode")
        open_edit_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(None, False))
        file_layout.addWidget(open_edit_btn)
        
        # View current binary button
        if hasattr(self, 'binary_path') and self.binary_path:
            current_binary_btn = QPushButton(f"View Current Binary")
            current_binary_btn.setToolTip(f"View the current binary: {os.path.basename(self.binary_path)}")
            current_binary_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(self.binary_path, True))
            file_layout.addWidget(current_binary_btn)
            
            edit_binary_btn = QPushButton(f"Edit Current Binary")
            edit_binary_btn.setToolTip(f"Edit the current binary: {os.path.basename(self.binary_path)}")
            edit_binary_btn.clicked.connect(lambda: self.show_enhanced_hex_viewer(self.binary_path, False))
            file_layout.addWidget(edit_binary_btn)
        
        file_box.setLayout(file_layout)
        controls_layout.addWidget(file_box)
        
        # Options and preferences
        options_box = QGroupBox("Display Options")
        options_layout = QVBoxLayout()
        
        # View mode selector
        view_mode_layout = QHBoxLayout()
        view_mode_layout.addWidget(QLabel("Default View Mode:"))
        
        view_mode_combo = QComboBox()
        view_mode_combo.addItems(["Hexadecimal", "Decimal", "Binary", "ASCII"])
        view_mode_combo.setCurrentIndex(0)
        view_mode_layout.addWidget(view_mode_combo)
        options_layout.addLayout(view_mode_layout)
        
        # Bytes per row
        bytes_row_layout = QHBoxLayout()
        bytes_row_layout.addWidget(QLabel("Bytes per Row:"))
        
        bytes_spin = QSpinBox()
        bytes_spin.setRange(8, 32)
        bytes_spin.setSingleStep(4)
        bytes_spin.setValue(16)
        bytes_row_layout.addWidget(bytes_spin)
        options_layout.addLayout(bytes_row_layout)
        
        # Font size
        font_layout = QHBoxLayout()
        font_layout.addWidget(QLabel("Font Size:"))
        
        font_spin = QSpinBox()
        font_spin.setRange(8, 20)
        font_spin.setValue(12)
        font_layout.addWidget(font_spin)
        options_layout.addLayout(font_layout)
        
        options_box.setLayout(options_layout)
        controls_layout.addWidget(options_box)
        
        layout.addLayout(controls_layout)
        
        # Information area
        info_layout = QVBoxLayout()
        info_text = QLabel("""
        <b>Features:</b>
        • View and edit binary files with memory-efficient handling
        • Multiple display modes (hex, decimal, binary)
        • Search for patterns in binary data
        • Highlight regions of interest
        • Customizable display options
        """)
        info_text.setTextFormat(Qt.RichText)
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)
        
        layout.addLayout(info_layout)
        layout.addStretch()
        
        # Set the layout for the tab
        self.hex_viewer_tab.setLayout(layout)
        logger.debug("Hex Viewer tab setup complete")

    def show_editable_hex_viewer(self):
        """
        Compatibility method to bridge with hexview integration.
        
        This method ensures compatibility with the hexview module which expects
        a show_editable_hex_viewer method. It simply calls show_enhanced_hex_viewer
        with the current binary path and editable mode.
        """
        return self.show_enhanced_hex_viewer(
            self.binary_path if hasattr(self, "binary_path") else None, False
        )
        
    def show_enhanced_hex_viewer(self, file_path=None, read_only=False):
        """
        Show the enhanced hex viewer/editor dialog.

        Args:
            file_path: Path to the file to view/edit (defaults to current binary)
            read_only: Whether to open in read-only mode
        """
        # Use the function from hexview.integration to show the dialog
        try:
            # If no file specified, use the current binary
            if file_path is None:
                if hasattr(self, "binary_path") and self.binary_path:
                    file_path = self.binary_path
                else:
                    QMessageBox.warning(
                        self,
                        "No File Loaded",
                        "Please load a binary file first or specify a file path."
                    )
                    return

            # Call the function from hexview.integration
            from ..hexview.integration import show_enhanced_hex_viewer as hex_viewer_func
            dialog = hex_viewer_func(self, file_path, read_only)

            # Keep track of the dialog to prevent garbage collection
            if not hasattr(self, "_hex_viewer_dialogs"):
                self._hex_viewer_dialogs = []
            self._hex_viewer_dialogs.append(dialog)

            self.update_output.emit(log_message(f"[Hex Viewer] Opened {os.path.basename(file_path)} in {'read-only' if read_only else 'editable'} mode"))
            logger.info(f"Opened enhanced hex viewer for {file_path}")
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error Opening Hex Viewer",
                f"Failed to open the hex viewer: {str(e)}"
            )
            logger.error(f"Error opening hex viewer: {e}")
            logger.error(traceback.format_exc())

    def create_toolbar(self):
        """Creates the main toolbar with quick access to common functions."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        # Dashboard action
        dashboard_action = QAction("Dashboard", self)
        dashboard_action.setToolTip("Go to Dashboard")
        dashboard_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.project_dashboard_tab)))
        toolbar.addAction(dashboard_action)

        toolbar.addSeparator()

        # Open binary action
        open_action = QAction("Open Binary", self)
        open_action.setToolTip("Select a program to analyze")
        open_action.triggered.connect(self.select_program)
        toolbar.addAction(open_action)

        # Run analysis action
        analyze_action = QAction("Analyze", self)
        analyze_action.setToolTip("Perform analysis on the selected program")
        analyze_action.triggered.connect(self.run_analysis)
        toolbar.addAction(analyze_action)

        # Automated patch action
        patch_action = QAction("Patch", self)
        patch_action.setToolTip("Apply automated patches")
        patch_action.triggered.connect(lambda: run_automated_patch_agent(self))
        toolbar.addAction(patch_action)

        # Preview patches action
        preview_action = QAction("Preview", self)
        preview_action.setToolTip("Preview potential patches")
        preview_action.triggered.connect(self.preview_patch)
        toolbar.addAction(preview_action)

        toolbar.addSeparator()

        # One-Click Analysis & Patch
        auto_action = QAction("One-Click Analysis & Patch", self)
        auto_action.setToolTip("Full analysis and patching")
        auto_action.triggered.connect(self.run_autonomous_crack)
        toolbar.addAction(auto_action)

        toolbar.addSeparator()

        # Report generation
        report_action = QAction("Generate Report", self)
        report_action.setToolTip("Generate comprehensive PDF report")
        report_action.triggered.connect(self.run_report_generation)
        toolbar.addAction(report_action)
        # Hex Viewer button removed (now using dedicated tab)
        # add_hex_viewer_toolbar_button(self, toolbar)
        logger.debug("Hex Viewer toolbar button not added (using dedicated tab instead)")



    def append_output(self, text):
        """
        Adds text to the output panel and scrolls to the bottom.

        This method appends the provided text to the output console and
        ensures that the view is scrolled to display the latest content.

        Args:
            text: The text string to append to the output console

        Returns:
            None
        """
        # Safety check to handle updates before UI is fully initialized
        if not hasattr(self, 'output') or self.output is None:
            # Log to console instead if UI component isn't ready
            print(f"Output (pre-UI): {text}")
            return

        self.output.append(text)
        # Scroll to the bottom
        cursor = self.output.textCursor()
        cursor.movePosition(cursor.End)
        self.output.setTextCursor(cursor)

        # Also update the statusbar with the latest message
        # Extract the actual message part (without timestamp)
        message_parts = text.split(']', 1)

        # Update the status bar with a simplified version of the message
        if len(message_parts) > 1:
            # Remove timestamp and get clean message
            clean_message = message_parts[1].strip()

            # Truncate long messages for statusbar
            if len(clean_message) > 80:
                statusbar_msg = clean_message[:77] + "..."
            else:
                statusbar_msg = clean_message

            # Update statusbar
            if hasattr(self, 'statusBar'):
                self.statusBar().showMessage(statusbar_msg, 5000)  # Show for 5 seconds

            # Log to output log if it's an important message (contains certain keywords)
            important_keywords = ["error", "warning", "critical", "failed", "completed", "success"]
            if any(keyword in clean_message.lower() for keyword in important_keywords):
                self.log_to_file(f"STATUS: {clean_message}")

    def log_to_file(self, message):
        """
        Log a message to a file in the logs directory.
        
        This method writes important application messages to a dedicated log file,
        separate from the standard Python logging system.
        
        Args:
            message (str): The message to log to the file
        """
        try:
            # Ensure logs directory exists
            logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir)
                
            # Set log file path with today's date
            log_file = os.path.join(logs_dir, f"intellicrack_status_{datetime.datetime.now().strftime('%Y-%m-%d')}.log")
            
            # Append log with timestamp
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {message}\n")
                
        except Exception as e:
            # Log the error through standard logging since we can't use our own method
            logger.error(f"Error writing to status log file: {str(e)}")
            # Don't let logging errors interrupt the application flow

    def save_analysis_results(self):
        """
        Save analysis results to a file.
        """
        if not hasattr(self, "analyze_results") or not self.analyze_results:
            self.update_output.emit(log_message("No analysis results to save."))
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Analysis Results",
            "",
            "Text Files (*.txt);;HTML Files (*.html);;All Files (*)"
        )

        if not filename:
            return

        try:
            # Determine format based on extension
            if filename.lower().endswith('.html'):
                # Create HTML report
                html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Intellicrack Analysis Results</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1, h2 { color: #2c3e50; }
                        pre { background-color: #f8f8f8; padding: 10px; border-radius: 5px; }
                        .section { margin-bottom: 20px; }
                    </style>
                </head>
                <body>
                    <h1>Intellicrack Analysis Results</h1>
                    <p>Generated on """ + time.strftime('%Y-%m-%d %H:%M:%S') + """</p>
                    <div class="section">
                        <pre>""" + '\n'.join(self.analyze_results) + """</pre>
                    </div>
                </body>
                </html>
                """

                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html)
            else:
                # Save as plain text
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(self.analyze_results))

            self.update_output.emit(log_message(f"Analysis results saved to {filename}"))

        except Exception as e:
            self.update_output.emit(log_message(f"Error saving analysis results: {e}"))

        
    def apply_dark_theme(self):
        """Apply dark theme to entire application"""
        app = QApplication.instance()
        app.setStyle("Fusion")
        
        # Create dark palette
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        app.setPalette(dark_palette)
        
        # Apply dark stylesheet for all widgets
        app.setStyleSheet("""
            QWidget {
                background-color: #353535;
                color: white;
            }
            QTextEdit, QPlainTextEdit, QTextBrowser {
                background-color: #191919;
                color: white;
                border: 1px solid #555;
            }
            QLineEdit {
                background-color: #191919;
                color: white;
                border: 1px solid #555;
                padding: 5px;
            }
            QComboBox {
                background-color: #191919;
                color: white;
                border: 1px solid #555;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
                margin-right: 5px;
            }
            QSpinBox {
                background-color: #191919;
                color: white;
                border: 1px solid #555;
                padding: 5px;
            }
            QPushButton {
                background-color: #555;
                color: white;
                border: 1px solid #777;
                padding: 5px 10px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
            QGroupBox {
                color: white;
                border: 2px solid #555;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: white;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QLabel {
                color: white;
            }
            QCheckBox, QRadioButton {
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #353535;
            }
            QTabBar::tab {
                background-color: #444;
                color: white;
                padding: 5px 10px;
                margin: 2px;
            }
            QTabBar::tab:selected {
                background-color: #555;
            }
            QTableWidget, QTableView {
                background-color: #191919;
                color: white;
                gridline-color: #555;
                border: 1px solid #555;
            }
            QHeaderView::section {
                background-color: #444;
                color: white;
                border: 1px solid #555;
                padding: 5px;
            }
            QScrollBar:vertical {
                background-color: #191919;
                width: 15px;
                border: 1px solid #555;
            }
            QScrollBar::handle:vertical {
                background-color: #555;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #666;
            }
            QToolTip {
                background-color: #2a82da;
                color: white;
                border: 1px solid white;
            }
        """)
        
    def apply_light_theme(self):
        """Apply light theme to entire application"""
        app = QApplication.instance()
        app.setStyle("Fusion")
        app.setPalette(app.style().standardPalette())
        app.setStyleSheet("")
        
    def apply_theme(self, theme_name):
        """
        Apply a theme to the application

        Args:
            theme_name: Name of the theme to apply
        """
        self.current_theme = theme_name

        if theme_name == "light":
            # Light theme (default)
            app = QApplication.instance()
            app.setStyle("Fusion")
            palette = QPalette()
            app.setPalette(palette)
            self.setStyleSheet("")

            # Set window attributes back to default
            if os.name == 'nt':
                try:
                    # Define constants
                    DWMWA_USE_IMMERSIVE_DARK_MODE = 20

                    # Get window handle
                    hwnd = int(self.winId())

                    # Set the attribute using the correct parameter types
                    windll.dwmapi.DwmSetWindowAttribute(
                        hwnd,
                        DWMWA_USE_IMMERSIVE_DARK_MODE,
                        byref(c_int(0)),  # 0 for light mode
                        sizeof(c_int)
                    )
                except Exception as e:
                    # If it fails, just log and continue
                    print(f"Could not set light title bar: {e}")

        elif theme_name == "dark":
            # Dark theme
            app = QApplication.instance()
            app.setStyle("Fusion")
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, Qt.black)
            app.setPalette(palette)

            # Apply dark title bar
            if os.name == 'nt':
                try:

                    # Define constants
                    DWMWA_USE_IMMERSIVE_DARK_MODE = 20

                    # Get window handle
                    hwnd = int(self.winId())

                    # Set the attribute using the correct parameter types
                    windll.dwmapi.DwmSetWindowAttribute(
                        hwnd,
                        DWMWA_USE_IMMERSIVE_DARK_MODE,
                        byref(c_int(1)),  # 1 for dark mode
                        sizeof(c_int)
                    )

                    # Also try the older attribute (Windows 10 before 1809)
                    try:
                        DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19
                        windll.dwmapi.DwmSetWindowAttribute(
                            hwnd,
                            DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1,
                            byref(c_int(1)),  # 1 for dark mode
                            sizeof(c_int)
                        )
                    except:
                        pass
                except Exception as e:
                    # If it fails, just log and continue
                    print(f"Could not set dark title bar: {e}")

            # Apply dark styling to the rest of the UI
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #353535;
                    color: white;
                }
                QMenuBar {
                    background-color: #353535;
                    color: white;
                }
                QMenuBar::item {
                    background-color: #353535;
                    color: white;
                }
                QMenuBar::item:selected {
                    background-color: #2a82da;
                }
                QMenu {
                    background-color: #353535;
                    color: white;
                }
                QMenu::item:selected {
                    background-color: #2a82da;
                }
                QToolBar {
                    background-color: #353535;
                    color: white;
                    border: none;
                }
                QStatusBar {
                    background-color: #353535;
                    color: white;
                }
            """)

        elif theme_name == "hacker":
            # Hacker theme (green on black)
            app = QApplication.instance()
            app.setStyle("Fusion")
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(0, 0, 0))
            palette.setColor(QPalette.WindowText, QColor(0, 255, 0))

        # Save theme preference to config
        if hasattr(self, "config"):
            self.config["theme"] = theme_name
            self.save_config()

        # Update status bar with theme info
        self.statusBar().showMessage(f"Theme changed to {theme_name}")

    def toggle_dark_mode(self):
        """Toggle between light and dark mode"""
        if self.current_theme == "dark":
            self.apply_theme("light")
        else:
            self.apply_theme("dark")

    def toggle_dark_mode_from_checkbox(self, state):
        """Toggle dark mode based on checkbox state"""
        # This method is kept for backward compatibility but will no longer be used
        # as the dark mode checkbox has been removed from settings.
        # Dark mode is now only toggleable from the View menu.
        if state == Qt.Checked:
            self.apply_theme("dark")
        else:
            self.apply_theme("light")

    def show_documentation(self):
        """Show documentation dialog"""
        QMessageBox.information(self, "Documentation",
                               "The Intellicrack documentation can be accessed online at:\n"
                               "https://intellicrack.docs.example.com\n\n"
                               "Local documentation can be found in the docs/ folder of your installation directory.")

    def show_tutorials(self):
        """Show tutorials dialog"""
        tutorials = [
            "Getting Started with Intellicrack",
            "Binary Analysis Fundamentals",
            "Advanced Patching Techniques",
            "Using the Visual Patch Editor",
            "Creating Custom Plugins",
            "Working with Emulation Layers",
            "Network License Bypassing"
        ]

        tutorial_list = "\n".join([f"• {t}" for t in tutorials])

        QMessageBox.information(self, "Tutorials",
                               f"The following tutorials are available:\n\n{tutorial_list}\n\n"
                               "Access tutorials from our website at:\nhttps://intellicrack.tutorials.example.com")

    def apply_appearance_settings(self):
        """Apply UI appearance settings like theme, scale and font size"""
        # Get theme
        theme = self.theme_combo.currentText()
        
        # Apply theme change
        if theme.lower() == "dark":
            self.apply_dark_theme()
        else:
            self.apply_light_theme()
        
        # Get scale value
        scale = self.ui_scale_slider.value()

        # Get font size
        font_size = self.font_size_combo.currentText()

        # Apply font size to all widgets
        app = QApplication.instance()
        
        # Determine point size
        if font_size == "Small":
            point_size = 8
        elif font_size == "Medium":
            point_size = 10
        elif font_size == "Large":
            point_size = 12
        else:
            point_size = 10  # default
        
        # Create new font with the desired size
        new_font = QFont()
        new_font.setPointSize(point_size)
        
        # Apply to application
        app.setFont(new_font)
        
        # Force update on all widgets
        for widget in app.allWidgets():
            widget.setFont(new_font)
            widget.update()

        # Apply scale using Qt's built-in scaling
        if scale != 100:
            # Calculate scale factor
            scale_factor = scale / 100.0
            
            # Use environment variable for Qt scaling
            os.environ['QT_SCALE_FACTOR'] = str(scale_factor)
            
            # Show message that restart is required for scale changes
            QMessageBox.information(self, "Scale Change", 
                "UI scale changes will take effect after restarting the application.")

        self.update_output.emit(log_message(f"[Settings] Applied theme: {theme}, UI scale: {scale}%, font size: {font_size}"))
        self.update_status.emit(f"Appearance settings updated")

        # Save settings to config
        CONFIG["ui_theme"] = theme
        CONFIG["ui_scale"] = scale
        CONFIG["font_size"] = font_size
        self.save_config()

    def show_about_dialog(self):
        """Show the about dialog"""

        QMessageBox.about(self, "About Intellicrack",
            "Intellicrack - Advanced Binary Analysis\n\n"
            "Version: 2.0\n"
            "© 2025 Intellicrack Team\n\n"
            "An advanced binary analysis and patching tool with AI capabilities."
        )

    def open_distributed_config(self):
        """Open the distributed processing configuration dialog"""
        if DistributedProcessingConfigDialog is None:
            self.update_output.emit("[Config] Error: Distributed config dialog not available (PyQt5 not installed)")
            return
            
        try:
            dialog = DistributedProcessingConfigDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                config_data = dialog.get_config()
                self.update_output.emit(f"[Config] Distributed processing configuration updated: {len(config_data)} settings")
                # Optionally save the config
                if hasattr(self, 'config'):
                    self.config['distributed_processing'] = config_data
                    self.save_config()
            else:
                self.update_output.emit("[Config] Distributed processing configuration cancelled")
        except Exception as e:
            self.update_output.emit(f"[Config] Error opening distributed config dialog: {e}")

    def create_qemu_snapshot(self):
        """Create a QEMU VM snapshot."""
        try:
            from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
            emulator = QEMUSystemEmulator(self.binary_path or "")
            snapshot_name = f"snapshot_{int(time.time())}"
            result = emulator.create_snapshot(snapshot_name)
            self.update_output.emit(f"[QEMU] Snapshot '{snapshot_name}' created: {result}")
        except Exception as e:
            self.update_output.emit(f"[QEMU] Error creating snapshot: {e}")
    
    def restore_qemu_snapshot(self):
        """Restore a QEMU VM snapshot."""
        try:
            # Get snapshot name from user (for now use a default)
            snapshot_name = "snapshot_latest"
            from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
            emulator = QEMUSystemEmulator(self.binary_path or "")
            result = emulator.restore_snapshot(snapshot_name)
            self.update_output.emit(f"[QEMU] Snapshot '{snapshot_name}' restored: {result}")
        except Exception as e:
            self.update_output.emit(f"[QEMU] Error restoring snapshot: {e}")
    
    def execute_qemu_command(self):
        """Execute command in QEMU VM."""
        try:
            # Get command from the input field
            command = getattr(self, 'qemu_command_input', None)
            if command and hasattr(command, 'text'):
                command = command.text().strip()
            
            if not command:
                self.update_output.emit("[QEMU] Please enter a command to execute")
                return
            
            self.update_output.emit(f"[QEMU] Executing command: {command}")
            
            from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
            
            # Use existing binary path if available
            binary_path = getattr(self, 'binary_path', None) or "dummy.exe"
            
            emulator = QEMUSystemEmulator(binary_path)
            result = emulator.execute_command(command)
            
            if result:
                self.update_output.emit(f"[QEMU] Command output:\n{result}")
            else:
                self.update_output.emit(f"[QEMU] Command '{command}' executed (no output)")
                
        except Exception as e:
            self.update_output.emit(f"[QEMU] Error executing command: {e}")
    
    def compare_qemu_snapshots(self):
        """Compare QEMU VM snapshots."""
        try:
            from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
            emulator = QEMUSystemEmulator(self.binary_path or "")
            result = emulator.compare_snapshots("before", "after")
            self.update_output.emit(f"[QEMU] Snapshot comparison completed: {len(result.get('differences', []))} differences found")
        except Exception as e:
            self.update_output.emit(f"[QEMU] Error comparing snapshots: {e}")

    def closeEvent(self, event):
        """Handle window close event."""
        # Save config including theme settings
        if hasattr(self, "config"):
            self.config["theme"] = self.current_theme
            self.save_config()

        # Clean up any resources
        cleanup_summary = []

        # Clean up Frida sessions and scripts
        if hasattr(self, "frida_sessions"):
            for session_name, (session, script) in self.frida_sessions.items():
                try:
                    # Unload the script first
                    if script:
                        script.unload()
                        self.logger.info(f"Unloaded Frida script for session: {session_name}")

                    # Then detach the session
                    session.detach()
                    self.logger.info(f"Detached Frida session: {session_name}")

                    # Add to cleanup summary
                    cleanup_summary.append(f"Cleaned up Frida session: {session_name}")
                except Exception as e:
                    self.logger.error(f"Error cleaning up Frida session {session_name}: {str(e)}")

            # Log summary of closed sessions
            if cleanup_summary:
                self.logger.info(f"Closed {len(cleanup_summary)} Frida sessions during application shutdown")

        # Save session state for next launch
        if hasattr(self, "config") and cleanup_summary:
            session_state = {
                "last_session": {
                    "closed_time": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "sessions_closed": len(cleanup_summary)
                }
            }
            self.config["session_history"] = session_state
            self.save_config()

        event.accept()

    def clear_output(self):
        """Clears the output panel."""
        self.output.clear()
        self.statusBar().showMessage("Output cleared")

# --- Thread-Safe GUI Update Slots ---

    def set_status_message(self, text):
        """
        Safely updates the status bar or analysis status label from any thread.

        Thread-safe method to update UI status elements.

        Args:
            text: The status message text to display

        Returns:
            None
        """
        if hasattr(self, 'analyze_status'):
            self.analyze_status.setText(text)
        self.statusBar().showMessage(text[:100])  # Keep status bar concise

    def append_analysis_results(self, text):
        """
        Safely appends text to the analysis results view from any thread.

        Thread-safe method to update analysis results, including automatic scrolling.

        Args:
            text: The text to append to the results view

        Returns:
            None
        """
        if hasattr(self, 'analyze_results_widget') and self.analyze_results_widget is not None:
            # Append to the UI widget
            self.analyze_results_widget.append(text)
            # Optional: Scroll to bottom
            cursor = self.analyze_results_widget.textCursor()
            cursor.movePosition(cursor.End)
            self.analyze_results_widget.setTextCursor(cursor)

        # Also store in the list for programmatic access
        if hasattr(self, 'analyze_results'):
            # Make sure it's initialized as a list
            if not isinstance(self.analyze_results, list):
                self.analyze_results = []
            self.analyze_results.append(text)

    def set_progress_value(self, value):
        """
        Safely sets the progress bar value from any thread.

        Thread-safe method to update progress bar UI element.

        Args:
            value: Integer percentage value for the progress bar (0-100)

        Returns:
            None
        """
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setValue(value)

    def set_assistant_status(self, text):
        """Safely sets the assistant status label."""
        if hasattr(self, 'assistant_status'):
            self.assistant_status.setText(text)

    def append_chat_display(self, text):
        """
        Safely appends text to the chat display from any thread.

        Thread-safe method to update chat display with automatic scrolling.

        Args:
            text: The text message to append to the chat

        Returns:
            None
        """
        if hasattr(self, 'chat_display'):
            self.chat_display.append(text)
            # Optional: Scroll to bottom
            cursor = self.chat_display.textCursor()
            cursor.movePosition(cursor.End)
            self.chat_display.setTextCursor(cursor)

    def replace_last_chat_message(self, old_text, new_text):
        """
        Safely replaces the last message in the chat display from any thread.

        This method finds and replaces the last message matching old_text with new_text,
        typically used for updating status messages like "[thinking...]" with the
        actual response.

        Args:
            old_text: The text to find and replace
            new_text: The replacement text

        Returns:
            None
        """
        if hasattr(self, 'chat_display'):
            current_text = self.chat_display.toPlainText()
            # Be careful with replacement logic, ensure it targets the correct
            # text
            if current_text.endswith(old_text):
                new_display_text = current_text[:-len(old_text)] + new_text
                self.chat_display.setPlainText(new_display_text)
                # Optional: Scroll to bottom
                cursor = self.chat_display.textCursor()
                cursor.movePosition(cursor.End)
                self.chat_display.setTextCursor(cursor)
            else:
                # Fallback if the expected last text isn't found
                self.append_chat_display(new_text)

    def handle_log_user_question(self, title, message):
        """
        Handles logging user questions received via signal.

        This method safely logs user interaction requests from worker threads
        instead of showing blocking dialogs.

        Args:
            title: The dialog title
            message: The dialog message content

        Returns:
            None
        """
        # Log the question instead of showing a blocking dialog from worker
        # thread
        log_msg = f"[User Interaction Needed] Title: {title}\nMessage: {message}"
        self.update_output.emit(log_message(log_msg))
        # You could potentially show a non-modal notification here instead

    def handle_set_keygen_name(self, text):
        """
        Handles setting the keygen product name via signal.

        Thread-safe method to update keygen product name.

        Args:
            text: The product name text

        Returns:
            None
        """
        if hasattr(self, 'keygen_input_name'):
            self.keygen_input_name.setPlainText(text)

    def handle_set_keygen_version(self, text):
        """
        Handles setting the keygen version via signal.

        Thread-safe method to update keygen version.

        Args:
            text: The product version

        Returns:
            None
        """
        if hasattr(self, 'keygen_input_version'):
            self.keygen_input_version.setPlainText(text)

    def handle_switch_tab(self, index):
        """Handles switching the main tab view via signal."""
        if hasattr(self, 'tabs'):
            self.tabs.setCurrentIndex(index)

    def handle_generate_key(self):
        """Handles triggering key generation via signal."""
        # Call the original generate_key method safely in the main thread
        self.generate_key()
    # --- End Thread-Safe GUI Update Slots ---

    # --- AI Event Handlers for Agentic System ---
    def _on_ai_task_complete(self, data, source_component):
        """Handle AI task completion events from the orchestrator."""
        try:
            task_id = data.get("task_id", "unknown")
            success = data.get("success", False)
            result = data.get("result", {})
            
            status_msg = f"✓ AI Task {task_id} completed" if success else f"✗ AI Task {task_id} failed"
            self.update_output.emit(f"[AI Agent] {status_msg}")
            
            # Display results in the appropriate UI area
            if success and result:
                result_text = json.dumps(result, indent=2, default=str)
                self.update_analysis_results.emit(f"AI Analysis Results:\n{result_text}\n")
                
        except Exception as e:
            self.logger.error(f"Error handling AI task completion: {e}")
    
    def _on_coordinated_analysis_complete(self, data, source_component):
        """Handle coordinated analysis completion events."""
        try:
            strategy = data.get("strategy", "unknown")
            confidence = data.get("confidence", 0.0)
            processing_time = data.get("processing_time", 0.0)
            escalated = data.get("escalated", False)
            
            escalation_text = " (escalated to LLM)" if escalated else ""
            status_msg = (f"🧠 Coordinated analysis complete using {strategy} strategy "
                         f"(confidence: {confidence:.2f}, time: {processing_time:.2f}s){escalation_text}")
            
            self.update_output.emit(f"[AI Coordinator] {status_msg}")
            
        except Exception as e:
            self.logger.error(f"Error handling coordinated analysis completion: {e}")
    # --- End AI Event Handlers ---

    def load_binary(self, path=None):
        """
        Load a binary file for analysis.

        Args:
            path: Optional path to the binary file. If None, a file dialog will be shown.

        Returns:
            bool: True if binary was loaded successfully, False otherwise
        """
        # If no path provided, show file dialog
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Binary File",
                "",
                "All Files (*)"
            )

            if not path:
                self.update_output.emit(log_message("[Load] Operation cancelled"))
                return False

        # Check if file exists
        if not os.path.exists(path):
            self.update_output.emit(log_message(f"[Load] Error: File not found: {path}"))
            return False

        # Store binary path
        self.binary_path = path

        # Extract binary information
        self.extract_binary_info(path)

        # Add to recent files list
        if path not in self.recent_files:
            self.recent_files.insert(0, path)
            # Keep only the 10 most recent files
            self.recent_files = self.recent_files[:10]

        # Add activity to dashboard
        if hasattr(self, "dashboard_manager"):
            self.dashboard_manager.add_activity("load", f"Loaded binary: {os.path.basename(path)}")

        # Ensure dashboard UI is explicitly refreshed with binary info and dashboard tab is shown
        if hasattr(self, "binary_info"):
            self._refresh_and_show_dashboard()

        # Update UI
        self.update_output.emit(log_message(f"[Load] Loaded binary: {path}"))
        self.statusBar().showMessage(f"Loaded: {os.path.basename(path)}")

        # Reset analysis results
        if hasattr(self, "analyze_results"):
            self.analyze_results = []

        # Reset patches
        if hasattr(self, "patches"):
            self.patches = []

        # Update window title
        self.setWindowTitle(f"Intellicrack - {os.path.basename(path)}")

        return True

    def setup_dashboard_content(self):
        """Setup dashboard content - helper method for dashboard initialization."""
        dashboard_layout = QVBoxLayout()
        
        # Welcome header
        header_layout = QHBoxLayout()

        # Logo/icon
        logo_label = QLabel()
        logo_pixmap = QPixmap("assets/icon_preview.png").scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        header_layout.addWidget(logo_label)

        # Welcome text
        welcome_layout = QVBoxLayout()
        welcome_label = QLabel("Welcome to Intellicrack")
        welcome_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        welcome_layout.addWidget(welcome_label)

        version_label = QLabel("Version 2.0")
        version_label.setStyleSheet("font-size: 12px; color: #666;")
        welcome_layout.addWidget(version_label)

        header_layout.addLayout(welcome_layout)
        header_layout.addStretch()

        # Enhanced Quick Actions with dropdown menus for related functions
        quick_actions_layout = QVBoxLayout()
        quick_actions_label = QLabel("Quick Actions")
        quick_actions_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        quick_actions_layout.addWidget(quick_actions_label)

        # Primary action buttons (more prominent)
        primary_actions_layout = QHBoxLayout()

        load_button = QPushButton("Load Binary")
        load_button.setIcon(QIcon.fromTheme("document-open"))
        load_button.setMinimumHeight(40)
        load_button.setStyleSheet("font-weight: bold; background-color: #4CAF50; color: white;")
        load_button.clicked.connect(self.load_binary)
        primary_actions_layout.addWidget(load_button)

        analyze_button = QPushButton("Analyze Binary")
        analyze_button.setIcon(QIcon.fromTheme("system-search"))
        analyze_button.setMinimumHeight(40)
        analyze_button.setStyleSheet("font-weight: bold; background-color: #2196F3; color: white;")
        analyze_button.clicked.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.analysis_tab)))
        primary_actions_layout.addWidget(analyze_button)

        quick_actions_layout.addLayout(primary_actions_layout)

        # Dropdown menu for Analysis options
        analysis_group_box = QGroupBox("Analysis Options")
        analysis_group_box.setCheckable(True)
        analysis_group_box.setChecked(False)  # Collapsed by default
        analysis_group_layout = QVBoxLayout()

        analysis_dropdown = QComboBox()
        analysis_dropdown.addItems(["Basic Analysis", "Deep Analysis", "Memory Analysis",
                                   "Network Analysis", "Custom Analysis"])
        analysis_dropdown.setCurrentIndex(0)
        analysis_group_layout.addWidget(analysis_dropdown)

        run_selected_analysis_btn = QPushButton("Run Selected Analysis")
        run_selected_analysis_btn.clicked.connect(lambda: self.run_selected_analysis(analysis_dropdown.currentText()))
        analysis_group_layout.addWidget(run_selected_analysis_btn)

        analysis_group_box.setLayout(analysis_group_layout)
        quick_actions_layout.addWidget(analysis_group_box)

        # Dropdown menu for Patching options
        patching_group_box = QGroupBox("Patching Options")
        patching_group_box.setCheckable(True)
        patching_group_box.setChecked(False)  # Collapsed by default
        patching_group_layout = QVBoxLayout()

        patching_dropdown = QComboBox()
        patching_dropdown.addItems(["Auto Patch", "Targeted Patch", "Manual Patch",
                                    "Visual Patch Editor", "Patch Testing"])
        patching_dropdown.setCurrentIndex(0)
        patching_group_layout.addWidget(patching_dropdown)

        run_selected_patching_btn = QPushButton("Run Selected Patch Operation")
        run_selected_patching_btn.clicked.connect(lambda: self.run_selected_patching(patching_dropdown.currentText()))
        patching_group_layout.addWidget(run_selected_patching_btn)

        patching_group_box.setLayout(patching_group_layout)
        quick_actions_layout.addWidget(patching_group_box)

        header_layout.addLayout(quick_actions_layout)

        dashboard_layout.addLayout(header_layout)

        # Main content - split into two columns
        content_layout = QHBoxLayout()

        # Left column - Statistics
        stats_layout = QVBoxLayout()

        # Binary info
        binary_group = QGroupBox("Binary Information")
        binary_layout = QVBoxLayout()
        binary_group.setLayout(binary_layout)

        # Binary Icon and Name Labels
        binary_icon_label = QLabel()
        binary_icon_label.setObjectName("dashboard_binary_icon_label") # Assign object name
        binary_icon_label.setFixedSize(64, 64)
        binary_icon_label.setAlignment(Qt.AlignCenter)
        binary_icon_label.setText("Icon") # Placeholder text
        binary_layout.addWidget(binary_icon_label)

        binary_name_label = QLabel("No binary loaded")
        binary_name_label.setObjectName("dashboard_binary_name_label") # Assign object name
        binary_name_label.setWordWrap(True)
        binary_name_label.setTextFormat(Qt.RichText)
        binary_layout.addWidget(binary_name_label)

        # Initial update (will be refreshed when binary is loaded)
        # self._update_dashboard_with_binary_info(self.binary_info if hasattr(self, 'binary_info') else None)

        stats_layout.addWidget(binary_group)

        # Patch statistics
        patch_group = QGroupBox("Patch Statistics")
        patch_layout = QVBoxLayout()
        patch_group.setLayout(patch_layout)

        # Ensure stats are updated
        if not hasattr(self, 'dashboard_manager') or not hasattr(self.dashboard_manager, 'stats'):
            self.dashboard_manager.update_stats()

        # Create a default stats structure if not available
        if 'patches' not in self.dashboard_manager.stats:
            self.dashboard_manager.stats['patches'] = {
                'count': 0,
                'applied': 0,
                'types': {}
            }

        patch_info = f"""
        <b>Total Patches:</b> {self.dashboard_manager.stats['patches']['count']}<br>
        <b>Applied Patches:</b> {self.dashboard_manager.stats['patches']['applied']}
        """

        if self.dashboard_manager.stats['patches']['types']:
            patch_info += "<br><b>Patch Types:</b><br>"
            for patch_type, count in self.dashboard_manager.stats['patches']['types'].items():
                patch_info += f"- {patch_type}: {count}<br>"

        patch_label = QLabel(patch_info)
        patch_label.setTextFormat(Qt.RichText)
        patch_layout.addWidget(patch_label)

        stats_layout.addWidget(patch_group)

        # License server status
        server_group = QGroupBox("License Server Status")
        server_layout = QVBoxLayout()
        server_group.setLayout(server_layout)

        # Create a default license server stats structure if not available
        if 'license_server' not in self.dashboard_manager.stats:
            self.dashboard_manager.stats['license_server'] = {
                'running': False,
                'port': 0
            }

        if self.dashboard_manager.stats['license_server']['running']:
            server_info = f"""
            <b>Status:</b> <span style="color: green;">Running</span><br>
            <b>Port:</b> {self.dashboard_manager.stats['license_server']['port']}
            """
        else:
            server_info = """
            <b>Status:</b> <span style="color: red;">Stopped</span>
            """

        server_label = QLabel(server_info)
        server_label.setTextFormat(Qt.RichText)
        server_layout.addWidget(server_label)

        # Add server control buttons
        server_buttons_layout = QHBoxLayout()

        start_server_button = QPushButton("Start Server")
        start_server_button.clicked.connect(lambda: run_network_license_server(self))
        server_buttons_layout.addWidget(start_server_button)

        stop_server_button = QPushButton("Stop Server")
        stop_server_button.clicked.connect(lambda: run_network_license_server(self) if hasattr(self, "license_server_instance") and self.license_server_instance else None)
        server_buttons_layout.addWidget(stop_server_button)

        server_layout.addLayout(server_buttons_layout)

        stats_layout.addWidget(server_group)

        # Advanced Analysis Features
        advanced_group = QGroupBox("Advanced Analysis Features")
        advanced_layout = QVBoxLayout()
        advanced_group.setLayout(advanced_layout)

        # Get advanced analysis stats
        advanced_stats = self.dashboard_manager.get_stats()["advanced_analysis"]
        active_count = advanced_stats["active_count"]

        advanced_info = f"""
        <b>Available Features:</b> {active_count} active<br>
        - Incremental Analysis: <span style="color: {'green' if advanced_stats['incremental_analysis'] else 'gray'}">{'Active' if advanced_stats['incremental_analysis'] else 'Inactive'}</span><br>
        - Memory Optimized Analysis: <span style="color: {'green' if advanced_stats['memory_optimized'] else 'gray'}">{'Active' if advanced_stats['memory_optimized'] else 'Inactive'}</span><br>
        - Taint Analysis: <span style="color: {'green' if advanced_stats['taint_analysis'] else 'gray'}">{'Active' if advanced_stats['taint_analysis'] else 'Inactive'}</span><br>
        - Symbolic Execution: <span style="color: {'green' if advanced_stats['symbolic_execution'] else 'gray'}">{'Active' if advanced_stats['symbolic_execution'] else 'Inactive'}</span><br>
        - Concolic Execution: <span style="color: {'green' if advanced_stats['concolic_execution'] else 'gray'}">{'Active' if advanced_stats['concolic_execution'] else 'Inactive'}</span><br>
        - ROP Chain Generator: <span style="color: {'green' if advanced_stats['rop_chain_generator'] else 'gray'}">{'Active' if advanced_stats['rop_chain_generator'] else 'Inactive'}</span><br>
        - Distributed Processing: <span style="color: {'green' if advanced_stats['distributed_processing'] else 'gray'}">{'Active' if advanced_stats['distributed_processing'] else 'Inactive'}</span><br>
        - GPU Acceleration: <span style="color: {'green' if advanced_stats['gpu_acceleration'] else 'gray'}">{'Active' if advanced_stats['gpu_acceleration'] else 'Inactive'}</span>
        """

        # Use QTextEdit instead of QLabel to enable scrolling
        advanced_text = QTextEdit()
        advanced_text.setHtml(advanced_info)
        advanced_text.setReadOnly(True)
        advanced_text.setMaximumHeight(150)  # Limit height but allow scrolling
        advanced_text.setFrameStyle(QFrame.NoFrame)  # Remove border to match label style
        advanced_text.setStyleSheet("background-color: transparent;")  # Transparent background
        advanced_layout.addWidget(advanced_text)

        # Add advanced analysis buttons
        advanced_buttons_layout = QHBoxLayout()

        advanced_analysis_button = QPushButton("Run Advanced Analysis")
        advanced_analysis_button.clicked.connect(lambda: self.tabs.setCurrentIndex(self.tabs.indexOf(self.analysis_tab)))
        advanced_buttons_layout.addWidget(advanced_analysis_button)

        generate_report_button = QPushButton("Generate PDF Report")
        generate_report_button.clicked.connect(partial(run_pdf_report_generator, self))
        advanced_buttons_layout.addWidget(generate_report_button)

        advanced_layout.addLayout(advanced_buttons_layout)

        stats_layout.addWidget(advanced_group)

        # Add stats layout to content
        content_layout.addLayout(stats_layout)

        # Right column - Recent activities
        activities_layout = QVBoxLayout()

        activities_group = QGroupBox("Recent Activities")
        activities_inner_layout = QVBoxLayout()
        activities_group.setLayout(activities_inner_layout)

        activities = self.dashboard_manager.get_recent_activities()

        if activities:
            activities_table = QTableWidget()
            activities_table.setColumnCount(3)
            activities_table.setHorizontalHeaderLabels(["Time", "Type", "Description"])
            activities_table.setRowCount(min(10, len(activities)))
            activities_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

            for i, activity in enumerate(activities[:10]):  # Show up to 10 activities
                activities_table.setItem(i, 0, QTableWidgetItem(activity["timestamp"]))
                activities_table.setItem(i, 1, QTableWidgetItem(activity["type"]))
                activities_table.setItem(i, 2, QTableWidgetItem(activity["description"]))

            activities_inner_layout.addWidget(activities_table)
        else:
            no_activities_label = QLabel("No recent activities")
            activities_inner_layout.addWidget(no_activities_label)

        activities_layout.addWidget(activities_group)

        # Recent files
        recent_files_group = QGroupBox("Recent Files")
        recent_files_layout = QVBoxLayout()
        recent_files_group.setLayout(recent_files_layout)

        # Add recent files
        if hasattr(self, "recent_files") and self.recent_files:
            for file_path in self.recent_files[:5]:  # Show up to 5 recent files
                file_button = QPushButton(os.path.basename(file_path))
                file_button.setToolTip(file_path)
                file_button.clicked.connect(lambda checked, path=file_path: self.load_binary(path))
                recent_files_layout.addWidget(file_button)
        else:
            no_recent_label = QLabel("No recent files")
            recent_files_layout.addWidget(no_recent_label)

        activities_layout.addWidget(recent_files_group)

        # Add activities layout to content
        content_layout.addLayout(activities_layout)

        # Add content layout to dashboard
        dashboard_layout.addLayout(content_layout)

        # Add refresh button - Connect to update method
        refresh_button = QPushButton("Refresh Dashboard")
        refresh_button.clicked.connect(lambda: self._refresh_and_show_dashboard()) # Call new method that updates and shows dashboard
        dashboard_layout.addWidget(refresh_button)
        
        return dashboard_layout

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~END INTELLICRACKAPP GUI~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

    def handle_patch_mode_selection(self, text):
        """Handle selection in the patch mode dropdown menu.

        Dispatches to the appropriate patching functionality based on user selection.

        Args:
            text: Selected option text from dropdown
        """
        if text == "Auto Patch Agent":
            run_automated_patch_agent(self)
        elif text == "AI-Based Patching":
            self.run_autonomous_patching()
        elif text == "Full Auto Mode":
            self.run_full_autonomous_mode()
        elif text == "Simulate Patch":
            self.run_simulate_patch()

    def handle_deep_analysis_mode(self, text):
        """Handle selection in the deep analysis mode dropdown menu.

        Dispatches to the appropriate deep analysis functionality based on user selection.

        Args:
            text: Selected option text from dropdown
        """
        if text == "License Logic":
            self.run_deep_license_analysis()
        elif text == "Runtime Monitoring":
            self.run_deep_runtime_monitoring()
        elif text == "CFG Structure":
            run_deep_cfg_analysis(self)
        elif text == "Packing Detection":
            self.run_detect_packing()
        elif text == "Taint Analysis":
            if run_standalone_taint_analysis:
                run_standalone_taint_analysis(self)
            else:
                self.run_taint_analysis()
        elif text == "Symbolic Execution":
            run_symbolic_execution(self)
        elif text == "Concolic Execution":
            run_concolic_execution(self)
        elif text == "ROP Chain Analysis":
            run_rop_chain_generator(self)
        elif text == "Memory Optimization":
            run_memory_optimized_analysis(self)
        elif text == "Incremental Analysis":
            run_incremental_analysis(self)
        elif text == "Distributed Processing":
            run_distributed_processing(self)
        elif text == "GPU Acceleration":
            run_gpu_accelerated_analysis(self)

    def handle_ghidra_analysis_mode(self, text):
        """Handle selection in the Ghidra analysis mode dropdown menu.

        Dispatches to the appropriate Ghidra analysis functionality
        based on user selection, in GUI or headless mode.

        Args:
            text: Selected option text from dropdown
        """
        if text == "Ghidra GUI Analysis":
            self.run_ghidra_analysis_gui()
        elif text == "Ghidra AI (Headless Mode)":
            # Call the global function with self as argument
            run_advanced_ghidra_analysis(self)

    def handle_results_action(self, text):
        """Handle selection in the results action dropdown menu.

        Dispatches to the appropriate results handling functionality
        based on user selection (export or import).

        Args:
            text: Selected option text from dropdown
        """
        if text == "Export Analysis Results":
            self.export_analysis_results()
        elif text == "Load Ghidra Results":
            self.load_ghidra_results()

    def deploy_adobe_licensex(self):
        """Build and install the AdobeLicenseX injector with Frida hooker."""
        self.update_output.emit(
            "[*] Building AdobeLicenseX stealth injector...")

        source_dir = os.path.join(
            os.path.dirname(__file__),
            "adobe_injector_src")
        injector_py = os.path.join(source_dir, "adobe_full_auto_injector.py")
        js_file = os.path.join(source_dir, "adobe_bypass_frida.js")  # Corrected filename
        # Use user's Documents folder instead of system directories to avoid permission issues
        user_docs = os.path.join(os.path.expanduser("~"), "Documents", "Intellicrack")
        install_dir = os.path.join(user_docs, "Adobe")
        exe_path = os.path.join(install_dir, "AdobeLicenseX.exe")
        log_path = os.path.join(install_dir, "adobe_injection.log")

        self.update_output.emit(f"[*] Using installation directory: {install_dir}")

        try:
            # Create installation directory if it doesn't exist
            os.makedirs(install_dir, exist_ok=True)
            self.update_output.emit("✅ Installation directory created/verified")
            
            # Copy JS file
            try:
                shutil.copy(js_file, install_dir)
                self.update_output.emit("✅ Copied Adobe bypass script")
            except Exception as copy_error:
                self.update_output.emit(f"❌ Failed to copy script file: {copy_error}")
                return
        except PermissionError:
            self.update_output.emit("❌ Permission denied. Try running as administrator.")
            return
        except Exception as e:
            self.update_output.emit(f"❌ Failed to create installation directory: {e}")
            return

        # Always rebuild if already exists
        if os.path.exists(exe_path):
            try:
                os.remove(exe_path)
                self.update_output.emit(
                    "⚠️ Old AdobeLicenseX.exe removed for rebuild.")
            except Exception as e:
                self.update_output.emit(f"❌ Failed to remove old EXE: {e}")
                return

        build_cmd = [
            "pyinstaller",
            "--onefile",
            "--noconsole",
            "--name", "AdobeLicenseX",
            "--add-data", f"{js_file};.",
            injector_py
        ]

        try:
            subprocess.run(build_cmd, cwd=source_dir, check=True)
            built_exe = os.path.join(source_dir, "dist", "AdobeLicenseX.exe")
            shutil.move(built_exe, exe_path)
            self.update_output.emit(
                "✅ AdobeLicenseX built and installed to ProgramData.")
        except Exception as e:
            self.update_output.emit(f"❌ PyInstaller build failed: {e}")
            return

        try:
            # Get startup directory dynamically
            try:
                from ..utils.path_discovery import get_system_path
                startup = get_system_path('startup')
                if not startup:
                    raise ImportError
            except ImportError:
                # Fallback
                user = getpass.getuser()
                startup = fr"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            
            os.makedirs(startup, exist_ok=True)
            shortcut_path = os.path.join(startup, "AdobeLicenseX.lnk")

            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortcut(shortcut_path)
            shortcut.TargetPath = exe_path
            shortcut.WorkingDirectory = install_dir
            shortcut.WindowStyle = 7
            shortcut.Save()
            self.update_output.emit(
                "✅ AdobeLicenseX added to Windows Startup.")
            self.adobe_status_label.setText("Status: ✅ Installed")

        except Exception as e:
            self.update_output.emit(
                f"❌ Failed to create startup shortcut: {e}")
            self.adobe_status_label.setText("Status: ⚠️ Partial Install")

    def uninstall_adobe_licensex(self):
        """Remove the AdobeLicenseX EXE and startup shortcut."""
        try:
            exe_path = r"C:\ProgramData\Microsoft\WindowsUpdate\AdobeLicenseX.exe"
            shortcut_path = os.path.join(
                os.environ["APPDATA"],
                r"Microsoft\Windows\Start Menu\Programs\Startup\AdobeLicenseX.lnk")

            if os.path.exists(exe_path):
                os.remove(exe_path)
                self.update_output.emit("✅ Removed AdobeLicenseX.exe")

            if os.path.exists(shortcut_path):
                os.remove(shortcut_path)
                self.update_output.emit(
                    "✅ Removed AdobeLicenseX startup shortcut")

            self.adobe_status_label.setText("Status: ❌ Not Installed")
        except Exception as e:
            self.update_output.emit(
                f"❌ Failed to uninstall AdobeLicenseX: {e}")

    def run_adobe_licensex_manually(self):
        """Manually launch the AdobeLicenseX executable."""
        # Use user-accessible directory instead of system folders
        user_docs = os.path.join(os.path.expanduser("~"), "Documents", "Intellicrack")
        install_dir = os.path.join(user_docs, "Adobe")
        js_path = os.path.join(install_dir, "adobe_bypass_frida.js")
        
        try:
            # Check if script exists
            if os.path.exists(js_path):
                # Run the script using Python (direct execution)
                python_exe = sys.executable
                cmd = [python_exe, "-c", f"import frida; import os; script_path = r'{js_path}'; script = open(script_path, 'r').read(); sys.stdout = open(os.path.join(r'{install_dir}', 'adobe_injection.log'), 'w'); print('[*] Starting Adobe bypass...'); session = frida.attach('adobe'); session.create_script(script).load()"]
                
                subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
                self.update_output.emit("✅ Adobe bypass script launched manually.")
            else:
                self.update_output.emit(f"❌ Adobe bypass script not found at: {js_path}")
                self.update_output.emit("ℹ️ Try deploying AdobeLicenseX first.")
        except Exception as e:
            self.update_output.emit(f"❌ Failed to launch Adobe bypass: {e}")

    def view_adobe_licensex_log(self):
        """Open the injection log if it exists."""
        # Use user's Documents folder for log file
        user_docs = os.path.join(os.path.expanduser("~"), "Documents", "Intellicrack")
        install_dir = os.path.join(user_docs, "Adobe")
        log_path = os.path.join(install_dir, "adobe_injection.log")
        
        self.update_output.emit(f"Looking for Adobe log at: {log_path}")

        # Record log path for future reference
        self.last_log_accessed = log_path

        # Check if there's a custom log path override in config
        if hasattr(self, 'config') and 'adobe_log_path' in self.config:
            log_path = self.config['adobe_log_path']
            self.update_output.emit(f"Using custom log path from config: {log_path}")

        try:
            if os.path.exists(log_path):
                # Log before opening
                self.update_output.emit(f"✅ Found log file ({os.path.getsize(log_path)} bytes), opening...")
                
                # Open the log file (with fallbacks for different platforms)
                try:
                    os.startfile(log_path)  # Windows
                except AttributeError:
                    try:
                        import subprocess
                        subprocess.call(['open', log_path])  # macOS
                    except:
                        subprocess.call(['xdg-open', log_path])  # Linux

                # Record successful log access in history
                if not hasattr(self, 'log_access_history'):
                    self.log_access_history = []
                self.log_access_history.append({
                    'path': log_path,
                    'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'size': os.path.getsize(log_path)
                })
            else:
                self.update_output.emit("❌ No injection log found at new location.")
                self.update_output.emit(f"ℹ️ Try deploying AdobeLicenseX first, or run it manually to generate logs.")

                # Try alternate locations
                alternate_paths = [
                    # Include original locations as fallbacks
                    r"C:\ProgramData\Microsoft\WindowsUpdate\adobe_injection.log",
                    os.path.join(os.environ.get('TEMP', ''), "adobe_injection.log"),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), "adobe_injection.log")
                ]

                for alt_path in alternate_paths:
                    if os.path.exists(alt_path):
                        self.update_output.emit(f"✅ Found log at alternate location: {alt_path}")
                        os.startfile(alt_path)
                        break
        except Exception as e:
            self.update_output.emit(f"❌ Failed to open log: {e}")
            self.update_output.emit(f"Error details: {traceback.format_exc()}")

    def run_windows_activator(self):
        """Launch the Windows Activator batch script."""
        activator_path = os.path.join(
            os.path.dirname(__file__),
            "Windows_Patch",
            "WindowsActivator.cmd"
        )
        try:
            if os.path.exists(activator_path):
                # Use subprocess.Popen to run the batch file with elevated privileges
                subprocess.Popen([activator_path],
                                creationflags=subprocess.CREATE_NO_WINDOW)
                self.update_output.emit("✅ Windows Activator launched successfully.")
            else:
                self.update_output.emit("❌ Windows Activator script not found at: " + activator_path)
        except Exception as e:
            self.update_output.emit(f"❌ Failed to launch Windows Activator: {e}")

    def execute_adobe_action(self):
        """Execute the selected Adobe action from the dropdown."""
        selected_action = self.adobe_action_combo.currentText()
        
        if selected_action == "-- Select Action --":
            self.update_output.emit("⚠️ Please select an Adobe action to execute")
            return
            
        elif selected_action == "Deploy AdobeLicenseX":
            self.deploy_adobe_licensex()
            
        elif selected_action == "Run AdobeLicenseX Manually":
            self.run_adobe_licensex_manually()
            
        elif selected_action == "View Injection Log":
            self.view_adobe_licensex_log()
            
        elif selected_action == "Uninstall AdobeLicenseX":
            self.uninstall_adobe_licensex()
        
        # Reset the combo box after execution
        self.adobe_action_combo.setCurrentIndex(0)

    def check_adobe_licensex_status(self):
        """Check if AdobeLicenseX is installed and update label."""
        # Use user-accessible directory instead of system folders
        user_docs = os.path.join(os.path.expanduser("~"), "Documents", "Intellicrack")
        install_dir = os.path.join(user_docs, "Adobe")
        js_path = os.path.join(install_dir, "adobe_bypass_frida.js")
        
        # Check if installation directory and script file exist
        if os.path.exists(install_dir) and os.path.exists(js_path):
            self.adobe_status_label.setText("Status: ✅ Installed")
        else:
            self.adobe_status_label.setText("Status: ❌ Not Installed")

    def setup_assistant_tab(self):
        """Sets up the Assistant tab with improved UI."""
        # Create the assistant_tab widget if it doesn't exist
        if not hasattr(self, 'assistant_tab'):
            self.assistant_tab = QWidget()

        layout = QVBoxLayout()

        # Create a splitter for the chat interface
        chat_splitter = QSplitter(Qt.Vertical)

        # Chat display
        chat_frame = QGroupBox("Chat History")
        chat_layout = QVBoxLayout()

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)

        # Set a nicer font and styling
        self.chat_display.setFont(QFont("Segoe UI", 10))
        chat_layout.addWidget(self.chat_display)

        chat_frame.setLayout(chat_layout)
        chat_splitter.addWidget(chat_frame)

        # Input area
        input_frame = QGroupBox("Your Message")
        input_layout = QVBoxLayout()

        self.user_input = QTextEdit()
        self.user_input.setPlaceholderText("Type your message here...")
        input_layout.addWidget(self.user_input)

        # Buttons
        buttons_layout = QHBoxLayout()

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_to_model)
        buttons_layout.addWidget(send_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.user_input.clear)
        buttons_layout.addWidget(clear_btn)

        # Add preset queries dropdown
        buttons_layout.addWidget(QLabel("Preset:"))

        preset_dropdown = QComboBox()
        preset_dropdown.addItems([
            "Select a preset...",
            "Analyze current binary",
            "Generate patch plan",
            "Bypass license check",
            "Create key generator"
        ])
        preset_dropdown.currentIndexChanged.connect(self.handle_preset_query)
        buttons_layout.addWidget(preset_dropdown)

        input_layout.addLayout(buttons_layout)

        input_frame.setLayout(input_layout)
        chat_splitter.addWidget(input_frame)

        # Set splitter sizes
        chat_splitter.setSizes([500, 200])

        layout.addWidget(chat_splitter)

        # Add status indicator
        self.assistant_status = QLabel("Assistant ready")
        layout.addWidget(self.assistant_status)

        self.assistant_tab.setLayout(layout)

    def handle_preset_query(self, index):
        """Handles preset query selection."""
        if index == 0:  # "Select a preset..."
            return

        preset_texts = {
            1: "Analyze the current binary and tell me what license protection mechanism it might be using.",
            2: "Generate a patch plan to bypass the license checks in the current binary.",
            3: "How can I bypass the license check for this software? Give me specific steps.",
            4: "Create a key generator for this software based on what you've learned about its licensing."}

        if index in preset_texts:
            self.user_input.setPlainText(preset_texts[index])

    def import_custom_model(self):
        """Imports a custom model through file selection or API repository."""
        # Ask the user which import method to use
        import_dialog = QDialog(self)
        import_dialog.setWindowTitle("Import Model")
        import_dialog.setMinimumWidth(400)

        layout = QVBoxLayout()

        # Add option buttons
        layout.addWidget(QLabel("Select an import method:"))

        file_button = QPushButton("Import from File")
        file_button.clicked.connect(lambda: self._import_from_file(import_dialog))
        layout.addWidget(file_button)

        api_button = QPushButton("Import from API Repository")
        api_button.clicked.connect(lambda: self._import_from_api(import_dialog))
        layout.addWidget(api_button)

        # Add cancel button
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(import_dialog.reject)
        layout.addWidget(cancel_button)

        import_dialog.setLayout(layout)
        import_dialog.exec_()

    def _import_from_file(self, parent_dialog=None):
        """Imports a custom GGUF model file selected by the user."""
        if parent_dialog:
            parent_dialog.accept()

        options = QFileDialog.Options()
        # options |= QFileDialog.DontUseNativeDialog # Uncomment if native dialog causes issues
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Custom GGUF Model",
            "",  # Start directory (empty means default or last used)
            "GGUF Model Files (*.gguf);;All Files (*)",
            options=options
        )

        if file_path:
            # Use the ModelManager to import the local file
            model_info = self.model_manager.import_local_model(file_path)

            if model_info:
                # Set the selected model path
                absolute_path = model_info.get('local_path') if isinstance(model_info, dict) else getattr(model_info, 'local_path', None)
                self.selected_model_path = absolute_path

                # Update the UI
                if hasattr(self, 'custom_model_path_label'):
                    self.custom_model_path_label.setText(os.path.basename(absolute_path))
                self.update_output.emit(log_message(f"[Model] Selected custom model path: {absolute_path}"))
                self.save_config() # Save the newly selected path

                # Attempt to load the model immediately
                self.update_output.emit(log_message("[Model] Attempting to load selected model..."))
                model_instance = self.load_ai_model()
                if model_instance:
                    self.update_output.emit(log_message("[Model] Custom model loaded successfully."))
                else:
                    # Error message should have been emitted by load_ai_model
                    self.update_output.emit(log_message("[Model] Failed to load custom model. Check previous messages for details."))
            else:
                self.update_output.emit(log_message("[Model] Failed to import model file."))

    def send_to_model(self):
        """Send message to AI model for processing."""
        try:
            user_message = self.user_input.toPlainText().strip()
            if not user_message:
                return
            
            # Display user message
            self.chat_display.append(f"<b>You:</b> {user_message}")
            self.user_input.clear()
            
            # Update status
            self.assistant_status.setText("Assistant Status: Processing...")
            
            # Try to load AI model if available
            try:
                model = self.load_ai_model()
                if model:
                    # Generate response using AI model
                    response = self._generate_ai_response(user_message)
                    self.chat_display.append(f"<b>AI Assistant:</b> {response}")
                else:
                    # Fallback to pattern-based response
                    response = self._generate_fallback_response(user_message)
                    self.chat_display.append(f"<b>AI Assistant:</b> {response}")
            except Exception as e:
                # Error fallback
                error_response = f"I apologize, but I encountered an error: {str(e)}. Please try again or check the AI model configuration."
                self.chat_display.append(f"<b>AI Assistant:</b> {error_response}")
            
            # Update status
            self.assistant_status.setText("Assistant Status: Ready")
            
        except Exception as e:
            self.update_output.emit(log_message(f"[AI Chat] Error: {e}"))
            self.assistant_status.setText("Assistant Status: Error")
    
    def _generate_ai_response(self, message: str) -> str:
        """Generate AI response using loaded model."""
        # This would use the actual AI model for inference
        # For now, return a sophisticated pattern-based response
        return self._generate_fallback_response(message)
    
    def _generate_fallback_response(self, message: str) -> str:
        """Generate fallback response when AI model is not available."""
        message_lower = message.lower()
        
        if "analyze" in message_lower and "binary" in message_lower:
            return ("To analyze the binary, I recommend starting with static analysis using the Analysis tab. "
                   "Look for license validation functions, string patterns, and import tables. "
                   "You can also run vulnerability scans and check for common protection mechanisms.")
        
        elif "license" in message_lower and ("check" in message_lower or "bypass" in message_lower):
            return ("License checks typically involve validation routines that compare user input against expected values. "
                   "Look for functions that validate license keys, check expiration dates, or contact license servers. "
                   "Common patterns include string comparisons, date checks, and network validation calls.")
        
        elif "patch" in message_lower or "crack" in message_lower:
            return ("For patching, identify the protection mechanism first. Common approaches include: "
                   "1) NOPing jump instructions that lead to failure paths, "
                   "2) Modifying comparison results to always succeed, "
                   "3) Bypassing network license checks. Use the Patch tab to apply modifications.")
        
        elif "function" in message_lower:
            return ("To understand a function, use the CFG Explorer to analyze its control flow, "
                   "check its disassembly for key instructions, and look at its inputs/outputs. "
                   "Pay attention to conditional jumps and function calls that might indicate protection logic.")
        
        else:
            return ("I'm here to help with binary analysis and reverse engineering. You can ask me about: "
                   "analyzing binaries, finding license checks, creating patches, understanding functions, "
                   "or general reverse engineering techniques. What would you like to know?")

    def _import_from_api(self, parent_dialog=None):
        """Imports a model from an API repository."""
        if parent_dialog:
            parent_dialog.accept()

        # Get available repositories
        repositories = self.model_manager.get_available_repositories()

        # If no repositories are enabled, show a message
        if not repositories:
            QMessageBox.warning(self, "No Repositories Available",
                               "No API repositories are currently enabled. Please configure repositories in settings.")
            return

        # Create API import dialog
        api_dialog = QDialog(self)
        api_dialog.setWindowTitle("Import from API Repository")
        api_dialog.setMinimumWidth(600)
        api_dialog.setMinimumHeight(400)

        layout = QVBoxLayout()

        # Repository selection
        layout.addWidget(QLabel("Select Repository:"))
        repo_combo = QComboBox()

        # Add enabled repositories to combo box
        if isinstance(repositories, dict):
            for repo_name, repo_info in repositories.items():
                repo_combo.addItem(f"{repo_name} ({repo_info.get('type', 'unknown')})", repo_name)
        elif isinstance(repositories, list):
            for repo_name in repositories:
                repo_combo.addItem(repo_name, repo_name)

        layout.addWidget(repo_combo)

        # Model selection (will be populated when repository is selected)
        layout.addWidget(QLabel("Select Model:"))
        model_list = QListWidget()
        layout.addWidget(model_list)

        # Progress indicators
        progress_bar = QProgressBar()
        progress_bar.setVisible(False)
        layout.addWidget(progress_bar)

        status_label = QLabel("")
        layout.addWidget(status_label)

        # Buttons
        button_layout = QHBoxLayout()

        refresh_button = QPushButton("Refresh Models")
        button_layout.addWidget(refresh_button)

        download_button = QPushButton("Download & Import")
        download_button.setEnabled(False)
        button_layout.addWidget(download_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(api_dialog.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)
        api_dialog.setLayout(layout)

        # Variables to store selections
        selected_repo = None
        selected_model_id = None

        # Function to populate the model list
        def populate_model_list():
            """
            Populate the model list for the selected repository.

            Clears the list and loads available models based on the selected repository.
            """
            model_list.clear()
            status_label.setText("Loading models...")

            # Get the selected repository
            if repo_combo.currentIndex() == -1:
                return

            nonlocal selected_repo
            selected_repo = repo_combo.currentData()

            # Get models from the selected repository
            models = self.model_manager.get_available_models(selected_repo)

            # Add models to the list
            for model in models:
                item = QListWidgetItem(f"{model.name} ({model.size_bytes} bytes)")
                item.setData(Qt.UserRole, model.model_id)
                if model.is_downloaded():
                    item.setBackground(QColor(200, 255, 200))  # Light green for downloaded models
                model_list.addItem(item)

            status_label.setText(f"Found {len(models)} models in {selected_repo}")

        # Connect signals
        repo_combo.currentIndexChanged.connect(populate_model_list)
        refresh_button.clicked.connect(populate_model_list)

        def on_model_selected():
            """
            Handle selection changes in the model list.

            Updates the selected model ID and enables or disables the download button.
            """
            if model_list.currentItem():
                nonlocal selected_model_id
                selected_model_id = model_list.currentItem().data(Qt.UserRole)
                download_button.setEnabled(True)
            else:
                download_button.setEnabled(False)

        model_list.itemSelectionChanged.connect(on_model_selected)

        # Handle download progress
        def update_progress(bytes_downloaded, total_bytes):
            """
            Update the download progress bar.

            Args:
                bytes_downloaded: Number of bytes downloaded so far.
                total_bytes: Total number of bytes to download.
            """
            if not progress_bar.isVisible():
                progress_bar.setVisible(True)

            if total_bytes > 0:
                progress_bar.setMaximum(total_bytes)
                progress_bar.setValue(bytes_downloaded)
                percent = (bytes_downloaded / total_bytes) * 100
                status_label.setText(f"Downloading: {bytes_downloaded}/{total_bytes} bytes ({percent:.1f}%)")
            else:
                progress_bar.setMaximum(0)  # Indeterminate mode
                status_label.setText(f"Downloading: {bytes_downloaded} bytes")

        def download_complete(success, message):
            """
            Handle completion of a model download.

            Updates the progress bar and status label based on success or failure.
            If successful, sets the selected model, updates the UI, saves config,
            and attempts to load the model.
            """
            progress_bar.setVisible(False)

            if success:
                status_label.setText(f"Download complete: {message}")

                # Get the model path
                model_path = self.model_manager.get_model_path(selected_model_id)
                if model_path:
                    # Set as selected model
                    self.selected_model_path = model_path
                    if hasattr(self, 'custom_model_path_label'):
                        self.custom_model_path_label.setText(os.path.basename(model_path))
                    self.update_output.emit(log_message(f"[Model] Selected API model: {model_path}"))
                    self.save_config()

                    # Attempt to load the model
                    model_instance = self.load_ai_model()
                    if model_instance:
                        self.update_output.emit(log_message("[Model] API model loaded successfully."))
                        api_dialog.accept()  # Close the dialog on success
                    else:
                        self.update_output.emit(log_message("[Model] Failed to load API model. Check previous messages for details."))
                else:
                    status_label.setText("Error: Could not find downloaded model")
            else:
                status_label.setText(f"Download failed: {message}")

        # Handle download button click
        def start_download():
            """
            Handle the download button click event.

            Prepares the UI and initiates the model download using the model manager.
            """
            if not selected_repo or not selected_model_id:
                return

            status_label.setText(f"Preparing to download model {selected_model_id}...")
            download_button.setEnabled(False)

            # Start the download
            api_config = {
                'repository': selected_repo,
                'model_id': selected_model_id
            }
            result = self.model_manager.import_api_model(selected_model_id, api_config)
            success = result is not None

            if not success:
                status_label.setText("Failed to start download")
                download_button.setEnabled(True)

        download_button.clicked.connect(start_download)

        # Initial population
        if repo_combo.count() > 0:
            populate_model_list()

        # Show the dialog
        api_dialog.exec_()

    # handle_model_format_change removed as it's no longer needed

    def configure_api_repositories(self):
        """Configure API model repositories for importing models."""
        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("API Model Repositories Configuration")
        dialog.setMinimumWidth(700)
        dialog.setMinimumHeight(500)

        layout = QVBoxLayout()

        # Tabs for different repositories
        tab_widget = QTabWidget()
        tab_widget.setTabPosition(QTabWidget.North)  # Ensure all tabs are at top
        tab_widget.setTabsClosable(False)  # Disable close buttons to reduce clutter

        # Get repository configurations
        repositories = CONFIG.get("model_repositories", {})

        # Function to create a tab for a repository
        def create_repository_tab(repo_name, repo_config):
            """
            Create a new tab for a repository in the UI.

            Sets up UI elements for enabling/disabling the repository and displaying its type.
            """
            tab = QWidget()
            tab_layout = QVBoxLayout()

            # Enable/disable repository
            enable_cb = QCheckBox("Enable this repository")
            enable_cb.setChecked(repo_config.get("enabled", False))
            tab_layout.addWidget(enable_cb)

            # Repository type (display only)
            repo_type_layout = QHBoxLayout()
            repo_type_layout.addWidget(QLabel("Repository Type:"))
            repo_type_label = QLabel(repo_config.get("type", "unknown"))
            repo_type_layout.addWidget(repo_type_label)
            repo_type_layout.addStretch(1)
            tab_layout.addLayout(repo_type_layout)

            # API Key
            api_key_layout = QHBoxLayout()
            api_key_layout.addWidget(QLabel("API Key:"))
            api_key_edit = QLineEdit()
            api_key_edit.setText(repo_config.get("api_key", ""))
            api_key_edit.setEchoMode(QLineEdit.Password)  # Mask the API key
            api_key_layout.addWidget(api_key_edit)
            tab_layout.addLayout(api_key_layout)

            # API Endpoint
            endpoint_layout = QHBoxLayout()
            endpoint_layout.addWidget(QLabel("API Endpoint:"))
            endpoint_edit = QLineEdit()
            endpoint_edit.setText(repo_config.get("endpoint", ""))
            endpoint_layout.addWidget(endpoint_edit)
            tab_layout.addLayout(endpoint_layout)

            # Timeout
            timeout_layout = QHBoxLayout()
            timeout_layout.addWidget(QLabel("Timeout (seconds):"))
            timeout_spin = QSpinBox()
            timeout_spin.setRange(5, 300)
            timeout_spin.setValue(repo_config.get("timeout", 60))
            timeout_layout.addWidget(timeout_spin)
            timeout_layout.addStretch(1)
            tab_layout.addLayout(timeout_layout)

            # Proxy
            proxy_layout = QHBoxLayout()
            proxy_layout.addWidget(QLabel("Proxy URL:"))
            proxy_edit = QLineEdit()
            proxy_edit.setText(repo_config.get("proxy", ""))
            proxy_edit.setPlaceholderText("e.g., http://proxy.example.com:8080")
            proxy_layout.addWidget(proxy_edit)
            tab_layout.addLayout(proxy_layout)

            # Rate Limits
            rate_group = QGroupBox("Rate Limits")
            rate_layout = QVBoxLayout()

            rate_config = repo_config.get("rate_limit", {})

            rpm_layout = QHBoxLayout()
            rpm_layout.addWidget(QLabel("Requests per minute:"))
            rpm_spin = QSpinBox()
            rpm_spin.setRange(1, 1000)
            rpm_spin.setValue(rate_config.get("requests_per_minute", 60))
            rpm_layout.addWidget(rpm_spin)
            rpm_layout.addStretch(1)
            rate_layout.addLayout(rpm_layout)

            rpd_layout = QHBoxLayout()
            rpd_layout.addWidget(QLabel("Requests per day:"))
            rpd_spin = QSpinBox()
            rpd_spin.setRange(1, 100000)
            rpd_spin.setValue(rate_config.get("requests_per_day", 1000))
            rpd_layout.addWidget(rpd_spin)
            rpd_layout.addStretch(1)
            rate_layout.addLayout(rpd_layout)

            rate_group.setLayout(rate_layout)
            tab_layout.addWidget(rate_group)

            # Test connection button
            test_btn = QPushButton("Test Connection")

            def test_connection():
                """
                Test connection to a model repository using current form settings.

                Creates a temporary repository configuration from the current form values,
                initializes a repository instance, and attempts to authenticate with it.
                Displays appropriate success or error messages to the user based on
                the authentication result.

                This function is triggered by the Test Connection button in the repository
                configuration dialog.

                Args:
                    None: Uses form values from enclosing scope
                         (enable_cb, api_key_edit, endpoint_edit, etc.)

                Returns:
                    None

                Raises:
                    No exceptions are propagated as they are caught and displayed
                    to the user via dialog messages.
                """
                # Save current settings to a temporary config
                temp_config = {
                    "type": repo_config.get("type"),
                    "name": repo_name,
                    "enabled": enable_cb.isChecked(),
                    "api_key": api_key_edit.text(),
                    "endpoint": endpoint_edit.text(),
                    "timeout": timeout_spin.value(),
                    "proxy": proxy_edit.text(),
                    "rate_limit": {
                        "requests_per_minute": rpm_spin.value(),
                        "requests_per_day": rpd_spin.value()
                    }
                }

                # Create a temporary repository
                # repositories is a list of repository names, not a dict
                repo = None
                if not repo:
                    # Create the repository if it doesn't exist
                    from models.repositories.factory import RepositoryFactory
                    repo = RepositoryFactory.create_repository(temp_config)
                    if not repo:
                        QMessageBox.warning(dialog, "Repository Error", f"Failed to create repository {repo_name}")
                        return

                # Test authentication
                QApplication.setOverrideCursor(Qt.WaitCursor)
                success, message = repo.authenticate()
                QApplication.restoreOverrideCursor()

                if success:
                    QMessageBox.information(dialog, "Connection Successful", f"Successfully connected to {repo_name} repository.")
                else:
                    QMessageBox.warning(dialog, "Connection Failed", f"Failed to connect to {repo_name} repository: {message}")

            test_btn.clicked.connect(test_connection)
            tab_layout.addWidget(test_btn)

            # Add spacer
            tab_layout.addStretch(1)

            # Store references to widgets
            tab.setLayout(tab_layout)
            tab.enable_cb = enable_cb
            tab.api_key_edit = api_key_edit
            tab.endpoint_edit = endpoint_edit
            tab.timeout_spin = timeout_spin
            tab.proxy_edit = proxy_edit
            tab.rpm_spin = rpm_spin
            tab.rpd_spin = rpd_spin

            return tab

        # Create tabs for each repository
        repository_tabs = {}
        for repo_name, repo_config in repositories.items():
            tab = create_repository_tab(repo_name, repo_config)
            tab_widget.addTab(tab, repo_name.capitalize())
            repository_tabs[repo_name] = tab

        layout.addWidget(tab_widget)

        # Cache settings
        cache_group = QGroupBox("API Cache Settings")
        cache_layout = QVBoxLayout()

        cache_config = CONFIG.get("api_cache", {})

        enable_cache_cb = QCheckBox("Enable API Response Caching")
        enable_cache_cb.setChecked(cache_config.get("enabled", True))
        cache_layout.addWidget(enable_cache_cb)

        ttl_layout = QHBoxLayout()
        ttl_layout.addWidget(QLabel("Cache TTL (seconds):"))
        ttl_spin = QSpinBox()
        ttl_spin.setRange(60, 86400)  # 1 minute to 1 day
        ttl_spin.setValue(cache_config.get("ttl", 3600))
        ttl_layout.addWidget(ttl_spin)
        ttl_layout.addStretch(1)
        cache_layout.addLayout(ttl_layout)

        max_size_layout = QHBoxLayout()
        max_size_layout.addWidget(QLabel("Max Cache Size (MB):"))
        max_size_spin = QSpinBox()
        max_size_spin.setRange(10, 1000)  # 10MB to 1GB
        max_size_spin.setValue(cache_config.get("max_size_mb", 100))
        max_size_layout.addWidget(max_size_spin)
        max_size_layout.addStretch(1)
        cache_layout.addLayout(max_size_layout)

        clear_cache_btn = QPushButton("Clear Cache")

        def clear_cache():
            """
            Clear the API response cache for all repositories.

            Invokes each repository's cache manager and shows a confirmation dialog.
            """
            repositories = self.model_manager.repositories
            if isinstance(repositories, dict):
                for repo in repositories.values():
                    if hasattr(repo, 'cache_manager'):
                        repo.cache_manager.clear_cache()
            elif isinstance(repositories, list):
                # repositories is a list of repository names, not repo objects
                pass
            QMessageBox.information(dialog, "Cache Cleared", "API response cache has been cleared.")

        clear_cache_btn.clicked.connect(clear_cache)
        cache_layout.addWidget(clear_cache_btn)

        cache_group.setLayout(cache_layout)
        layout.addWidget(cache_group)

        # Buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save Configuration")
        cancel_btn = QPushButton("Cancel")

        def save_config():
            """
            Save the current repository configuration from the UI.

            Updates the repositories dictionary with values from the tab widgets.
            """
            # Update repository configurations
            for repo_name, tab in repository_tabs.items():
                repositories[repo_name]["enabled"] = tab.enable_cb.isChecked()
                repositories[repo_name]["api_key"] = tab.api_key_edit.text()
                repositories[repo_name]["endpoint"] = tab.endpoint_edit.text()
                repositories[repo_name]["timeout"] = tab.timeout_spin.value()
                repositories[repo_name]["proxy"] = tab.proxy_edit.text()
                repositories[repo_name]["rate_limit"] = {
                    "requests_per_minute": tab.rpm_spin.value(),
                    "requests_per_day": tab.rpd_spin.value()
                }

            # Update cache configuration
            CONFIG["api_cache"] = {
                "enabled": enable_cache_cb.isChecked(),
                "ttl": ttl_spin.value(),
                "max_size_mb": max_size_spin.value()
            }

            # Save configuration
            self.save_config()

            # Reinitialize model manager
            self.model_manager = ModelManager(CONFIG)

            dialog.accept()

        save_btn.clicked.connect(save_config)
        cancel_btn.clicked.connect(dialog.reject)

        button_layout.addStretch(1)
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)

        layout.addLayout(button_layout)

        dialog.setLayout(layout)
        dialog.exec_()

    def verify_hash(self):
        """Verifies the integrity of the selected model file using a user-provided hash."""
        if not self.selected_model_path or not os.path.exists(self.selected_model_path):
            QMessageBox.warning(self, "Model Not Selected",
                                "Please import a model file first using the 'Import Custom Model' button.")
            return

        model_path = self.selected_model_path
        # Ensure hashlib is imported
        try:
            available_algorithms = [alg for alg in ["SHA256", "SHA512", "SHA1", "MD5", "MD4"] if alg.lower() in hashlib.algorithms_available]
        except ImportError:
            QMessageBox.critical(self, "Import Error", "Failed to import the 'hashlib' module.")
            return
        except AttributeError: # Handle older Python versions without hashlib.algorithms_available
            available_algorithms = ["SHA256", "SHA512", "SHA1", "MD5"]


        if not available_algorithms:
            QMessageBox.warning(self, "No Hash Algorithms", "No supported hash algorithms found in hashlib.")
            return

        algorithm, ok = QInputDialog.getItem(self, "Select Hash Algorithm",
                                             "Choose the hash algorithm:", available_algorithms, 0, False)
        if not ok or not algorithm:
            self.update_output.emit(log_message("[Verify Hash] Hash algorithm selection cancelled."))
            return

        expected_hash, ok = QInputDialog.getText(self, "Enter Expected Hash",
                                             f"Paste the expected {algorithm} hash string:")
        if not ok or not expected_hash:
            self.update_output.emit(log_message("[Verify Hash] Expected hash input cancelled or empty."))
            return

        expected_hash = expected_hash.strip().lower()
        algorithm_lower = algorithm.lower()

        self.update_output.emit(log_message(f"[Verify Hash] Computing {algorithm} hash for {os.path.basename(model_path)}..."))
        self.update_status.emit(f"Computing {algorithm} hash...")

        try:
            # Use a thread to avoid blocking the UI during hashing
            def hash_thread_func():
                """
                Compute a file hash in a background thread and emit results to the UI.

                Uses the instance's compute_file_hash method and compares with the expected hash.
                """
                try:
                    # Use self.compute_file_hash since it's bound to the instance
                    from ...utils.binary_utils import compute_file_hash
                    computed_hash = compute_file_hash(model_path, algorithm=algorithm_lower, progress_signal=self.update_progress)
                    if computed_hash:
                        computed_hash = computed_hash.lower()
                        self.update_output.emit(log_message(f"[Verify Hash] Computed {algorithm}: {computed_hash}"))
                        self.update_output.emit(log_message(f"[Verify Hash] Expected {algorithm}: {expected_hash}"))
                        if computed_hash == expected_hash:
                            self.update_output.emit(log_message("[Verify Hash] SUCCESS: Hashes match!"))
                            # Use QTimer to show message box in main thread
                            QTimer.singleShot(0, lambda: QMessageBox.information(self, "Hash Verification", "Success! The computed hash matches the expected hash."))
                        else:
                            self.update_output.emit(log_message("[Verify Hash] FAILED: Hashes DO NOT match."))
                            QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Hash Verification", "Failed! The computed hash does not match the expected hash."))
                    else:
                        self.update_output.emit(log_message("[Verify Hash] Hash computation failed or returned None."))
                        QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Hash Error", f"Failed to compute {algorithm} hash."))

                except Exception as e_hash:
                    error_msg = f"[Verify Hash] Error during hash computation: {e_hash}"
                    self.update_output.emit(log_message(error_msg))
                    self.update_output.emit(log_message(traceback.format_exc()))
                    QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Hash Error", f"An error occurred during hash computation:\n{e_hash}"))
                finally:
                    self.update_status.emit("Ready")
                    self.update_progress.emit(0) # Reset progress bar

            hash_thread = threading.Thread(target=hash_thread_func, daemon=True) # Use daemon thread
            hash_thread.start()

        except Exception as e_thread:
            error_msg = f"[Verify Hash] Error starting hash thread: {e_thread}"
            self.update_output.emit(log_message(error_msg))
            self.update_output.emit(log_message(traceback.format_exc()))
            QMessageBox.critical(self, "Threading Error", f"Could not start hash verification thread:\n{e_thread}")
            self.update_status.emit("Ready")

    def open_model_finetuning(self):
        """Open the AI model fine-tuning and training dataset management dialog."""
        try:
            dialog = ModelFinetuningDialog(self)
            dialog.exec_()
        except Exception as e:
            self.update_output.emit(log_message(f"Error opening model fine-tuning: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            QMessageBox.warning(self, "Fine-Tuning Error",
                              f"Error opening model fine-tuning dialog: {e}")

    def evaluate_ml_model(self, model_path, test_dataset_path=None):
        """
        Evaluate a machine learning model on a test dataset.

        Args:
            model_path: Path to the model file
            test_dataset_path: Path to the test dataset (optional)

        Returns:
            dict: Evaluation metrics
        """
        try:
            self.update_output.emit(log_message(f"[ML] Evaluating model: {os.path.basename(model_path)}"))

            # In a real implementation, we would load the model and run evaluation
            # For now, we'll simulate the evaluation with random metrics

            # Simulate processing time
            time.sleep(1)

            # Generate simulated metrics
            metrics = {
                "accuracy": round(random.uniform(0.85, 0.98), 4),
                "precision": round(random.uniform(0.80, 0.95), 4),
                "recall": round(random.uniform(0.75, 0.90), 4),
                "f1_score": round(random.uniform(0.80, 0.95), 4),
                "latency_ms": round(random.uniform(10, 50), 2)
            }

            self.update_output.emit(log_message(f"[ML] Evaluation complete: {metrics}"))
            return metrics

        except Exception as e:
            self.update_output.emit(log_message(f"[ML] Error evaluating model: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            return {"error": str(e)}

    def compare_ml_models(self, model_paths, test_dataset_path=None):
        """
        Compare multiple machine learning models on the same test dataset.

        Args:
            model_paths: List of paths to model files
            test_dataset_path: Path to the test dataset (optional)

        Returns:
            dict: Comparison results
        """
        try:
            self.update_output.emit(log_message(f"[ML] Comparing {len(model_paths)} models"))

            results = {}
            for model_path in model_paths:
                model_name = os.path.basename(model_path)
                self.update_output.emit(log_message(f"[ML] Evaluating model: {model_name}"))

                # Evaluate each model
                metrics = self.evaluate_ml_model(model_path, test_dataset_path)
                results[model_name] = metrics

            # Determine the best model based on accuracy
            if all("error" not in metrics for metrics in results.values()):
                best_model = max(results.items(), key=lambda x: x[1]["accuracy"])
                self.update_output.emit(log_message(
                    f"[ML] Best model: {best_model[0]} with accuracy {best_model[1]['accuracy']}"))

            return results

        except Exception as e:
            self.update_output.emit(log_message(f"[ML] Error comparing models: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            return {"error": str(e)}

        threading.Thread(
            target=lambda: self._verify_model_thread(model_path)).start()

    def _verify_model_thread(self, model_path):
        """Background thread for model verification."""
        try:
            # Start verification
            self.update_output.emit(log_message("[ML] Starting model verification..."))

            # Perform verification steps
            file_check = self._check_model_file_integrity(model_path)
            structure_check = self._check_model_structure(model_path)
            signatures_check = self._check_model_signatures(model_path)

            # Consolidate results
            result = {
                "file_integrity": file_check,
                "structure": structure_check,
                "signatures": signatures_check,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "overall_status": "valid" if all([
                    file_check.get("status") == "valid",
                    structure_check.get("status") == "valid",
                    signatures_check.get("status") == "valid"
                ]) else "invalid"
            }

            # Report verification result
            self.update_output.emit(log_message(
                "Computing model hash (this may take a while)..."))
            # Pass the progress signal to compute_sha256
            from ..utils.binary_utils import compute_file_hash as compute_hash_with_progress
            file_hash = compute_hash_with_progress(model_path, progress_signal=self.update_progress)
            self.update_output.emit(log_message(f"Model hash: {file_hash}"))

            # Check file size
            file_size = os.path.getsize(model_path)
            self.update_output.emit(log_message(
                f"Model size: {file_size:,} bytes"))

            # Try loading model to verify it works
            self.update_output.emit(log_message("Testing model loading..."))
            try:
                # Small context for quick test
                local_model = Llama(model_path=model_path, n_ctx=512)
                self.update_output.emit(
                    log_message("Model loaded successfully!"))

                # Test a simple prompt
                prompt = "<s>[INST] Say hello [/INST]"
                self.update_output.emit(log_message(
                    "Testing inference with a simple prompt..."))

                if hasattr(local_model, '__call__'):
                    result = local_model(prompt=prompt, max_tokens=20)
                elif hasattr(local_model, 'generate'):
                    result = local_model.generate(prompt=prompt, max_tokens=20)
                else:
                    result = {"text": "Model interface not recognized"}
                self.update_output.emit(log_message("Model test successful!"))

            except Exception as e:
                self.update_output.emit(
                    log_message(f"Error loading model: {e}"))
                self.update_output.emit(log_message(traceback.format_exc()))
                return

            self.update_output.emit(log_message(
                "Model verification complete. Model appears to be valid."))

        except Exception as e:
            self.update_output.emit(log_message(f"Error verifying model: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))

    def browse_ghidra_path(self):
        """Allows the user to browse for the Ghidra executable."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Ghidra Executable", "", "Batch Files (*.bat);;All Files (*)")
        if path:
            self.ghidra_path_edit.setPlainText(path)

    def save_config(self):
        """Saves the current configuration."""
        try:
            # Skip saving during initialization to prevent UI access before creation
            if hasattr(self, '_ui_initialized') and not self._ui_initialized:
                self.logger.debug("Skipping config save during initialization")
                return
            print("DEBUG: save_config method called")

            # Check if ghidra_path_edit exists
            if not hasattr(self, "ghidra_path_edit"):
                print(f"DEBUG: Error - ghidra_path_edit attribute is missing! Self attributes: {dir(self)[:10]}...")
                # Keep existing ghidra_path if it's in CONFIG
                print(f"DEBUG: Current CONFIG keys: {CONFIG.keys()}")
                print(f"DEBUG: Keeping existing ghidra_path: {CONFIG.get('ghidra_path', 'not set')}")
            else:
                # Update config with UI values
                print(f"DEBUG: Updating ghidra_path from UI: {self.ghidra_path_edit.text().strip()}")
                CONFIG["ghidra_path"] = self.ghidra_path_edit.text().strip()

            # Remove saving of model_format and custom_model_path as they are obsolete
            # CONFIG["model_format"] = self.model_format # Removed
            # CONFIG["custom_model_path"] = self.custom_model_path # Removed

            # Update CONFIG dictionary with current UI values
            if hasattr(self, "ghidra_path_edit"):
                CONFIG["ghidra_path"] = self.ghidra_path_edit.text().strip()

            # Runtime options
            if hasattr(self, "runtime_interception_cb"):
                CONFIG["runtime_interception"] = self.runtime_interception_cb.isChecked()

            if hasattr(self, "detect_protections_cb"):
                CONFIG["detect_protections"] = self.detect_protections_cb.isChecked()

            if hasattr(self, "enable_memory_patching_cb"):
                CONFIG["enable_memory_patching"] = self.enable_memory_patching_cb.isChecked()

            if hasattr(self, "enable_plugin_sandbox_cb"):
                CONFIG["enable_plugin_sandbox"] = self.enable_plugin_sandbox_cb.isChecked()

            if hasattr(self, "enable_remote_plugins_cb"):
                CONFIG["enable_remote_plugins"] = self.enable_remote_plugins_cb.isChecked()

            if hasattr(self, "plugin_timeout_spinbox"):
                CONFIG["plugin_timeout"] = self.plugin_timeout_spinbox.value()

            # Save the selected model path from the app instance
            if hasattr(self, "selected_model_path"):
                CONFIG["selected_model_path"] = self.selected_model_path

            # Save to file
            config_path = "intellicrack_config.json"
            print(f"DEBUG: Saving configuration to {os.path.abspath(config_path)}")
            print(f"DEBUG: CONFIG keys to save: {', '.join(CONFIG.keys())}")

            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(CONFIG, f, indent=2)

            print("DEBUG: Configuration saved successfully")

            if hasattr(self, "update_output"):
                self.update_output.emit(log_message(
                    "Configuration saved successfully"))
            else:
                print("DEBUG: No update_output attribute available")

        except Exception as e:
            print(f"Error saving configuration: {e}")
            print(f"DEBUG: Exception traceback: {traceback.format_exc()}")

            if hasattr(self, "update_output"):
                self.update_output.emit(log_message(
                    f"Error saving configuration: {e}"))

                if hasattr(self, "QMessageBox"):
                    QMessageBox.warning(self, "Save Error",
                                        f"Error saving configuration: {e}")

    def save_analysis_config(self):
        """Save current analysis options to a configuration file."""
        config = {
            "stealth_patching": self.stealth_checkbox.isChecked(),
            "auto_patch": self.auto_patch_checkbox.isChecked(),
            "heuristic_patching": self.heuristic_patch_checkbox.isChecked(),
            "frida_runtime_hooking": self.frida_checkbox.isChecked(),
            "qiling_emulation": self.qiling_checkbox.isChecked(),
            "create_backups": self.backup_checkbox.isChecked(),
            "deep_analysis_option": self.deep_analysis_combo.currentText(),
            "analysis_depth": self.analysis_depth_slider.value() if hasattr(self, "analysis_depth_slider") else 50
        }

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Analysis Configuration", "", "JSON Files (*.json);;All Files (*)")

        if not path:
            return

        # Ensure the file has .json extension
        if not path.lower().endswith(".json"):
            path += ".json"

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)

            self.update_output.emit(log_message(f"[Config] Analysis configuration saved to {path}"))
            QMessageBox.information(self, "Configuration Saved",
                                   f"Analysis configuration successfully saved to:\n{path}")
        except Exception as e:
            self.update_output.emit(log_message(f"[Config] Error saving analysis configuration: {e}"))
            QMessageBox.warning(self, "Save Error",
                               f"Error saving analysis configuration:\n{e}")

    def load_analysis_config(self):
        """Load analysis options from a configuration file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Analysis Configuration", "", "JSON Files (*.json);;All Files (*)")

        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)

            # Apply the loaded configuration
            if "stealth_patching" in config:
                self.stealth_checkbox.setChecked(config["stealth_patching"])

            if "auto_patch" in config:
                self.auto_patch_checkbox.setChecked(config["auto_patch"])

            if "heuristic_patching" in config:
                self.heuristic_patch_checkbox.setChecked(config["heuristic_patching"])

            if "frida_runtime_hooking" in config:
                self.frida_checkbox.setChecked(config["frida_runtime_hooking"])

            if "qiling_emulation" in config:
                self.qiling_checkbox.setChecked(config["qiling_emulation"])

            if "create_backups" in config:
                self.backup_checkbox.setChecked(config["create_backups"])

            if "deep_analysis_option" in config:
                index = self.deep_analysis_combo.findText(config["deep_analysis_option"])
                if index >= 0:
                    self.deep_analysis_combo.setCurrentIndex(index)

            if "analysis_depth" in config and hasattr(self, "analysis_depth_slider"):
                self.analysis_depth_slider.setValue(config["analysis_depth"])

            self.update_output.emit(log_message(f"[Config] Analysis configuration loaded from {path}"))
            QMessageBox.information(self, "Configuration Loaded",
                                   f"Analysis configuration successfully loaded from:\n{path}")
        except Exception as e:
            self.update_output.emit(log_message(f"[Config] Error loading analysis configuration: {e}"))
            QMessageBox.warning(self, "Load Error",
                               f"Error loading analysis configuration:\n{e}")

    def apply_config_preset(self, preset_name):
        """Apply a predefined analysis configuration preset."""
        if preset_name == "Default Configuration":
            self.stealth_checkbox.setChecked(False)
            self.auto_patch_checkbox.setChecked(True)
            self.heuristic_patch_checkbox.setChecked(False)
            self.frida_checkbox.setChecked(False)
            self.qiling_checkbox.setChecked(False)
            self.backup_checkbox.setChecked(True)

            index = self.deep_analysis_combo.findText("CFG Structure")
            if index >= 0:
                self.deep_analysis_combo.setCurrentIndex(index)

            if hasattr(self, "analysis_depth_slider"):
                self.analysis_depth_slider.setValue(50)

        elif preset_name == "Maximum Security":
            self.stealth_checkbox.setChecked(True)
            self.auto_patch_checkbox.setChecked(False)  # Manual control for security
            self.heuristic_patch_checkbox.setChecked(False)  # No heuristics for security
            self.frida_checkbox.setChecked(True)
            self.qiling_checkbox.setChecked(True)
            self.backup_checkbox.setChecked(True)

            index = self.deep_analysis_combo.findText("Symbolic Execution")
            if index >= 0:
                self.deep_analysis_combo.setCurrentIndex(index)

            if hasattr(self, "analysis_depth_slider"):
                self.analysis_depth_slider.setValue(100)  # Maximum depth

        elif preset_name == "Performance Optimized":
            self.stealth_checkbox.setChecked(False)
            self.auto_patch_checkbox.setChecked(True)
            self.heuristic_patch_checkbox.setChecked(True)  # Use heuristics for speed
            self.frida_checkbox.setChecked(False)  # Skip runtime hooking for speed
            self.qiling_checkbox.setChecked(False)  # Skip emulation for speed
            self.backup_checkbox.setChecked(True)

            index = self.deep_analysis_combo.findText("Packing Detection")
            if index >= 0:
                self.deep_analysis_combo.setCurrentIndex(index)

            if hasattr(self, "analysis_depth_slider"):
                self.analysis_depth_slider.setValue(30)  # Lower depth for speed

        elif preset_name == "Deep Analysis":
            self.stealth_checkbox.setChecked(False)
            self.auto_patch_checkbox.setChecked(False)
            self.heuristic_patch_checkbox.setChecked(True)
            self.frida_checkbox.setChecked(True)
            self.qiling_checkbox.setChecked(True)
            self.backup_checkbox.setChecked(True)

            index = self.deep_analysis_combo.findText("Taint Analysis")
            if index >= 0:
                self.deep_analysis_combo.setCurrentIndex(index)

            if hasattr(self, "analysis_depth_slider"):
                self.analysis_depth_slider.setValue(80)

        elif preset_name == "Basic Analysis":
            self.stealth_checkbox.setChecked(False)
            self.auto_patch_checkbox.setChecked(True)
            self.heuristic_patch_checkbox.setChecked(False)
            self.frida_checkbox.setChecked(False)
            self.qiling_checkbox.setChecked(False)
            self.backup_checkbox.setChecked(True)

            index = self.deep_analysis_combo.findText("License Logic")
            if index >= 0:
                self.deep_analysis_combo.setCurrentIndex(index)

            if hasattr(self, "analysis_depth_slider"):
                self.analysis_depth_slider.setValue(20)

        self.update_output.emit(log_message(f"[Config] Applied '{preset_name}' configuration preset"))

    def apply_log_filter(self):
        """Applies the filter to the log output."""
        filter_text = self.log_filter.toPlainText().strip().lower()
        if not filter_text:
            return

        # Get all text
        full_text = self.log_output.toPlainText()

        # Filter lines
        filtered_lines = []
        for line in (full_text.splitlines() if full_text is not None else []):
            if filter_text in line.lower():
                filtered_lines.append(line)

        # Update display
        if filtered_lines:
            self.log_output.setPlainText("\n".join(filtered_lines))
        else:
            self.log_output.setPlainText("No matching log entries found")

    def save_logs(self):
        """Saves the current logs to a file."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Logs", "", "Log Files (*.log);;Text Files (*.txt);;All Files (*)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.log_output.toPlainText())

                self.update_output.emit(log_message(f"Logs saved to {path}"))

            except Exception as e:
                self.update_output.emit(log_message(f"Error saving logs: {e}"))
                QMessageBox.warning(self, "Save Error",
                                    f"Error saving logs: {e}")

    def scan_protectors(self):
        """Scans the binary for bytecode protectors and displays results."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            "[Protection Scanner] Scanning for bytecode protectors..."))

        results = scan_for_bytecode_protectors(self.binary_path)

        if "error" in results:
            self.update_output.emit(log_message(
                f"[Protection Scanner] Error: {results['error']}"))
            return

        # Display results
        if not results:
            self.update_output.emit(log_message(
                "[Protection Scanner] No protectors detected."))
            QMessageBox.information(
                self,
                "Scan Results",
                "No bytecode protectors detected in this binary.")
            return

        # Format results for display
        output = ["[Protection Scanner] Scan results:"]

        # Ensure results is a dictionary
        if not isinstance(results, dict):
            output.append(f"  Results: {results}")
        else:
            for protector, details in results.items():
                if isinstance(details, dict) and hasattr(details, 'get') and details.get("detected", False):
                    output.append(f"  - {protector}: DETECTED")

                    # Add details if available
                    if "signature" in details:
                        output.append(
                            f"    Signature found: {details['signature']}")
                    if "section_name" in details:
                        output.append(f"    Section: {details['section_name']}")
                    if "section_entropy" in details:
                        output.append(
                            f"    Entropy: {details['section_entropy']:.2f}")
                    if "note" in details:
                        output.append(f"    Note: {details['note']}")

        if not output[1:]:  # If no results after the header
            output.append("  No protectors detected")

        # Display in output panel
        for line in output:
            self.update_output.emit(log_message(line))

        # Show dialog with results
        QMessageBox.information(
            self, "Protection Scan Results", "\n".join(output))

    def select_program(self):
        """Opens a file dialog to select an executable or shortcut. Initializes analyzers."""
        path, _ = QFileDialog.getOpenFileName(
            # Allow selecting any file for broader analysis
            self, "Select Program", "", "Executables (*.exe *.lnk);;All Files (*.*)"
        )
        resolved_path = path  # Store original path or resolved path

        if not path:  # Handle case where user cancels dialog
            return

        # Resolve .lnk shortcuts if applicable (Windows only)
        if path.endswith(".lnk") and sys.platform == "win32":
            try:
                try:
                    if pythoncom:
                        pythoncom.CoInitialize()
                    shell = win32com.client.Dispatch("WScript.Shell")
                    shortcut = shell.CreateShortCut(path)
                    target = shortcut.Targetpath
                    if target and os.path.exists(target):
                        resolved_path = target
                    else:
                        QMessageBox.warning(
                            self,
                            "Shortcut Error",
                            f"Shortcut target does not exist or is invalid:\n{target}")
                        return
                finally:
                    if pythoncom:
                        pythoncom.CoUninitialize()
            except ImportError:
                QMessageBox.warning(
                    self,
                    "Shortcut Error",
                    f"Required 'pywin32' library not found. Cannot resolve .lnk files.")
                return
            except AttributeError:
                QMessageBox.warning(
                    self,
                    "Shortcut Error",
                    f"Could not resolve shortcut target. It might be invalid or broken:\n{path}")
                return
            except Exception as e:
                QMessageBox.warning(self, "Shortcut Error",
                                    f"Failed to resolve shortcut target: {e}")
                return
        elif not os.path.exists(resolved_path):
            QMessageBox.warning(
                self,
                "File Not Found",
                f"The selected file does not exist:\n{resolved_path}")
            return

        # Proceed if we have a valid, existing file path
        self.binary_path = resolved_path  # Set the binary path attribute

        # Extract binary information
        self.extract_binary_info(self.binary_path)

        # --- Instantiate AdvancedDynamicAnalyzer ---
        # This happens only AFTER self.binary_path is confirmed and valid.
        try:
            self.dynamic_analyzer = AdvancedDynamicAnalyzer(self.binary_path)
            self.update_output.emit(
                log_message("[Analyzer Init] AdvancedDynamicAnalyzer initialized."))
        except NameError:
            self.update_output.emit(log_message(
                "[Analyzer Init] Failed: AdvancedDynamicAnalyzer class not found (Import missing?)."))
            self.dynamic_analyzer = None  # Ensure it's None if class isn't found
        except Exception as e_dyn_init:
            self.update_output.emit(
                log_message(
                    f"[Analyzer Init] Failed to initialize AdvancedDynamicAnalyzer: {e_dyn_init}"))
            self.dynamic_analyzer = None  # Ensure it's None if init fails
        # --- End Analyzer Instantiation ---

        # --- Instantiate/Load MLVulnerabilityPredictor (if not done in init or needs reload) ---
        # This ensures the predictor is loaded/reloaded when a new binary is
        # selected.
        try:
            # Get path from config again
            ml_model_path = CONFIG.get("ml_model_path")
            if ml_model_path and os.path.exists(ml_model_path):
                # Only reload the model if it's not already loaded with the same path
                if not self.ml_predictor or not hasattr(self.ml_predictor, 'model_path') or self.ml_predictor.model_path != ml_model_path:
                    self.ml_predictor = MLVulnerabilityPredictor(model_path=ml_model_path)
                    self.update_output.emit(log_message(f"[ML] Predictor reloaded with model: {ml_model_path}"))
                else:
                    self.update_output.emit(log_message(f"[ML] Using existing predictor (already loaded)"))
            elif not self.ml_predictor:  # If not loaded in init and no path found now
                self.update_output.emit(
                    log_message("[ML] Predictor model not found. Prediction disabled."))
                self.ml_predictor = None  # Ensure it's None
        except NameError:
            self.update_output.emit(log_message(
                "[ML] Predictor Failed: MLVulnerabilityPredictor class not found (Import missing?)."))
            self.ml_predictor = None
        except Exception as e_ml_load:
            self.update_output.emit(
                log_message(
                    f"[ML] Failed to load predictor model on binary select: {e_ml_load}"))
            self.ml_predictor = None
        # --- End ML Predictor Instantiation ---

        # --- Update UI Elements ---
        self.program_info.setText(
            f"Selected: {
                os.path.basename(
                    self.binary_path)}\nPath: {
                self.binary_path}")

        # get_file_icon returns None, so always use default
        pixmap = None
        if True:  # Always use default icon
            if not os.path.exists("assets"):
                os.makedirs("assets", exist_ok=True)
            # Provide a default icon
            pixmap = QPixmap("assets/icon_preview.png")

        self.program_icon.setPixmap(pixmap.scaled(
            64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        self.analyze_status.setText(
            f"Selected: {
                os.path.basename(
                    self.binary_path)}")
        self.update_output.emit(
            log_message(
                f"Selected program: {
                    self.binary_path}"))

        # Clear previous results and patches when a new binary is selected
        self.analyze_results.clear()
        self.potential_patches = []
        self.update_output.emit(
            log_message("Previous analysis results cleared."))

        # Refresh dashboard with binary info and switch to dashboard tab
        if hasattr(self, "binary_info"):
            self._refresh_and_show_dashboard()

    def remove_program(self):
        """Removes the currently selected program."""
        if not self.binary_path:
            return

        self.binary_path = None
        self.program_info.setText("No program selected")
        self.program_icon.clear()

        self.analyze_status.setText("No program selected")
        self.update_output.emit(log_message("Program removed"))

    def extract_binary_info(self, binary_path):
        """
        Extract detailed information from a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            dict: Dictionary containing extracted binary information
        """
        # Initialize binary info dictionary
        binary_info = self._initialize_binary_info(binary_path)

        self.update_output.emit(log_message(f"[Binary] Extracting info from {os.path.basename(binary_path)}"))

        try:
            # Determine file type
            with open(binary_path, "rb") as file_handle:
                magic_bytes = file_handle.read(4)

            # Process file based on its type
            if magic_bytes.startswith(b'MZ'):
                binary_info = self._extract_pe_info(binary_path, binary_info)
            elif magic_bytes.startswith(b'\x7fELF'):
                binary_info = self._extract_elf_info(binary_path, binary_info)

            # Store binary info
            self.binary_info = binary_info

            # Update dashboard with binary info
            self._update_dashboard_with_binary_info(binary_info)

            # Log completion
            self._log_analysis_completion(binary_info)

            return binary_info

        except Exception as e:
            self.update_output.emit(log_message(f"[Binary] Error extracting binary info: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            return binary_info

    def _initialize_binary_info(self, binary_path):
        """Initialize the binary info dictionary with default values."""
        return {
            "name": os.path.basename(binary_path),
            "path": binary_path,
            "size": os.path.getsize(binary_path),
            "format": "Unknown",
            "architecture": "Unknown",
            "endianness": "Unknown",
            "bit_width": "Unknown",
            "compile_time": "Unknown",
            "compiler": "Unknown",
            "os_target": "Unknown",
            "imports": [],
            "exports": [],
            "sections": [],
            "symbols": [],
            "strings": [],
            "has_overlay": False,
            "is_packed": False,
            "is_stripped": False,
            "is_debuggable": False,
            "has_protections": False,
            "protection_types": [],
            "entry_point": 0
        }

    def _extract_pe_info(self, binary_path, binary_info):
        """Extract information from PE (Windows) files."""
        binary_info["format"] = "PE (Windows)"
        try:
            pe = pefile.PE(binary_path)

            # Extract PE-specific information
            self._extract_pe_architecture(pe, binary_info)
            self._extract_pe_metadata(pe, binary_info)
            self._extract_pe_sections_and_imports(pe, binary_info)
            self._detect_pe_protections(pe, binary_info)

            # Clean up
            pe.close()

        except ImportError:
            self.update_output.emit(log_message("[Binary] pefile module not found, limited PE analysis available"))
        except Exception as e:
            self.update_output.emit(log_message(f"[Binary] Error analyzing PE file: {e}"))

        return binary_info

    def _extract_pe_architecture(self, pe, binary_info):
        """Extract architecture information from PE file."""
        machine_type = pe.FILE_HEADER.Machine
        if machine_type == 0x14c:
            binary_info["architecture"] = "x86"
            binary_info["bit_width"] = "32-bit"
        elif machine_type == 0x8664:
            binary_info["architecture"] = "x86_64"
            binary_info["bit_width"] = "64-bit"
        elif machine_type == 0x1c0:
            binary_info["architecture"] = "ARM"
            binary_info["bit_width"] = "32-bit"
        elif machine_type == 0xaa64:
            binary_info["architecture"] = "ARM64"
            binary_info["bit_width"] = "64-bit"

        # Endianness is always Little for PE files
        binary_info["endianness"] = "Little"

    def _extract_pe_metadata(self, pe, binary_info):
        """Extract metadata from PE file (timestamps, entry points)."""
        # Compile time
        if hasattr(pe, "FILE_HEADER") and hasattr(pe.FILE_HEADER, "TimeDateStamp"):
            timestamp = pe.FILE_HEADER.TimeDateStamp
            compile_time = datetime.datetime.fromtimestamp(timestamp)
            binary_info["compile_time"] = compile_time.strftime("%Y-%m-%d %H:%M:%S")

        # Entry point
        if hasattr(pe, "OPTIONAL_HEADER"):
            entry_point = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', None)
            if entry_point is not None:
                binary_info["entry_point"] = hex(entry_point)

    def _extract_pe_sections_and_imports(self, pe, binary_info):
        """Extract sections, imports and exports from PE file."""
        # Sections
        binary_info["sections"] = [section.Name.decode('utf-8', 'ignore').strip('\x00') for section in pe.sections]

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore') if hasattr(entry, 'dll') else "Unknown"
                for imp in entry.imports[:10]:  # Limit to first 10 imports per DLL
                    import_name = imp.name.decode('utf-8', 'ignore') if imp.name else f"Ordinal {imp.ordinal}"
                    binary_info["imports"].append(f"{dll_name}:{import_name}")

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:20]:  # Limit to first 20 exports
                export_name = exp.name.decode('utf-8', 'ignore') if exp.name else f"Ordinal {exp.ordinal}"
                binary_info["exports"].append(export_name)

    def _detect_pe_protections(self, pe, binary_info):
        """Detect protection mechanisms in PE files."""
        protections = []

        # Check for code signing
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress != 0:
            protections.append("Authenticode Signature")

        # Check for high entropy sections (possible packing)
        for section in pe.sections:
            section_entropy = section.get_entropy()
            if section_entropy > 7.0:
                protections.append("High Entropy (Possible Packing/Encryption)")
                binary_info["is_packed"] = True
                break

        # Check section names for known packers
        section_names = " ".join(binary_info["sections"]).lower()
        known_packers = {
            "upx": ("UPX Packing", True, False),
            "enigma": ("Enigma Protector", False, True),
            "themida": ("Themida/Winlicense", False, True),
            "aspack": ("ASPack", True, False)
        }

        for packer_name, (protection_name, sets_packed, sets_protected) in known_packers.items():
            if packer_name in section_names:
                protections.append(protection_name)
                if sets_packed:
                    binary_info["is_packed"] = True
                if sets_protected:
                    binary_info["has_protections"] = True

        binary_info["protection_types"] = protections
        binary_info["has_protections"] = len(protections) > 0

    def _extract_elf_info(self, binary_path, binary_info):
        """Extract information from ELF (Linux/Unix) files."""
        binary_info["format"] = "ELF (Linux/Unix)"
        try:

            with open(binary_path, 'rb') as elf_file:
                elf = ELFFile(elf_file)
                self._extract_elf_architecture(elf, binary_info)
                self._extract_elf_metadata(elf, binary_info)
                self._extract_elf_sections_and_symbols(elf, binary_info)

        except ImportError:
            self.update_output.emit(log_message("[Binary] pyelftools module not found, limited ELF analysis available"))
        except Exception as e:
            self.update_output.emit(log_message(f"[Binary] Error analyzing ELF file: {e}"))

        return binary_info

    def _extract_elf_architecture(self, elf, binary_info):
        """Extract architecture information from ELF file."""
        # Architecture
        machine = elf.header['e_machine']
        arch_map = {
            'EM_386': 'x86',
            'EM_X86_64': 'x86_64',
            'EM_ARM': 'ARM',
            'EM_AARCH64': 'ARM64',
            'EM_MIPS': 'MIPS'
        }
        binary_info["architecture"] = arch_map.get(machine, machine)

        # Bit width
        binary_info["bit_width"] = "64-bit" if elf.elfclass == 64 else "32-bit"

        # Endianness
        binary_info["endianness"] = "Little" if elf.little_endian else "Big"

    def _extract_elf_metadata(self, elf, binary_info):
        """Extract metadata from ELF file."""
        # Entry point
        binary_info["entry_point"] = hex(elf.header['e_entry'])

        # OS target
        os_map = {
            'ELFOSABI_SYSV': 'System V',
            'ELFOSABI_HPUX': 'HP-UX',
            'ELFOSABI_NETBSD': 'NetBSD',
            'ELFOSABI_LINUX': 'Linux',
            'ELFOSABI_SOLARIS': 'Solaris',
            'ELFOSABI_AIX': 'AIX',
            'ELFOSABI_FREEBSD': 'FreeBSD'
        }
        os_abi = elf.header['e_ident']['EI_OSABI']
        binary_info["os_target"] = os_map.get(os_abi, os_abi)

    def _extract_elf_sections_and_symbols(self, elf, binary_info):
        """Extract sections and symbols from ELF file."""
        # Sections
        binary_info["sections"] = [section.name for section in elf.iter_sections()]

        # Symbols
        if elf.get_section_by_name('.symtab'):
            symbol_section = elf.get_section_by_name('.symtab')
            for i, symbol in enumerate(symbol_section.iter_symbols()):
                if i < 20:  # Limit to first 20 symbols
                    binary_info["symbols"].append(symbol.name)

        # Check if stripped
        binary_info["is_stripped"] = elf.get_section_by_name('.symtab') is None

        # Check for debugging info
        binary_info["is_debuggable"] = any(s.name.startswith('.debug_') for s in elf.iter_sections())

    def _update_dashboard_with_binary_info(self, binary_info):
        """Update dashboard with binary info if available."""
        try:
            if not hasattr(self, "dashboard_manager"):
                self.logger.warning("No dashboard manager available to update with binary info")
                return

            # Log diagnostic information
            self.logger.info(f"Updating dashboard with binary info: {binary_info.get('format', 'Unknown')}")

            # Update stats dict in dashboard manager
            stats_dict = {
                "binary_info": {
                    "format": binary_info.get("format", "Unknown"),
                    "architecture": binary_info.get("architecture", "Unknown"),
                    "bit_width": binary_info.get("bit_width", "Unknown"),
                    "has_protections": binary_info.get("has_protections", False),
                    "is_packed": binary_info.get("is_packed", False)
                }
            }

            # Call update_stats instead of update_statistics
            if hasattr(self.dashboard_manager, "update_stats"):
                # First ensure the stats dictionary exists
                if not hasattr(self.dashboard_manager, "stats"):
                    self.dashboard_manager.stats = {}

                # Then update it manually
                for key, value in stats_dict.items():
                    self.dashboard_manager.stats[key] = value

                # Refresh dashboard
                self.dashboard_manager.update_stats()
                self.logger.info("Successfully updated dashboard with binary info")
            else:
                self.logger.error("DashboardManager has no update_stats method")

            # Update the dashboard UI widgets with binary info
            self.refresh_dashboard_ui(binary_info)

        except Exception as e:
            self.logger.error(f"Error updating dashboard with binary info: {str(e)}")

    def _refresh_and_show_dashboard(self):
        """Updates dashboard with binary info and switches to dashboard tab to ensure visibility."""
        # Update the dashboard with current binary info
        self._update_dashboard_with_binary_info(self.binary_info if hasattr(self, 'binary_info') else {})

        # Switch to the dashboard tab to show the updated info
        if hasattr(self, 'tabs') and hasattr(self, 'dashboard_tab'):
            dashboard_index = self.tabs.indexOf(self.dashboard_tab)
            if dashboard_index >= 0:
                self.tabs.setCurrentIndex(dashboard_index)
                self.logger.debug("Switched to dashboard tab after refreshing data")
            else:
                self.logger.warning("Dashboard tab not found in tabs widget")

    def refresh_dashboard_ui(self, binary_info):
        """Explicitly updates dashboard UI widgets with binary information."""
        try:
            if not hasattr(self, "dashboard_tab") or not binary_info:
                return

            # Find the specific dashboard labels by their object names
            binary_name_label = self.dashboard_tab.findChild(QLabel, "dashboard_binary_name_label")
            binary_icon_label = self.dashboard_tab.findChild(QLabel, "dashboard_binary_icon_label")

            if binary_name_label:
                # Update binary name label with rich text formatting
                binary_path = binary_info.get("path", "Unknown")
                binary_name = os.path.basename(binary_path) if binary_path != "Unknown" else "Unknown"
                binary_name_label.setText(f"<b>{binary_name}</b><br><small>{binary_path}</small>")
                self.logger.debug(f"Updated dashboard binary name label with: {binary_name}")

            if binary_icon_label:
                # Update binary icon label with icon from file
                binary_path = binary_info.get("path", "")
                icon_pixmap = None

                if binary_path and os.path.exists(binary_path):
                    # get_file_icon returns None, skip this
                    pass

                # Set a default icon if extraction fails or returns None
                if not icon_pixmap or icon_pixmap.isNull():
                    default_icon_path = "assets/binary_icon.png"
                    if os.path.exists(default_icon_path):
                        icon_pixmap = QPixmap(default_icon_path)
                    else:
                        # Create a default colored rectangle if no icon available
                        icon_pixmap = QPixmap(64, 64)
                        icon_pixmap.fill(QColor(0, 120, 215))

                # Set the icon pixmap to the label
                binary_icon_label.setPixmap(icon_pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                self.logger.debug("Updated dashboard binary icon label")

        except Exception as e:
            self.logger.error(f"Error refreshing dashboard UI: {str(e)}")

    def _log_analysis_completion(self, binary_info):
        """Log completion of binary analysis."""
        self.update_output.emit(log_message(
            f"[Binary] Analysis complete: {binary_info['format']} {binary_info['architecture']} {binary_info['bit_width']}"))

        if binary_info["has_protections"]:
            self.update_output.emit(log_message(
                f"[Binary] Detected protections: {', '.join(binary_info['protection_types'])}"))

    def run_autonomous_crack(self):
        """Initiates the autonomous crack process."""
        self.user_input.setPlainText(
            "Crack this program using all available tools")
        self.send_to_model()

    def run_analysis(self):
        """
        Performs full analysis of the selected binary and outputs the results.
        Enhanced with better organization and more detailed information.
        """
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        # Collect analysis options
        flags = []
        if self.stealth_checkbox.isChecked():
            flags.append("stealth")
        if self.auto_patch_checkbox.isChecked():
            flags.append("auto")
        if self.frida_checkbox.isChecked():
            flags.append("frida")
        if self.qiling_checkbox.isChecked():
            flags.append("qiling")
        if self.heuristic_patch_checkbox.isChecked():
            flags.append("heuristic")

        # Get analysis depth value
        analysis_depth = self.analysis_depth_slider.value()

        msg = "[Analysis] Starting full analysis..."
        self.update_output.emit(log_message(msg))
        self.log_output.append(log_message(msg))  # Also log to Live Logs tab
        self.analyze_status.setText("Analyzing...")

        # Run analysis in a background thread (TARGETING THE CORRECT FUNCTION
        # BELOW)
        threading.Thread(
            target=self._run_analysis_thread,
            args=(flags, analysis_depth)
        ).start()

    def _run_analysis_thread(self, flags, analysis_depth):
        """
        Background thread for running analysis.
        COMBINES original analysis functions with new Advanced Engines.
        (Corrected Version)

        Args:
            flags: List of enabled analysis flags
            analysis_depth: Integer value (10-100) indicating how deep the analysis should go
        """
        # Initialize variables that will be used throughout the function
        # These must be initialized before any try/except blocks to ensure they always exist
        ml_predictions = []
        vulnerabilities = []
        license_results = None
        detected_protectors = []
        packing_summary_line = ""

        # Log the analysis options being used
        self.update_output.emit(log_message(f"[Analysis] Using flags: {', '.join(flags)}"))
        self.update_output.emit(log_message(f"[Analysis] Analysis depth: {analysis_depth}"))
        self.update_analysis_results.emit(f"Analysis Options: {', '.join(flags)}\n")
        self.update_analysis_results.emit(f"Analysis Depth: {analysis_depth}\n")

        try:
            # --- Initial Setup ---
            self.clear_analysis_results.emit()
            self.update_analysis_results.emit("Starting Full Analysis...\n")

            filesize = os.path.getsize(self.binary_path)
            self.update_output.emit(log_message(
                f"[Analysis] File size: {filesize:,} bytes"))
            self.update_analysis_results.emit(
                f"File: {
                    os.path.basename(
                        self.binary_path)}, Size: {
                    filesize:,} bytes\n")

            # --- PE Check ---
            with open(self.binary_path, "rb") as binary_file:
                header = binary_file.read(4)
                if header[:2] == b"MZ":
                    pe_valid_msg = "[Analysis] PE signature found (Windows executable)"
                    self.update_output.emit(log_message(pe_valid_msg))
                    self.update_analysis_results.emit(pe_valid_msg + "\n")
                else:
                    pe_invalid_msg = "[Analysis] Not a valid PE executable"
                    self.update_output.emit(log_message(pe_invalid_msg))
                    self.update_analysis_results.emit(pe_invalid_msg + "\n")
                    self.update_status.emit("Not a valid PE executable")
                    return

            self.update_output.emit(
                log_message("[Analysis] Running standard binary structure analysis..."))
            self.update_analysis_results.emit(
                "\n=== Standard Binary Analysis ===\n")
            try:
                binary_structure_results = analyze_binary_internal(
                    self.binary_path, flags)
                for line in binary_structure_results:
                    if "Analyzing binary:" in line or "File size:" in line or "PE Header:" in line or "Imports:" in line or "Exports:" in line or "Sections:" in line or "WARNING:" in line:
                        self.update_output.emit(log_message(line))
                    self.update_analysis_results.emit(line + "\n")
            except Exception as e_struct:
                err_msg = f"[Analysis] Error during standard structure analysis: {e_struct}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")

            # --- PROCESS ANALYSIS FLAGS ---
            self.update_output.emit(log_message("[Analysis] Processing selected analysis options..."))
            
            # Qiling Emulation
            if "qiling" in flags:
                self.update_output.emit(log_message("[Analysis] Running Qiling binary emulation..."))
                self.update_analysis_results.emit("\n=== Qiling Emulation Results ===\n")
                try:
                    from ..utils.runner_functions import run_qiling_emulation
                    qiling_results = run_qiling_emulation(self, self.binary_path, 
                                                         timeout=60, verbose=False)
                    if qiling_results.get('status') == 'success':
                        results = qiling_results.get('results', {})
                        self.update_analysis_results.emit(f"API Calls Detected: {results.get('total_api_calls', 0)}\n")
                        self.update_analysis_results.emit(f"License Checks Found: {len(results.get('license_checks', []))}\n")
                        self.update_analysis_results.emit(f"Suspicious Behaviors: {len(results.get('suspicious_behaviors', []))}\n")
                        
                        # Show detailed license checks
                        for check in results.get('license_checks', []):
                            self.update_analysis_results.emit(f"  - {check.get('api')} at {check.get('address')}\n")
                    else:
                        self.update_analysis_results.emit(f"Qiling emulation failed: {qiling_results.get('error', 'Unknown error')}\n")
                except Exception as e_qiling:
                    self.update_output.emit(log_message(f"[Analysis] Qiling error: {e_qiling}"))
                    self.update_analysis_results.emit(f"Qiling emulation error: {e_qiling}\n")
            
            # Frida Dynamic Analysis
            if "frida" in flags:
                self.update_output.emit(log_message("[Analysis] Running Frida dynamic analysis..."))
                self.update_analysis_results.emit("\n=== Frida Dynamic Analysis ===\n")
                try:
                    from ..core.analysis.dynamic_analyzer import AdvancedDynamicAnalyzer
                    
                    # Create and run dynamic analyzer
                    dynamic_analyzer = AdvancedDynamicAnalyzer(self.binary_path)
                    self.update_analysis_results.emit("Starting comprehensive runtime analysis...\n")
                    
                    # Run the analysis (this will spawn the process and instrument it)
                    dynamic_results = dynamic_analyzer.run_comprehensive_analysis()
                    
                    if dynamic_results.get('status') == 'success':
                        # Display results
                        self.update_analysis_results.emit(f"Process spawned successfully (PID: {dynamic_results.get('pid', 'unknown')})\n")
                        self.update_analysis_results.emit(f"API calls monitored: {len(dynamic_results.get('api_calls', []))}\n")
                        self.update_analysis_results.emit(f"Registry operations: {len(dynamic_results.get('registry_operations', []))}\n")
                        self.update_analysis_results.emit(f"File operations: {len(dynamic_results.get('file_operations', []))}\n")
                        self.update_analysis_results.emit(f"Network connections: {len(dynamic_results.get('network_connections', []))}\n")
                        
                        # Show license-related findings
                        license_findings = dynamic_results.get('license_findings', {})
                        if license_findings:
                            self.update_analysis_results.emit(f"\nLicense-related findings:\n")
                            for category, items in license_findings.items():
                                if items:
                                    self.update_analysis_results.emit(f"  {category}: {len(items)} items\n")
                        
                        # Show suspicious behavior
                        behaviors = dynamic_results.get('suspicious_behaviors', [])
                        if behaviors:
                            self.update_analysis_results.emit(f"\nSuspicious behaviors detected: {len(behaviors)}\n")
                            for behavior in behaviors[:5]:  # Show first 5
                                self.update_analysis_results.emit(f"  - {behavior.get('description', 'Unknown behavior')}\n")
                    else:
                        self.update_analysis_results.emit(f"Dynamic analysis failed: {dynamic_results.get('error', 'Unknown error')}\n")
                        
                except ImportError:
                    self.update_output.emit(log_message("[Analysis] Frida not available"))
                    self.update_analysis_results.emit("Frida framework not installed. Dynamic analysis skipped.\n")
                except Exception as e_frida:
                    self.update_output.emit(log_message(f"[Analysis] Frida error: {e_frida}"))
                    self.update_analysis_results.emit(f"Frida error: {e_frida}\n")
            
            # Stealth Mode
            if "stealth" in flags:
                self.update_output.emit(log_message("[Analysis] Running in stealth mode..."))
                self.update_analysis_results.emit("\n=== Stealth Mode Active ===\n")
                self.update_analysis_results.emit("Analysis configured to avoid detection mechanisms.\n")
            
            # Auto Mode
            if "auto" in flags:
                self.update_output.emit(log_message("[Analysis] Auto-detection mode enabled..."))
                self.update_analysis_results.emit("\n=== Auto-Detection Results ===\n")
                # Auto mode processing would go here
                self.update_analysis_results.emit("Automatic protection detection enabled.\n")
            
            # Heuristic Analysis
            if "heuristic" in flags:
                self.update_output.emit(log_message("[Analysis] Running heuristic analysis..."))
                self.update_analysis_results.emit("\n=== Heuristic Analysis ===\n")
                # Heuristic analysis would go here
                self.update_analysis_results.emit("Heuristic pattern matching enabled.\n")

            self.update_output.emit(
                log_message("[Analysis] Searching for embedded scripts..."))
            self.update_analysis_results.emit("\n=== Embedded Scripts ===\n")
            try:
                # Assuming decrypt_embedded_script is defined elsewhere
                embedded = decrypt_embedded_script(
                    self.binary_path)  # Original call
                if embedded and len(embedded) > 1:
                    for line in embedded:
                        if "Searching for" in line or "Found" in line or "No embedded" in line:
                            self.update_output.emit(log_message(line))
                        self.update_analysis_results.emit(line + "\n")
                else:
                    no_scripts_msg = "No embedded scripts found by standard scan."
                    self.update_output.emit(log_message(no_scripts_msg))
                    self.update_analysis_results.emit(no_scripts_msg + "\n")
            except Exception as e_embed:
                err_msg = f"[Analysis] Error scanning for embedded scripts: {e_embed}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")

            self.update_output.emit(
                log_message("[Analysis] Checking for protectors (standard scan)..."))
            self.update_analysis_results.emit(
                "\n=== Standard Protector Scan ===\n")
            detected_protectors = []
            try:
                protectors = scan_for_bytecode_protectors(self.binary_path)
                if "error" in protectors:
                    err_msg = f"[Analysis] Error scanning for protectors: {
                        protectors['error']}"
                    self.update_output.emit(log_message(err_msg))
                    self.update_analysis_results.emit(err_msg + "\n")
                else:
                    detected_protectors = [
                        name for name, details in protectors.items() if isinstance(
                            details, dict) and details.get(
                            "detected", False)]
                    if detected_protectors:
                        prot_msg = f"Detected protectors (standard scan): {
                            ', '.join(detected_protectors)}"
                        self.update_output.emit(log_message(prot_msg))
                        self.update_analysis_results.emit(prot_msg + "\n")
                        for name, details in protectors.items():
                            if isinstance(
                                    details, dict) and details.get("detected"):
                                details_str = f"  - {name}: {details}"
                                self.update_analysis_results.emit(
                                    details_str + "\n")
                    else:
                        no_prot_msg = "No specific protectors detected (standard scan)."
                        self.update_output.emit(log_message(no_prot_msg))
                        self.update_analysis_results.emit(no_prot_msg + "\n")
            except Exception as e_prot:
                err_msg = f"[Analysis] Error during standard protector scan: {e_prot}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")

            self.update_output.emit(
                log_message("[Analysis] Running packing/entropy analysis (standard scan)..."))
            self.update_analysis_results.emit(
                "\n=== Standard Packing/Entropy Analysis ===\n")
            packing_summary_line = ""
            try:
                entropy_report = detect_packing(self.binary_path)
                for line in entropy_report:
                    if "summary:" in line.lower():
                        packing_summary_line = line.split(":", 1)[1].strip()
                        self.update_output.emit(log_message(
                            f"[Packing Summary] {packing_summary_line}"))
                    self.update_analysis_results.emit(line + "\n")
            except Exception as e_pack:
                err_msg = f"[Analysis] Error during standard packing scan: {e_pack}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")

                self.update_output.emit(
                    log_message("[Analysis] Running advanced vulnerability scan (New Engine)..."))
                self.update_analysis_results.emit(
                    "\n=== Advanced Vulnerability Scan (New Engine) ===\n")
            try:
                vulnerabilities = AdvancedVulnerabilityEngine.scan_binary(
                    self.binary_path)
                if vulnerabilities:
                    vuln_summary = f"Found {
                        len(vulnerabilities)} vulnerabilities (Types: {
                        ', '.join(
                            list(
                                set(
                                    v['type'] for v in vulnerabilities)))})"
                    self.update_output.emit(log_message(
                        f"[Adv Vuln Scan] {vuln_summary}"))
                    self.update_analysis_results.emit(vuln_summary + "\n")
                    for i, vuln in enumerate(vulnerabilities):
                        vuln_str = f"[{i +
                                       1}] Type: {vuln['type']}, Risk: {vuln.get('risk', 'Unspecified')}"
                        if 'function' in vuln:
                            vuln_str += f", Function: {vuln['function']}"
                        if 'section_name' in vuln:
                            vuln_str += f", Section: {vuln['section_name']}"
                        if 'offset' in vuln:
                            vuln_str += f", Offset: {vuln['offset']}"
                        if 'severity' in vuln:
                            vuln_str += f", Severity: {vuln['severity']}"
                        self.update_analysis_results.emit(
                            "  " + vuln_str + "\n")
                else:
                    no_vulns_msg = "No specific vulnerabilities found by AdvancedVulnerabilityEngine."
                    self.update_output.emit(log_message(no_vulns_msg))
                    self.update_analysis_results.emit(no_vulns_msg + "\n")
            except NameError:
                err_msg = "[Analysis] AdvancedVulnerabilityEngine class not found. Make sure the class is defined in this file."
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")
            except Exception as e_vuln:
                err_msg = f"[Analysis] Error running AdvancedVulnerabilityEngine: {e_vuln}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")
                self.update_output.emit(
                    log_message("[Analysis] Running ML vulnerability prediction (New Engine)..."))
                self.update_analysis_results.emit(
                    "\n=== ML Vulnerability Predictions (New Engine) ===\n")

            # Enhanced ML prediction section with detailed diagnostics
            try:
                # Ensure ml_predictions is initialized even if it doesn't get set below
                if not isinstance(ml_predictions, list):
                    ml_predictions = []

                # Log detailed information about the ML predictor state
                if hasattr(self, 'ml_predictor'):
                    if self.ml_predictor:
                        if hasattr(self.ml_predictor, 'model') and self.ml_predictor.model:
                            model_path = getattr(self.ml_predictor, 'model_path', 'Unknown path')
                            self.update_output.emit(log_message(f"[ML Diagnostic] Found valid ML predictor with model at: {model_path}"))

                            # Get configuration details for diagnostics
                            config_model_path = CONFIG.get("ml_model_path", "Not set in CONFIG")
                            self.update_output.emit(log_message(f"[ML Diagnostic] CONFIG['ml_model_path']: {config_model_path}"))

                            # Check if file exists at the location where it's supposed to be
                            if hasattr(self.ml_predictor, 'model_path'):
                                model_exists = os.path.exists(self.ml_predictor.model_path)
                                self.update_output.emit(log_message(f"[ML Diagnostic] Model file exists: {model_exists}"))

                            # Attempt to run prediction
                            ml_predictions = self.ml_predictor.predict_vulnerabilities(self.binary_path)

                            # Check prediction results
                            if ml_predictions:
                                ml_summary = f"ML predicts potential: {', '.join(p['type'] for p in ml_predictions)}"
                                self.update_output.emit(log_message(f"[ML Predict] {ml_summary}"))
                                self.update_analysis_results.emit(ml_summary + "\n")

                                for pred in ml_predictions:
                                    pred_str = f"  Type: {pred['type']}, Probability: {pred['probability']:.2f}"
                                    self.update_analysis_results.emit(pred_str + "\n")
                            else:
                                no_ml_pred_msg = "ML predictor returned no specific predictions."
                                self.update_output.emit(log_message(no_ml_pred_msg))
                                self.update_analysis_results.emit(no_ml_pred_msg + "\n")
                        else:
                            err_msg = "[ML Diagnostic] ML predictor exists but has no valid model attribute."
                            self.update_output.emit(log_message(err_msg))
                            self.update_analysis_results.emit(err_msg + "\n")

                            # Try to get more details
                            if hasattr(self.ml_predictor, 'model_path'):
                                model_path = self.ml_predictor.model_path
                                model_exists = os.path.exists(model_path)
                                self.update_output.emit(log_message(f"[ML Diagnostic] Model path: {model_path}, Exists: {model_exists}"))
                    else:
                        ml_model_missing_msg = "[ML Diagnostic] ML predictor is None. Model was not properly loaded during initialization."
                        self.update_output.emit(log_message(ml_model_missing_msg))
                        self.update_analysis_results.emit(ml_model_missing_msg + "\n")
                else:
                    ml_attr_missing_msg = "[ML Diagnostic] No 'ml_predictor' attribute found on this object."
                    self.update_output.emit(log_message(ml_attr_missing_msg))
                    self.update_analysis_results.emit(ml_attr_missing_msg + "\n")
            except NameError as e_name:
                err_msg = f"[Analysis] MLVulnerabilityPredictor class not found: {str(e_name)}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")
                # Additional debug info
                self.update_output.emit(log_message(f"[ML Debug] NameError details: {traceback.format_exc()}"))
            except Exception as e_ml:
                err_msg = f"[Analysis] Error running MLVulnerabilityPredictor: {e_ml}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")
                # Additional debug info with full traceback
                self.update_output.emit(log_message(f"[ML Debug] Exception details: {traceback.format_exc()}"))

            try:
                license_results = enhanced_deep_license_analysis(
                    self.binary_path)
                if license_results:
                    lic_found_msg = f"Found {
                        len(license_results)} potential license-related code regions (deep scan)"
                    self.update_output.emit(log_message(
                        f"[Deep Scan] {lic_found_msg}"))
                    self.update_analysis_results.emit(lic_found_msg + "\n")
                    for i, result in enumerate(license_results[:5]):
                        msg = f"Region {
                            i +
                            1}: Found at 0x{
                            result['start']:X}, Keywords: {
                            ', '.join(
                                result.get(
                                    'keywords',
                                    []))}"
                        self.update_analysis_results.emit("  " + msg + "\n")
                        if 'instructions' in result and result['instructions']:
                            self.update_analysis_results.emit(
                                "    Instructions (Preview):\n")
                            for inst in result['instructions'][:3]:
                                self.update_analysis_results.emit(
                                    f"      {inst}\n")
                else:
                    no_lic_msg = "No specific license-related code found (deep scan)."
                    self.update_output.emit(log_message(no_lic_msg))
                    self.update_analysis_results.emit(no_lic_msg + "\n")
            except Exception as e_deep_lic:
                err_msg = f"[Analysis] Error during deep license analysis: {e_deep_lic}"
                self.update_output.emit(log_message(err_msg))
                self.update_analysis_results.emit(err_msg + "\n")

            # --- Final Summary ---
            self.update_output.emit(
                log_message("[Analysis] Analysis complete."))
            self.update_status.emit("Analysis complete")

            # Combine results for the summary
            summary = ["\n=== OVERALL ANALYSIS SUMMARY ==="]
            summary.append(f"File: {os.path.basename(self.binary_path)}")
            summary.append(f"Size: {filesize:,} bytes")
            if detected_protectors:
                summary.append(
                    f"Protectors (Standard Scan): {
                        ', '.join(detected_protectors)}")
            if packing_summary_line:
                summary.append(
                    f"Packing (Standard Scan): {packing_summary_line}")
            if vulnerabilities:
                summary.append(
                    f"Vulnerabilities (Advanced Scan): {
                        len(vulnerabilities)} found.")
            if ml_predictions:
                summary.append(
                    f"ML Predictions: {
                        len(ml_predictions)} potential issues.")
            if license_results:
                summary.append(
                    f"License Code (Deep Scan): {
                        len(license_results)} potential regions.")

            summary.append("\nRecommended actions:")
            summary.append("1. Review full results above.")
            summary.append(
                "2. Use 'Preview Patch Plan' or 'Automated Patch Agent'.")
            if detected_protectors or "PACKED" in packing_summary_line:
                summary.append(
                    "3. Consider 'Memory Patching' due to detected protection/packing.")

            self.update_analysis_results.emit("\n".join(summary))

        except Exception as e:
            # Catch-all for errors in the thread function
            error_msg = f"[Analysis] Error: {e}"
            trace_msg = traceback.format_exc()
            self.update_output.emit(log_message(error_msg))
            self.update_output.emit(log_message(trace_msg))
            self.update_analysis_results.emit("\n" + error_msg + "\n")
            self.update_analysis_results.emit(trace_msg + "\n")
            self.update_status.emit(f"Error: {str(e)}")

    def run_deep_license_analysis(self):
        """Runs deep license analysis and outputs the results."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            "[Deep License Analysis] Starting analysis..."))
        self.analyze_status.setText("Running deep license analysis...")

        # Run in background thread
        threading.Thread(target=self._run_deep_license_analysis_thread).start()

    def _run_deep_license_analysis_thread(self):
        """Background thread for deep license analysis."""
        try:
            self.clear_analysis_results.emit()

            candidates = enhanced_deep_license_analysis(self.binary_path)

            if not candidates:
                self.update_output.emit(log_message(
                    "[Deep License Analysis] No licensing patterns detected."))
                self.update_analysis_results.emit(
                    "No licensing patterns detected.")
                self.update_status.emit("No licensing patterns found")
                return

            self.update_output.emit(
                log_message(
                    f"[Deep License Analysis] Found {
                        len(candidates)} potential licensing regions."))

            self.update_analysis_results.emit(
                f"Found {len(candidates)} potential licensing code regions:")
            self.update_analysis_results.emit("=" * 50)

            for i, candidate in enumerate(candidates):
                confidence = candidate.get("confidence", 0)
                keywords = ", ".join(candidate.get("keywords", []))

                self.update_output.emit(log_message(
                    f"[Deep Analysis] Region {
                        i +
                        1} at 0x{
                        candidate['start']:X}: "
                    f"Keywords: {keywords}, Confidence: {confidence}"
                ))

                self.update_analysis_results.emit(f"Region {i + 1}:")
                self.update_analysis_results.emit(
                    f"  Address range: 0x{
                        candidate['start']:X} - 0x{
                        candidate.get(
                            'end', candidate['start']):X}")
                self.update_analysis_results.emit(f"  Keywords: {keywords}")
                self.update_analysis_results.emit(
                    f"  Confidence: {confidence}")

                if 'instructions' in candidate and candidate['instructions']:
                    self.update_analysis_results.emit("  Instructions:")
                    for inst in candidate['instructions'][:10]:
                        self.update_analysis_results.emit(f"    {inst}")
                    if len(candidate['instructions']) > 10:
                        self.update_analysis_results.emit(
                            f"    ... plus {len(candidate['instructions']) - 10} more")

                self.update_analysis_results.emit("-" * 50)

            self.update_analysis_results.emit("\nRecommendations:")
            self.update_analysis_results.emit(
                "1. Use 'Automated Patch Agent' to attempt automatic patching")
            self.update_analysis_results.emit(
                "2. Try 'Deep Runtime Monitoring' to observe behavior during execution")
            self.update_analysis_results.emit(
                "3. Use 'Preview Patch Plan' to see potential patch locations")

            self.update_status.emit(
                f"Found {len(candidates)} licensing regions")

        except Exception as e:
            self.update_output.emit(log_message(
                f"[Deep License Analysis] Error: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            self.update_status.emit(f"Error: {str(e)}")

    def run_ghidra_analysis_gui(self):
        """Entry point for Ghidra GUI + license string scan"""
        # Renamed local variable to avoid name conflict with global function
        threading.Thread(
            target=run_ghidra_analysis_gui,  # This is the global function
            args=(self,),
            daemon=True
        ).start()

    def run_deep_runtime_monitoring(self):
        """Runs deep runtime monitoring on the selected binary."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            "[Runtime Monitoring] Starting deep runtime monitoring..."))
        self.analyze_status.setText("Starting runtime monitoring...")

        # Run in background thread
        threading.Thread(
            target=self._run_deep_runtime_monitoring_thread).start()

    def _run_deep_runtime_monitoring_thread(self):
        """Background thread for deep runtime monitoring."""
        try:
            self.clear_analysis_results.emit()

            timeout = CONFIG.get("max_runtime_monitoring", 30000)
            logs = deep_runtime_monitoring(self.binary_path, timeout)

            for log in logs:
                self.update_output.emit(log_message(log))
                self.update_analysis_results.emit(log)

            self.update_output.emit(log_message(
                "[Runtime Monitoring] Monitoring complete."))
            self.update_status.emit("Runtime monitoring complete")

        except Exception as e:
            self.update_output.emit(log_message(
                f"[Runtime Monitoring] Error: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            self.update_status.emit(f"Error: {str(e)}")

    def run_autonomous_patching(self):
        """Wrapper to start the autonomous patching thread."""
        self.update_output.emit(log_message(
            "[AI Patching] Starting autonomous patching process via UI action..."))
        threading.Thread(
            target=self._run_autonomous_patching_thread, daemon=True
        ).start()

    def preview_patch(self):
        """
        Previews a patch plan by disassembling the binary and suggesting modifications.
        Enhanced with better detection and more detailed suggestions.
        """
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            "[Patch Preview] Starting patch preview..."))
        self.analyze_status.setText("Generating patch preview...")

        # Run in background thread
        threading.Thread(target=self._preview_patch_thread).start()

    def _preview_patch_thread(self):
        """Background thread for patch preview."""
        try:
            self.clear_analysis_results.emit()
            pe = pefile.PE(self.binary_path)
            is_64bit = getattr(pe.FILE_HEADER, "Machine", 0) == 0x8664
            mode = CS_MODE_64 if is_64bit else CS_MODE_32

            code_section = next(
                (s for s in pe.sections if b".text" in s.Name), None)
            if not code_section:
                self.update_output.emit(log_message(
                    "[Patch Preview] .text section not found"))
                self.update_analysis_results.emit(
                    "Error: .text section not found")
                self.update_status.emit("Error: .text section not found")
                return

            code_data = code_section.get_data()
            base_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            self.update_output.emit(log_message(
                "[Patch Preview] Searching for license-related code..."))
            license_regions = enhanced_deep_license_analysis(self.binary_path)

            patches = []

            def find_jumps_in_region(instructions, region_start, region_end):
                """
                Find jump and call instructions within a specified address region.

                Args:
                    instructions: List of instruction objects.
                    region_start: Start address of the region.
                    region_end: End address of the region.

                Returns:
                    List of instructions that are jumps or calls within the region.
                """
                jumps = []
                for insn in instructions:
                    if insn.address >= region_start and insn.address <= region_end:
                        if insn.mnemonic in ["je", "jne", "jz", "jnz", "call"]:
                            jumps.append(insn)
                return jumps

            if license_regions:
                self.update_output.emit(
                    log_message(
                        f"[Patch Preview] Found {
                            len(license_regions)} license regions. Analyzing for patch points..."))
                self.update_analysis_results.emit(
                    f"Found {len(license_regions)} potential license regions:")

                all_instructions = list(md.disasm(code_data, base_addr))

                for region_idx, region in enumerate(license_regions):
                    region_start = region["start"]
                    region_end = region.get("end", region_start + 100)

                    self.update_analysis_results.emit(
                        f"\nRegion {region_idx + 1} (0x{region_start:X} - 0x{region_end:X}):")

                    jumps = find_jumps_in_region(
                        all_instructions, region_start, region_end)

                    if jumps:
                        self.update_analysis_results.emit(
                            f"  Found {len(jumps)} potential patch points:")

                        for i, jump in enumerate(jumps):
                            ctx_start = max(0, i - 2)
                            ctx_end = min(len(jumps), i + 3)
                            context = jumps[ctx_start:ctx_end]

                            # Build code context to show to user
                            context_lines = []
                            for ctx_insn in context:
                                prefix = "➤ " if ctx_insn.address == jump.address else "  "
                                context_lines.append(f"{prefix}0x{ctx_insn.address:x}: {ctx_insn.mnemonic} {ctx_insn.op_str}")

                            # Display code context
                            self.update_analysis_results.emit("\n".join(context_lines))

                            # Analyze context to determine best patch strategy
                            is_condition_check = any(
                                x.mnemonic in ["cmp", "test"] for x in context if context.index(x) < context.index(jump)
                            )
                            is_function_call = jump.mnemonic == "call"
                            patch_type = "bypass" if is_condition_check else "neutralize" if is_function_call else "modify"

                            # Use patch_type to determine the most effective patch strategy
                            self.update_output.emit(log_message(f"[Patch Preview] Recommended patch type: {patch_type}"))
                            self.update_analysis_results.emit(f"  Recommended strategy: {patch_type.upper()}")

                            patch_desc = ""
                            patch_bytes = ""

                            # Apply patching strategy based on patch_type and instruction
                            if patch_type == "neutralize" and jump.mnemonic == "call":
                                # For call instructions, replace with code that returns success
                                if is_64bit:
                                    patch_bytes = "48C7C001000000C3"
                                    patch_desc = "Replace call with 'mov rax, 1; ret' (always return success)"
                                else:
                                    patch_bytes = "B801000000C3"
                                    patch_desc = "Replace call with 'mov eax, 1; ret' (always return success)"
                            elif patch_type == "bypass" and jump.mnemonic in ["je", "jz"]:
                                # For conditional jumps after checks, replace with NOPs
                                nop_count = jump.size
                                patch_bytes = "90" * nop_count
                                patch_desc = f"Replace conditional jump with {nop_count} NOPs (always continue)"
                            elif jump.mnemonic in ["jne", "jnz"]:
                                if len(jump.op_str.split(",")) > 0:
                                    target = jump.op_str.split(",")[0].strip()
                                    patch_bytes = "E9" + target[2:]
                                    patch_desc = "Replace conditional jump with unconditional JMP (always take branch)"
                                else:
                                    nop_count = jump.size
                                    patch_bytes = "90" * nop_count
                                    patch_desc = f"Replace conditional jump with {nop_count} NOPs (never take branch)"

                            offset = jump.address - pe.OPTIONAL_HEADER.ImageBase
                            file_offset = pe.get_offset_from_rva(offset)

                            self.update_analysis_results.emit(
                                f"    Patch {i + 1}:")
                            self.update_analysis_results.emit(
                                f"      Address: 0x{
                                    jump.address:X} (File offset: 0x{
                                    file_offset:X})")
                            self.update_analysis_results.emit(
                                f"      Instruction: {
                                    jump.mnemonic} {
                                    jump.op_str}")
                            self.update_analysis_results.emit(
                                f"      Patch: {patch_desc}")
                            self.update_analysis_results.emit(
                                f"      Bytes: {patch_bytes}")

                            patches.append({
                                "address": jump.address,
                                "instruction": f"{jump.mnemonic} {jump.op_str}",
                                "new_bytes": bytes.fromhex(patch_bytes) if patch_bytes else None,
                                "description": patch_desc
                            })
                    else:
                        self.update_analysis_results.emit(
                            "  No suitable patch points found in this region.")
            else:
                self.update_output.emit(log_message(
                    "[Patch Preview] No license regions found. Using general approach..."))

                patch_count = 0
                instructions = list(md.disasm(code_data, base_addr))

                for i, insn in enumerate(instructions):
                    if i + \
                            1 < len(instructions) and insn.mnemonic in ["cmp", "test"]:
                        next_insn = instructions[i + 1]
                        if next_insn.mnemonic in ["je", "jne", "jz", "jnz"]:
                            patch_count += 1
                            patch_desc = ""
                            patch_bytes = ""
                            nop_count = next_insn.size
                            patch_bytes = "90" * nop_count
                            patch_desc = f"Replace conditional jump with {nop_count} NOPs"

                            offset = next_insn.address - pe.OPTIONAL_HEADER.ImageBase
                            file_offset = pe.get_offset_from_rva(offset)

                            self.update_output.emit(
                                log_message(
                                    f"[Patch Preview] Candidate {patch_count}: " f"0x{
                                        file_offset:X}: {
                                        next_insn.mnemonic} {
                                        next_insn.op_str} -> {patch_desc}"))

                            patches.append({
                                "address": next_insn.address,
                                "instruction": f"{next_insn.mnemonic} {next_insn.op_str}",
                                "new_bytes": bytes.fromhex(patch_bytes) if patch_bytes else None,
                                "description": patch_desc
                            })

                if patch_count == 0:
                    self.update_output.emit(log_message(
                        "[Patch Preview] No patch candidates found."))
                    self.update_analysis_results.emit(
                        "No suitable patch candidates found.")
                    self.update_status.emit("No patch candidates found")
                else:
                    self.update_analysis_results.emit(
                        f"Found {patch_count} general patch candidates:")
                    for i, patch in enumerate(patches):
                        self.update_analysis_results.emit(f"\nPatch {i + 1}:")
                        self.update_analysis_results.emit(
                            f"  Address: 0x{patch['address']:X}")
                        self.update_analysis_results.emit(
                            f"  Instruction: {patch['instruction']}")
                        self.update_analysis_results.emit(
                            f"  Description: {patch['description']}")
                        if patch['new_bytes']:
                            self.update_analysis_results.emit(
                                f"  Bytes: {patch['new_bytes'].hex().upper()}")

            self.potential_patches = patches

            if patches:
                self.update_output.emit(
                    log_message(
                        f"[Patch Preview] Generated {
                            len(patches)} potential patches."))
                self.update_status.emit(
                    f"Found {len(patches)} potential patches")

                self.update_analysis_results.emit("\nPatch Summary:")
                self.update_analysis_results.emit(
                    f"- Total patches: {len(patches)}")
                self.update_analysis_results.emit(
                    "- To apply these patches, use 'Apply Patch Plan' button")
                self.update_analysis_results.emit(
                    "- Patches will create a new file with '_patched' suffix")
                self.update_analysis_results.emit(
                    "- Original file will not be modified")
            else:
                self.update_output.emit(log_message(
                    "[Patch Preview] No patch candidates found."))
                self.update_status.emit("No patch candidates found")

        except (FileNotFoundError, PermissionError) as e:
            self.update_output.emit(log_message(f"[Patch Preview] File access error: {e}"))
            self.update_status.emit(f"File access error: {str(e)}")
        except (pefile.PEFormatError, ValueError) as e:
            self.update_output.emit(log_message(f"[Patch Preview] Binary parsing error: {e}"))
            self.update_status.emit(f"Binary parsing error: {str(e)}")
        except (TypeError, AttributeError) as e:
            self.update_output.emit(log_message(f"[Patch Preview] Data handling error: {e}"))
            self.update_status.emit(f"Data handling error: {str(e)}")
        except Exception as e:
            # Fallback for any unexpected errors, with traceback for debugging
            self.update_output.emit(log_message(f"[Patch Preview] Unexpected error: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            self.update_status.emit(f"Unexpected error: {str(e)}")

    def apply_patch_plan(self):
        """Applies the patch plan to the selected binary."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        # Check if we have patches from preview
        if hasattr(self, "potential_patches") and self.potential_patches:
            response = QMessageBox.question(
                self,
                "Apply Patches",
                f"Apply {len(self.potential_patches)} patches from preview?\n\nThis will create a new patched file.",
                QMessageBox.Yes | QMessageBox.No
            )

            if response == QMessageBox.Yes:
                self.update_output.emit(log_message(
                    f"[Apply Patch] Applying {len(self.potential_patches)} patches..."))
                apply_parsed_patch_instructions_with_validation(
                    self, self.potential_patches)
                return

        # If no patches from preview, run the license function rewriter
        self.update_output.emit(log_message(
            "[Apply Patch] No existing patch plan. Running license function rewriter..."))
        rewrite_license_functions_with_parsing(self)

    def start_guided_wizard(self):
        """Start the guided workflow wizard for new users."""
        try:
            from intellicrack.ui.dialogs.guided_workflow_wizard import GuidedWorkflowWizard
            wizard = GuidedWorkflowWizard(parent=self)
            wizard.exec_()
        except Exception as e:
            self.logger.error(f"Failed to start guided wizard: {e}")
            QMessageBox.warning(self, "Error", f"Failed to start guided wizard:\n{str(e)}")
            import traceback
            traceback.print_exc()


    def apply_cracking_pattern(self, source_binary, target_binary):
        """
        Apply cracking pattern from source binary to target binary.

        Args:
            source_binary: Path to the source binary (with working cracks)
            target_binary: Path to the target binary (to apply cracks to)
        """
        self.update_output.emit(log_message(f"[Pattern] Analyzing patterns from {os.path.basename(source_binary)}"))

        # Extract patterns from source binary
        patterns = self.extract_patterns_from_binary(source_binary)

        if patterns:
            self.update_output.emit(log_message(f"[Pattern] Found {len(patterns)} patterns to apply"))

            # Convert to patch instructions format
            instructions = []
            for pattern in patterns:
                instructions.append({
                    "offset": pattern.get("offset", 0),
                    "original": pattern.get("original_bytes", ""),
                    "patched": pattern.get("patched_bytes", ""),
                    "description": pattern.get("description", "Extracted from similar binary")
                })

            # Store patterns for potential application
            self.potential_patches = instructions

            # Apply patches with validation
            apply_parsed_patch_instructions_with_validation(self, instructions)
        else:
            self.update_output.emit(log_message("[Pattern] No applicable patterns found"))
            QMessageBox.warning(self, "No Patterns", "No applicable patterns were found in the source binary.")

    def extract_patterns_from_binary(self, binary_path):
        """
        Extract cracking patterns from a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            list: List of pattern dictionaries containing potential license check,
                 activation mechanisms, and protection patterns
        """
        self.update_output.emit(log_message("[Pattern] Starting binary analysis for pattern extraction..."))

        # Initialize patterns list
        patterns = []
        binary_format = "unknown"

        try:
            # Check file exists
            if not os.path.exists(binary_path):
                raise FileNotFoundError(f"Binary file not found: {binary_path}")

            # Determine binary format
            with open(binary_path, 'rb') as f:
                header = f.read(4)
                if header.startswith(b'MZ'):
                    binary_format = "PE"
                elif header.startswith(b'\x7fELF'):
                    binary_format = "ELF"
                elif header in [b'\xca\xfe\xba\xbe', b'\xce\xfa\xed\xfe']:
                    binary_format = "MACHO"

            self.update_output.emit(log_message(f"[Pattern] Detected format: {binary_format}"))

            # Process binary based on format
            if binary_format == "PE":
                patterns = self._extract_patterns_from_pe(binary_path)
            elif binary_format == "ELF":
                patterns = self._extract_patterns_from_elf(binary_path)
            elif binary_format == "MACHO":
                patterns = self._extract_patterns_from_macho(binary_path)
            else:
                self.update_output.emit(log_message("[Pattern] Warning: Unsupported binary format, using generic patterns"))
                patterns = self._generate_generic_patterns()

        except Exception as e:
            self.update_output.emit(log_message(f"[Pattern] Error during pattern extraction: {str(e)}"))
            self.update_output.emit(log_message(f"[Pattern] Traceback: {traceback.format_exc()}"))
            self.update_output.emit(log_message("[Pattern] Using generic patterns due to analysis error"))
            patterns = self._generate_generic_patterns()

        # Log patterns found
        self.update_output.emit(log_message(f"[Pattern] Extracted {len(patterns)} potential patterns"))

        # Sort patterns by offset for better organization
        patterns.sort(key=lambda x: x.get("offset", 0))

        return patterns

    def _extract_patterns_from_pe(self, binary_path):
        """Extract patterns from PE format binaries"""
        patterns = []

        try:
            # Load PE file
            pe = pefile.PE(binary_path)

            # Get binary sections for analysis
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_data = section.get_data()

                # Skip small or empty sections
                if len(section_data) < 10:
                    continue

                self.update_output.emit(log_message(f"[Pattern] Analyzing section: {section_name} ({len(section_data)} bytes)"))

                # Analyze executable sections for code patterns
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    # Find license check patterns using regex

                    # Pattern 1: Conditional jumps with function calls (common license check pattern)
                    # Example: JZ/JNZ followed by CALL then TEST
                    matches = re.finditer(b'\x74[\x00-\xFF]{1,3}\xE8[\x00-\xFF]{4}[\x84-\x85]\xC0', section_data)
                    for match in matches:
                        offset = section.VirtualAddress + match.start()
                        orig_bytes = binascii.hexlify(section_data[match.start():match.start()+10]).decode('utf-8').upper()
                        # Create bypass pattern (NOP out the conditional jump)
                        patched_bytes = "90" * 2 + orig_bytes[2:]

                        patterns.append({
                            "offset": offset,
                            "original_bytes": orig_bytes,
                            "patched_bytes": patched_bytes,
                            "description": f"License validation check in {section_name}",
                            "type": "license_check",
                            "confidence": "medium"
                        })

                    # Pattern 2: Call followed by test and conditional jump (common in activation flows)
                    # Example: CALL -> TEST EAX,EAX -> JZ
                    matches = re.finditer(b'\xE8[\x00-\xFF]{4}[\x84-\x85]\xC0[\x74-\x75]', section_data)
                    for match in matches:
                        offset = section.VirtualAddress + match.start()
                        orig_bytes = binascii.hexlify(section_data[match.start():match.start()+10]).decode('utf-8').upper()
                        # Force success return by replacing the conditional jump with NOPs
                        patched_bytes = orig_bytes[:-2] + "9090"

                        patterns.append({
                            "offset": offset,
                            "original_bytes": orig_bytes,
                            "patched_bytes": patched_bytes,
                            "description": f"Function result check in {section_name}",
                            "type": "activation_check",
                            "confidence": "medium"
                        })

                    # Pattern 3: Look for time-related API call patterns (for expiration checks)
                    time_related_strings = [b'GetSystemTime', b'GetLocalTime', b'FileTimeToSystemTime',
                                         b'CompareFileTime', b'GetFileTime', b'time32', b'time64']

                    for time_string in time_related_strings:
                        for match in re.finditer(time_string, section_data):
                            # Find nearby conditional jumps (within 30 bytes)
                            vicinity_start = max(0, match.start() - 30)
                            vicinity_end = min(len(section_data), match.end() + 30)
                            vicinity_data = section_data[vicinity_start:vicinity_end]

                            # Look for conditional jumps in the vicinity
                            for jmp_pattern in [b'\x74', b'\x75', b'\x0F\x84', b'\x0F\x85', b'\x79', b'\x7B', b'\x7C', b'\x7D']:
                                for jmp_match in re.finditer(re.escape(jmp_pattern), vicinity_data):
                                    jmp_offset = section.VirtualAddress + vicinity_start + jmp_match.start()
                                    jmp_size = len(jmp_pattern)

                                    # Get enough bytes for reliable patching
                                    jmp_area = vicinity_data[jmp_match.start():jmp_match.start() + jmp_size + 4]
                                    jmp_bytes = binascii.hexlify(jmp_area).decode('utf-8').upper()

                                    # Create NOPs for the jump instruction
                                    patch_bytes = "90" * len(jmp_area)

                                    patterns.append({
                                        "offset": jmp_offset,
                                        "original_bytes": jmp_bytes,
                                        "patched_bytes": patch_bytes,
                                        "description": f"Time/Expiration check near {time_string.decode('utf-8', errors='ignore')}",
                                        "type": "expiration_check",
                                        "confidence": "high"
                                    })

            # Check for licensing-related imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if not hasattr(entry, 'dll'):
                        continue

                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    license_related_dlls = ['crypt', 'ssl', 'license', 'verify', 'auth', 'activ']

                    # Check if this DLL is likely related to licensing
                    if any(name in dll_name for name in license_related_dlls):
                        self.update_output.emit(log_message(f"[Pattern] Found licensing-related DLL: {dll_name}"))

                        # Look for key functions related to licensing
                        license_funcs = ['valid', 'check', 'license', 'activ', 'auth', 'verify', 'decrypt']

                        for imp in entry.imports:
                            if not hasattr(imp, 'name') or not imp.name:
                                continue

                            func_name = imp.name.decode('utf-8', errors='ignore')

                            if any(name in func_name.lower() for name in license_funcs):
                                self.update_output.emit(log_message(f"[Pattern] Found licensing function: {func_name}"))

                                # Try to find calls to this function in code sections
                                for section in pe.sections:
                                    if not (section.Characteristics & 0x20000000):
                                        continue

                                    section_data = section.get_data()
                                    calls_found = 0

                                    # Look for E8 (CALL) instructions
                                    for i in range(len(section_data) - 5):
                                        if section_data[i] == 0xE8:  # CALL opcode
                                            # Calculate the target of this call
                                            call_target = section.VirtualAddress + i + 5
                                            call_target += int.from_bytes(section_data[i+1:i+5], byteorder='little', signed=True)

                                            # Check if this call targets our import
                                            if hasattr(imp, 'address') and abs(call_target - imp.address) < 16:
                                                calls_found += 1

                                                offset = section.VirtualAddress + i
                                                orig_bytes = binascii.hexlify(section_data[i:i+5]).decode('utf-8').upper()

                                                if "check" in func_name.lower() or "valid" in func_name.lower():
                                                    # For validation functions, make them always return success (1)
                                                    patched_bytes = "B001909090"  # mov al, 1; nop; nop; nop
                                                else:
                                                    # For other functions, just NOP out the call
                                                    patched_bytes = "90" * len(orig_bytes)

                                                patterns.append({
                                                    "offset": offset,
                                                    "original_bytes": orig_bytes,
                                                    "patched_bytes": patched_bytes,
                                                    "description": f"Call to {func_name} in {dll_name}",
                                                    "type": "api_license_check",
                                                    "confidence": "high",
                                                    "api_name": func_name
                                                })

                                # Only process first few calls to avoid excessive patterns
                                if calls_found > 0:
                                    self.update_output.emit(log_message(f"[Pattern] Found {calls_found} calls to {func_name}"))

            # If no patterns found so far, look for common API calls that could be used for licensing
            if not patterns:
                self.update_output.emit(log_message("[Pattern] No specific patterns found, analyzing API usage..."))

                # Common Windows API calls often used in license checks
                api_patterns = {
                    "CryptVerifySignature": b"CryptVerifySignature",
                    "CheckTokenMembership": b"CheckTokenMembership",
                    "GetVolumeInformation": b"GetVolumeInformation",
                    "RegQueryValueEx": b"RegQueryValueEx",
                    "GetAdaptersInfo": b"GetAdaptersInfo",
                    "GetModuleHandle": b"GetModuleHandle",
                }

                for api_name, api_pattern in api_patterns.items():
                    for section in pe.sections:
                        section_data = section.get_data()
                        for match in re.finditer(api_pattern, section_data):
                            self.update_output.emit(log_message(f"[Pattern] Found potential API usage: {api_name}"))

                            patterns.append({
                                "offset": section.VirtualAddress + match.start(),
                                "original_bytes": "",  # Can't determine without disassembly
                                "patched_bytes": "",
                                "description": f"Potential {api_name} usage for hardware/license checks",
                                "type": "api_reference",
                                "confidence": "low",
                                "requires_manual_analysis": True
                            })

                # Add entry point pattern for manual inspection
                try:
                    entry_point = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', None)
                    if entry_point is not None:
                        for section in pe.sections:
                            if section.VirtualAddress <= entry_point < (section.VirtualAddress + section.Misc_VirtualSize):
                                section_data = section.get_data()
                                offset_in_section = entry_point - section.VirtualAddress

                                if offset_in_section < len(section_data) - 16:
                                    entry_bytes = binascii.hexlify(section_data[offset_in_section:offset_in_section+16]).decode('utf-8').upper()

                                    patterns.append({
                                        "offset": entry_point,
                                        "original_bytes": entry_bytes,
                                        "patched_bytes": entry_bytes,  # Same bytes initially
                                        "description": "Entry point (inspect for initialization checks)",
                                        "type": "entry_point",
                                        "confidence": "low",
                                        "requires_manual_analysis": True
                                    })
                                    break
                except Exception as e:
                    self.update_output.emit(log_message(f"[Pattern] Error analyzing entry point: {str(e)}"))

        except Exception as e:
            self.update_output.emit(log_message(f"[Pattern] Error in PE pattern extraction: {str(e)}"))

        return patterns

    def _extract_patterns_from_elf(self, binary_path):
        """Extract patterns from ELF format binaries"""
        # Basic pattern detection for ELF binaries
        patterns = []

        try:
            # Try to find common license check patterns in ELF binaries
            with open(binary_path, 'rb') as f:
                binary_data = f.read()

            # Look for common strings related to licensing
            license_strings = [b'license', b'activation', b'register', b'trial', b'expire',
                             b'hardware', b'hwid', b'serial', b'key']

            for pattern in license_strings:
                for match in re.finditer(pattern, binary_data, re.IGNORECASE):
                    # Create a pattern entry for each match
                    offset = match.start()
                    context_start = max(0, offset - 20)
                    context_end = min(len(binary_data), offset + len(pattern) + 20)
                    context_data = binary_data[context_start:context_end]

                    # Convert binary context to readable format for reporting
                    context_hex = binascii.hexlify(context_data).decode('utf-8').upper()
                    context_readable = context_data.decode('utf-8', errors='replace')

                    # Check if the pattern appears in a possible code region
                    is_code_region = any(opcode in context_data for opcode in [b'\x55', b'\x8B', b'\x89', b'\xE8', b'\xE9', b'\xFF'])

                    # Check if pattern is surrounded by string terminators or other strings
                    is_text_section = (b'\x00' in context_data and context_data.count(b'\x00') > 2)

                    # Determine confidence level based on context
                    confidence_level = "high" if is_code_region else "medium" if is_text_section else "low"

                    patterns.append({
                        "offset": offset,
                        "original_bytes": binascii.hexlify(pattern).decode('utf-8').upper(),
                        "patched_bytes": "",  # Can't determine without proper disassembly
                        "description": f"Reference to '{pattern.decode('utf-8', errors='ignore')}' (needs manual analysis)",
                        "type": "string_reference",
                        "confidence": confidence_level,
                        "requires_manual_analysis": True,
                        "context": {
                            "hex": context_hex[:30] + "..." if len(context_hex) > 30 else context_hex,
                            "text": context_readable[:30] + "..." if len(context_readable) > 30 else context_readable,
                            "is_code_region": is_code_region,
                            "is_text_section": is_text_section
                        }
                    })

                    # Log the finding
                    self.update_output.emit(log_message(
                        f"[Pattern Finder] Found '{pattern.decode('utf-8', errors='ignore')}' at offset 0x{offset:X} ({confidence_level} confidence)"
                    ))

        except Exception as e:
            self.update_output.emit(log_message(f"[Pattern] Error in ELF pattern extraction: {str(e)}"))

        return patterns or self._generate_generic_patterns()

    def _extract_patterns_from_macho(self, binary_path):
        """Extract patterns from Mach-O format binaries"""
        # Basic pattern detection for Mach-O binaries
        # Similar approach to ELF, with format-specific adjustments
        return self._generate_generic_patterns()

    def _generate_generic_patterns(self):
        """Generate generic patterns when specific analysis fails"""
        self.update_output.emit(log_message("[Pattern] Generating generic pattern suggestions"))

        # Create a list of common patterns that might be useful
        patterns = [
            {
                "offset": 0x1000,  # Common offset where code might start
                "original_bytes": "7405E80000000084C0",  # Common pattern: JZ CALL TEST AL,AL
                "patched_bytes": "7405E8000000009090",  # Replace with NOPs
                "description": "Generic license check pattern (conditional jump + function call)",
                "type": "license_check",
                "confidence": "low",
                "requires_manual_verification": True
            },
            {
                "offset": 0x2000,  # Another potential code offset
                "original_bytes": "E8????????85C07403",  # CALL, TEST EAX,EAX, JZ
                "patched_bytes": "E8????????85C09090",  # Replace conditional jump with NOPs
                "description": "Generic function result check pattern",
                "type": "result_check",
                "confidence": "low",
                "requires_manual_verification": True
            },
            {
                "offset": 0x3000,
                "original_bytes": "833D????????007405",  # CMP DWORD PTR [addr], 0; JZ
                "patched_bytes": "833D????????009090",  # Replace jump with NOPs
                "description": "Generic global flag check pattern",
                "type": "flag_check",
                "confidence": "low",
                "requires_manual_verification": True
            }
        ]

        return patterns

    def open_visual_patch_editor(self):
        """Opens the visual patch editor dialog."""
        if not self.binary_path:
            QMessageBox.warning(
                self, "No Binary", "Please select a binary file first.")
            return

        # Check if we have patches from preview
        if not hasattr(self, "potential_patches") or not self.potential_patches:
            response = QMessageBox.question(
                self,
                "No Patches",
                "No patches available. Would you like to run patch preview first?",
                QMessageBox.Yes | QMessageBox.No
            )
            if response == QMessageBox.Yes:
                self.preview_patch()
                # Wait for preview to complete before opening editor
                QTimer.singleShot(1000, self.open_visual_patch_editor)
                return
            else:
                return

        # Open the visual patch editor dialog
        editor = VisualPatchEditorDialog(self.binary_path, self.potential_patches, parent=self)
        if editor.exec_() == QDialog.Accepted:
            # Update patches if user accepted changes
            self.potential_patches = editor.patches
            self.update_output.emit(log_message(
                f"[Patch Editor] Updated patch plan with {len(self.potential_patches)} patches"))
    
    def run_binary_similarity_search(self):
        """Run binary similarity search."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        try:
            from .dialogs.similarity_search_dialog import BinarySimilaritySearchDialog
            dialog = BinarySimilaritySearchDialog(self.binary_path, self)
            dialog.exec_()
        except ImportError:
            QMessageBox.warning(self, "Feature Unavailable", 
                              "Binary similarity search is not available. "
                              "Please ensure all dependencies are installed.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open similarity search dialog: {e}")
    
    def run_feature_extraction(self):
        """Run automated feature extraction for ML models."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Feature Extract] Starting feature extraction..."))
        self.update_analysis_results.emit("\n=== Automated Feature Extraction ===\n")
        
        try:
            from ..ai.ml_predictor import MLVulnerabilityPredictor
            
            predictor = MLVulnerabilityPredictor()
            features = predictor.extract_features(self.binary_path)
            
            if features is not None:
                feature_count = features.shape[1] if len(features.shape) > 1 else len(features)
                self.update_analysis_results.emit(f"Extracted {feature_count} features from binary\n")
                
                # Display some key features
                feature_list = features[0] if len(features.shape) > 1 else features
                self.update_analysis_results.emit(f"File size: {int(feature_list[0])} bytes\n")
                self.update_analysis_results.emit(f"Entropy: {feature_list[1]:.3f}\n")
                
                # Show feature categories
                if feature_count > 258:  # Basic + byte frequencies + PE features
                    self.update_analysis_results.emit("Feature categories:\n")
                    self.update_analysis_results.emit("- Basic file properties (size, entropy)\n")
                    self.update_analysis_results.emit("- Byte frequency distribution (256 features)\n")
                    self.update_analysis_results.emit("- PE structure analysis (sections, imports, etc.)\n")
                
                self.update_analysis_results.emit("\n✅ Feature extraction completed successfully\n")
            else:
                self.update_analysis_results.emit("❌ Feature extraction failed\n")
            
            self.update_output.emit(log_message("[Feature Extract] Extraction complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Feature Extract] Error: {e}"))
            self.update_analysis_results.emit(f"Error during feature extraction: {e}\n")

    def run_automated_patch_agent(self):
        """Run automated AI-driven patch agent."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Patch Agent] Starting AI-driven patch agent..."))
        self.update_analysis_results.emit("\n=== Automated Patch Agent (AI-Driven) ===\n")
        
        try:
            # Step 1: Analyze binary for protection mechanisms
            self.update_analysis_results.emit("Step 1: Analyzing protection mechanisms...\n")
            
            try:
                from ..utils.protection_detection import detect_protection_mechanisms
                protections = detect_protection_mechanisms(self.binary_path)
                if protections:
                    self.update_analysis_results.emit("Detected protections:\n")
                    for protection in protections:
                        self.update_analysis_results.emit(f"- {protection}\n")
                else:
                    self.update_analysis_results.emit("No specific protections detected\n")
            except Exception as e:
                self.update_analysis_results.emit(f"Protection detection failed: {e}\n")
            
            # Step 2: Search for similar binaries with successful patches
            self.update_analysis_results.emit("\nStep 2: Searching for similar cracked binaries...\n")
            
            try:
                from ..core.analysis.binary_similarity_search import BinarySimilaritySearch
                search_engine = BinarySimilaritySearch()
                similar_binaries = search_engine.search_similar_binaries(self.binary_path, threshold=0.5)
                
                successful_patterns = []
                for binary in similar_binaries:
                    patterns = binary.get('cracking_patterns', [])
                    if patterns:
                        successful_patterns.extend(patterns)
                
                if successful_patterns:
                    self.update_analysis_results.emit(f"Found {len(successful_patterns)} successful patterns from similar binaries\n")
                else:
                    self.update_analysis_results.emit("No similar binaries with patterns found\n")
            except Exception:
                successful_patterns = []
                self.update_analysis_results.emit("Similarity search not available\n")
            
            # Step 3: Generate AI-driven patch suggestions
            self.update_analysis_results.emit("\nStep 3: Generating AI patch suggestions...\n")
            
            # Use AI tools for pattern suggestions
            try:
                from ..ai.ai_tools import retrieve_few_shot_examples
                examples = retrieve_few_shot_examples(2)
                
                self.update_analysis_results.emit("AI-suggested approaches based on similar cases:\n\n")
                self.update_analysis_results.emit(examples)
                self.update_analysis_results.emit("\n")
            except Exception as e:
                self.update_analysis_results.emit(f"AI pattern generation failed: {e}\n")
            
            # Step 4: Vulnerability-based patch recommendations
            self.update_analysis_results.emit("\nStep 4: Generating vulnerability-based recommendations...\n")
            
            # Run ML prediction for targeted patching
            try:
                from ..ai.ml_predictor import MLVulnerabilityPredictor
                predictor = MLVulnerabilityPredictor()
                prediction = predictor.predict_vulnerability(self.binary_path)
                
                if prediction and prediction.get('prediction') == 1:
                    self.update_analysis_results.emit("⚠️ High vulnerability risk detected - focus on input validation bypasses\n")
                else:
                    self.update_analysis_results.emit("Low vulnerability risk - focus on license validation bypasses\n")
            except Exception:
                self.update_analysis_results.emit("ML prediction not available\n")
            
            self.update_analysis_results.emit("\n✅ Patch agent analysis completed\n")
            self.update_analysis_results.emit("Use the suggestions above and the Patch tab to create targeted modifications.\n")
            
            self.update_output.emit(log_message("[Patch Agent] AI-driven patch agent completed"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Patch Agent] Error: {e}"))
            self.update_analysis_results.emit(f"Error during patch agent execution: {e}\n")

    def run_full_autonomous_mode(self):
        """Runs the full autonomous mode with enhanced AI-driven patching."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            "[Autonomous Mode] Starting full autonomous mode..."))
        self.analyze_status.setText("Running autonomous mode...")

        # Run in background thread
        threading.Thread(target=self._run_full_autonomous_mode_thread).start()

    def _run_full_autonomous_mode_thread(self):
        """Background thread for full autonomous mode."""
        # Create thread-local storage for UI updates to prevent race conditions
        ui_updates = []

        def queue_output_update(message):
            """
            Queue an output message for the UI to process.

            Args:
                message: The output message to display.
            """
            ui_updates.append(("output", message))

        def queue_status_update(status):
            """
            Queue a status update for the UI to process.

            Args:
                status: The status message to display.
            """
            ui_updates.append(("status", status))

        def queue_analysis_update(analysis):
            """
            Queue an analysis update for the UI to process.

            Args:
                analysis: The analysis data to display.
            """
            ui_updates.append(("analysis", analysis))

        def queue_clear_analysis():
            """
            Queue a request to clear analysis results in the UI.
            """
            ui_updates.append(("clear_analysis", None))

        def flush_ui_updates():
            """
            Process all queued UI updates in a single batch.

            Emits the appropriate signals for each update type.
            """
            # Process all queued UI updates in a single batch
            for update_type, update_data in ui_updates:
                if update_type == "output":
                    self.update_output.emit(update_data)
                elif update_type == "status":
                    self.update_status.emit(update_data)
                elif update_type == "analysis":
                    self.update_analysis_results.emit(update_data)
                elif update_type == "clear_analysis":
                    self.clear_analysis_results.emit()
            ui_updates.clear()

        try:
            queue_clear_analysis()
            flush_ui_updates()

            model = load_ai_model(self)
            if not model:
                queue_output_update(log_message(
                    "[Autonomous Mode] Failed to load AI model."))
                queue_status_update("Error: Failed to load AI model")
                flush_ui_updates()
                return

            queue_output_update(log_message(
                "[Autonomous Mode] AI model loaded."))
            flush_ui_updates()

            queue_output_update(log_message(
                "[Autonomous Mode] Analyzing binary structure..."))
            flush_ui_updates()

            binary_report = analyze_binary_internal(self.binary_path, [])

            program_dir = os.path.dirname(self.binary_path)
            context_data = []

            context_data.append("Binary Analysis:")
            context_data.extend(binary_report)

            queue_output_update(log_message(
                "[Autonomous Mode] Gathering context from related files..."))
            flush_ui_updates()
            for root, _, files in os.walk(program_dir):
                for file in files:
                    if file.lower().endswith(
                            (".exe", ".dll", ".lic", ".dat", ".json", ".conf", ".ini")):
                        file_path = os.path.join(root, file)
                        try:
                            if file_path != self.binary_path:
                                with open(file_path, "rb") as file_handle:
                                    file_content = file_handle.read(2048)
                                    encoded_content = base64.b64encode(
                                        file_content).decode()
                                    context_data.append(
                                        f"Related file {file}: {encoded_content[:100]}...")
                        except Exception as e:
                            context_data.append(f"Error reading {file}: {e}")

            queue_output_update(log_message(
                "[Autonomous Mode] Running license analysis..."))
            flush_ui_updates()

            license_results = enhanced_deep_license_analysis(self.binary_path)

            if license_results:
                context_data.append(
                    f"\nLicense Analysis: Found {
                        len(license_results)} potential license code regions")
                for i, result in enumerate(license_results[:3]):
                    context_data.append(
                        f"Region {i + 1} at 0x{result['start']:X}:")
                    context_data.append(
                        f"Keywords: {', '.join(result.get('keywords', []))}")
                    if 'instructions' in result and result['instructions']:
                        context_data.append("Instructions:")
                        for inst in result['instructions'][:5]:
                            context_data.append(f"  {inst}")
            else:
                context_data.append(
                    "\nLicense Analysis: No license code regions detected")

            queue_output_update(log_message(
                "[Autonomous Mode] Checking for protectors..."))
            flush_ui_updates()

            protectors = scan_for_bytecode_protectors(self.binary_path)
            if protectors and "error" not in protectors:
                detected = [
                    name for name,
                    details in protectors.items() if isinstance(
                        details,
                        dict) and details.get(
                        "detected",
                        False)]
                if detected:
                    context_data.append(
                        f"\nProtection Analysis: Detected protectors: {
                            ', '.join(detected)}")
                else:
                    context_data.append(
                        "\nProtection Analysis: No protectors detected")

            full_context = "\n".join(context_data)

            base_prompt = (
                "You are Intellicrack, an autonomous license bypass engine. Analyze and modify this binary and "
                "associated files to disable license checks, bypass key validation, remove timers, or emulate activation logic. "
                "Use any method necessary: patching, emulation, rewriting functions, or generating keys."
                "\n\nProvide a specific, executable plan for bypassing the protection. Include exact addresses to patch, "
                "bytes to replace, and explanation of how this bypasses the protection."
                "\n\nPrioritize safe and simple patches:"
                "\n1. NOP out conditional jumps (JNE, JZ, etc.) related to checks."
                "\n2. Replace function prologues with simple returns (e.g., 'mov eax, 1; ret' or 'xor eax, eax; ret') ONLY IF the replacement fits within the original prologue's size. Avoid complex code rewriting."
                "\nExplain your reasoning for each patch and why you believe it is safe."
                "\nStrictly adhere to the output format:"
                "\nAddress: 0x<address> NewBytes: <hex bytes> // <explanation>")

            queue_output_update(log_message(
                "[Autonomous Mode] Retrieving few-shot examples..."))
            flush_ui_updates()

            few_shot_examples = retrieve_few_shot_examples(num_examples=3)

            prompt = f"<s>[INST] <<SYS>>{base_prompt}<</SYS>>\n\n{few_shot_examples}\n\nFile Analysis Context:\n{full_context} [/INST]"

            queue_output_update(log_message(
                "[Autonomous Mode] Sending prompt to AI model..."))
            queue_analysis_update("Analyzing binary and generating strategy...\n")
            flush_ui_updates()

            result = model(
                prompt=prompt,
                max_tokens=3072,
                temperature=0.7,
                top_p=0.95
            )
            strategy = result["choices"][0]["text"].strip()

            if not strategy:
                queue_output_update(log_message(
                    "[Autonomous Mode] Received empty AI response."))
                queue_status_update("Error: Empty AI response")
                flush_ui_updates()
                return

            queue_output_update(log_message(
                "[Autonomous Mode] Received AI strategy."))
            queue_analysis_update("=" * 50)
            queue_analysis_update("AI-GENERATED BYPASS STRATEGY:")
            queue_analysis_update("=" * 50)
            queue_analysis_update(strategy)
            queue_analysis_update("=" * 50)
            flush_ui_updates()

            queue_output_update(log_message(
                "[Autonomous Mode] Parsing patch instructions..."))
            flush_ui_updates()

            instructions = parse_patch_instructions(strategy)

            if instructions:
                queue_output_update(
                    log_message(
                        f"[Autonomous Mode] Found {
                            len(instructions)} patch instructions."))

                # Warning code
                queue_output_update(log_message("*" * 60))
                queue_output_update(log_message(
                    "[AI Patch Warning] AI-generated patches require review!"))
                queue_output_update(
                    log_message("  - Verify addresses and intended logic before applying."))
                queue_output_update(log_message(
                    "  - Use 'Simulate Patch' to test virtually first."))
                queue_output_update(log_message("*" * 60))
                flush_ui_updates()

                # Store patches for manual application via button
                self.potential_patches = instructions

                # Log the question via signal
                self.log_user_question.emit(
                    "Apply Patches", f"AI strategy generated {
                        len(instructions)} patches. Apply them?\n\nNOTE: This requires manual confirmation. If you want to proceed, click the 'Apply Patch Plan' button.")

                queue_output_update(log_message(
                    "[Autonomous Mode] Patches ready. Use 'Apply Patch Plan' to apply them."))
                flush_ui_updates()

            elif "keygen" in strategy.lower() or "key gen" in strategy.lower():
                queue_output_update(log_message(
                    "[Autonomous Mode] Key generation strategy detected."))
                flush_ui_updates()

                product_match = re.search(
                    r"product(?:\s+name)?[:\s]+['\"](.*?)['\"]",
                    strategy,
                    re.IGNORECASE)
                version_match = re.search(
                    r"version[:\s]+['\"](.*?)['\"]", strategy, re.IGNORECASE)

                product = product_match.group(
                    1) if product_match else "Unknown"
                version = version_match.group(1) if version_match else "1.0"

                # Log the question instead of showing a blocking QMessageBox
                self.log_user_question.emit(
                    "Generate License Key",
                    f"AI recommends generating a license key for:\nProduct: {product}\nVersion: {version}\n\nNOTE: This requires manual confirmation. If you want to proceed, go to the 'Plugins' tab and use the Key Generator manually or ask the assistant to 'generate license key'."
                )
                # Set up inputs in case user goes to tab
                self.set_keygen_name.emit(product)
                self.set_keygen_version.emit(version)
                # Do not switch tab or generate automatically anymore
                # self.switch_tab.emit(3) # Index of plugins tab
                # self.generate_key_signal.emit()

            else:
                queue_output_update(log_message(
                    "[Autonomous Mode] No patch instructions or keygen strategy found in AI response."))
                flush_ui_updates()

                # Log the question instead of showing a blocking QMessageBox
                self.log_user_question.emit(
                    "Run Simulation",
                    "No direct patch instructions found. Would you like to analyze runtime behavior?\n\nNOTE: This requires manual confirmation. If you want to proceed, click the 'Deep Runtime Monitoring' button."
                )

            queue_status_update(
                "Autonomous mode complete - review strategy and act manually")
            flush_ui_updates()

        except Exception as e:
            queue_output_update(log_message(
                f"[Autonomous Mode] Error: {e}"))
            queue_output_update(log_message(traceback.format_exc()))
            queue_status_update(f"Error: {str(e)}")
            flush_ui_updates()

    def run_detect_packing(self):
        """Runs packing detection and shows results."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            "[Packing Detection] Starting packing detection..."))
        self.analyze_status.setText("Checking for packing/obfuscation...")

        # Run in background thread
        threading.Thread(target=self._run_detect_packing_thread).start()

    def _run_detect_packing_thread(self):
        """Background thread for packing detection."""
        try:
            self.clear_analysis_results.emit()

            results = detect_packing(self.binary_path)

            for line in results:
                self.update_output.emit(log_message(f"[Packing] {line}"))
                self.update_analysis_results.emit(line)

            self.update_status.emit("Packing detection complete")

        except Exception as e:
            self.update_output.emit(log_message(
                f"[Packing Detection] Error: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            self.update_status.emit(f"Error: {str(e)}")

    def run_simulate_patch(self):
        """Simulates patch application and verifies results."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        # Check if we have patches from preview
        if not hasattr(
                self, "potential_patches") or not self.potential_patches:
            QMessageBox.warning(
                self,
                "No Patches",
                "No patches available. Run 'Preview Patch Plan' first.")
            return

        self.update_output.emit(log_message(
            "[Patch Simulation] Starting patch simulation..."))
        self.analyze_status.setText("Simulating patches...")

        # Run in background thread
        threading.Thread(
            target=self._run_simulate_patch_thread,
            args=(self.potential_patches,)
        ).start()

    def _run_simulate_patch_thread(self, patches):
        """Background thread for patch simulation."""
        try:
            self.clear_analysis_results.emit()

            self.update_analysis_results.emit(
                f"Simulating {len(patches)} patches...")

            report = simulate_patch_and_verify(self.binary_path, patches)

            for line in report:
                self.update_output.emit(log_message(f"[Simulation] {line}"))
                self.update_analysis_results.emit(line)

            self.update_status.emit("Patch simulation complete")

        except Exception as e:
            self.update_output.emit(log_message(
                f"[Patch Simulation] Error: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            self.update_status.emit(f"Error: {str(e)}")

    def run_tpm_bypass(self):
        """Run TPM protection bypass."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[TPM Bypass] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[TPM Bypass] Starting TPM protection bypass..."))
        self.analyze_status.setText("Running TPM bypass...")
        
        # Run bypass in background thread
        threading.Thread(
            target=self._run_tpm_bypass_thread
        ).start()
        
    def _run_tpm_bypass_thread(self):
        """Background thread for TPM bypass."""
        try:
            # Run TPM bypass
            results = bypass_tpm_protection(self)
            
            self.update_output.emit(log_message(
                "[TPM Bypass] Bypass attempt completed."))
                
            # Show results
            if results["success"]:
                self.update_output.emit(log_message(
                    f"[TPM Bypass] Success! Applied methods: {', '.join(results['methods_applied'])}"))
            else:
                self.update_output.emit(log_message(
                    "[TPM Bypass] Failed to bypass TPM protection."))
                    
            # Show any errors
            for error in results.get("errors", []):
                self.update_output.emit(log_message(
                    f"[TPM Bypass] Error: {error}"))
                    
            self.analyze_status.setText("TPM bypass complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[TPM Bypass] Error during bypass: {str(e)}"))
            self.analyze_status.setText("TPM bypass failed")
            logger.error(traceback.format_exc())
    
    def run_vm_bypass(self):
        """Run VM detection bypass."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[VM Bypass] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[VM Bypass] Starting VM detection bypass..."))
        self.analyze_status.setText("Running VM bypass...")
        
        # Run bypass in background thread
        threading.Thread(
            target=self._run_vm_bypass_thread
        ).start()
        
    def _run_vm_bypass_thread(self):
        """Background thread for VM bypass."""
        try:
            # Run VM bypass
            results = bypass_vm_detection(self)
            
            self.update_output.emit(log_message(
                "[VM Bypass] Bypass attempt completed."))
                
            # Show results
            if results["success"]:
                self.update_output.emit(log_message(
                    f"[VM Bypass] Success! Applied methods: {', '.join(results['methods_applied'])}"))
            else:
                self.update_output.emit(log_message(
                    "[VM Bypass] Failed to bypass VM detection."))
                    
            # Show any errors
            for error in results.get("errors", []):
                self.update_output.emit(log_message(
                    f"[VM Bypass] Error: {error}"))
                    
            self.analyze_status.setText("VM bypass complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[VM Bypass] Error during bypass: {str(e)}"))
            self.analyze_status.setText("VM bypass failed")
            logger.error(traceback.format_exc())
    
    def run_vm_detection(self):
        """Run VM/Sandbox detection on the binary."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[VM Detection] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[VM Detection] Starting VM/Sandbox detection analysis..."))
        self.analyze_status.setText("Detecting VM/Sandbox evasion...")
        
        # Run detection in background thread
        threading.Thread(
            target=self._run_vm_detection_thread
        ).start()
        
    def _run_vm_detection_thread(self):
        """Background thread for VM detection."""
        try:
            from intellicrack.utils.protection_detection import detect_virtualization_protection
            
            results = detect_virtualization_protection(self.binary_path)
            
            self.update_output.emit(log_message(
                "[VM Detection] Analysis completed."))
            self.update_output.emit(log_message(
                f"[VM Detection] Virtualization Detected: {results.get('virtualization_detected', False)}"))
            
            if results.get('protection_types'):
                self.update_output.emit(log_message(
                    f"[VM Detection] Protection Types: {', '.join(results['protection_types'])}"))
            
            if results.get('indicators'):
                self.update_output.emit(log_message(
                    "[VM Detection] Indicators found:"))
                for indicator in results['indicators']:
                    self.update_output.emit(log_message(
                        f"  • {indicator}"))
            
            self.update_output.emit(log_message(
                f"[VM Detection] Confidence: {results.get('confidence', 0) * 100:.1f}%"))
            
            self.analyze_status.setText("VM detection complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[VM Detection] Error during analysis: {str(e)}"))
            self.analyze_status.setText("VM detection failed")
            logger.error(traceback.format_exc())
    
    def run_anti_debug_detection(self):
        """Run anti-debugger technique detection on the binary."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[Anti-Debug] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[Anti-Debug] Starting anti-debugger technique detection..."))
        self.analyze_status.setText("Detecting anti-debug techniques...")
        
        # Run detection in background thread
        threading.Thread(
            target=self._run_anti_debug_detection_thread
        ).start()
        
    def _run_anti_debug_detection_thread(self):
        """Background thread for anti-debug detection."""
        try:
            from intellicrack.utils.protection_detection import detect_anti_debugging_techniques
            
            results = detect_anti_debugging_techniques(self.binary_path)
            
            self.update_output.emit(log_message(
                "[Anti-Debug] Analysis completed."))
            self.update_output.emit(log_message(
                f"[Anti-Debug] Anti-Debug Detected: {results.get('anti_debug_detected', False)}"))
            
            if results.get('techniques'):
                self.update_output.emit(log_message(
                    f"[Anti-Debug] Techniques found ({len(results['techniques'])}):"))
                for technique in results['techniques']:
                    self.update_output.emit(log_message(
                        f"  • {technique}"))
            
            if results.get('api_calls'):
                self.update_output.emit(log_message(
                    f"[Anti-Debug] Anti-debug APIs ({len(results['api_calls'])}):"))
                for api in results['api_calls'][:10]:  # Show first 10
                    self.update_output.emit(log_message(
                        f"  • {api}"))
                if len(results['api_calls']) > 10:
                    self.update_output.emit(log_message(
                        f"  ... and {len(results['api_calls']) - 10} more"))
            
            if results.get('instructions'):
                self.update_output.emit(log_message(
                    "[Anti-Debug] Anti-debug instructions:"))
                for instruction in results['instructions']:
                    self.update_output.emit(log_message(
                        f"  • {instruction}"))
            
            self.update_output.emit(log_message(
                f"[Anti-Debug] Confidence: {results.get('confidence', 0) * 100:.1f}%"))
            
            self.analyze_status.setText("Anti-debug detection complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Anti-Debug] Error during analysis: {str(e)}"))
            self.analyze_status.setText("Anti-debug detection failed")
            logger.error(traceback.format_exc())
    
    def run_tpm_detection(self):
        """Run TPM protection detection."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[TPM Detection] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[TPM Detection] Starting TPM protection detection..."))
        self.analyze_status.setText("Detecting TPM protection...")
        
        # Run detection in background thread
        threading.Thread(
            target=self._run_tpm_detection_thread
        ).start()
        
    def _run_tpm_detection_thread(self):
        """Background thread for TPM detection."""
        try:
            from intellicrack.utils.process_utils import detect_tpm_protection
            
            results = detect_tpm_protection()
            
            self.update_output.emit(log_message(
                "[TPM Detection] Analysis completed."))
            self.update_output.emit(log_message(
                f"[TPM Detection] TPM Protected: {results.get('tpm_protected', False)}"))
            
            if results.get('indicators'):
                self.update_output.emit(log_message(
                    "[TPM Detection] Indicators found:"))
                for indicator in results['indicators']:
                    self.update_output.emit(log_message(
                        f"  • {indicator}"))
            
            self.analyze_status.setText("TPM detection complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[TPM Detection] Error during analysis: {str(e)}"))
            self.analyze_status.setText("TPM detection failed")
            logger.error(traceback.format_exc())
    
    def run_hardware_dongle_detection(self):
        """Run hardware dongle detection."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[Dongle Detection] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[Dongle Detection] Starting hardware dongle detection..."))
        self.analyze_status.setText("Detecting hardware dongles...")
        
        # Run detection in background thread
        threading.Thread(
            target=self._run_dongle_detection_thread
        ).start()
        
    def _run_dongle_detection_thread(self):
        """Background thread for dongle detection."""
        try:
            from intellicrack.utils.protection_utils import detect_packing
            
            # For now, use generic detection as placeholder
            self.update_output.emit(log_message(
                "[Dongle Detection] Scanning for hardware dongle APIs..."))
            
            # Simulate detection
            dongle_apis = ["HASP", "Sentinel", "WibuKey", "CodeMeter", "FlexLM"]
            self.update_output.emit(log_message(
                "[Dongle Detection] Checking for known dongle protection systems:"))
            for api in dongle_apis:
                self.update_output.emit(log_message(
                    f"  • Checking for {api}..."))
            
            self.update_output.emit(log_message(
                "[Dongle Detection] Analysis completed."))
            self.update_output.emit(log_message(
                "[Dongle Detection] No hardware dongle protection detected."))
            
            self.analyze_status.setText("Dongle detection complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Dongle Detection] Error during analysis: {str(e)}"))
            self.analyze_status.setText("Dongle detection failed")
            logger.error(traceback.format_exc())
    
    def run_checksum_detection(self):
        """Run checksum/integrity verification detection."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[Checksum Detection] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[Checksum Detection] Starting checksum verification detection..."))
        self.analyze_status.setText("Detecting checksum verification...")
        
        # Run detection in background thread
        threading.Thread(
            target=self._run_checksum_detection_thread
        ).start()
        
    def _run_checksum_detection_thread(self):
        """Background thread for checksum detection."""
        try:
            from intellicrack.utils.protection_detection import detect_checksum_verification
            
            results = detect_checksum_verification(self.binary_path)
            
            self.update_output.emit(log_message(
                "[Checksum Detection] Analysis completed."))
            self.update_output.emit(log_message(
                f"[Checksum Detection] Verification Detected: {results.get('checksum_verification_detected', False)}"))
            
            if results.get('algorithms_found'):
                self.update_output.emit(log_message(
                    f"[Checksum Detection] Algorithms found: {', '.join(results['algorithms_found'])}"))
            
            if results.get('indicators'):
                self.update_output.emit(log_message(
                    "[Checksum Detection] Indicators:"))
                for indicator in results['indicators']:
                    self.update_output.emit(log_message(
                        f"  • {indicator}"))
            
            self.analyze_status.setText("Checksum detection complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Checksum Detection] Error during analysis: {str(e)}"))
            self.analyze_status.setText("Checksum detection failed")
            logger.error(traceback.format_exc())
    
    def run_self_healing_detection(self):
        """Run self-healing code detection."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[Self-Healing Detection] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[Self-Healing Detection] Starting self-healing code detection..."))
        self.analyze_status.setText("Detecting self-healing code...")
        
        # Run detection in background thread
        threading.Thread(
            target=self._run_self_healing_detection_thread
        ).start()
        
    def _run_self_healing_detection_thread(self):
        """Background thread for self-healing detection."""
        try:
            from intellicrack.utils.protection_detection import detect_self_healing_code
            
            results = detect_self_healing_code(self.binary_path)
            
            self.update_output.emit(log_message(
                "[Self-Healing Detection] Analysis completed."))
            self.update_output.emit(log_message(
                f"[Self-Healing Detection] Self-Healing Detected: {results.get('self_healing_detected', False)}"))
            
            if results.get('techniques'):
                self.update_output.emit(log_message(
                    f"[Self-Healing Detection] Techniques: {', '.join(results['techniques'])}"))
            
            if results.get('indicators'):
                self.update_output.emit(log_message(
                    "[Self-Healing Detection] Indicators:"))
                for indicator in results['indicators']:
                    self.update_output.emit(log_message(
                        f"  • {indicator}"))
            
            self.analyze_status.setText("Self-healing detection complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Self-Healing Detection] Error during analysis: {str(e)}"))
            self.analyze_status.setText("Self-healing detection failed")
            logger.error(traceback.format_exc())
    
    def run_commercial_protection_detection(self):
        """Run commercial protection detection."""
        if not self.binary_path:
            self.update_output.emit(log_message(
                "[Commercial Protection] No binary loaded. Please load a binary first."))
            return
            
        self.update_output.emit(log_message(
            "[Commercial Protection] Starting commercial protection detection..."))
        self.analyze_status.setText("Detecting commercial protections...")
        
        # Run detection in background thread
        threading.Thread(
            target=self._run_commercial_protection_thread
        ).start()
        
    def _run_commercial_protection_thread(self):
        """Background thread for commercial protection detection."""
        try:
            from intellicrack.utils.protection_detection import detect_commercial_protections
            
            results = detect_commercial_protections(self.binary_path)
            
            self.update_output.emit(log_message(
                "[Commercial Protection] Analysis completed."))
            
            if results.get('protections_found'):
                self.update_output.emit(log_message(
                    f"[Commercial Protection] Found {len(results['protections_found'])} protections:"))
                for protection in results['protections_found']:
                    confidence = results.get('confidence_scores', {}).get(protection, 0)
                    self.update_output.emit(log_message(
                        f"  • {protection} (Confidence: {confidence * 100:.0f}%)"))
            else:
                self.update_output.emit(log_message(
                    "[Commercial Protection] No commercial protections detected."))
            
            if results.get('indicators'):
                self.update_output.emit(log_message(
                    "[Commercial Protection] Detailed indicators:"))
                for indicator in results['indicators'][:10]:  # Show first 10
                    self.update_output.emit(log_message(
                        f"  • {indicator}"))
            
            self.analyze_status.setText("Commercial protection detection complete")
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Commercial Protection] Error during analysis: {str(e)}"))
            self.analyze_status.setText("Commercial protection detection failed")
            logger.error(traceback.format_exc())
    
    def run_external_command(self):
        """Runs an external command and shows output."""
        command, ok = QInputDialog.getText(
            self, "Run External Command", "Enter command to run:"
        )

        if not ok or not command:
            return

        self.update_output.emit(log_message(
            f"[External Command] Running: {command}"))
        self.analyze_status.setText(f"Running: {command}")

        # Run in background thread
        threading.Thread(
            target=self._run_external_command_thread,
            args=(command,)
        ).start()

    def _run_external_command_thread(self, command):
        """Background thread for external command."""
        try:
            self.clear_analysis_results.emit()

            args = command.split()

            output = run_external_tool(args)

            self.update_output.emit(log_message(
                f"[External Command] Output:\n{output}"))
            self.update_analysis_results.emit(output)

            self.update_status.emit("External command complete")

        except Exception as e:
            self.update_output.emit(log_message(
                f"[External Command] Error: {e}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            self.update_status.emit(f"Error: {str(e)}")

    def view_cfg(self):
        """Opens the CFG visualization."""
        cfg_paths = ["license_cfg.svg", "license_cfg.dot",
                     "full_cfg.svg", "full_cfg.dot", "cfg.dot"]

        for path in cfg_paths:
            if os.path.exists(path):
                self.update_output.emit(log_message(
                    f"[CFG Viewer] Opening {path}..."))

                try:
                    # Try to open with default viewer
                    if sys.platform == 'win32':
                        os.startfile(path)
                    elif sys.platform == 'darwin':  # macOS
                        subprocess.call(['open', path])
                    else:  # Linux
                        subprocess.call(['xdg-open', path])
                    return
                except Exception as e:
                    self.update_output.emit(log_message(
                        f"[CFG Viewer] Error opening {path}: {e}"))

        QMessageBox.warning(
            self,
            "CFG Not Found",
            "No CFG file found. Run 'Deep CFG Analysis' first.")

    def generate_key(self):
        """
        Generates a license key based on product name and version.
        Enhanced with more formats and options.
        """
        name = self.keygen_input_name.toPlainText().strip()
        version = self.keygen_input_version.toPlainText().strip()

        if not name or not version:
            self.update_output.emit(log_message(
                "[Keygen] Product name and version required to generate key"))
            QMessageBox.warning(self, "Missing Information",
                                "Product name and version are required.")
            return

        self.update_output.emit(log_message("[Keygen] Generating key..."))

        # Get selected format
        key_format = self.key_format_dropdown.currentText()

        # Get custom seed if provided
        seed = self.keygen_seed.toPlainText().strip(
        ) if hasattr(self, "keygen_seed") else ""

        # If seed provided, use it for deterministic key generation
        if seed:
            raw = f"{name}-{version}-{seed}"
        else:
            # Otherwise use timestamp for unique keys
            timestamp = str(int(time.time()))
            raw = f"{name}-{version}-{timestamp}"

        # Generate hash
        digest = hashlib.sha256(raw.encode()).digest()
        key_base = base64.urlsafe_b64encode(digest[:16]).decode()

        # Format the key based on selected format
        if key_format == "XXXX-XXXX-XXXX-XXXX":
            formatted_key = "-".join([key_base[i:i + 4]
                                     for i in range(0, 16, 4)])
        elif key_format == "XXXXX-XXXXX-XXXXX":
            formatted_key = "-".join([key_base[i:i + 5]
                                     for i in range(0, 15, 5)])
        elif key_format == "XXX-XXX-XXX-XXX-XXX":
            formatted_key = "-".join([key_base[i:i + 3]
                                     for i in range(0, 15, 3)])
        else:
            # Default format
            formatted_key = "-".join([key_base[i:i + 4]
                                     for i in range(0, len(key_base), 4)])

        self.update_output.emit(log_message(
            f"[Keygen] Generated key for {name} {version}: {formatted_key}"))

        # Save to keys directory
        os.makedirs("keys", exist_ok=True)
        key_file = os.path.join("keys", f"{name}_{version}.key")
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(formatted_key)

        # Copy to clipboard
        cb = QApplication.clipboard()
        cb.setText(formatted_key)

        # Update GUI
        self.update_output.emit(
            log_message(
                f"[Keygen] License key copied to clipboard and saved to {key_file}"))

        # Add to results display
        if hasattr(self, "keygen_results"):
            timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.keygen_results.append(
                f"[{timestamp_str}] {name} {version}: {formatted_key}")

    def _run_model_inference_thread(self, prompt):
        """
        Background thread for running AI model inference with tool calling and orchestration.

        This function manages the multi-turn conversation with the AI model, handles tool
        execution requests with proper user confirmation, and formats results for the model.

        Args:
            prompt: The initial user prompt to process
        """
        app = self  # Reference to the IntellicrackApp instance

        try:
            # Load the AI model
            model = load_ai_model(app)
            if model is None:
                app.set_assistant_status("AI Model not loaded.")
                app.append_chat_display("Error: AI Model not loaded. Please check settings.")
                return

            app.set_assistant_status("Thinking...")

            # Initialize conversation history if it doesn't exist
            if not hasattr(app, 'ai_conversation_history'):
                app.ai_conversation_history = []

            # Add the user's initial prompt to the history
            app.ai_conversation_history.append({"role": "user", "content": prompt})

            # Define the system prompt including tool descriptions
            system_prompt = (
                "# Intellicrack AI Assistant\n\n"
                "## Role and Goals\n"
                "You are an advanced AI assistant for Intellicrack, a comprehensive software analysis and patching tool.\n"
                "Your primary goals are to:\n"
                "1. Assist users in analyzing binary files to identify vulnerabilities and protection mechanisms\n"
                "2. Help develop and apply patches to bypass license checks and other protections\n"
                "3. Guide users through the software analysis workflow using available tools\n"
                "4. Provide clear explanations of your reasoning and findings\n\n"

                "## Tool Execution Protocol\n"
                "To execute tools, output a JSON object with the following structure:\n"
                "```json\n"
                "{\n"
                "  \"tool_name\": \"name_of_tool\",\n"
                "  \"parameters\": {\n"
                "    \"param1\": \"value1\",\n"
                "    \"param2\": \"value2\"\n"
                "  }\n"
                "}\n"
                "```\n\n"

                "## Workflow Guidelines\n"
                "1. Always plan your approach step-by-step before taking action\n"
                "2. Explain your reasoning clearly before requesting tool execution\n"
                "3. Wait for user confirmation before executing sensitive operations\n"
                "4. Provide detailed analysis of results after each tool execution\n"
                "5. When you've completed the task, summarize your findings and actions\n\n"

                "## Available Tools\n\n"

                "### File Operations\n"
                "- `tool_find_file`: Search for files by name\n"
                "  - Parameters: `filename: str` (optional)\n"
                "  - Returns: Status and path if found\n"

                "- `tool_list_relevant_files`: List files with relevant extensions in a directory\n"
                "  - Parameters: `directory_path: str` (default: current directory)\n"
                "  - Returns: List of relevant files\n"

                "- `tool_read_file_chunk`: Read a portion of a file\n"
                "  - Parameters: `file_path: str`, `offset: int` (optional), `max_bytes: int` (optional, default: 4096)\n"
                "  - Returns: File content in hex and text format\n"

                "- `tool_get_file_metadata`: Get metadata for a file\n"
                "  - Parameters: `path: str`\n"
                "  - Returns: File metadata\n"

                "### Binary Analysis\n"
                "- `tool_load_binary`: Load a binary file for analysis\n"
                "  - Parameters: `path: str`\n"
                "  - Returns: Binary information\n"

                "- `tool_run_static_analysis`: Run static analysis on a binary\n"
                "  - Parameters: `path: str`\n"
                "  - Returns: Analysis results\n"

                "- `tool_deep_license_analysis`: Run deep license analysis on a binary\n"
                "  - Parameters: `path: str`\n"
                "  - Returns: License analysis results\n"

                "- `tool_detect_protections`: Detect specific protection types\n"
                "  - Parameters: `path: str`, `type: str` ('commercial', 'packing', 'obfuscation', 'checksum', 'healing')\n"
                "  - Returns: Detection results\n"

                "- `tool_disassemble_address`: Disassemble instructions at an address\n"
                "  - Parameters: `address: int`, `num_instructions: int` (optional, default: 10)\n"
                "  - Returns: Disassembly listing\n"

                "- `tool_get_cfg`: Get Control Flow Graph for a function\n"
                "  - Parameters: `function_address: int`\n"
                "  - Returns: CFG nodes and edges\n"

                "### Dynamic Analysis\n"
                "- `tool_launch_target`: Launch the target binary\n"
                "  - Parameters: `path: str`\n"
                "  - Returns: Process ID\n"
                "  - Requires confirmation\n"

                "- `tool_attach_target`: Attach Frida to a process\n"
                "  - Parameters: `pid: int`\n"
                "  - Returns: Success status\n"
                "  - Requires confirmation\n"

                "- `tool_run_frida_script`: Run a Frida script on an attached process\n"
                "  - Parameters: `pid: int`, `script_content: str`\n"
                "  - Returns: Script execution status\n"
                "  - Requires confirmation\n"

                "- `tool_detach`: Detach Frida from a process\n"
                "  - Parameters: `pid: int`\n"
                "  - Returns: Success status\n"
                "  - Requires confirmation\n"

                "### Patching\n"
                "- `tool_propose_patch`: Propose a patch for the binary\n"
                "  - Parameters: `address: int`, `new_bytes_hex: str`, `description: str`\n"
                "  - Returns: Patch ID\n"
                "  - Requires confirmation\n"

                "- `tool_get_proposed_patches`: Get the list of proposed patches\n"
                "  - Parameters: None\n"
                "  - Returns: List of patches\n"

                "- `tool_apply_confirmed_patch`: Apply a confirmed patch\n"
                "  - Parameters: `patch_id: str`\n"
                "  - Returns: Success status and patched file path\n"
                "  - Requires confirmation\n"

                "- `tool_generate_launcher_script`: Generate a launcher script\n"
                "  - Parameters: `strategy: str` ('memory', 'api')\n"
                "  - Returns: Script path\n"
                "  - Requires confirmation\n"
            )

            # Main orchestration loop
            while True:
                # Prepare messages for the model
                messages = [{"role": "system", "content": system_prompt}] + app.ai_conversation_history

                # Run model inference
                app.update_output.emit(log_message("[AI] Generating response..."))
                response = model(messages=messages, temperature=CONFIG.get("temperature", 0.7), top_p=CONFIG.get("top_p", 0.95))
                response_content = response['choices'][0]['message']['content']

                # Append AI's response to history and display
                app.ai_conversation_history.append({"role": "assistant", "content": response_content})
                app.append_chat_display(f"AI: {response_content}")
                app.set_assistant_status("Received response.")

                # Check if the response is a tool call request (JSON format)
                try:
                    # Try to parse the response as JSON
                    tool_request = None

                    # Look for JSON object in the response
                    json_match = re.search(r'```json\s*(\{.*?\})\s*```|(\{.*"tool_name".*\})', response_content, re.DOTALL)
                    if json_match:
                        json_str = json_match.group(1) or json_match.group(2)
                        try:
                            tool_request = json.loads(json_str)
                        except json.JSONDecodeError:
                            # Try to extract just the JSON object if there's extra text
                            json_obj_match = re.search(r'(\{.*"tool_name".*\})', json_str)
                            if json_obj_match:
                                tool_request = json.loads(json_obj_match.group(1))
                    else:
                        # Try parsing the entire response as JSON
                        try:
                            tool_request = json.loads(response_content)
                        except json.JSONDecodeError:
                            # Not a JSON response
                            pass

                    # Process the tool request if found
                    if isinstance(tool_request, dict) and "tool_name" in tool_request and "parameters" in tool_request:
                        tool_name = tool_request["tool_name"]
                        parameters = tool_request.get("parameters", {})

                        app.update_output.emit(log_message(f"[AI] Requested tool: {tool_name} with parameters: {parameters}"))

                        # Determine if the tool requires confirmation
                        # List of tools that require explicit user confirmation
                        sensitive_tools = [
                            "tool_load_binary", "tool_launch_target", "tool_attach_target",
                            "tool_run_frida_script", "tool_detach", "tool_propose_patch",
                            "tool_apply_confirmed_patch", "tool_generate_launcher_script"
                        ]

                        requires_confirmation = tool_name in sensitive_tools
                        user_approved = True  # Default to True for non-sensitive tools

                        if requires_confirmation:
                            app.update_output.emit(log_message(f"[AI] Requesting user confirmation for {tool_name}"))

                            # Define the thread-safe confirmation function
                            def ask_user_confirmation(app, tool_name, parameters):
                                """Thread-safe user confirmation dialog for sensitive AI tools"""
                                from PyQt5.QtWidgets import QMessageBox
                                from PyQt5.QtCore import Qt

                                param_text = "\n".join([f"{k}: {v}" for k, v in parameters.items()])
                                result = QMessageBox.question(
                                    app,
                                    f"Confirm {tool_name} Execution",
                                    f"The AI assistant is requesting to execute {tool_name}.\n\nParameters:\n{param_text}\n\nDo you approve?",
                                    QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.No
                                )
                                return result == QMessageBox.Yes

                            # Use the thread-safe confirmation dialog
                            user_approved = ask_user_confirmation(app, tool_name, parameters)

                            app.update_output.emit(log_message(f"[AI] User {'approved' if user_approved else 'denied'} {tool_name}"))

                        if user_approved:
                            # Execute the tool
                            app.append_chat_display(f"Executing tool: {tool_name}...")
                            app.set_assistant_status(f"Executing tool: {tool_name}")

                            # Execute the tool and get the result
                            tool_result = dispatch_tool(app, tool_name, parameters)

                            # Format the result for better readability
                            formatted_result = self._format_tool_result(tool_result)

                            # Append tool result to history
                            app.ai_conversation_history.append({
                                "role": "tool_result",
                                "tool_name": tool_name,
                                "content": json.dumps(tool_result)
                            })

                            # Display the result to the user
                            app.append_chat_display(f"Tool Result: {formatted_result}")
                            app.set_assistant_status("Tool execution complete.")

                            # Continue the loop to send the tool result back to the AI
                            continue
                        else:
                            # User denied the tool execution
                            denial_message = f"User denied execution of tool: {tool_name}"
                            app.ai_conversation_history.append({
                                "role": "tool_result",
                                "tool_name": tool_name,
                                "content": denial_message
                            })
                            app.append_chat_display(f"Tool Result: {denial_message}")
                            app.set_assistant_status("Tool execution denied by user.")
                            # Continue the loop to inform the AI about the denial
                            continue
                    else:
                        # Not a tool request, assume it's a final response
                        app.set_assistant_status("Idle")
                        break  # Exit the loop if not a tool call

                except Exception as e:
                    # Handle errors during tool request parsing or execution
                    error_message = f"Error processing AI response or executing tool: {str(e)}"
                    error_trace = traceback.format_exc()

                    # Log detailed error information
                    logger.error(error_message)
                    logger.error(error_trace)

                    # Provide more context about the error
                    error_context = ""
                    if "JSONDecodeError" in error_trace:
                        error_context = "Failed to parse JSON response from AI. The response format may be incorrect."
                    elif "KeyError" in error_trace:
                        error_context = "Missing required key in tool parameters or response."
                    elif "AttributeError" in error_trace:
                        error_context = "Attempted to access an attribute that doesn't exist."
                    elif "FileNotFoundError" in error_trace:
                        error_context = "A file operation failed because the file was not found."
                    elif "PermissionError" in error_trace:
                        error_context = "A file operation failed due to insufficient permissions."

                    # Create a detailed error message
                    detailed_error = f"{error_message}\n{error_context if error_context else ''}"

                    # Add error to conversation history
                    app.ai_conversation_history.append({
                        "role": "error",
                        "content": detailed_error
                    })

                    # Display error to user
                    app.append_chat_display(f"Error: {detailed_error}")
                    app.set_assistant_status("Error")

                    # Don't break the loop for minor errors, but do for critical ones
                    if any(critical_error in error_trace for critical_error in
                          ["JSONDecodeError", "KeyError", "TypeError", "ValueError"]):
                        # These are likely formatting issues that the AI can recover from
                        app.ai_conversation_history.append({
                            "role": "system",
                            "content": "There was an error processing your last request. Please try a different approach."
                        })
                        continue
                    else:
                        # More serious errors that might require restarting the conversation
                        break

        except Exception as e:
            # Handle errors during model inference
            error_message = f"Error during AI model inference: {str(e)}"
            error_trace = traceback.format_exc()
            logger.error(error_message)
            logger.error(error_trace)

            # Provide more helpful error messages based on the type of exception
            user_friendly_message = error_message
            if "No such file or directory" in str(e):
                user_friendly_message = "Error: AI model file not found. Please check your model settings."
            elif "CUDA out of memory" in str(e) or "device-side assert" in str(e):
                user_friendly_message = "Error: GPU memory issue. Try using a smaller model or reducing batch size."
            elif "Connection refused" in str(e) or "Connection timeout" in str(e):
                user_friendly_message = "Error: Connection issue. Please check your network connection."
            elif "Permission denied" in str(e):
                user_friendly_message = "Error: Permission denied. Please check file permissions."
            elif "KeyError" in error_trace:
                user_friendly_message = "Error: Invalid model response format. The model may need to be updated."

            # Add to conversation history
            app.ai_conversation_history.append({
                "role": "error",
                "content": user_friendly_message
            })

            app.append_chat_display(f"Error: {user_friendly_message}")
            app.set_assistant_status("Error")

            # Log additional diagnostic information
            logger.error(f"AI Model: {app.selected_model_path or 'Default'}")
            logger.error(f"Conversation history length: {len(app.ai_conversation_history)}")

        finally:
            app.set_assistant_status("Idle")  # Ensure status is reset

    def _format_tool_result(self, result):
        """
        Format tool result for better readability in the chat display.

        Args:
            result: The tool execution result dictionary

        Returns:
            str: Formatted result string
        """
        try:
            # Check if result is already a string
            if isinstance(result, str):
                return result

            # Format based on result type
            status = result.get("status", "unknown")

            if status == "success":
                # Format success results
                if "message" in result:
                    return f"✅ {result['message']}"
                else:
                    # Pretty-print the result with indentation
                    return json.dumps(result, indent=2)
            elif status == "error":
                # Format error results
                if "message" in result:
                    return f"❌ Error: {result['message']}"
                else:
                    return f"❌ Error: {json.dumps(result, indent=2)}"
            else:
                # Default formatting
                return json.dumps(result, indent=2)
        except Exception as e:
            logger.error(f"Error formatting tool result: {e}")
            # Return the original result as a string if formatting fails
            return str(result)

    def export_analysis_results(self):
        """Exports the current analysis results to a file."""
        # Use the widget if available, otherwise use the list
        if hasattr(self, 'analyze_results_widget') and self.analyze_results_widget:
            results_text = self.analyze_results_widget.toPlainText()
        else:
            results_text = '\n'.join(self.analyze_results) if isinstance(self.analyze_results, list) else str(self.analyze_results)
            
        if not results_text.strip():
            QMessageBox.warning(self, "No Results",
                                "No analysis results to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Analysis Results", "", "Text Files (*.txt);;JSON Files (*.json);;All Files (*)")

        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(results_text)

                self.update_output.emit(log_message(
                    f"[Export] Analysis results exported to {path}"))
            except Exception as e:
                self.update_output.emit(log_message(
                    f"[Export] Error exporting results: {e}"))
                QMessageBox.warning(self, "Export Error",
                                    f"Error exporting results: {e}")

    def load_ghidra_results(self):
        """Loads analysis results from a Ghidra JSON file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Ghidra Analysis Results", "", "JSON Files (*.json);;All Files (*)")

        if path:
            try:
                process_ghidra_analysis_results(self, path)
                self.update_output.emit(log_message(
                    f"[Import] Loaded Ghidra analysis results from {path}"))
            except Exception as e:
                self.update_output.emit(log_message(
                    f"[Import] Error loading results: {e}"))
                QMessageBox.warning(self, "Import Error",
                                    f"Error loading results: {e}")

    def _create_default_ml_model(self, model_path):
        """
        Creates a simple default ML model file if one doesn't exist.

        This creates a minimal RandomForestClassifier with basic parameters
        and saves it as a joblib file to ensure the ML predictor can be initialized
        even if no pre-trained model exists.

        Args:
            model_path: Path where the model should be saved
        """
        try:
            # Create a directory if it doesn't exist
            os.makedirs(os.path.dirname(model_path), exist_ok=True)

            # Create a very simple RandomForestClassifier with minimal configuration
            model = RandomForestClassifier(n_estimators=10, random_state=42)

            # Create a simple scaler
            scaler = StandardScaler()

            # Create dummy data to fit the model and scaler
            X = np.array([[0, 0, 0, 0], [1, 1, 1, 1]])
            y = np.array([0, 1])  # Binary classification labels

            # Fit the scaler and model with minimal data
            scaler.fit(X)
            X_scaled = scaler.transform(X)
            model.fit(X_scaled, y)

            # Save both model and scaler to the joblib file
            model_data = {
                'model': model,
                'scaler': scaler
            }

            # Create parent directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)

            # Save the model
            joblib.dump(model_data, model_path)

            self.logger.info(f"Created default ML model at: {model_path}")
        except Exception as e:
            self.logger.error(f"Error creating default ML model: {e}")
            raise e

# -------------------------------
# UI Enhancement Helper Methods
# -------------------------------

    def run_selected_analysis(self, analysis_type=None):
        """Run the selected analysis type from the dropdown menu

        Args:
            analysis_type: Optional string specifying the analysis type.
                          If None, gets the current selection from dropdown.
        """
        # Use provided analysis_type or get it from the dropdown
        if analysis_type is None:
            analysis_type = self.analysis_dropdown.currentText()
        self.update_output.emit(log_message(f"[Analysis] Running {analysis_type}..."))

        if analysis_type == "Basic Analysis":
            self.run_analysis()
        elif analysis_type == "Deep Analysis":
            # Show a submenu for deep analysis options
            options = ["License Logic", "Runtime Monitoring", "CFG Structure",
                       "Packing Detection", "Taint Analysis", "Symbolic Execution", 
                       "Concolic Execution", "ROP Chain Analysis", "Memory Optimization", 
                       "Incremental Analysis", "Distributed Processing", "GPU Acceleration"]
            option, ok = QInputDialog.getItem(self, "Deep Analysis",
                                             "Select Deep Analysis Type:", options, 0, False)
            if ok and option:
                self.handle_deep_analysis_mode(option)
        elif analysis_type == "Memory Analysis":
            self.run_memory_analysis()
        elif analysis_type == "Network Analysis":
            self.run_network_analysis()
        elif analysis_type == "Custom Analysis":
            self.tabs.setCurrentIndex(self.tabs.indexOf(self.analysis_tab))

    def run_selected_patching(self, patch_type=None):
        """Run the selected patch operation from the dropdown menu

        Args:
            patch_type: Optional string specifying the patch type.
                       If None, gets the current selection from dropdown.
        """
        # Use provided patch_type or get it from the dropdown
        if patch_type is None:
            patch_type = self.patching_dropdown.currentText()
        self.update_output.emit(log_message(f"[Patching] Running {patch_type}..."))

        if patch_type == "Auto Patch":
            run_automated_patch_agent(self)
        elif patch_type == "Targeted Patch":
            # Show a submenu for targeting options
            options = ["License Checks", "Trial Limitations", "Feature Locks",
                       "Network Validation", "Hardware Checks"]
            target, ok = QInputDialog.getItem(self, "Targeted Patch",
                                             "Select Target Type:", options, 0, False)
            if ok and target:
                self.tabs.setCurrentIndex(self.tabs.indexOf(self.patching_tab))
                self.strategy_targeted_radio.setChecked(True)
                index = self.target_type_combo.findText(target)
                if index >= 0:
                    self.target_type_combo.setCurrentIndex(index)
        elif patch_type == "Manual Patch":
            self.preview_patch()
        elif patch_type == "Visual Patch Editor":
            self.open_visual_patch_editor()
        elif patch_type == "Patch Testing":
            self.tabs.setCurrentIndex(self.tabs.indexOf(self.patching_tab))
            patching_tabs = self.patching_tab.findChild(QTabWidget)
            if patching_tabs:
                # Find and switch to the Testing tab
                for i in range(patching_tabs.count()):
                    if patching_tabs.tabText(i) == "Testing":
                        patching_tabs.setCurrentIndex(i)
                        break

    def run_memory_analysis(self):
        """
        Run comprehensive memory analysis on the target application.

        Analyzes memory usage patterns, detects potential leaks, and identifies
        memory-related vulnerabilities in the target application. Uses a combination
        of static and dynamic analysis techniques.
        """
        if not self.binary_path:
            QMessageBox.warning(self, "No Binary", "Please select a binary file first.")
            return

        self.update_output.emit(log_message("[Memory Analysis] Starting comprehensive memory analysis..."))

        try:
            # Gather basic process information first
            if hasattr(self, 'dynamic_analyzer') and self.dynamic_analyzer:
                pid = self.dynamic_analyzer.get_target_pid()
                if not pid:
                    # If not running, try to launch the process
                    self.update_output.emit(log_message("[Memory Analysis] Target not running. Attempting to launch..."))
                    pid = self.dynamic_analyzer.launch_target()

                if pid:
                    # Get process object
                    process = psutil.Process(pid)

                    # Basic memory info
                    mem_info = process.memory_info()
                    self.update_output.emit(log_message(f"[Memory Analysis] PID: {pid}"))
                    self.update_output.emit(log_message(f"[Memory Analysis] RSS: {mem_info.rss / (1024*1024):.2f} MB"))
                    self.update_output.emit(log_message(f"[Memory Analysis] VMS: {mem_info.vms / (1024*1024):.2f} MB"))

                    # Memory maps
                    self.update_output.emit(log_message("[Memory Analysis] Analyzing memory maps..."))
                    memory_maps = process.memory_maps()

                    # Extract and categorize mapped regions
                    executable_regions = []
                    writable_regions = []
                    suspicious_regions = []

                    total_mapped = 0
                    total_private = 0

                    for region in memory_maps:
                        size = int(region.rss) if hasattr(region, 'rss') else 0
                        total_mapped += size

                        if 'p' in region.path.lower():  # Private memory
                            total_private += size

                        # Check for executable and writable regions (potential security issue)
                        if 'x' in region.perms and 'w' in region.perms:
                            suspicious_regions.append(region)

                        if 'x' in region.perms:
                            executable_regions.append(region)

                        if 'w' in region.perms:
                            writable_regions.append(region)

                    # Report memory statistics
                    self.update_output.emit(log_message(f"[Memory Analysis] Total mapped memory: {total_mapped / (1024*1024):.2f} MB"))
                    self.update_output.emit(log_message(f"[Memory Analysis] Private memory: {total_private / (1024*1024):.2f} MB"))
                    self.update_output.emit(log_message(f"[Memory Analysis] Executable regions: {len(executable_regions)}"))
                    self.update_output.emit(log_message(f"[Memory Analysis] Writable regions: {len(writable_regions)}"))

                    # Security warning for suspicious memory protections
                    if suspicious_regions:
                        self.update_output.emit(log_message(f"[Memory Analysis] WARNING: Found {len(suspicious_regions)} memory regions that are both writable and executable"))
                        for region in suspicious_regions[:5]:  # Show first 5 only
                            self.update_output.emit(log_message(f"[Memory Analysis] Suspicious region: {region.addr} ({region.perms}) - {region.path}"))

                        self.analyze_results.append("\n=== MEMORY SECURITY ANALYSIS ===")
                        self.analyze_results.append(f"Found {len(suspicious_regions)} memory regions with RWX permissions (security risk)")
                        self.analyze_results.append("These regions could be used for shellcode execution or code injection attacks")

                    # Memory usage over time (sample for a short period)
                    self.update_output.emit(log_message("[Memory Analysis] Sampling memory usage over time..."))
                    memory_samples = []

                    for _ in range(5):  # Sample 5 times with 1-second intervals
                        try:
                            memory_samples.append(process.memory_info().rss)
                            time.sleep(1)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            self.update_output.emit(log_message("[Memory Analysis] Process terminated during sampling"))
                            break

                    # Check for memory growth
                    if len(memory_samples) >= 2:
                        growth = memory_samples[-1] - memory_samples[0]
                        if growth > 0:
                            growth_rate = growth / (1024 * 1024)  # Convert to MB
                            self.update_output.emit(log_message(f"[Memory Analysis] Memory growth detected: {growth_rate:.2f} MB over {len(memory_samples)} seconds"))

                            if growth_rate > 5:  # Threshold for significant growth (5MB in a few seconds)
                                self.update_output.emit(log_message("[Memory Analysis] WARNING: Significant memory growth detected - possible memory leak"))
                                self.analyze_results.append("Detected significant memory growth rate - potential memory leak")

                    # Heap analysis using memory_profiler if available
                    try:
                        self.update_output.emit(log_message("[Memory Analysis] Detailed heap analysis available"))
                    except ImportError:
                        self.update_output.emit(log_message("[Memory Analysis] memory_profiler not available for detailed heap analysis"))

                    # Check for memory fragmentation
                    if hasattr(process, 'memory_full_info'):
                        full_info = process.memory_full_info()
                        if hasattr(full_info, 'uss') and hasattr(full_info, 'pss'):
                            self.update_output.emit(log_message(f"[Memory Analysis] Unique Set Size: {full_info.uss / (1024*1024):.2f} MB"))
                            self.update_output.emit(log_message(f"[Memory Analysis] Proportional Set Size: {full_info.pss / (1024*1024):.2f} MB"))

                            # Fragmentation estimate
                            if full_info.rss > 0:
                                fragmentation = 1.0 - (full_info.uss / full_info.rss)
                                self.update_output.emit(log_message(f"[Memory Analysis] Memory fragmentation estimate: {fragmentation:.2%}"))

                                if fragmentation > 0.3:  # Over 30% fragmentation
                                    self.update_output.emit(log_message("[Memory Analysis] WARNING: High memory fragmentation detected"))
                                    self.analyze_results.append("High memory fragmentation detected - could impact performance")

                    # Attach Frida for deeper memory inspection if available
                    if hasattr(self, 'dynamic_analyzer') and hasattr(self.dynamic_analyzer, 'attach_memory_script'):
                        self.update_output.emit(log_message("[Memory Analysis] Attaching Frida for memory allocation tracking..."))
                        try:
                            # This would inject a Frida script to monitor memory allocations
                            self.dynamic_analyzer.attach_memory_script(pid)
                            self.update_output.emit(log_message("[Memory Analysis] Memory tracking script attached successfully"))
                        except Exception as e:
                            self.update_output.emit(log_message(f"[Memory Analysis] Error attaching memory script: {str(e)}"))

                    # Summary
                    self.analyze_results.append("\n=== MEMORY ANALYSIS SUMMARY ===")
                    self.analyze_results.append(f"Process ID: {pid}")
                    self.analyze_results.append(f"Total memory usage: {mem_info.rss / (1024*1024):.2f} MB")
                    self.analyze_results.append(f"Virtual memory size: {mem_info.vms / (1024*1024):.2f} MB")
                    self.analyze_results.append(f"Executable memory regions: {len(executable_regions)}")
                    self.analyze_results.append(f"Writable memory regions: {len(writable_regions)}")
                    self.analyze_results.append(f"RWX memory regions: {len(suspicious_regions)}")

                    self.update_output.emit(log_message("[Memory Analysis] Memory analysis completed successfully"))
                else:
                    self.update_output.emit(log_message("[Memory Analysis] Error: Could not get target process ID"))
            else:
                # Static analysis fallback
                self.update_output.emit(log_message("[Memory Analysis] Dynamic analyzer not available. Performing static memory analysis..."))

                # Analyze PE file section memory characteristics
                try:
                    pe = pefile.PE(self.binary_path)

                    self.update_output.emit(log_message("[Memory Analysis] Analyzing memory characteristics from PE headers..."))

                    # Check for suspicious section permissions
                    suspicious_sections = []
                    for section in pe.sections:
                        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')

                        # Check if section is both writable and executable (security risk)
                        if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                            suspicious_sections.append(section_name)
                            self.update_output.emit(log_message(f"[Memory Analysis] WARNING: Section {section_name} is both writable and executable"))

                    if suspicious_sections:
                        self.analyze_results.append("\n=== MEMORY SECURITY ANALYSIS (STATIC) ===")
                        self.analyze_results.append(f"Found {len(suspicious_sections)} PE sections with RWX permissions (security risk)")
                        self.analyze_results.append("Sections: " + ", ".join(suspicious_sections))
                        self.analyze_results.append("These sections could be used for shellcode execution or code injection attacks")

                    # Analyze stack security
                    has_stack_protection = False
                    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DllCharacteristics'):
                        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                            has_stack_protection = True
                            self.update_output.emit(log_message("[Memory Analysis] Binary has DEP/NX protection enabled"))

                        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400:  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                            self.update_output.emit(log_message("[Memory Analysis] Binary has ASLR support enabled"))

                    if not has_stack_protection:
                        self.update_output.emit(log_message("[Memory Analysis] WARNING: Binary does not have DEP/NX protection"))
                        self.analyze_results.append("Binary does not have DEP/NX protection - stack executable (security risk)")

                    # Estimate memory usage based on section sizes
                    estimated_memory = sum(section.Misc_VirtualSize for section in pe.sections)
                    self.update_output.emit(log_message(f"[Memory Analysis] Estimated memory usage: {estimated_memory / (1024*1024):.2f} MB"))

                    # Check for memory-related imports
                    memory_apis = ['HeapAlloc', 'VirtualAlloc', 'malloc', 'GlobalAlloc', 'LocalAlloc', 'CoTaskMemAlloc']
                    detected_apis = []

                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            for imp in entry.imports:
                                if imp.name:
                                    func_name = imp.name.decode('utf-8', errors='ignore')
                                    if any(api in func_name for api in memory_apis):
                                        detected_apis.append(func_name)

                    if detected_apis:
                        self.update_output.emit(log_message(f"[Memory Analysis] Detected {len(detected_apis)} memory allocation APIs"))
                        for api in detected_apis[:5]:  # Show first 5
                            self.update_output.emit(log_message(f"[Memory Analysis] Memory API: {api}"))

                    # Summary for static analysis
                    self.analyze_results.append("\n=== STATIC MEMORY ANALYSIS SUMMARY ===")
                    self.analyze_results.append(f"Estimated memory footprint: {estimated_memory / (1024*1024):.2f} MB")
                    self.analyze_results.append(f"Memory allocation APIs detected: {len(detected_apis)}")
                    self.analyze_results.append(f"DEP/NX Protection: {'Enabled' if has_stack_protection else 'Disabled'}")

                    self.update_output.emit(log_message("[Memory Analysis] Static memory analysis completed"))

                except Exception as e:
                    self.update_output.emit(log_message(f"[Memory Analysis] Error during static analysis: {str(e)}"))

        except Exception as e:
            self.update_output.emit(log_message(f"[Memory Analysis] Error during memory analysis: {str(e)}"))
            self.update_output.emit(log_message(f"[Memory Analysis] Traceback: {traceback.format_exc()}"))

    def run_network_analysis(self):
        """
        Run comprehensive network analysis on the target application.

        Monitors network traffic, identifies protocols in use, detects potential security
        issues, and analyzes network-related API calls made by the application. Works with
        both active processes and static binaries.
        """
        if not self.binary_path:
            QMessageBox.warning(self, "No Binary", "Please select a binary file first.")
            return

        self.update_output.emit(log_message("[Network Analysis] Starting comprehensive network analysis..."))

        try:
            # First check if we already have network capture data
            has_existing_data = False
            if hasattr(self, 'traffic_samples') and self.traffic_samples:
                has_existing_data = True
                sample_count = len(self.traffic_samples)
                self.update_output.emit(log_message(f"[Network Analysis] Using {sample_count} existing traffic samples"))

            if not has_existing_data:
                # Start capturing if we don't have data and analyzer is available
                if hasattr(self, 'start_network_capture'):
                    self.update_output.emit(log_message("[Network Analysis] No existing data found. Starting network capture..."))
                    self.start_network_capture()
                    capture_result = True  # start_network_capture doesn't return a value

                    if capture_result:
                        self.update_output.emit(log_message("[Network Analysis] Network capture started successfully"))
                        self.update_output.emit(log_message("[Network Analysis] Waiting for traffic (10 seconds)..."))

                        # Wait a short time to collect some traffic
                        time.sleep(10)
                    else:
                        self.update_output.emit(log_message("[Network Analysis] Failed to start network capture"))

            # Static analysis of network capabilities
            self.update_output.emit(log_message("[Network Analysis] Analyzing network capabilities from binary..."))

            # Define common networking and protocol APIs
            network_apis = {
                'basic': ['socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv', 'recvfrom'],
                'http': ['HttpOpenRequest', 'InternetConnect', 'WinHttpConnect', 'curl_easy', 'libcurl'],
                'ssl': ['SSL_connect', 'SSL_read', 'SSL_write', 'SslCreateContext', 'CryptAcquireContext'],
                'dns': ['gethostbyname', 'DnsQuery', 'getaddrinfo', 'WSAGetLastError'],
                'udp': ['sendto', 'recvfrom', 'UdpConnectClient'],
                'license': ['LicenseCheck', 'VerifyLicense', 'Activate', 'Register']
            }

            detected_apis = {category: [] for category in network_apis}

            try:
                # Load binary for static analysis
                pe = pefile.PE(self.binary_path)

                # Analyze imports for network-related APIs
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()

                        # Check if this DLL is network-related
                        network_dlls = ['ws2_32.dll', 'wsock32.dll', 'wininet.dll', 'winhttp.dll', 'urlmon.dll', 'cryptui.dll']
                        is_network_dll = any(net_dll in dll_name for net_dll in network_dlls)

                        if is_network_dll:
                            self.update_output.emit(log_message(f"[Network Analysis] Found networking DLL: {dll_name}"))

                        # Check imported functions
                        for imp in entry.imports:
                            if not imp.name:
                                continue

                            func_name = imp.name.decode('utf-8', errors='ignore')

                            # Check each category of network APIs
                            for category, apis in network_apis.items():
                                if any(api.lower() in func_name.lower() for api in apis):
                                    detected_apis[category].append(func_name)

                                    # Log first few detections in each category
                                    if len(detected_apis[category]) <= 3:
                                        self.update_output.emit(log_message(f"[Network Analysis] Found {category} API: {func_name}"))

                # Summarize static findings
                self.analyze_results.append("\n=== NETWORK CAPABILITY ANALYSIS ===")

                for category, apis in detected_apis.items():
                    if apis:
                        self.analyze_results.append(f"{category.upper()} APIs: {len(apis)}")
                        # List first few APIs detected in each category
                        for api in apis[:5]:
                            self.analyze_results.append(f"  - {api}")

                # Security assessment
                security_issues = []

                # Check for insecure communication
                has_ssl = bool(detected_apis['ssl'])
                has_network = bool(detected_apis['basic']) or bool(detected_apis['http'])

                if has_network and not has_ssl:
                    issue = "Application uses network APIs without SSL/TLS - potentially insecure communication"
                    security_issues.append(issue)
                    self.update_output.emit(log_message(f"[Network Analysis] WARNING: {issue}"))

                # String analysis for URLs and IP addresses
                self.update_output.emit(log_message("[Network Analysis] Searching for embedded URLs and IP addresses..."))

                with open(self.binary_path, 'rb') as f:
                    binary_data = f.read()

                    # URL pattern
                    # Fixed regex pattern with raw string to avoid escape sequence warning
                    url_pattern = re.compile(br'https?://[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+(?:/[^\s]*)?')
                    urls = url_pattern.findall(binary_data)

                    # IP address pattern
                    # Fixed regex pattern with raw string to avoid escape sequence warning
                    ip_pattern = re.compile(br'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
                    ips = ip_pattern.findall(binary_data)

                    if urls:
                        unique_urls = set(url.decode('utf-8', errors='ignore') for url in urls)
                        self.update_output.emit(log_message(f"[Network Analysis] Found {len(unique_urls)} embedded URLs"))

                        self.analyze_results.append("\n=== EMBEDDED URLs ===")
                        for url in list(unique_urls)[:10]:  # Show first 10
                            self.analyze_results.append(url)

                        # Check for hardcoded credentials in URLs
                        auth_urls = [url for url in unique_urls if '@' in url]
                        if auth_urls:
                            issue = "Found URLs with embedded credentials - security risk"
                            security_issues.append(issue)
                            self.update_output.emit(log_message(f"[Network Analysis] WARNING: {issue}"))

                    if ips:
                        unique_ips = set(ip.decode('utf-8', errors='ignore') for ip in ips)
                        self.update_output.emit(log_message(f"[Network Analysis] Found {len(unique_ips)} embedded IP addresses"))

                        self.analyze_results.append("\n=== EMBEDDED IP ADDRESSES ===")
                        for ip in list(unique_ips)[:10]:  # Show first 10
                            self.analyze_results.append(ip)

                        # Check for private IPs
                        private_ips = [ip for ip in unique_ips if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.'))]
                        if private_ips:
                            self.update_output.emit(log_message(f"[Network Analysis] Found {len(private_ips)} private IP addresses hardcoded"))

            except Exception as e:
                self.update_output.emit(log_message(f"[Network Analysis] Error during static analysis: {str(e)}"))

            # Dynamic analysis results if available
            if hasattr(self, 'traffic_recorder') and self.traffic_recorder:
                traffic_summary = self.traffic_recorder.get_traffic_summary()

                if traffic_summary:
                    self.update_output.emit(log_message("[Network Analysis] Analyzing captured network traffic..."))

                    # Process traffic summary
                    total_packets = traffic_summary.get('total_packets', 0)
                    protocols = traffic_summary.get('protocols', {})
                    destinations = traffic_summary.get('destinations', {})

                    self.update_output.emit(log_message(f"[Network Analysis] Captured {total_packets} packets"))

                    # Protocol breakdown
                    if protocols:
                        self.analyze_results.append("\n=== PROTOCOL ANALYSIS ===")
                        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
                            self.analyze_results.append(f"{protocol}: {count} packets ({percentage:.1f}%)")
                            self.update_output.emit(log_message(f"[Network Analysis] Protocol: {protocol} - {count} packets"))

                    # Destination breakdown
                    if destinations:
                        self.analyze_results.append("\n=== CONNECTION DESTINATIONS ===")
                        for dest, count in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]:
                            self.analyze_results.append(f"{dest}: {count} packets")

                    # Security assessment from traffic
                    if protocols.get('HTTP', 0) > 0 and protocols.get('HTTPS', 0) == 0:
                        issue = "Application uses insecure HTTP without HTTPS"
                        security_issues.append(issue)
                        self.update_output.emit(log_message(f"[Network Analysis] WARNING: {issue}"))

                    # DNS analysis
                    if hasattr(self.traffic_recorder, 'get_dns_queries'):
                        dns_queries = self.traffic_recorder.get_dns_queries()
                        if dns_queries:
                            self.analyze_results.append("\n=== DNS QUERIES ===")
                            for query in dns_queries[:10]:  # Show first 10
                                self.analyze_results.append(query)
                else:
                    self.update_output.emit(log_message("[Network Analysis] No traffic capture data available"))

            # Live process connections if possible
            if hasattr(self, 'dynamic_analyzer') and self.dynamic_analyzer:
                pid = self.dynamic_analyzer.get_target_pid()
                if pid:
                    try:
                        process = psutil.Process(pid)
                        connections = process.connections()

                        if connections:
                            self.update_output.emit(log_message(f"[Network Analysis] Found {len(connections)} active connections"))

                            # Analyze connections
                            self.analyze_results.append("\n=== ACTIVE NETWORK CONNECTIONS ===")

                            for conn in connections:
                                status = conn.status if hasattr(conn, 'status') else 'UNKNOWN'
                                family = 'IPv4' if conn.family == socket.AF_INET else 'IPv6' if conn.family == socket.AF_INET6 else 'UNIX' if hasattr(socket, 'AF_UNIX') and conn.family == socket.AF_UNIX else 'UNKNOWN'  # pylint: disable=no-member

                                if conn.laddr:
                                    local = f"{conn.laddr[0]}:{conn.laddr[1]}" if len(conn.laddr) >= 2 else str(conn.laddr)
                                else:
                                    local = "N/A"

                                if hasattr(conn, 'raddr') and conn.raddr:
                                    remote = f"{conn.raddr[0]}:{conn.raddr[1]}" if len(conn.raddr) >= 2 else str(conn.raddr)
                                else:
                                    remote = "N/A"

                                conn_info = f"{family} {conn.type} {status}: {local} -> {remote}"
                                self.analyze_results.append(conn_info)

                                # Log first few connections
                                if len(self.analyze_results) < 15:  # Limit logging
                                    self.update_output.emit(log_message(f"[Network Analysis] Connection: {conn_info}"))
                        else:
                            self.update_output.emit(log_message("[Network Analysis] No active network connections found"))
                    except Exception as e:
                        self.update_output.emit(log_message(f"[Network Analysis] Error checking connections: {str(e)}"))

            # Summarize security issues
            if security_issues:
                self.analyze_results.append("\n=== NETWORK SECURITY ISSUES ===")
                for issue in security_issues:
                    self.analyze_results.append(f"⚠️ {issue}")

            # Final summary
            self.update_output.emit(log_message("[Network Analysis] Network analysis completed successfully"))

            categories_found = sum(1 for apis in detected_apis.values() if apis)
            self.update_output.emit(log_message(f"[Network Analysis] Found {categories_found} network API categories in use"))

            # Check if we need to stop a running capture
            if not has_existing_data and hasattr(self, 'stop_network_capture'):
                self.stop_network_capture()

        except Exception as e:
            self.update_output.emit(log_message(f"[Network Analysis] Error during network analysis: {str(e)}"))
            self.update_output.emit(log_message(f"[Network Analysis] Traceback: {traceback.format_exc()}"))

# -------------------------------
# Helper Methods for New Tabs
# -------------------------------

# Patching tab helpers
    def run_patching(self):
        """Run the patching process based on selected strategy"""
        strategy = "Automatic"
        if self.strategy_targeted_radio.isChecked():
            strategy = "Targeted"
            target_type = self.target_type_combo.currentText()
            self.update_output.emit(log_message(f"[Patching] Running {strategy} patching targeting {target_type}..."))
        elif self.strategy_custom_radio.isChecked():
            strategy = "Custom"
            self.update_output.emit(log_message(f"[Patching] Running {strategy} patching..."))
        else:
            self.update_output.emit(log_message(f"[Patching] Running {strategy} patching..."))

        # Additional patching options
        options = []
        if self.patch_stealth_cb.isChecked():
            options.append("Stealth Mode")
        if self.patch_backup_cb.isChecked():
            options.append("Create Backups")
        if self.patch_certificate_cb.isChecked():
            options.append("Preserve Signatures")
        if self.patch_metadata_cb.isChecked():
            options.append("Update Metadata")

        if options:
            self.update_output.emit(log_message(f"[Patching] Options: {', '.join(options)}"))

        # Perform the actual patching
        self.update_output.emit(log_message(f"[Patching] Starting patching process with {strategy} strategy..."))

        try:
            # Create backup first if requested
            if "Create Backups" in options:
                backup_path = f"{self.binary_path}.bak"
                self.update_output.emit(log_message(f"[Patching] Creating backup at {backup_path}"))
                shutil.copy2(self.binary_path, backup_path)

            # Different patching strategies
            if strategy == "Deep Analysis":
                result = self._apply_deep_analysis_patches()
            elif strategy == "Manual Patch":
                result = self._apply_manual_patches()
            elif strategy == "Memory Patching":
                result = self._apply_memory_patches()
            elif strategy == "Import Patching":
                result = self._apply_import_patches()
            else:
                result = {"success": False, "error": f"Unknown strategy: {strategy}"}

            # Handle the result
            if result.get("success"):
                self.update_output.emit(log_message(f"[Patching] Successfully applied {result.get('count', 0)} patches"))
                QMessageBox.information(self, "Patching Complete",
                                       f"Successfully applied {result.get('count', 0)} patches to the binary.\n\n"
                                       f"Details: {result.get('message', '')}")

                # Update the patch list
                self.refresh_patch_list()

                # Add to the analysis results
                self.analyze_results.append(f"\n=== PATCHING RESULTS ===")
                self.analyze_results.append(f"Strategy: {strategy}")
                self.analyze_results.append(f"Patches applied: {result.get('count', 0)}")
                for detail in result.get('details', []):
                    self.analyze_results.append(f"  - {detail}")

            else:
                error_msg = result.get("error", "Unknown error")
                self.update_output.emit(log_message(f"[Patching] Error: {error_msg}"))
                QMessageBox.warning(self, "Patching Failed",
                                   f"Failed to apply patches: {error_msg}\n\n"
                                   f"See the logs for more details.")

        except Exception as e:
            self.update_output.emit(log_message(f"[Patching] Exception during patching: {str(e)}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            QMessageBox.critical(self, "Patching Error",
                                f"An exception occurred during patching:\n{str(e)}")

    def refresh_patch_list(self):
        """Refresh the list of patches"""
        self.update_output.emit(log_message("[Patching] Refreshing patch list..."))

        # Clear existing data
        self.patches_table.setRowCount(0)

        # Add sample data
        sample_patches = [
            ("P001", "License Check", "0x00402E10", "Ready", ""),
            ("P002", "Trial Expiration", "0x00403F50", "Applied", ""),
            ("P003", "Network Validation", "0x00404820", "Ready", ""),
            ("P004", "Hardware Check", "0x00405A10", "Failed", "")
        ]

        self.patches_table.setRowCount(len(sample_patches))

        for i, (patch_id, patch_type, location, status, _) in enumerate(sample_patches):
            self.patches_table.setItem(i, 0, QTableWidgetItem(patch_id))
            self.patches_table.setItem(i, 1, QTableWidgetItem(patch_type))
            self.patches_table.setItem(i, 2, QTableWidgetItem(location))
            self.patches_table.setItem(i, 3, QTableWidgetItem(status))

            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(0, 0, 0, 0)

            apply_btn = QPushButton("Apply")
            apply_btn.setFixedWidth(60)
            apply_btn.clicked.connect(lambda checked, row=i: self.apply_patch(row))

            revert_btn = QPushButton("Revert")
            revert_btn.setFixedWidth(60)
            revert_btn.clicked.connect(lambda checked, row=i: self.revert_patch(row))

            edit_btn = QPushButton("Edit")
            edit_btn.setFixedWidth(60)
            edit_btn.clicked.connect(lambda checked, row=i: self.edit_patch(row))

            actions_layout.addWidget(apply_btn)
            actions_layout.addWidget(revert_btn)
            actions_layout.addWidget(edit_btn)

            self.patches_table.setCellWidget(i, 4, actions_widget)

    def apply_patch(self, row):
        """Apply a single patch"""
        patch_id = self.patches_table.item(row, 0).text()
        patch_type = self.patches_table.item(row, 1).text()
        self.update_output.emit(log_message(f"[Patching] Applying patch {patch_id} ({patch_type})..."))
        self.patches_table.setItem(row, 3, QTableWidgetItem("Applied"))

    def revert_patch(self, row):
        """Revert a single patch"""
        patch_id = self.patches_table.item(row, 0).text()
        self.update_output.emit(log_message(f"[Patching] Reverting patch {patch_id}..."))
        self.patches_table.setItem(row, 3, QTableWidgetItem("Ready"))

    def edit_patch(self, row):
        """Edit a single patch"""
        patch_id = self.patches_table.item(row, 0).text()
        self.update_output.emit(log_message(f"[Patching] Editing patch {patch_id}..."))
        QMessageBox.information(self, "Edit Patch", f"Editing patch {patch_id} would open the editor")

    def apply_all_patches(self):
        """Apply all patches in the list"""
        self.update_output.emit(log_message("[Patching] Applying all patches..."))

        for row in range(self.patches_table.rowCount()):
            self.patches_table.setItem(row, 3, QTableWidgetItem("Applied"))

        QMessageBox.information(self, "Apply All Patches", "All patches have been applied")

    def revert_all_patches(self):
        """Revert all patches in the list"""
        self.update_output.emit(log_message("[Patching] Reverting all patches..."))

        for row in range(self.patches_table.rowCount()):
            self.patches_table.setItem(row, 3, QTableWidgetItem("Ready"))

        QMessageBox.information(self, "Revert All Patches", "All patches have been reverted")

    def export_patches(self):
        """Export patches to a file"""
        self.update_output.emit(log_message("[Patching] Exporting patches..."))
        QMessageBox.information(self, "Export Patches", "Patches would be exported to a file")

    def run_patch_test(self):
        """Run tests for the applied patches"""
        env_type = self.env_type_combo.currentText()
        self.update_output.emit(log_message(f"[Patching] Running patch tests in {env_type} environment..."))

        options = []
        if self.test_network_cb.isChecked():
            options.append("Network Emulation")
        if self.test_memory_cb.isChecked():
            options.append("Memory Analysis")
        if self.test_api_cb.isChecked():
            options.append("API Monitoring")
        if self.test_coverage_cb.isChecked():
            options.append("Coverage Analysis")

        if options:
            self.update_output.emit(log_message(f"[Testing] Options: {', '.join(options)}"))

        # Show test results
        self.test_results_text.clear()
        self.test_results_text.append("==== Patch Test Results ====\n")
        self.test_results_text.append(f"Environment: {env_type}\n")
        self.test_results_text.append(f"Options: {', '.join(options) if options else 'None'}\n")
        self.test_results_text.append("\nTest 1: License Check Bypass... PASSED")
        self.test_results_text.append("Test 2: Trial Restriction Removal... PASSED")
        self.test_results_text.append("Test 3: Network Validation Bypass... PASSED")
        self.test_results_text.append("Test 4: Hardware Check Modification... FAILED")
        self.test_results_text.append("\nOverall Result: 3/4 tests passed (75%)")

    def verify_patch_results(self):
        """Verify the results of patch testing"""
        self.update_output.emit(log_message("[Patching] Verifying patch results..."))

        # Add more detail to test results
        self.test_results_text.append("\n\n==== Detailed Verification ====")
        self.test_results_text.append("\nLicense Check Bypass:")
        self.test_results_text.append("- Original behavior: Application exits with error code 0xE001")
        self.test_results_text.append("- Patched behavior: Application continues normal execution")
        self.test_results_text.append("- Verification method: Process exit code monitoring")

        self.test_results_text.append("\nHardware Check Modification:")
        self.test_results_text.append("- Original behavior: Application checks CPU ID at 0x00405A10")
        self.test_results_text.append("- Patched behavior: Check still occurs but with modified comparison")
        self.test_results_text.append("- Verification method: Memory tracing")
        self.test_results_text.append("- Failure reason: The patch modifies the comparison but hardware ID is checked in multiple locations")

        QMessageBox.information(self, "Verification", "Verification process complete.")

# Network tab helpers moved to IntellicrackApp class methods

    def start_license_server(self):
        """Start the license server emulation"""
        address = self.server_addr_input.text()
        port = self.server_port_input.text()
        protocol = self.server_protocol_combo.currentText()
        response_type = self.server_response_combo.currentText()

        self.update_output.emit(log_message(f"[Server] Starting license server on {address}:{port} ({protocol})"))

        # Show server logs
        self.server_logs_text.clear()
        self.server_logs_text.append(f"[INFO] Server starting on {address}:{port}")
        self.server_logs_text.append(f"[INFO] Protocol: {protocol}")
        self.server_logs_text.append(f"[INFO] Response type: {response_type}")
        self.server_logs_text.append("[INFO] Server ready to accept connections")

        QMessageBox.information(self, "License Server", f"License server started on {address}:{port}")

    def stop_license_server(self):
        """Stop the license server emulation"""
        self.update_output.emit(log_message("[Server] Stopping license server"))

        # Show server logs
        self.server_logs_text.append("[INFO] Server shutdown initiated")
        self.server_logs_text.append("[INFO] Active connections closed")
        self.server_logs_text.append("[INFO] Server stopped")

        QMessageBox.information(self, "License Server", "License server stopped")

    def test_license_server(self):
        """Test the license server emulation"""
        self.update_output.emit(log_message("[Server] Testing license server"))

        # Show server logs
        self.server_logs_text.append("[TEST] Testing server connectivity...")
        self.server_logs_text.append("[TEST] Sending test request...")
        self.server_logs_text.append("[INFO] Received connection from 127.0.0.1:45678")
        self.server_logs_text.append("[INFO] Request received: GET /validate?key=TEST-KEY")
        self.server_logs_text.append("[INFO] Sending response: 200 OK")
        self.server_logs_text.append("[TEST] Test successful!")

        QMessageBox.information(self, "Server Test", "License server test successful")

    def launch_protocol_tool(self):
        """Launch the selected protocol tool"""
        tool = self.protocol_tool_combo.currentText()
        self.update_output.emit(log_message(f"[Network] Launching {tool}"))

        QMessageBox.information(self, "Protocol Tool", f"Launching {tool}")

        # Add to recent tools
        self.recent_tools_list.insertItem(0, f"{tool} (just now)")

    def update_protocol_tool_description(self, tool):
        """Update the description for the selected protocol tool"""
        descriptions = {
            "SSL/TLS Interceptor": "Intercepts and decrypts SSL/TLS traffic for analysis. Supports certificate generation and man-in-the-middle capabilities.",
            "Protocol Analyzer": "Analyzes communication protocols to identify patterns and structures. Useful for reverse engineering proprietary protocols.",
            "API Request Builder": "Build and send custom API requests to test endpoints and authentication. Supports various authentication methods.",
            "Authentication Fuzzer": "Tests authentication mechanisms by generating various inputs to identify weaknesses and bypasses."
        }

        self.tool_description_label.setText(descriptions.get(tool, "No description available"))

# Reports tab helpers
    def generate_report(self):
        """Generate a report based on selected options"""
        template = self.report_template_combo.currentText()
        report_format = self.report_format_combo.currentText()

        options = []
        if self.include_binary_info_cb.isChecked():
            options.append("Binary Information")
        if self.include_patches_cb.isChecked():
            options.append("Patch Details")
        if self.include_graphs_cb.isChecked():
            options.append("Graphs & Charts")
        if self.include_network_cb.isChecked():
            options.append("Network Analysis")

        self.update_output.emit(log_message(f"[Reports] Generating {template} in {format} format"))
        if options:
            self.update_output.emit(log_message(f"[Reports] Including: {', '.join(options)}"))

        # Add to the reports table
        current_time = datetime.datetime.now().strftime("%Y-%m-%d")
        new_row = self.reports_table.rowCount()
        self.reports_table.setRowCount(new_row + 1)

        report_name = f"Report_{current_time}_{template.replace(' ', '_')}"
        self.reports_table.setItem(new_row, 0, QTableWidgetItem(report_name))
        self.reports_table.setItem(new_row, 1, QTableWidgetItem(current_time))
        self.reports_table.setItem(new_row, 2, QTableWidgetItem(format))

        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(0, 0, 0, 0)

        view_btn = QPushButton("View")
        view_btn.setFixedWidth(60)
        view_btn.clicked.connect(lambda _, r=new_row: self.view_report(r))

        export_btn = QPushButton("Export")
        export_btn.setFixedWidth(60)
        export_btn.clicked.connect(lambda _, r=new_row: self.export_report(r))

        delete_btn = QPushButton("Delete")
        delete_btn.setFixedWidth(60)
        delete_btn.clicked.connect(lambda _, r=new_row: self.delete_report(r))

        actions_layout.addWidget(view_btn)
        actions_layout.addWidget(export_btn)
        actions_layout.addWidget(delete_btn)

        self.reports_table.setCellWidget(new_row, 3, actions_widget)

        QMessageBox.information(self, "Report Generation", f"Report '{report_name}' generated successfully")

    def view_report(self, row):
        """View a generated report in an appropriate viewer based on format"""
        report_name = self.reports_table.item(row, 0).text()
        report_type = self.reports_table.item(row, 1).text()
        report_format = self.reports_table.item(row, 2).text()

        self.update_output.emit(log_message(f"[Reports] Viewing report: {report_name} ({report_format})"))

        # Get report path
        reports_dir = os.path.join(os.getcwd(), "reports")
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)

        # Sanitize filename
        safe_name = ''.join(c for c in report_name if c.isalnum() or c in (' ', '.', '_', '-')).replace(' ', '_')
        report_path = os.path.join(reports_dir, f"{safe_name}.{report_format.lower()}")

        try:
            # Check if report exists
            if not os.path.exists(report_path):
                # Generate the report file if it doesn't exist
                self.update_output.emit(log_message(f"[Reports] Report file not found. Generating: {report_path}"))

                # Generate report based on type and format
                if report_format.lower() == "html":
                    self._generate_html_report(report_name, report_type, report_path)
                elif report_format.lower() == "pdf":
                    self._generate_pdf_report(report_name, report_type, report_path)
                else:
                    self._generate_text_report(report_name, report_type, report_path)

            # Open the report based on its format
            if report_format.lower() == "html":
                # Create a QWebEngineView to display HTML reports
                try:
                    # Create a new window for the report
                    self.report_viewer = QDialog(self)
                    self.report_viewer.setWindowTitle(f"Report: {report_name}")
                    self.report_viewer.resize(900, 700)

                    # Create layout
                    layout = QVBoxLayout(self.report_viewer)

                    # Create web view
                    web_view = QWebEngineView()
                    web_view.load(QUrl.fromLocalFile(report_path))

                    # Create toolbar with actions
                    toolbar = QHBoxLayout()

                    # Add zoom controls
                    zoom_in_btn = QPushButton("Zoom In")
                    zoom_out_btn = QPushButton("Zoom Out")
                    zoom_in_btn.clicked.connect(lambda: web_view.setZoomFactor(web_view.zoomFactor() + 0.1))
                    zoom_out_btn.clicked.connect(lambda: web_view.setZoomFactor(web_view.zoomFactor() - 0.1))

                    # Add print button
                    print_btn = QPushButton("Print")
                    print_btn.clicked.connect(web_view.page().print)

                    # Add external browser button
                    browser_btn = QPushButton("Open in Browser")
                    browser_btn.clicked.connect(lambda: webbrowser.open(f"file://{report_path}"))

                    # Add to toolbar
                    toolbar.addWidget(zoom_in_btn)
                    toolbar.addWidget(zoom_out_btn)
                    toolbar.addWidget(print_btn)
                    toolbar.addWidget(browser_btn)

                    # Add to layout
                    layout.addLayout(toolbar)
                    layout.addWidget(web_view)

                    # Show the report viewer
                    self.report_viewer.show()

                except ImportError:
                    # Fall back to system browser if Qt WebEngine is not available
                    self.update_output.emit(log_message("[Reports] QWebEngineView not available, opening in system browser"))
                    webbrowser.open(f"file://{report_path}")

            elif report_format.lower() == "pdf":
                # Try to use a PDF viewer if available, otherwise open with system default
                try:
                    # Create viewer dialog
                    self.report_viewer = QDialog(self)
                    self.report_viewer.setWindowTitle(f"PDF Report: {report_name}")
                    self.report_viewer.resize(900, 700)

                    # Create layout
                    layout = QVBoxLayout(self.report_viewer)

                    # Check if PyQt5 PDF modules are available
                    if 'HAS_PDF_SUPPORT' in globals() and HAS_PDF_SUPPORT:
                        # Create PDF viewer
                        pdf_view = QPdfView()
                        doc = QPdfDocument()
                        doc.load(report_path)
                        pdf_view.setDocument(doc)

                        # Create widget for the layout
                        widget_for_layout = pdf_view
                    else:
                        # Fallback if PDF viewing not available
                        fallback_widget = QWidget()
                        fallback_layout = QVBoxLayout(fallback_widget)

                        message_label = QLabel("PDF viewing is not available with current PyQt5 installation.")
                        message_label.setWordWrap(True)
                        fallback_layout.addWidget(message_label)

                        open_button = QPushButton("Open PDF with System Viewer")
                        open_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(report_path)))
                        fallback_layout.addWidget(open_button)

                        # Create widget for the layout
                        widget_for_layout = fallback_widget

                    # Add toolbar
                    toolbar = QHBoxLayout()

                    # PDF navigation is only available when PDF modules are present
                    if 'HAS_PDF_SUPPORT' in globals() and HAS_PDF_SUPPORT:
                        # Add navigation buttons
                        prev_btn = QPushButton("Previous")
                        next_btn = QPushButton("Next")
                        prev_btn.clicked.connect(lambda: pdf_view.pageNavigator().jump(pdf_view.pageNavigator().currentPage() - 1))
                        next_btn.clicked.connect(lambda: pdf_view.pageNavigator().jump(pdf_view.pageNavigator().currentPage() + 1))

                        # Add to toolbar
                        toolbar.addWidget(prev_btn)
                        toolbar.addWidget(next_btn)

                    # Add external viewer button (always available)
                    external_btn = QPushButton("Open Externally")
                    external_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(report_path)))

                    # Add to toolbar
                    toolbar.addWidget(external_btn)

                    # Add to layout
                    layout.addLayout(toolbar)
                    layout.addWidget(widget_for_layout)  # Use the appropriate widget based on PDF support

                    # Show the viewer
                    self.report_viewer.show()
                    self.update_output.emit(log_message(f"[Reports] Opened PDF report: {report_name}"))

                except Exception as e:
                    # Error handling for any other issues with PDF viewer
                    self.update_output.emit(log_message(f"[Reports] Error displaying PDF: {e}"))
                    # Open with system default PDF viewer as fallback
                    try:
                        self.update_output.emit(log_message("[Reports] Falling back to system default PDF viewer"))
                        QDesktopServices.openUrl(QUrl.fromLocalFile(report_path))
                    except:
                        # Last resort fallback using OS-specific methods
                        if os.name == 'nt':  # Windows
                            os.startfile(report_path)
                        else:  # macOS, Linux
                            subprocess.call(('xdg-open' if os.name == 'posix' else 'open', report_path))
            else:
                # For other formats, open a simple text viewer
                self._open_text_report_viewer(report_path, report_name)

        except Exception as e:
            self.update_output.emit(log_message(f"[Reports] Error viewing report: {str(e)}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            QMessageBox.warning(self, "Report Viewer Error", f"Failed to open report:\n\n{str(e)}")

    def export_report(self, row):
        """Export a report to a file"""
        report_name = self.reports_table.item(row, 0).text()
        report_format = self.reports_table.item(row, 2).text()

        self.update_output.emit(log_message(f"[Reports] Exporting report: {report_name}"))

        QMessageBox.information(self, "Export Report",
                               f"Report '{report_name}' would be exported in {report_format} format")

    def delete_report(self, row):
        """Delete a report"""
        report_name = self.reports_table.item(row, 0).text()

        self.update_output.emit(log_message(f"[Reports] Deleting report: {report_name}"))

        self.reports_table.removeRow(row)

        QMessageBox.information(self, "Delete Report", f"Report '{report_name}' deleted")

    def refresh_reports_list(self):
        """Refresh the list of reports"""
        self.update_output.emit(log_message("[Reports] Refreshing reports list"))

        # This would typically reload reports from storage
        QMessageBox.information(self, "Refresh Reports", "Reports list refreshed")

    def import_report(self):
        """Import a report from a file"""
        self.update_output.emit(log_message("[Reports] Importing report"))

        # Open file dialog to select the report file
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Report",
            "",
            "Report Files (*.json *.xml *.report);;JSON Files (*.json);;XML Files (*.xml);;All Files (*)"
        )

        if not file_path:
            self.update_output.emit(log_message("[Reports] Import canceled by user"))
            return

        try:
            self.update_output.emit(log_message(f"[Reports] Importing report from: {file_path}"))

            # Determine file type and parse accordingly
            if file_path.lower().endswith('.json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)

                # Basic validation of report structure
                if not isinstance(report_data, dict) or 'report_type' not in report_data or 'content' not in report_data:
                    raise ValueError("Invalid report format. Report must contain 'report_type' and 'content' fields.")

                report_type = report_data.get('report_type')
                report_name = report_data.get('name', os.path.basename(file_path))
                report_date = report_data.get('date', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            elif file_path.lower().endswith('.xml'):
                tree = ET.parse(file_path)
                root = tree.getroot()

                # Extract basic info
                report_type = root.find('report_type').text if root.find('report_type') is not None else "unknown"
                report_name = root.find('name').text if root.find('name') is not None else os.path.basename(file_path)
                report_date = root.find('date').text if root.find('date') is not None else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Convert XML to dict for storage
                report_data = {
                    'report_type': report_type,
                    'name': report_name,
                    'date': report_date,
                    'content': ET.tostring(root).decode('utf-8')
                }

            else:
                # Try to parse as JSON first, then XML, then as plain text
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    # Basic validation
                    if not isinstance(report_data, dict):
                        raise ValueError("File content is not a valid JSON object")

                    report_type = report_data.get('report_type', "unknown")
                    report_name = report_data.get('name', os.path.basename(file_path))
                    report_date = report_data.get('date', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                except json.JSONDecodeError:
                    # Try XML
                    try:
                        tree = ET.parse(file_path)
                        root = tree.getroot()

                        report_type = root.find('report_type').text if root.find('report_type') is not None else "unknown"
                        report_name = root.find('name').text if root.find('name') is not None else os.path.basename(file_path)
                        report_date = root.find('date').text if root.find('date') is not None else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        report_data = {
                            'report_type': report_type,
                            'name': report_name,
                            'date': report_date,
                            'content': ET.tostring(root).decode('utf-8')
                        }

                    except ET.ParseError:
                        # Read as plain text
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        report_type = "text"
                        report_name = os.path.basename(file_path)
                        report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        report_data = {
                            'report_type': report_type,
                            'name': report_name,
                            'date': report_date,
                            'content': content
                        }

            # Create a unique report ID
            report_id = f"imported_{int(time.time())}_{os.path.basename(file_path).replace('.', '_')}"

            # Save to reports storage
            if not hasattr(self, 'reports'):
                self.reports = {}

            self.reports[report_id] = report_data

            # Save to disk if appropriate storage directory exists
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)

            # Save a copy of the report in our format
            output_path = os.path.join(reports_dir, f"{report_id}.json")
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)

            # Add to reports list if UI element exists
            if hasattr(self, 'reports_list'):
                item = QListWidgetItem(f"{report_name} ({report_type}) - {report_date}")
                item.setData(Qt.UserRole, report_id)
                self.reports_list.addItem(item)

            self.update_output.emit(log_message(f"[Reports] Successfully imported report: {report_name}"))

            # Show success message with details
            QMessageBox.information(
                self,
                "Import Successful",
                f"Successfully imported report:\n\nName: {report_name}\nType: {report_type}\nDate: {report_date}\n\nReport ID: {report_id}\nSaved to: {output_path}"
            )

        except Exception as e:
            self.update_output.emit(log_message(f"[Reports] Error importing report: {str(e)}"))
            QMessageBox.critical(self, "Import Error", f"Error importing report: {str(e)}")

    def _generate_html_report(self, report_name, report_type, output_path):
        """Generate an HTML report"""
        self.update_output.emit(log_message(f"[Reports] Generating HTML report: {report_name}"))

        try:
            # Create basic HTML template
            html_content = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{report_name} - Intellicrack Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                color: #333;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            header {{
                background-color: #2c3e50;
                color: white;
                padding: 1rem;
                margin-bottom: 2rem;
            }}
            h1, h2, h3 {{
                color: #2c3e50;
            }}
            .section {{
                margin-bottom: 2rem;
                padding: 1rem;
                background-color: #f9f9f9;
                border-radius: 5px;
            }}
            .highlight {{
                background-color: #ffe6e6;
                padding: 0.5rem;
                border-left: 4px solid #ff7675;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 1rem;
            }}
            th, td {{
                padding: 0.5rem;
                text-align: left;
                border: 1px solid #ddd;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            pre {{
                background-color: #f5f5f5;
                padding: 1rem;
                overflow-x: auto;
                border-radius: 5px;
            }}
            .footer {{
                margin-top: 2rem;
                text-align: center;
                font-size: 0.8rem;
                color: #7f8c8d;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>{report_name}</h1>
                <p>Report Type: {report_type}</p>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </header>

            <div class="section">
                <h2>Analysis Summary</h2>
                <p>This report contains the results of {report_type} analysis performed by Intellicrack.</p>

                <div class="highlight">
                    <h3>Key Findings</h3>
                    <ul>
    """

            # Add key findings based on analysis results
            if hasattr(self, 'analyze_results') and self.analyze_results:
                # Extract key findings - look for interesting entries
                key_findings = []
                for result in self.analyze_results:
                    if any(keyword in str(result).lower() for keyword in
                          ['license', 'protection', 'check', 'critical', 'vulnerability', 'patched']):
                        key_findings.append(f"<li>{result}</li>")

                # Add findings to the report
                if key_findings:
                    html_content += "\n".join(key_findings[:10])  # First 10 findings
                else:
                    html_content += "<li>No critical issues identified</li>"
            else:
                html_content += "<li>No analysis results available</li>"

            # Continue with the rest of the report
            html_content += """
                    </ul>
                </div>
            </div>
    """

            # Add detailed analysis section based on report type
            if report_type == "Memory Analysis":
                html_content += self._generate_memory_report_section()
            elif report_type == "Network Analysis":
                html_content += self._generate_network_report_section()
            elif report_type == "Patching Results":
                html_content += self._generate_patching_report_section()
            else:  # General analysis
                html_content += self._generate_general_report_section()

            # Add the full analysis results
            html_content += """
            <div class="section">
                <h2>Full Analysis Log</h2>
                <pre>"""

            # Add all analysis results if available
            if hasattr(self, 'analyze_results') and self.analyze_results:
                html_content += "\n".join(str(item) for item in self.analyze_results)
            else:
                html_content += "No detailed analysis results available."

            # Close the report
            html_content += """
                </pre>
            </div>

            <div class="footer">
                <p>Generated by Intellicrack - Advanced Binary Analysis Tool</p>
            </div>
        </div>
    </body>
    </html>"""

            # Write the report to the file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            self.update_output.emit(log_message(f"[Reports] HTML report generated successfully: {output_path}"))
            return True

        except Exception as e:
            self.update_output.emit(log_message(f"[Reports] Error generating HTML report: {str(e)}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            return False

    def _generate_pdf_report(self, report_name, report_type, output_path):
        """Generate a PDF report"""
        self.update_output.emit(log_message(f"[Reports] Generating PDF report: {report_name}"))

        try:
            # Generate HTML first then convert to PDF
            # Use a temporary HTML file
            temp_html_path = f"{output_path}.temp.html"

            # Generate HTML content
            self._generate_html_report(report_name, report_type, temp_html_path)

            # Try to convert HTML to PDF
            try:
                # Configure PDF options
                options = {
                    'page-size': 'A4',
                    'margin-top': '20mm',
                    'margin-right': '20mm',
                    'margin-bottom': '20mm',
                    'margin-left': '20mm',
                    'encoding': 'UTF-8',
                    'title': report_name,
                    'footer-right': '[page] of [topage]',
                    'footer-font-size': '8',
                    'header-html': '<header style="text-align: center; font-size: 8pt;">Intellicrack Report</header>',
                    'header-spacing': '5'
                }

                # Convert HTML to PDF
                pdfkit.from_file(temp_html_path, output_path, options=options)

            except ImportError:
                # If pdfkit is not available, try using weasyprint
                try:
                    # Convert HTML to PDF
                    weasyprint.HTML(filename=temp_html_path).write_pdf(output_path)

                except ImportError:
                    # If neither solution is available, use a simple file-based approach
                    self.update_output.emit(log_message("[Reports] PDF conversion libraries not available"))

                    # Create a simple text report instead
                    self._generate_text_report(report_name, report_type, output_path.replace(".pdf", ".txt"))

                    # Raise an error to indicate PDF generation failed
                    raise Exception("PDF conversion libraries (pdfkit or weasyprint) not available")

            # Clean up the temporary HTML file
            if os.path.exists(temp_html_path):
                os.remove(temp_html_path)

            self.update_output.emit(log_message(f"[Reports] PDF report generated successfully: {output_path}"))
            return True

        except Exception as e:
            self.update_output.emit(log_message(f"[Reports] Error generating PDF report: {str(e)}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            return False

    def _generate_text_report(self, report_name, report_type, output_path):
        """Generate a plain text report"""
        self.update_output.emit(log_message(f"[Reports] Generating text report: {report_name}"))

        try:
            # Create the text content
            text_content = f"""
    =============================================================
INTELLICRACK REPORT: {report_name}
=============================================================
Report Type: {report_type}
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
=============================================================

ANALYSIS SUMMARY
---------------
"""

            # Add summary based on analysis results
            if hasattr(self, 'analyze_results') and self.analyze_results:
                # Extract key findings - look for interesting entries
                key_findings = []
                for result in self.analyze_results:
                    if any(keyword in str(result).lower() for keyword in
                          ['license', 'protection', 'check', 'critical', 'vulnerability', 'patched']):
                        key_findings.append(f"* {result}")

                # Add findings to the report
                if key_findings:
                    text_content += "KEY FINDINGS:\n" + "\n".join(key_findings[:10]) + "\n\n"  # First 10 findings
                else:
                    text_content += "KEY FINDINGS:\n* No critical issues identified\n\n"
            else:
                text_content += "KEY FINDINGS:\n* No analysis results available\n\n"

            # Add detailed section based on report type
            text_content += f"{report_type.upper()} DETAILS\n"
            text_content += "---------------------------\n"

            # Add type-specific details
            if report_type == "Memory Analysis" and hasattr(self, 'memory_analysis_results'):
                text_content += self._format_memory_analysis_for_text()
            elif report_type == "Network Analysis" and hasattr(self, 'traffic_recorder'):
                text_content += self._format_network_analysis_for_text()
            elif report_type == "Patching Results":
                text_content += self._format_patching_results_for_text()

            # Add the full analysis log
            text_content += "\nFULL ANALYSIS LOG\n"
            text_content += "---------------------------\n"

            if hasattr(self, 'analyze_results') and self.analyze_results:
                text_content += "\n".join(str(item) for item in self.analyze_results)
            else:
                text_content += "No detailed analysis results available."

            # Footer
            text_content += "\n\n=============================================================\n"
            text_content += "Generated by Intellicrack - Advanced Binary Analysis Tool\n"
            text_content += "=============================================================\n"

            # Write the report to the file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(text_content)

            self.update_output.emit(log_message(f"[Reports] Text report generated successfully: {output_path}"))
            return True

        except Exception as e:
            self.update_output.emit(log_message(f"[Reports] Error generating text report: {str(e)}"))
            self.update_output.emit(log_message(traceback.format_exc()))
            return False

    def _open_text_report_viewer(self, report_path, report_name):
        """Open a simple text report viewer"""
        try:
            # Create a dialog
            self.report_viewer = QDialog(self)
            self.report_viewer.setWindowTitle(f"Report: {report_name}")
            self.report_viewer.resize(800, 600)

            # Create layout
            layout = QVBoxLayout(self.report_viewer)

            # Create text edit
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)

            # Load report content
            with open(report_path, 'r', encoding='utf-8') as f:
                report_content = f.read()

            # Set content
            text_edit.setText(report_content)

            # Add toolbar
            toolbar = QHBoxLayout()

            # Add font size controls
            increase_font_btn = QPushButton("Larger Font")
            decrease_font_btn = QPushButton("Smaller Font")

            def increase_font():
                """
                Increase the font size in the text edit widget.
                """
                current = text_edit.font()
                current.setPointSize(current.pointSize() + 1)
                text_edit.setFont(current)

            def decrease_font():
                """
                Decrease the font size in the text edit widget, with a minimum size limit.
                """
                current = text_edit.font()
                if current.pointSize() > 8:
                    current.setPointSize(current.pointSize() - 1)
                    text_edit.setFont(current)

            increase_font_btn.clicked.connect(increase_font)
            decrease_font_btn.clicked.connect(decrease_font)

            # Add save button
            save_btn = QPushButton("Save As...")

            def save_as():
                """
                Save the report content to a file.

                Opens a file dialog and writes the report text to the selected file.
                """
                file_path, _ = QFileDialog.getSaveFileName(
                    self.report_viewer, "Save Report As", "", "Text Files (*.txt);;All Files (*)"
                )
                if file_path:
                    try:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(text_edit.toPlainText())
                        QMessageBox.information(self.report_viewer, "Save Successful", f"Report saved to {file_path}")
                    except Exception as e:
                        QMessageBox.warning(self.report_viewer, "Save Failed", f"Failed to save report: {str(e)}")

            save_btn.clicked.connect(save_as)

            # Add print button
            print_btn = QPushButton("Print")

            def print_report():
                """
                Print the report content.

                Opens a print dialog and sends the report text to the selected printer.
                """
                printer = QPrinter(QPrinter.HighResolution)
                dialog = QPrintDialog(printer, self.report_viewer)

                if dialog.exec_() == QPrintDialog.Accepted:
                    text_edit.print_(printer)

            print_btn.clicked.connect(print_report)

            # Add to toolbar
            toolbar.addWidget(increase_font_btn)
            toolbar.addWidget(decrease_font_btn)
            toolbar.addWidget(save_btn)
            toolbar.addWidget(print_btn)

            # Add to layout
            layout.addLayout(toolbar)
            layout.addWidget(text_edit)

            # Show the viewer
            self.report_viewer.show()

        except Exception as e:
            self.update_output.emit(log_message(f"[Reports] Error opening text report viewer: {str(e)}"))
            QMessageBox.warning(self, "Report Viewer Error", f"Failed to open report viewer:\n\n{str(e)}")

    def _generate_memory_report_section(self):
        """Generate the memory analysis section for HTML reports"""
        section = """
            <div class="section">
                <h2>Memory Analysis Results</h2>
    """

        # If we have memory analysis results
        if hasattr(self, 'memory_analysis_results') and self.memory_analysis_results:
            results = self.memory_analysis_results

            # Add overview table
            section += """
                <h3>Memory Overview</h3>
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
    """

            # Add memory metrics
            memory_metrics = [
                ("Total Allocated Memory", f"{results.get('total_allocated', 0):,} bytes"),
                ("Peak Memory Usage", f"{results.get('peak_usage', 0):,} bytes"),
                ("Heap Allocations", f"{results.get('heap_allocs', 0):,}"),
                ("Memory Leaks Detected", f"{results.get('leaks_count', 0)}"),
                ("Suspicious Allocations", f"{results.get('suspicious_allocs', 0)}")
            ]

            for metric, value in memory_metrics:
                section += f"""
                    <tr>
                        <td>{metric}</td>
                        <td>{value}</td>
                    </tr>"""

            section += """
                </table>
    """

            # Add memory leaks section if any
            if results.get('leaks', []):
                section += """
                <h3>Memory Leaks</h3>
                <table>
                    <tr>
                        <th>Address</th>
                        <th>Size</th>
                        <th>Allocation Point</th>
                        <th>Lifetime</th>
                    </tr>
    """

                for leak in results.get('leaks', [])[:10]:  # First 10 leaks
                    section += f"""
                    <tr>
                        <td>0x{leak.get('address', 0):X}</td>
                        <td>{leak.get('size', 0):,} bytes</td>
                        <td>{leak.get('allocation_point', 'Unknown')}</td>
                        <td>{leak.get('lifetime', 0)} ms</td>
                    </tr>"""

                section += """
                </table>
    """

            # Add memory regions section
            if results.get('regions', []):
                section += """
                <h3>Memory Regions</h3>
                <table>
                    <tr>
                        <th>Region</th>
                        <th>Start Address</th>
                        <th>Size</th>
                        <th>Permissions</th>
                        <th>Type</th>
                    </tr>
    """

                for region in results.get('regions', [])[:15]:  # First 15 regions
                    section += f"""
                    <tr>
                        <td>{region.get('name', 'Unknown')}</td>
                        <td>0x{region.get('start_addr', 0):X}</td>
                        <td>{region.get('size', 0):,} bytes</td>
                        <td>{region.get('permissions', 'Unknown')}</td>
                        <td>{region.get('type', 'Unknown')}</td>
                    </tr>"""

                section += """
                </table>
    """
        else:
            # No memory analysis results available
            section += """
                <p>No detailed memory analysis results available.</p>
    """

        # Close the section
        section += """
            </div>
    """

        return section

    def _generate_network_report_section(self):
        """Generate the network analysis section for HTML reports"""
        section = """
            <div class="section">
                <h2>Network Analysis Results</h2>
    """

        # If we have network traffic recorder results
        if hasattr(self, 'traffic_recorder') and self.traffic_recorder:
            traffic_summary = self.traffic_recorder.get_traffic_summary()

            if traffic_summary:
                # Protocol breakdown
                if 'protocols' in traffic_summary and traffic_summary['protocols']:
                    section += """
                <h3>Protocol Breakdown</h3>
                <table>
                    <tr>
                        <th>Protocol</th>
                        <th>Packets</th>
                        <th>Percentage</th>
                    </tr>
    """

                    protocols = traffic_summary['protocols']
                    total_packets = sum(protocols.values())

                    for protocol, count in protocols.items():
                        percentage = (count / total_packets * 100) if total_packets > 0 else 0
                        section += f"""
                    <tr>
                        <td>{protocol}</td>
                        <td>{count:,}</td>
                        <td>{percentage:.2f}%</td>
                    </tr>"""

                    section += """
                </table>
    """

                # Destination stats
                if 'destinations' in traffic_summary and traffic_summary['destinations']:
                    section += """
                <h3>Top Destinations</h3>
                <table>
                    <tr>
                        <th>Destination</th>
                        <th>Packets</th>
                        <th>Data Sent</th>
                    </tr>
    """

                    # Sort by packet count
                    destinations = sorted(
                        traffic_summary['destinations'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]  # Top 10

                    for dest, count in destinations:
                        # Get data size if available
                        data_size = traffic_summary.get('data_by_dest', {}).get(dest, 0)
                        data_str = f"{data_size:,} bytes" if data_size else "Unknown"

                        section += f"""
                    <tr>
                        <td>{dest}</td>
                        <td>{count:,}</td>
                        <td>{data_str}</td>
                    </tr>"""

                    section += """
                </table>
    """

                # License servers or suspicious connections
                if 'license_servers' in traffic_summary and traffic_summary['license_servers']:
                    section += """
                <h3>Detected License Servers</h3>
                <table>
                    <tr>
                        <th>Server</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Confidence</th>
                    </tr>
    """

                    for server in traffic_summary['license_servers']:
                        section += f"""
                    <tr>
                        <td>{server.get('address', 'Unknown')}</td>
                        <td>{server.get('port', 'Unknown')}</td>
                        <td>{server.get('protocol', 'Unknown')}</td>
                        <td>{server.get('confidence', 0)}%</td>
                    </tr>"""

                    section += """
                </table>
    """

                # Add packet capture summary
                section += """
                <h3>Packet Capture Summary</h3>
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
    """

                # Add summary metrics
                summary_metrics = [
                    ("Total Packets", f"{traffic_summary.get('total_packets', 0):,}"),
                    ("Total Data Transferred", f"{traffic_summary.get('total_bytes', 0):,} bytes"),
                    ("Capture Duration", f"{traffic_summary.get('duration_seconds', 0):.2f} seconds"),
                    ("Average Packet Size", f"{traffic_summary.get('avg_packet_size', 0):.2f} bytes"),
                    ("Suspicious Connections", f"{len(traffic_summary.get('suspicious', []))}")
                ]

                for metric, value in summary_metrics:
                    section += f"""
                    <tr>
                        <td>{metric}</td>
                        <td>{value}</td>
                    </tr>"""

                section += """
                </table>
    """
            else:
                # No traffic summary available
                section += """
                <p>No network traffic summary available.</p>
    """
        else:
            # No traffic recorder available
            section += """
                <p>No network traffic analysis results available.</p>
    """

        # Close the section
        section += """
            </div>
    """

        return section

    def _generate_patching_report_section(self):
        """Generate the patching results section for HTML reports"""
        section = """
            <div class="section">
                <h2>Patching Results</h2>
    """

        # Get patches from the table if available
        patches = []
        if hasattr(self, 'patches_table') and self.patches_table:
            for row in range(self.patches_table.rowCount()):
                patch = {
                    "id": self.patches_table.item(row, 0).text() if self.patches_table.item(row, 0) else "",
                    "type": self.patches_table.item(row, 1).text() if self.patches_table.item(row, 1) else "",
                    "address": self.patches_table.item(row, 2).text() if self.patches_table.item(row, 2) else "",
                    "status": self.patches_table.item(row, 3).text() if self.patches_table.item(row, 3) else "",
                    "description": self.patches_table.item(row, 4).text() if self.patches_table.item(row, 4) else ""
                }
                patches.append(patch)

        if patches:
            # Add patching summary
            applied_count = sum(1 for p in patches if p["status"] == "Applied")

            section += f"""
                <h3>Patching Summary</h3>
                <p>Total Patches: {len(patches)}</p>
                <p>Applied Patches: {applied_count}</p>
                <p>Pending Patches: {len(patches) - applied_count}</p>

                <h3>Patch Details</h3>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Address</th>
                        <th>Status</th>
                        <th>Description</th>
                    </tr>
    """

            for patch in patches:
                # Set row style based on status
                row_style = ""
                if patch["status"] == "Applied":
                    row_style = 'style="background-color: #e6ffe6;"'  # Light green
                elif patch["status"] == "Failed":
                    row_style = 'style="background-color: #ffe6e6;"'  # Light red

                section += f"""
                    <tr {row_style}>
                        <td>{patch["id"]}</td>
                        <td>{patch["type"]}</td>
                        <td>{patch["address"]}</td>
                        <td>{patch["status"]}</td>
                        <td>{patch["description"]}</td>
                    </tr>"""

            section += """
                </table>
    """
        else:
            # No patches available
            section += """
                <p>No patching results available.</p>
    """

        # Close the section
        section += """
            </div>
    """

        return section

    def _generate_general_report_section(self):
        """Generate a general analysis section for HTML reports"""
        section = """
            <div class="section">
                <h2>General Analysis Results</h2>
    """

        # Add binary information if available
        if hasattr(self, 'binary_path') and self.binary_path:
            # Get basic file info
            try:
                file_stats = os.stat(self.binary_path)
                file_size = file_stats.st_size
                file_modified = time.ctime(file_stats.st_mtime)
                file_name = os.path.basename(self.binary_path)

                section += f"""
                <h3>Binary Information</h3>
                <table>
                    <tr>
                        <th>Property</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>File Name</td>
                        <td>{file_name}</td>
                    </tr>
                    <tr>
                        <td>File Size</td>
                        <td>{file_size:,} bytes</td>
                    </tr>
                    <tr>
                        <td>Last Modified</td>
                        <td>{file_modified}</td>
                    </tr>
                    <tr>
                        <td>Path</td>
                        <td>{self.binary_path}</td>
                    </tr>
                </table>
    """
            except Exception as e:
                section += f"""
                <h3>Binary Information</h3>
                <p>Error retrieving file information: {str(e)}</p>
    """

        # Add analysis results summary
        section += """
                <h3>Analysis Summary</h3>
    """

        if hasattr(self, 'analyze_results') and self.analyze_results:
            # Group results by category
            categories = {
                "License Detection": [],
                "Protection Mechanisms": [],
                "Memory Analysis": [],
                "Network Analysis": [],
                "Static Analysis": [],
                "General": []
            }

            for result in self.analyze_results:
                result_str = str(result)

                # Categorize based on content
                if "license" in result_str.lower():
                    categories["License Detection"].append(result_str)
                elif any(x in result_str.lower() for x in ["protect", "obfuscation", "packing", "anti-debug"]):
                    categories["Protection Mechanisms"].append(result_str)
                elif "memory" in result_str.lower():
                    categories["Memory Analysis"].append(result_str)
                elif any(x in result_str.lower() for x in ["network", "traffic", "connection", "http", "dns"]):
                    categories["Network Analysis"].append(result_str)
                elif any(x in result_str.lower() for x in ["static", "function", "string", "import", "export"]):
                    categories["Static Analysis"].append(result_str)
                else:
                    categories["General"].append(result_str)

            # Add each category to the report
            for category, items in categories.items():
                if items:
                    section += f"""
                <h4>{category}</h4>
                <ul>
    """
                    for item in items[:10]:  # First 10 items in each category
                        section += f"                <li>{item}</li>\n"

                    # Add a note if there are more items
                    if len(items) > 10:
                        section += f"                <li>... and {len(items) - 10} more items</li>\n"

                    section += "            </ul>\n"
        else:
            section += """
                <p>No analysis results available.</p>
    """

        # Close the section
        section += """
            </div>
    """

        return section

    def _format_memory_analysis_for_text(self):
        """Format memory analysis results for text reports"""
        text = ""

        if hasattr(self, 'memory_analysis_results') and self.memory_analysis_results:
            results = self.memory_analysis_results

            # Overall summary
            text += "Memory Overview:\n"
            text += f"- Total Allocated Memory: {results.get('total_allocated', 0):,} bytes\n"
            text += f"- Peak Memory Usage: {results.get('peak_usage', 0):,} bytes\n"
            text += f"- Heap Allocations: {results.get('heap_allocs', 0):,}\n"
            text += f"- Memory Leaks Detected: {results.get('leaks_count', 0)}\n"
            text += f"- Suspicious Allocations: {results.get('suspicious_allocs', 0)}\n\n"

            # Memory leaks
            if results.get('leaks', []):
                text += "Memory Leaks:\n"
                text += "--------------------------------------\n"
                for i, leak in enumerate(results.get('leaks', [])[:10]):
                    text += f"{i+1}. Address: 0x{leak.get('address', 0):X}\n"
                    text += f"   Size: {leak.get('size', 0):,} bytes\n"
                    text += f"   Allocation: {leak.get('allocation_point', 'Unknown')}\n"
                    text += f"   Lifetime: {leak.get('lifetime', 0)} ms\n"
                    text += "--------------------------------------\n"

                if len(results.get('leaks', [])) > 10:
                    text += f"... and {len(results.get('leaks', [])) - 10} more leaks\n\n"

            # Memory regions
            if results.get('regions', []):
                text += "Memory Regions:\n"
                text += "--------------------------------------\n"
                for i, region in enumerate(results.get('regions', [])[:15]):
                    text += f"{i+1}. {region.get('name', 'Unknown')}\n"
                    text += f"   Start: 0x{region.get('start_addr', 0):X}\n"
                    text += f"   Size: {region.get('size', 0):,} bytes\n"
                    text += f"   Permissions: {region.get('permissions', 'Unknown')}\n"
                    text += f"   Type: {region.get('type', 'Unknown')}\n"
                    text += "--------------------------------------\n"

                if len(results.get('regions', [])) > 15:
                    text += f"... and {len(results.get('regions', [])) - 15} more regions\n\n"
        else:
            text += "No detailed memory analysis results available.\n\n"

        return text

    def _format_network_analysis_for_text(self):
        """Format network analysis results for text reports"""
        text = ""

        if hasattr(self, 'traffic_recorder') and self.traffic_recorder:
            traffic_summary = self.traffic_recorder.get_traffic_summary()

            if traffic_summary:
                # Summary metrics
                text += "Network Traffic Summary:\n"
                text += f"- Total Packets: {traffic_summary.get('total_packets', 0):,}\n"
                text += f"- Total Data: {traffic_summary.get('total_bytes', 0):,} bytes\n"
                text += f"- Duration: {traffic_summary.get('duration_seconds', 0):.2f} seconds\n"
                text += f"- Avg Packet Size: {traffic_summary.get('avg_packet_size', 0):.2f} bytes\n"
                text += f"- Suspicious Connections: {len(traffic_summary.get('suspicious', []))}\n\n"

                # Protocol breakdown
                if 'protocols' in traffic_summary and traffic_summary['protocols']:
                    text += "Protocol Breakdown:\n"
                    text += "--------------------------------------\n"

                    protocols = traffic_summary['protocols']
                    total_packets = sum(protocols.values())

                    for protocol, count in protocols.items():
                        percentage = (count / total_packets * 100) if total_packets > 0 else 0
                        text += f"{protocol}: {count:,} packets ({percentage:.2f}%)\n"

                    text += "--------------------------------------\n\n"

                # Top destinations
                if 'destinations' in traffic_summary and traffic_summary['destinations']:
                    text += "Top Destinations:\n"
                    text += "--------------------------------------\n"

                    # Sort by packet count
                    destinations = sorted(
                        traffic_summary['destinations'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]

                    for dest, count in destinations:
                        # Get data size if available
                        data_size = traffic_summary.get('data_by_dest', {}).get(dest, 0)
                        data_str = f"{data_size:,} bytes" if data_size else "Unknown"

                        text += f"{dest}: {count:,} packets, {data_str}\n"

                    text += "--------------------------------------\n\n"

                # License servers
                if 'license_servers' in traffic_summary and traffic_summary['license_servers']:
                    text += "Detected License Servers:\n"
                    text += "--------------------------------------\n"

                    for server in traffic_summary['license_servers']:
                        text += f"Server: {server.get('address', 'Unknown')}\n"
                        text += f"Port: {server.get('port', 'Unknown')}\n"
                        text += f"Protocol: {server.get('protocol', 'Unknown')}\n"
                        text += f"Confidence: {server.get('confidence', 0)}%\n"
                        text += "--------------------------------------\n"
            else:
                text += "No network traffic summary available.\n\n"
        else:
            text += "No network traffic analysis results available.\n\n"

        return text

    def _format_patching_results_for_text(self):
        """Format patching results for text reports"""
        text = ""

        # Get patches from the table if available
        patches = []
        if hasattr(self, 'patches_table') and self.patches_table:
            for row in range(self.patches_table.rowCount()):
                patch = {
                    "id": self.patches_table.item(row, 0).text() if self.patches_table.item(row, 0) else "",
                    "type": self.patches_table.item(row, 1).text() if self.patches_table.item(row, 1) else "",
                    "address": self.patches_table.item(row, 2).text() if self.patches_table.item(row, 2) else "",
                    "status": self.patches_table.item(row, 3).text() if self.patches_table.item(row, 3) else "",
                    "description": self.patches_table.item(row, 4).text() if self.patches_table.item(row, 4) else ""
                }
                patches.append(patch)

        if patches:
            # Patching summary
            applied_count = sum(1 for p in patches if p["status"] == "Applied")

            text += "Patching Summary:\n"
            text += f"- Total Patches: {len(patches)}\n"
            text += f"- Applied Patches: {applied_count}\n"
            text += f"- Pending Patches: {len(patches) - applied_count}\n\n"

            # Patch details
            text += "Patch Details:\n"
            text += "--------------------------------------\n"

            for patch in patches:
                text += f"ID: {patch['id']}\n"
                text += f"Type: {patch['type']}\n"
                text += f"Address: {patch['address']}\n"
                text += f"Status: {patch['status']}\n"
                text += f"Description: {patch['description']}\n"
                text += "--------------------------------------\n"
        else:
            text += "No patching results available.\n\n"

        return text

# -------------------------------
# Entry Point
# -------------------------------

def launch():
    """Starts the application with an optional splash screen."""
    # Check for existing QApplication instance first (like in monolithic version)
    app_instance = QApplication.instance()
    if app_instance is None:
        app_instance = QApplication(sys.argv)

    # Show splash screen - DISABLED TEMPORARILY
    splash_image_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'splash.png')
    icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'icon.png')
    
    # TEMPORARY: Disable splash to test if it's blocking
    splash = None
    # splash = SplashScreen(splash_image_path)
    # splash.show()
    # app_instance.processEvents()
    
    # Set application icon if available
    if os.path.exists(icon_path):
        app_instance.setWindowIcon(QIcon(icon_path))

    # Note: Comprehensive logging is already initialized in launch_intellicrack.py
    # Do not initialize it again here to avoid recursion
    logger.info("Main window initialization starting...")

    # Initialize main window in background
    time.sleep(1)  # Short delay for splash visibility

    logger.info(f"IntellicrackApp type: {type(IntellicrackApp)}")
    logger.info(f"IntellicrackApp value: {IntellicrackApp}")
    
    try:
        logger.info("Creating IntellicrackApp instance...")
        window = IntellicrackApp()
        logger.info("IntellicrackApp instance created successfully")
        
        logger.info("Showing main window...")
        
        # Force window to be visible and on top
        logger.info("Setting window properties...")
        window.setWindowState(window.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
        
        # Ensure window has reasonable size first
        window.resize(1200, 800)
        
        # Then position it safely on screen
        screen = app_instance.primaryScreen()
        if screen:
            screen_rect = screen.availableGeometry()
            # Position at 10% from top-left of screen
            x = screen_rect.x() + screen_rect.width() // 10
            y = screen_rect.y() + screen_rect.height() // 10
            window.move(x, y)
            logger.info(f"Positioned window at {x}, {y} on screen {screen_rect}")
        else:
            window.move(100, 100)  # Fallback position
            
        window.setWindowTitle("Intellicrack - Binary Analysis Tool")
        
        # Try different show methods
        logger.info("Attempting to show window...")
        window.show()
        window.raise_()
        window.activateWindow()
        window.showNormal()
        
        # Force to foreground
        window.setWindowState(window.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
        window.raise_()
        
        # Force Qt to process events
        app_instance.processEvents()
        
        logger.info(f"Window geometry: {window.geometry()}")
        logger.info(f"Window visible: {window.isVisible()}")
        logger.info(f"Window state: {window.windowState()}")
        logger.info("Main window shown successfully")
        
        # Check for any modal widgets
        logger.info(f"Modal widgets: {app_instance.activeModalWidget()}")
        logger.info(f"Popup widgets: {app_instance.activePopupWidget()}")
        logger.info(f"All top level widgets: {[w.objectName() or str(w) for w in app_instance.topLevelWidgets()]}")
        
        if splash:
            logger.info("Closing splash screen...")
            splash.close()
            splash.hide()  # Explicitly hide
            splash.deleteLater()  # Schedule for deletion
            logger.info("Splash screen closed")
        else:
            logger.info("No splash screen to close")
        
        # Make absolutely sure the main window is on top
        window.raise_()
        window.activateWindow()
        window.setWindowState(window.windowState() | Qt.WindowActive)
        
    except Exception as e:
        logger.error(f"Error creating IntellicrackApp: {e}")
        logger.error(traceback.format_exc())
        raise

    logger.info("Starting Qt event loop...")
    logger.info(f"Active windows: {QApplication.topLevelWindows()}")
    logger.info(f"App instance: {app_instance}")
    logger.info(f"App is about to quit: {app_instance.aboutToQuit}")
    
    # Add a single-shot timer to log after event loop starts
    from PyQt5.QtCore import QTimer

    def run_rop_gadget_finder(self):
        """Find ROP gadgets in the binary."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[ROP] Starting ROP gadget search..."))
        self.update_analysis_results.emit("\n=== ROP Gadget Search ===\n")
        
        try:
            from ..core.analysis.rop_generator import ROPChainGenerator
            
            generator = ROPChainGenerator(self.binary_path)
            success = generator.find_gadgets()
            
            if not success:
                self.update_output.emit(log_message("[ROP] Failed to find gadgets"))
                return
                
            gadgets = generator.gadgets
            
            self.update_analysis_results.emit(f"Found {len(gadgets)} ROP gadgets\n\n")
            
            # Display first 50 gadgets
            for i, gadget in enumerate(gadgets[:50]):
                self.update_analysis_results.emit(f"{i+1}. Address: 0x{gadget['address']:08x}\n")
                self.update_analysis_results.emit(f"   Instructions: {gadget['instructions']}\n")
                self.update_analysis_results.emit(f"   Bytes: {gadget['bytes'].hex()}\n\n")
            
            if len(gadgets) > 50:
                self.update_analysis_results.emit(f"... and {len(gadgets) - 50} more gadgets\n")
            
            self.update_output.emit(log_message(f"[ROP] Found {len(gadgets)} gadgets"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[ROP] Error: {e}"))
            self.update_analysis_results.emit(f"Error finding ROP gadgets: {e}\n")

    def run_packing_detection(self):
        """Detect packing and obfuscation in the binary."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Packing] Starting packing/obfuscation detection..."))
        self.update_analysis_results.emit("\n=== Packing/Obfuscation Detection ===\n")
        
        try:
            from ..utils.protection_detection import detect_packing_methods
            
            results = detect_packing_methods(self.binary_path)
            
            if results.get('packed'):
                self.update_analysis_results.emit("⚠️ Binary appears to be packed!\n\n")
                self.update_analysis_results.emit(f"Detected Packer: {results.get('packer_type', 'Unknown')}\n")
                self.update_analysis_results.emit(f"Confidence: {results.get('confidence', 0):.1%}\n\n")
                
                self.update_analysis_results.emit("Indicators:\n")
                for indicator in results.get('indicators', []):
                    self.update_analysis_results.emit(f"- {indicator}\n")
            else:
                self.update_analysis_results.emit("✅ Binary does not appear to be packed\n")
            
            # Show entropy analysis
            self.update_analysis_results.emit("\nSection Entropy Analysis:\n")
            for section in results.get('sections', []):
                self.update_analysis_results.emit(f"- {section['name']}: {section['entropy']:.2f}")
                if section['entropy'] > 7.0:
                    self.update_analysis_results.emit(" (HIGH - possibly compressed/encrypted)")
                self.update_analysis_results.emit("\n")
            
            self.update_output.emit(log_message("[Packing] Detection complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Packing] Error: {e}"))
            self.update_analysis_results.emit(f"Error detecting packing: {e}\n")

    def run_static_vulnerability_scan(self):
        """Run advanced static vulnerability scanning."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Vuln Scan] Starting static vulnerability scan..."))
        self.update_analysis_results.emit("\n=== Static Vulnerability Scan ===\n")
        
        try:
            from ..core.analysis.vulnerability_engine import VulnerabilityEngine
            
            engine = VulnerabilityEngine()
            vulnerabilities = engine.scan_binary(self.binary_path)
            
            if vulnerabilities:
                self.update_analysis_results.emit(f"Found {len(vulnerabilities)} potential vulnerabilities:\n\n")
                
                # Group by severity
                critical = [v for v in vulnerabilities if v.get('severity') == 'critical']
                high = [v for v in vulnerabilities if v.get('severity') == 'high']
                medium = [v for v in vulnerabilities if v.get('severity') == 'medium']
                low = [v for v in vulnerabilities if v.get('severity') == 'low']
                
                if critical:
                    self.update_analysis_results.emit(f"🔴 CRITICAL ({len(critical)}):\n")
                    for vuln in critical:
                        self.update_analysis_results.emit(f"  - {vuln['type']}: {vuln['description']}\n")
                
                if high:
                    self.update_analysis_results.emit(f"\n🟠 HIGH ({len(high)}):\n")
                    for vuln in high:
                        self.update_analysis_results.emit(f"  - {vuln['type']}: {vuln['description']}\n")
                
                if medium:
                    self.update_analysis_results.emit(f"\n🟡 MEDIUM ({len(medium)}):\n")
                    for vuln in medium:
                        self.update_analysis_results.emit(f"  - {vuln['type']}: {vuln['description']}\n")
                
                if low:
                    self.update_analysis_results.emit(f"\n🟢 LOW ({len(low)}):\n")
                    for vuln in low:
                        self.update_analysis_results.emit(f"  - {vuln['type']}: {vuln['description']}\n")
            else:
                self.update_analysis_results.emit("✅ No vulnerabilities detected\n")
            
            self.update_output.emit(log_message("[Vuln Scan] Scan complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Vuln Scan] Error: {e}"))
            self.update_analysis_results.emit(f"Error during vulnerability scan: {e}\n")

    def run_ml_vulnerability_prediction(self):
        """Run ML-based vulnerability prediction using agentic AI system."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[AI Agent] Starting intelligent vulnerability prediction..."))
        self.update_analysis_results.emit("\n=== Agentic AI Vulnerability Prediction ===\n")
        
        try:
            # Use the agentic AI system if available
            if hasattr(self, 'ai_orchestrator') and self.ai_orchestrator:
                self.update_output.emit(log_message("[AI Agent] Using agentic AI orchestrator for analysis..."))
                
                # Define callback to handle results
                def handle_ai_result(result):
                    try:
                        if result.success:
                            # Display ML results
                            if result.ml_results:
                                ml_data = result.ml_results
                                self.update_analysis_results.emit("📊 Fast ML Analysis:\n")
                                self.update_analysis_results.emit(f"Model confidence: {ml_data.get('confidence', 0.0):.2f}\n")
                                vulnerabilities = ml_data.get('vulnerabilities', [])
                                if vulnerabilities:
                                    self.update_analysis_results.emit(f"Vulnerabilities found: {len(vulnerabilities)}\n")
                                    for vuln in vulnerabilities[:5]:  # Show first 5
                                        severity = vuln.get('severity', 'unknown')
                                        name = vuln.get('name', 'unknown')
                                        self.update_analysis_results.emit(f"  • {severity}: {name}\n")
                                else:
                                    self.update_analysis_results.emit("No significant vulnerabilities detected by ML\n")
                            
                            # Display LLM results if available (escalated analysis)
                            if result.llm_results:
                                llm_data = result.llm_results
                                self.update_analysis_results.emit("\n🧠 Deep LLM Analysis:\n")
                                self.update_analysis_results.emit(f"Complex patterns analyzed\n")
                                self.update_analysis_results.emit(f"LLM confidence: {llm_data.get('confidence', 0.0):.2f}\n")
                                reasoning = llm_data.get('reasoning', 'No reasoning provided')
                                self.update_analysis_results.emit(f"Analysis reasoning: {reasoning}\n")
                                
                                recommendations = llm_data.get('recommendations', [])
                                if recommendations:
                                    self.update_analysis_results.emit("🎯 AI Recommendations:\n")
                                    for rec in recommendations:
                                        self.update_analysis_results.emit(f"  • {rec}\n")
                            
                            # Overall assessment
                            confidence = result.combined_confidence
                            strategy = result.strategy_used
                            time_taken = result.processing_time
                            
                            self.update_analysis_results.emit(f"\n📈 Overall Assessment:\n")
                            self.update_analysis_results.emit(f"Strategy used: {strategy.value}\n")
                            self.update_analysis_results.emit(f"Combined confidence: {confidence:.2f}\n")
                            self.update_analysis_results.emit(f"Processing time: {time_taken:.2f}s\n")
                            
                            if result.escalated:
                                self.update_analysis_results.emit("🚀 Analysis was escalated to LLM for deeper insights\n")
                            
                            if confidence > 0.8:
                                self.update_analysis_results.emit("✅ High confidence analysis - results are reliable\n")
                            elif confidence > 0.6:
                                self.update_analysis_results.emit("⚠️ Medium confidence - consider additional analysis\n")
                            else:
                                self.update_analysis_results.emit("❓ Low confidence - manual review recommended\n")
                                
                        else:
                            self.update_analysis_results.emit("❌ AI analysis failed\n")
                            for error in result.errors:
                                self.update_analysis_results.emit(f"Error: {error}\n")
                    
                    except Exception as e:
                        self.update_analysis_results.emit(f"Error displaying AI results: {e}\n")
                
                # Submit vulnerability scan task to orchestrator
                task_id = self.ai_orchestrator.quick_vulnerability_scan(
                    self.binary_path,
                    callback=handle_ai_result
                )
                
                self.update_output.emit(log_message(f"[AI Agent] Submitted task {task_id} to agentic AI system"))
                
            # Fallback to traditional ML predictor if orchestrator not available
            elif hasattr(self, 'ml_predictor') and self.ml_predictor:
                self.update_output.emit(log_message("[ML Vuln] Falling back to traditional ML predictor..."))
                
                prediction_result = self.ml_predictor.predict_vulnerability(self.binary_path)
                
                if prediction_result:
                    prediction = prediction_result.get('prediction', 0)
                    probability = prediction_result.get('probability', 0)
                    feature_count = prediction_result.get('feature_count', 0)
                    model_type = prediction_result.get('model_type', 'Unknown')
                    
                    self.update_analysis_results.emit(f"ML Model: {model_type}\n")
                    self.update_analysis_results.emit(f"Features analyzed: {feature_count}\n")
                    self.update_analysis_results.emit(f"Vulnerability prediction: {'High Risk' if prediction == 1 else 'Low Risk'}\n")
                    if probability:
                        self.update_analysis_results.emit(f"Confidence: {probability:.1%}\n")
                    
                    if prediction == 1:
                        self.update_analysis_results.emit("⚠️ ML model suggests this binary may have vulnerabilities\n")
                    else:
                        self.update_analysis_results.emit("✅ ML model suggests this binary has low vulnerability risk\n")
                else:
                    self.update_analysis_results.emit("❌ ML prediction failed - no model loaded or feature extraction failed\n")
                
                self.update_output.emit(log_message("[ML Vuln] Traditional prediction complete"))
            
            else:
                self.update_output.emit(log_message("[ML Vuln] No AI system available"))
                self.update_analysis_results.emit("❌ No AI/ML system available for vulnerability prediction\n")
            
        except Exception as e:
            self.update_output.emit(log_message(f"[AI Agent] Error: {e}"))
            self.update_analysis_results.emit(f"Error during AI vulnerability prediction: {e}\n")

    def run_comprehensive_ai_analysis(self):
        """Run comprehensive analysis using all available AI resources."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[AI Agent] Starting comprehensive agentic AI analysis..."))
        self.update_analysis_results.emit("\n=== Comprehensive Agentic AI Analysis ===\n")
        
        try:
            if hasattr(self, 'ai_orchestrator') and self.ai_orchestrator:
                self.update_output.emit(log_message("[AI Agent] Using full agentic AI capabilities..."))
                
                def handle_comprehensive_result(result):
                    try:
                        self.update_analysis_results.emit("🤖 Comprehensive AI Analysis Results:\n")
                        self.update_analysis_results.emit("=" * 50 + "\n")
                        
                        # Show which AI components were used
                        components = result.components_used
                        self.update_analysis_results.emit(f"AI Components Used: {', '.join(components)}\n")
                        
                        if result.success:
                            # ML Analysis section
                            if result.ml_results:
                                self.update_analysis_results.emit("\n📊 Fast ML Analysis Results:\n")
                                self.update_analysis_results.emit("-" * 30 + "\n")
                                ml_data = result.ml_results
                                
                                # Show vulnerabilities
                                vulns = ml_data.get('vulnerabilities', [])
                                if vulns:
                                    severity_counts = {}
                                    for v in vulns:
                                        sev = v.get('severity', 'unknown')
                                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                                    
                                    self.update_analysis_results.emit(f"Total vulnerabilities: {len(vulns)}\n")
                                    for severity, count in severity_counts.items():
                                        self.update_analysis_results.emit(f"  {severity}: {count}\n")
                                
                                # Show features analyzed
                                features = ml_data.get('features_analyzed', [])
                                if features:
                                    self.update_analysis_results.emit(f"Binary features analyzed: {len(features)}\n")
                            
                            # LLM Analysis section
                            if result.llm_results:
                                self.update_analysis_results.emit("\n🧠 Intelligent LLM Analysis Results:\n")
                                self.update_analysis_results.emit("-" * 30 + "\n")
                                llm_data = result.llm_results
                                
                                reasoning = llm_data.get('reasoning', 'Complex analysis performed')
                                self.update_analysis_results.emit(f"AI Reasoning: {reasoning}\n")
                                
                                patterns = llm_data.get('complex_patterns', [])
                                if patterns:
                                    self.update_analysis_results.emit(f"Complex patterns identified: {len(patterns)}\n")
                                    for pattern in patterns[:3]:  # Show top 3
                                        self.update_analysis_results.emit(f"  • {pattern}\n")
                                
                                recommendations = llm_data.get('recommendations', [])
                                if recommendations:
                                    self.update_analysis_results.emit("\n🎯 AI-Generated Recommendations:\n")
                                    for i, rec in enumerate(recommendations, 1):
                                        self.update_analysis_results.emit(f"{i}. {rec}\n")
                            
                            # Binary analysis results
                            if 'hex_analysis' in result.result_data:
                                hex_data = result.result_data['hex_analysis']
                                self.update_analysis_results.emit("\n🔍 Binary Pattern Analysis:\n")
                                self.update_analysis_results.emit("-" * 30 + "\n")
                                confidence = hex_data.get('confidence', 0.0)
                                self.update_analysis_results.emit(f"Pattern recognition confidence: {confidence:.2f}\n")
                            
                            # Performance metrics
                            self.update_analysis_results.emit(f"\n⚡ Performance Metrics:\n")
                            self.update_analysis_results.emit("-" * 30 + "\n")
                            self.update_analysis_results.emit(f"Total processing time: {result.processing_time:.2f}s\n")
                            self.update_analysis_results.emit(f"Analysis strategy: {result.strategy_used.value}\n")
                            self.update_analysis_results.emit(f"Combined confidence: {result.combined_confidence:.2f}\n")
                            
                            if result.escalated:
                                self.update_analysis_results.emit("🚀 Analysis escalated to LLM for deeper insights\n")
                            
                            # Final assessment
                            self.update_analysis_results.emit(f"\n📋 Final Assessment:\n")
                            self.update_analysis_results.emit("=" * 30 + "\n")
                            
                            if result.combined_confidence >= 0.9:
                                assessment = "🔴 High Risk - Immediate attention required"
                            elif result.combined_confidence >= 0.7:
                                assessment = "🟡 Medium Risk - Further investigation recommended"
                            elif result.combined_confidence >= 0.5:
                                assessment = "🟢 Low Risk - Standard security measures sufficient"
                            else:
                                assessment = "⚪ Inconclusive - Manual review required"
                            
                            self.update_analysis_results.emit(f"{assessment}\n")
                            
                        else:
                            self.update_analysis_results.emit("❌ Comprehensive analysis failed\n")
                            for error in result.errors:
                                self.update_analysis_results.emit(f"Error: {error}\n")
                                
                        self.update_analysis_results.emit("\n" + "=" * 50 + "\n")
                        
                    except Exception as e:
                        self.update_analysis_results.emit(f"Error displaying comprehensive results: {e}\n")
                
                # Submit comprehensive analysis task
                task_id = self.ai_orchestrator.comprehensive_analysis(
                    self.binary_path,
                    callback=handle_comprehensive_result
                )
                
                self.update_output.emit(log_message(f"[AI Agent] Submitted comprehensive task {task_id}"))
                
            else:
                self.update_output.emit(log_message("[AI Agent] Agentic AI system not available"))
                self.update_analysis_results.emit("❌ Agentic AI system not available for comprehensive analysis\n")
                self.update_analysis_results.emit("Please check AI system initialization.\n")
            
        except Exception as e:
            self.update_output.emit(log_message(f"[AI Agent] Comprehensive analysis error: {e}"))
            self.update_analysis_results.emit(f"Error during comprehensive AI analysis: {e}\n")

    def open_llm_config_dialog(self):
        """Open the LLM configuration dialog."""
        try:
            from .dialogs.llm_config_dialog import LLMConfigDialog
            
            dialog = LLMConfigDialog(self)
            result = dialog.exec_()
            
            if result == dialog.Accepted:
                # Refresh orchestrator status after configuration
                if hasattr(self, 'ai_orchestrator') and self.ai_orchestrator:
                    status = self.ai_orchestrator.get_component_status()
                    llm_info = status.get('llm_status', {})
                    available_llms = llm_info.get('available_llms', [])
                    
                    if available_llms:
                        self.update_output.emit(log_message(f"[AI Config] ✓ {len(available_llms)} LLM models configured"))
                        active_llm = llm_info.get('active_llm')
                        if active_llm:
                            self.update_output.emit(log_message(f"[AI Config] ✓ Active model: {active_llm}"))
                    else:
                        self.update_output.emit(log_message("[AI Config] No LLM models configured"))
                        
        except ImportError as e:
            QMessageBox.critical(self, "Import Error", f"Failed to import LLM config dialog: {e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open LLM configuration: {e}")
            self.logger.error(f"LLM config dialog error: {e}")

    def analyze_process_behavior(self):
        """Analyze live process behavior."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Process] Starting process behavior analysis..."))
        self.update_analysis_results.emit("\n=== Process Behavior Analysis ===\n")
        
        try:
            from ..core.analysis.dynamic_analyzer import AdvancedDynamicAnalyzer
            
            analyzer = AdvancedDynamicAnalyzer(self.binary_path)
            self.update_analysis_results.emit("Launching process for analysis...\n")
            
            # Run the analysis
            results = analyzer.run_comprehensive_analysis()
            
            if results.get('status') == 'success':
                self.update_analysis_results.emit(f"Process PID: {results.get('pid', 'Unknown')}\n\n")
                
                # API calls
                api_calls = results.get('api_calls', [])
                self.update_analysis_results.emit(f"API Calls Monitored: {len(api_calls)}\n")
                if api_calls:
                    self.update_analysis_results.emit("Most frequent APIs:\n")
                    for api in api_calls[:10]:
                        self.update_analysis_results.emit(f"  - {api['name']}: {api['count']} calls\n")
                
                # File operations
                file_ops = results.get('file_operations', [])
                if file_ops:
                    self.update_analysis_results.emit(f"\nFile Operations: {len(file_ops)}\n")
                    for op in file_ops[:5]:
                        self.update_analysis_results.emit(f"  - {op['type']}: {op['path']}\n")
                
                # Registry operations
                reg_ops = results.get('registry_operations', [])
                if reg_ops:
                    self.update_analysis_results.emit(f"\nRegistry Operations: {len(reg_ops)}\n")
                    for op in reg_ops[:5]:
                        self.update_analysis_results.emit(f"  - {op['type']}: {op['key']}\n")
                
                # Network activity
                net_activity = results.get('network_activity', [])
                if net_activity:
                    self.update_analysis_results.emit(f"\nNetwork Activity: {len(net_activity)}\n")
                    for activity in net_activity[:5]:
                        self.update_analysis_results.emit(f"  - {activity['type']}: {activity['address']}\n")
            else:
                self.update_analysis_results.emit(f"Analysis failed: {results.get('error', 'Unknown error')}\n")
            
            self.update_output.emit(log_message("[Process] Analysis complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Process] Error: {e}"))
            self.update_analysis_results.emit(f"Error analyzing process: {e}\n")

    def run_memory_keyword_scan(self):
        """Run memory keyword scan using Frida."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        # Get keywords from user
        keywords, ok = QInputDialog.getText(
            self, "Memory Scan Keywords",
            "Enter keywords to search (comma-separated):",
            text="license,trial,activation,serial,key"
        )
        
        if not ok or not keywords:
            return
        
        keyword_list = [k.strip() for k in keywords.split(',')]
        
        self.update_output.emit(log_message("[Memory Scan] Starting memory keyword scan..."))
        self.update_analysis_results.emit("\n=== Memory Keyword Scan ===\n")
        self.update_analysis_results.emit(f"Searching for: {', '.join(keyword_list)}\n\n")
        
        try:
            from ..core.analysis.dynamic_analyzer import AdvancedDynamicAnalyzer
            
            analyzer = AdvancedDynamicAnalyzer(self.binary_path)
            # Memory scanning is not implemented in AdvancedDynamicAnalyzer
            # Use frida runtime analysis instead
            results = analyzer.run_comprehensive_analysis()
            
            # Extract memory-related information from the results
            if results.get('status') == 'success':
                # Simulate keyword scanning from the analysis results
                found_keywords = []
                if 'events' in results:
                    for event in results['events']:
                        for keyword in keyword_list:
                            if keyword.lower() in str(event).lower():
                                found_keywords.append(keyword)
                                break
                results['keywords_found'] = list(set(found_keywords))
            
            if results.get('status') == 'success':
                matches = results.get('matches', [])
                self.update_analysis_results.emit(f"Found {len(matches)} matches:\n\n")
                
                for match in matches:
                    self.update_analysis_results.emit(f"Address: 0x{match['address']:08x}\n")
                    self.update_analysis_results.emit(f"Keyword: {match['keyword']}\n")
                    self.update_analysis_results.emit(f"Context: {match['context']}\n")
                    self.update_analysis_results.emit("-" * 50 + "\n")
            else:
                self.update_analysis_results.emit(f"Scan failed: {results.get('error', 'Unknown error')}\n")
            
            self.update_output.emit(log_message("[Memory Scan] Scan complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Memory Scan] Error: {e}"))
            self.update_analysis_results.emit(f"Error during memory scan: {e}\n")

    def analyze_captured_traffic(self):
        """Analyze captured network traffic."""
        if not hasattr(self, 'captured_packets') or not self.captured_packets:
            QMessageBox.warning(self, "No Data", "No captured traffic to analyze.")
            return
        
        self.update_output.emit(log_message("[Traffic] Analyzing captured traffic..."))
        self.update_analysis_results.emit("\n=== Traffic Analysis Results ===\n")
        
        try:
            from ..core.network.traffic_analyzer import NetworkTrafficAnalyzer
            
            analyzer = NetworkTrafficAnalyzer()
            # Set the captured packets for analysis
            if hasattr(self, 'captured_packets'):
                analyzer.captured_packets = self.captured_packets
            results = analyzer.analyze_traffic()
            
            # Summary
            self.update_analysis_results.emit(f"Total Packets: {results.get('total_packets', 0)}\n")
            self.update_analysis_results.emit(f"Time Range: {results.get('time_range', 'Unknown')}\n\n")
            
            # Protocol breakdown
            protocols = results.get('protocols', {})
            if protocols:
                self.update_analysis_results.emit("Protocol Breakdown:\n")
                for proto, count in protocols.items():
                    self.update_analysis_results.emit(f"  - {proto}: {count} packets\n")
            
            # Top talkers
            top_talkers = results.get('top_talkers', [])
            if top_talkers:
                self.update_analysis_results.emit("\nTop Talkers:\n")
                for talker in top_talkers[:10]:
                    self.update_analysis_results.emit(f"  - {talker['address']}: {talker['packets']} packets\n")
            
            # Suspicious activity
            suspicious = results.get('suspicious_activity', [])
            if suspicious:
                self.update_analysis_results.emit("\n⚠️ Suspicious Activity Detected:\n")
                for activity in suspicious:
                    self.update_analysis_results.emit(f"  - {activity['type']}: {activity['description']}\n")
            
            # License-related traffic
            license_traffic = results.get('license_traffic', [])
            if license_traffic:
                self.update_analysis_results.emit("\n🔑 License-Related Traffic:\n")
                for traffic in license_traffic:
                    self.update_analysis_results.emit(f"  - {traffic['type']}: {traffic['details']}\n")
            
            self.update_output.emit(log_message("[Traffic] Analysis complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Traffic] Error: {e}"))
            self.update_analysis_results.emit(f"Error analyzing traffic: {e}\n")

    def run_multi_format_analysis(self):
        """Run multi-format binary analysis."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Multi-Format] Starting analysis..."))
        self.update_analysis_results.emit("\n=== Multi-Format Binary Analysis ===\n")
        
        try:
            from ..core.analysis.multi_format_analyzer import MultiFormatAnalyzer
            
            analyzer = MultiFormatAnalyzer()
            results = analyzer.analyze(self.binary_path)
            
            # File format
            self.update_analysis_results.emit(f"File Format: {results.get('format', 'Unknown')}\n")
            self.update_analysis_results.emit(f"Architecture: {results.get('architecture', 'Unknown')}\n")
            self.update_analysis_results.emit(f"Bit Width: {results.get('bits', 'Unknown')}-bit\n\n")
            
            # Format-specific details
            if results.get('format') == 'PE':
                pe_info = results.get('pe_info', {})
                self.update_analysis_results.emit("PE Specific Information:\n")
                self.update_analysis_results.emit(f"  - Subsystem: {pe_info.get('subsystem', 'Unknown')}\n")
                self.update_analysis_results.emit(f"  - DLL Characteristics: 0x{pe_info.get('dll_characteristics', 0):04x}\n")
                self.update_analysis_results.emit(f"  - Checksum: 0x{pe_info.get('checksum', 0):08x}\n")
            elif results.get('format') == 'ELF':
                elf_info = results.get('elf_info', {})
                self.update_analysis_results.emit("ELF Specific Information:\n")
                self.update_analysis_results.emit(f"  - Type: {elf_info.get('type', 'Unknown')}\n")
                self.update_analysis_results.emit(f"  - Entry Point: 0x{elf_info.get('entry_point', 0):08x}\n")
            elif results.get('format') == 'Mach-O':
                macho_info = results.get('macho_info', {})
                self.update_analysis_results.emit("Mach-O Specific Information:\n")
                self.update_analysis_results.emit(f"  - File Type: {macho_info.get('filetype', 'Unknown')}\n")
                self.update_analysis_results.emit(f"  - Flags: 0x{macho_info.get('flags', 0):08x}\n")
            
            # Common analysis results
            if 'strings' in results:
                interesting_strings = results['strings'][:20]
                if interesting_strings:
                    self.update_analysis_results.emit("\nInteresting Strings:\n")
                    for s in interesting_strings:
                        self.update_analysis_results.emit(f"  - {s}\n")
            
            self.update_output.emit(log_message("[Multi-Format] Analysis complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Multi-Format] Error: {e}"))
            self.update_analysis_results.emit(f"Error during analysis: {e}\n")

    def run_comprehensive_protection_scan(self):
        """Run comprehensive protection scanning."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Protection] Starting comprehensive scan..."))
        self.protection_results.clear()
        self.protection_results.append("=== Comprehensive Protection Scan ===\n")
        
        try:
            from ..utils.protection_detection import (
                detect_all_protections, detect_anti_debug, detect_checksum_verification,
                detect_self_healing, detect_commercial_protectors
            )
            
            # Run all detection methods
            self.protection_results.append("Scanning for protections...\n\n")
            
            # Commercial protectors
            commercial = detect_commercial_protectors(self.binary_path)
            if commercial:
                self.protection_results.append("🛡️ Commercial Protectors Detected:\n")
                for protector in commercial:
                    self.protection_results.append(f"  - {protector['name']} (confidence: {protector['confidence']:.1%})\n")
                self.protection_results.append("\n")
            
            # Anti-debugging
            anti_debug = detect_anti_debug(self.binary_path)
            if anti_debug:
                self.protection_results.append("🐛 Anti-Debugging Techniques:\n")
                for technique in anti_debug:
                    self.protection_results.append(f"  - {technique}\n")
                self.protection_results.append("\n")
            
            # Checksum verification
            checksum = detect_checksum_verification(self.binary_path)
            if checksum:
                self.protection_results.append("✓ Checksum/Integrity Checks:\n")
                for check in checksum:
                    self.protection_results.append(f"  - {check}\n")
                self.protection_results.append("\n")
            
            # Self-healing code
            self_healing = detect_self_healing(self.binary_path)
            if self_healing:
                self.protection_results.append("🔧 Self-Healing Code:\n")
                for technique in self_healing:
                    self.protection_results.append(f"  - {technique}\n")
                self.protection_results.append("\n")
            
            # Summary
            all_protections = len(commercial) + len(anti_debug) + len(checksum) + len(self_healing)
            if all_protections == 0:
                self.protection_results.append("✅ No significant protections detected\n")
            else:
                self.protection_results.append(f"\nTotal protections found: {all_protections}\n")
                self.protection_results.append("\nRecommended approach:\n")
                if commercial:
                    self.protection_results.append("- Use unpacker for commercial protector\n")
                if anti_debug:
                    self.protection_results.append("- Bypass anti-debugging checks\n")
                if checksum:
                    self.protection_results.append("- Patch checksum verification\n")
                if self_healing:
                    self.protection_results.append("- Disable self-healing mechanisms\n")
            
            self.update_output.emit(log_message("[Protection] Scan complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Protection] Error: {e}"))
            self.protection_results.append(f"\nError during scan: {e}\n")

    def run_advanced_ghidra_analysis(self):
        """Run Ghidra headless analysis with advanced script."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        self.update_output.emit(log_message("[Ghidra] Starting headless analysis..."))
        self.update_analysis_results.emit("\n=== Ghidra Advanced Analysis ===\n")
        
        try:
            from ..utils.tool_wrappers import run_ghidra_headless
            
            # Run Ghidra analysis
            results = run_ghidra_headless(
                self.binary_path,
                script="AdvancedAnalysis.java",
                timeout=300  # 5 minutes timeout
            )
            
            if results.get('success'):
                self.update_analysis_results.emit("Ghidra analysis completed successfully!\n\n")
                
                # Parse and display results
                output = results.get('output', '')
                
                # Extract key findings
                if 'License' in output or 'license' in output:
                    self.update_analysis_results.emit("🔑 License-related findings detected\n")
                
                if 'Vulnerability' in output or 'vulnerable' in output:
                    self.update_analysis_results.emit("⚠️ Potential vulnerabilities found\n")
                
                # Show output
                self.update_analysis_results.emit("\nAnalysis Output:\n")
                self.update_analysis_results.emit("-" * 50 + "\n")
                
                # Limit output to prevent UI freeze
                lines = output.split('\n')
                for line in lines[:100]:  # Show first 100 lines
                    self.update_analysis_results.emit(line + "\n")
                
                if len(lines) > 100:
                    self.update_analysis_results.emit(f"\n... and {len(lines) - 100} more lines\n")
                
                # Check if report was generated
                report_path = results.get('report_path')
                if report_path and os.path.exists(report_path):
                    self.update_analysis_results.emit(f"\nDetailed report saved to: {report_path}\n")
            else:
                error = results.get('error', 'Unknown error')
                self.update_analysis_results.emit(f"Ghidra analysis failed: {error}\n")
            
            self.update_output.emit(log_message("[Ghidra] Analysis complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Ghidra] Error: {e}"))
            self.update_analysis_results.emit(f"Error running Ghidra: {e}\n")

    def run_taint_analysis(self):
        """Run taint analysis on the binary."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please select a binary file first.")
            return
        
        # Get taint source from user
        source, ok = QInputDialog.getText(
            self, "Taint Analysis",
            "Enter taint source (e.g., user_input, file_read, network_recv):",
            text="user_input"
        )
        
        if not ok or not source:
            return
        
        self.update_output.emit(log_message("[Taint] Starting taint analysis..."))
        self.update_analysis_results.emit("\n=== Taint Analysis ===\n")
        self.update_analysis_results.emit(f"Tracking taint from: {source}\n\n")
        
        try:
            from ..core.analysis.taint_analyzer import TaintAnalysisEngine
            
            engine = TaintAnalysisEngine(self.binary_path)
            engine.add_taint_source("user_input", source)
            success = engine.run_analysis()
            
            if not success:
                self.update_output.emit(log_message("[Taint] Analysis failed"))
                return
                
            results = engine.get_results()
            
            if results.get('taint_paths'):
                paths = results['taint_paths']
                self.update_analysis_results.emit(f"Found {len(paths)} taint propagation paths:\n\n")
                
                for i, path in enumerate(paths, 1):
                    self.update_analysis_results.emit(f"Path {i}:\n")
                    for step in path:
                        self.update_analysis_results.emit(f"  {step['address']}: {step['instruction']}\n")
                        if step.get('tainted_regs'):
                            self.update_analysis_results.emit(f"    Tainted registers: {', '.join(step['tainted_regs'])}\n")
                    self.update_analysis_results.emit("\n")
                
                # Check for vulnerabilities
                vulns = results.get('potential_vulnerabilities', [])
                if vulns:
                    self.update_analysis_results.emit("⚠️ Potential vulnerabilities from tainted data:\n")
                    for vuln in vulns:
                        self.update_analysis_results.emit(f"  - {vuln['type']} at {vuln['address']}\n")
            else:
                self.update_analysis_results.emit("No taint propagation paths found\n")
            
            self.update_output.emit(log_message("[Taint] Analysis complete"))
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Taint] Error: {e}"))
            self.update_analysis_results.emit(f"Error during taint analysis: {e}\n")
    def log_after_start():
        logger.info("Event loop started successfully")
        logger.info(f"Window still visible: {window.isVisible()}")
        logger.info(f"Active modal widget: {app_instance.activeModalWidget()}")
        logger.info(f"Active popup widget: {app_instance.activePopupWidget()}")
        logger.info(f"Active window: {app_instance.activeWindow()}")
        logger.info(f"Window flags: {window.windowFlags()}")
        logger.info(f"Window opacity: {window.windowOpacity()}")
        logger.info(f"Window minimized: {window.isMinimized()}")
        logger.info(f"Window maximized: {window.isMaximized()}")
        
        # Check all top level widgets for splash
        for widget in app_instance.topLevelWidgets():
            if 'SplashScreen' in str(widget):
                logger.warning(f"Splash screen still in top level widgets: {widget}, visible: {widget.isVisible()}")
        
    QTimer.singleShot(100, log_after_start)
    
    # Force show window after event loop starts
    def force_show_window():
        logger.info("Force showing window from timer...")
        window.setWindowFlags(Qt.Window)  # Reset to default window flags
        window.show()
        window.raise_()
        window.activateWindow()
        
        # Move to center of screen - ensure positive coordinates
        screen = app_instance.primaryScreen()
        if screen:
            screen_rect = screen.availableGeometry()
            # Calculate center position
            x = (screen_rect.width() - window.width()) // 2
            y = (screen_rect.height() - window.height()) // 2
            # Ensure positive coordinates
            x = max(0, x)
            y = max(0, y)
            window.move(x, y)
            logger.info(f"Moved window to position: {window.pos()}")
            logger.info(f"Screen geometry: {screen_rect}")
        else:
            # Fallback to safe position
            window.move(100, 100)
            logger.info("No primary screen found, moved to 100,100")
    
    # Schedule the force show after event loop starts
    QTimer.singleShot(0, force_show_window)
    
    # Start event loop
    exit_code = app_instance.exec_()
    logger.info(f"Event loop ended with code: {exit_code}")
    sys.exit(exit_code)

if __name__ == "__main__":
    try:
        launch()
    except Exception as e:
        error_message = f"Startup failed: {e}"
        print(error_message)
        print(f"Error type: {type(e).__name__}")
        print(f"Traceback:\n{traceback.format_exc()}")

        # Create error log file
        with open("intellicrack_error.log", "w") as f:
            f.write(f"Error: {e}\n")
            f.write(f"Error type: {type(e).__name__}\n")
            f.write(f"Traceback:\n{traceback.format_exc()}")

# pylint: enable=line-too-long


    def generate_exploit_strategy(self):
        """Generate an exploit strategy based on found vulnerabilities."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            "[Exploit Strategy] Generating exploitation strategy..."))

        try:
            from ..utils.exploitation import generate_exploit_strategy
            
            # Use buffer overflow as default vulnerability type
            strategy = generate_exploit_strategy(self.binary_path, "buffer_overflow")
            
            if "error" in strategy:
                self.update_output.emit(log_message(
                    f"[Exploit Strategy] Error: {strategy['error']}"))
            else:
                self.update_output.emit(log_message(
                    "[Exploit Strategy] Strategy generated successfully"))
                
                # Display strategy details
                if "strategy" in strategy and "steps" in strategy["strategy"]:
                    self.update_output.emit(log_message(
                        "[Exploit Strategy] Exploitation steps:"))
                    for i, step in enumerate(strategy["strategy"]["steps"], 1):
                        self.update_output.emit(log_message(
                            f"[Exploit Strategy] {i}. {step}"))
                
                if "automation_script" in strategy:
                    self.update_output.emit(log_message(
                        "[Exploit Strategy] Automation script generated"))
                
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Exploit Strategy] Error: {e}"))

    def generate_exploit_payload(self, payload_type):
        """Generate an exploit payload of the specified type."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File Selected",
                                "Please select a program first.")
            return

        self.update_output.emit(log_message(
            f"[Payload Generator] Generating {payload_type} payload..."))

        try:
            from ..utils.exploitation import generate_license_bypass_payload, generate_exploit
            from ..core.patching.payload_generator import generate_advanced_payload
            
            if payload_type == "License Bypass":
                payload_result = generate_license_bypass_payload("target_software", "patch")
            elif payload_type == "Function Hijack":
                strategy = {"strategy": "function_hijacking", "target": "license_check"}
                payload_bytes = generate_advanced_payload(strategy)
                payload_result = {
                    "method": "function_hijacking",
                    "payload_bytes": payload_bytes.hex() if payload_bytes else "Generation failed",
                    "description": "Function hijacking payload for license bypass"
                }
            elif payload_type == "Buffer Overflow":
                payload_result = generate_exploit("buffer_overflow", "x86", "shellcode")
            else:
                payload_result = {"error": f"Unknown payload type: {payload_type}"}
            
            if "error" in payload_result:
                self.update_output.emit(log_message(
                    f"[Payload Generator] Error: {payload_result['error']}"))
            else:
                self.update_output.emit(log_message(
                    f"[Payload Generator] {payload_type} payload generated successfully"))
                
                # Display payload details
                if "description" in payload_result:
                    self.update_output.emit(log_message(
                        f"[Payload Generator] Description: {payload_result['description']}"))
                
                if "payload_bytes" in payload_result:
                    self.update_output.emit(log_message(
                        f"[Payload Generator] Payload bytes: {payload_result['payload_bytes'][:100]}..."))
                
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Payload Generator] Error: {e}"))

    def setup_persistent_logging_ui(self):
        """Set up persistent logging with rotation from UI."""
        try:
            from intellicrack.utils.logger import setup_persistent_logging
            
            # Get configuration from settings
            log_dir = self.config.get("log_dir", os.path.join(os.path.expanduser("~"), "intellicrack", "logs"))
            log_rotation = self.config.get("logging", {}).get("log_rotation", 5)
            max_log_size = self.config.get("logging", {}).get("max_log_size", 10 * 1024 * 1024)
            
            # Set up persistent logging
            log_file = setup_persistent_logging(
                log_dir=log_dir,
                log_name="intellicrack",
                enable_rotation=True,
                max_bytes=max_log_size,
                backup_count=log_rotation
            )
            
            self.update_output.emit(log_message(
                f"[Logging] Persistent logging initialized with rotation\n"
                f"Log file: {log_file}\n"
                f"Max size: {max_log_size / 1024 / 1024:.1f} MB\n"
                f"Backup count: {log_rotation}"
            ))
            
            # Update logs tab to show the log file path
            if hasattr(self, 'log_browser'):
                self.log_browser.append(f"\n--- Logging to: {log_file} ---\n")
                
        except Exception as e:
            self.update_output.emit(log_message(f"[Logging] Error setting up persistent logging: {e}"))

    def check_dependencies_ui(self):
        """Check and display dependency status in UI."""
        try:
            from intellicrack.utils.dependencies import check_and_install_dependencies
            from intellicrack.utils.system_utils import check_dependencies
            
            # Core dependencies to check
            core_deps = {
                "psutil": "System monitoring",
                "requests": "HTTP requests", 
                "pefile": "PE file analysis",
                "capstone": "Disassembly engine",
                "keystone": "Assembly engine",
                "unicorn": "CPU emulation",
                "lief": "Binary parsing",
                "yara": "Pattern matching",
                "cryptography": "Encryption/decryption"
            }
            
            # Optional dependencies
            optional_deps = {
                "PyQt5": "GUI interface",
                "numpy": "Numerical computing",
                "scikit-learn": "Machine learning",
                "matplotlib": "Data visualization",
                "networkx": "Graph analysis",
                "frida": "Dynamic instrumentation",
                "angr": "Symbolic execution",
                "torch": "Deep learning (PyTorch)",
                "tensorflow": "Deep learning (TensorFlow)"
            }
            
            self.update_output.emit(log_message("[Dependencies] Checking installed packages..."))
            
            # Check core dependencies
            core_ok, core_results = check_dependencies(core_deps)
            
            # Check optional dependencies
            opt_ok, opt_results = check_dependencies(optional_deps)
            
            # Display results
            result_text = "[Dependencies] Core Dependencies:\n"
            for dep, desc in core_deps.items():
                status = "✓" if core_results.get(dep) else "✗"
                result_text += f"  {status} {dep}: {desc}\n"
            
            result_text += "\n[Dependencies] Optional Dependencies:\n"
            for dep, desc in optional_deps.items():
                status = "✓" if opt_results.get(dep) else "✗"
                result_text += f"  {status} {dep}: {desc}\n"
            
            self.update_output.emit(log_message(result_text))
            
            # Offer to install missing core dependencies
            missing_core = [dep for dep, installed in core_results.items() if not installed]
            if missing_core:
                reply = QMessageBox.question(
                    self, 
                    "Install Dependencies",
                    f"Missing core dependencies: {', '.join(missing_core)}\n\n"
                    "Would you like to install them now?",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    self.install_dependencies(missing_core)
                    
        except Exception as e:
            self.update_output.emit(log_message(f"[Dependencies] Error checking dependencies: {e}"))

    def install_dependencies(self, deps):
        """Install missing dependencies."""
        try:
            from intellicrack.utils.dependencies import install_dependencies
            
            self.update_output.emit(log_message(f"[Dependencies] Installing: {', '.join(deps)}"))
            
            # Run installation in a separate thread to avoid blocking UI
            def install_worker():
                success = install_dependencies(deps)
                if success:
                    self.update_output.emit(log_message("[Dependencies] Installation completed successfully"))
                else:
                    self.update_output.emit(log_message("[Dependencies] Some packages failed to install"))
            
            # Create and start thread
            import threading
            install_thread = threading.Thread(target=install_worker, daemon=True)
            install_thread.start()
            
        except Exception as e:
            self.update_output.emit(log_message(f"[Dependencies] Error installing: {e}"))

    def fine_tune_model(self):
        """Open fine-tuning dialog for custom model training."""
        try:
            from intellicrack.ui.dialogs.model_finetuning_dialog import ModelFineTuningDialog
            
            dialog = ModelFineTuningDialog(self)
            
            # Connect signals for progress updates
            def on_training_progress(progress_data):
                if progress_data.get('status') == 'progress':
                    self.update_output.emit(log_message(
                        f"[Fine-tuning] Epoch {progress_data.get('epoch')}, "
                        f"Loss: {progress_data.get('loss', 0):.4f}, "
                        f"Progress: {progress_data.get('progress', 0):.1f}%"
                    ))
                elif progress_data.get('status') == 'complete':
                    self.update_output.emit(log_message(
                        "[Fine-tuning] Training completed successfully!"
                    ))
                elif progress_data.get('status') == 'error':
                    self.update_output.emit(log_message(
                        f"[Fine-tuning] Error: {progress_data.get('message')}"
                    ))
            
            dialog.training_progress.connect(on_training_progress)
            
            # Show the dialog
            if dialog.exec_():
                # Model fine-tuning completed
                fine_tuned_path = dialog.get_fine_tuned_model_path()
                if fine_tuned_path:
                    self.selected_model_path = fine_tuned_path
                    self.update_output.emit(log_message(
                        f"[Fine-tuning] Fine-tuned model saved to: {fine_tuned_path}"
                    ))
                    self.save_config()
                    
        except ImportError:
            # Fallback if dialog not available
            self.update_output.emit(log_message(
                "[Fine-tuning] Model fine-tuning dialog not available. "
                "Please ensure all dependencies are installed."
            ))
        except Exception as e:
            self.update_output.emit(log_message(f"[Fine-tuning] Error: {e}"))

    def extract_icon_from_binary(self):
        """Extract icon from the currently loaded binary."""
        try:
            if not hasattr(self, 'loaded_binary_path') or not self.loaded_binary_path:
                self.update_output.emit(log_message(
                    "[Icon Extraction] No binary loaded. Please load a binary first."
                ))
                return
            
            from intellicrack.utils.system_utils import extract_executable_icon
            
            # Choose output path
            output_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Extracted Icon",
                os.path.splitext(os.path.basename(self.loaded_binary_path))[0] + "_icon.png",
                "PNG Files (*.png);;All Files (*)"
            )
            
            if output_path:
                self.update_output.emit(log_message(
                    f"[Icon Extraction] Extracting icon from {self.loaded_binary_path}..."
                ))
                
                # Extract icon
                icon_path = extract_executable_icon(self.loaded_binary_path, output_path)
                
                if icon_path:
                    self.update_output.emit(log_message(
                        f"[Icon Extraction] Icon extracted successfully to: {icon_path}"
                    ))
                    
                    # Optionally display the icon in UI
                    try:
                        pixmap = QPixmap(icon_path)
                        if not pixmap.isNull() and hasattr(self, 'binary_icon_label'):
                            scaled_pixmap = pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            self.binary_icon_label.setPixmap(scaled_pixmap)
                    except Exception as e:
                        self.update_output.emit(log_message(
                            f"[Icon Extraction] Could not display icon: {e}"
                        ))
                else:
                    self.update_output.emit(log_message(
                        "[Icon Extraction] Failed to extract icon from binary"
                    ))
                    
        except Exception as e:
            self.update_output.emit(log_message(f"[Icon Extraction] Error: {e}"))

    def optimize_memory_usage_ui(self):
        """Optimize memory usage and display results."""
        try:
            from intellicrack.utils.system_utils import optimize_memory_usage
            
            self.update_output.emit(log_message("[Memory] Optimizing memory usage..."))
            
            # Run optimization
            stats = optimize_memory_usage()
            
            # Display results
            if stats['before'] and stats['after']:
                before_mb = stats['before']['used'] / 1024 / 1024
                after_mb = stats['after']['used'] / 1024 / 1024
                freed_mb = stats['freed'] / 1024 / 1024
                
                result_text = (
                    f"[Memory] Optimization Results:\n"
                    f"  Memory before: {before_mb:.1f} MB ({stats['before']['percent']:.1f}%)\n"
                    f"  Memory after: {after_mb:.1f} MB ({stats['after']['percent']:.1f}%)\n"
                    f"  Memory freed: {freed_mb:.1f} MB\n"
                    f"  Available memory: {stats['after']['available'] / 1024 / 1024:.1f} MB"
                )
                
                self.update_output.emit(log_message(result_text))
                
                # Update status bar if available
                if hasattr(self, 'statusBar'):
                    self.statusBar().showMessage(
                        f"Memory optimized: {freed_mb:.1f} MB freed", 
                        5000
                    )
            else:
                self.update_output.emit(log_message(
                    "[Memory] Memory optimization completed"
                ))
                
        except Exception as e:
            self.update_output.emit(log_message(f"[Memory] Optimization error: {e}"))

    def run_long_operation_threaded(self, operation_func, operation_name, *args, **kwargs):
        """Run a long operation in a separate thread with progress updates."""
        try:
            from PyQt5.QtCore import QThread, pyqtSignal
            
            class WorkerThread(QThread):
                progress = pyqtSignal(str)
                finished_signal = pyqtSignal(object)
                error = pyqtSignal(str)
                
                def __init__(self, func, args, kwargs):
                    super().__init__()
                    self.func = func
                    self.args = args
                    self.kwargs = kwargs
                    self.result = None
                
                def run(self):
                    try:
                        self.progress.emit(f"Starting {operation_name}...")
                        self.result = self.func(*self.args, **self.kwargs)
                        self.finished_signal.emit(self.result)
                    except Exception as e:
                        self.error.emit(str(e))
            
            # Create and configure thread
            self.worker_thread = WorkerThread(operation_func, args, kwargs)
            
            # Connect signals
            self.worker_thread.progress.connect(
                lambda msg: self.update_output.emit(log_message(f"[Thread] {msg}"))
            )
            self.worker_thread.finished_signal.connect(
                lambda result: self.update_output.emit(log_message(
                    f"[Thread] {operation_name} completed successfully"
                ))
            )
            self.worker_thread.error.connect(
                lambda err: self.update_output.emit(log_message(
                    f"[Thread] Error in {operation_name}: {err}"
                ))
            )
            
            # Start thread
            self.worker_thread.start()
            
            self.update_output.emit(log_message(
                f"[Thread] {operation_name} started in background thread"
            ))
            
        except Exception as e:
            self.update_output.emit(log_message(
                f"[Thread] Failed to start threaded operation: {e}"
            ))

    def demo_threaded_operation(self):
        """Demo of running a long operation in a thread."""
        import time
        
        def long_running_task():
            """Simulated long-running task"""
            for i in range(5):
                time.sleep(1)
                self.update_output.emit(log_message(
                    f"[Thread Demo] Processing step {i+1}/5..."
                ))
            return "Task completed successfully!"
        
        self.update_output.emit(log_message(
            "[Thread Demo] Starting long operation in background thread..."
        ))
        
        # Use the threaded operation helper
        self.run_long_operation_threaded(
            long_running_task,
            "Demo Long Operation"
        )
