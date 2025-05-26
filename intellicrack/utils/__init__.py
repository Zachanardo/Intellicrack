"""
Intellicrack Utils Package

This package provides utility functions and helper modules for the Intellicrack framework.
It includes tools for binary manipulation, logging, patching, protection analysis, reporting,
system operations, and UI utilities.

Modules:
    - binary_utils: Binary file manipulation and analysis utilities
    - logger: Logging configuration and management
    - misc_utils: Miscellaneous utility functions
    - patch_utils: Patching and modification utilities
    - protection_utils: Protection mechanism analysis utilities
    - report_generator: Report generation utilities
    - system_utils: System-level operations and helpers
    - ui_utils: User interface utility functions

Key Features:
    - Binary file operations
    - Comprehensive logging system
    - Cross-platform compatibility
    - Protection analysis helpers
    - Report generation tools
    - System interaction utilities
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import utility modules with error handling
try:
    from .binary_utils import *
except ImportError as e:
    logger.warning(f"Failed to import binary_utils: {e}")

try:
    from .logger import *
except ImportError as e:
    logger.warning(f"Failed to import logger: {e}")

try:
    from .misc_utils import *
except ImportError as e:
    logger.warning(f"Failed to import misc_utils: {e}")

try:
    from .patch_utils import *
except ImportError as e:
    logger.warning(f"Failed to import patch_utils: {e}")

try:
    from .protection_utils import *
except ImportError as e:
    logger.warning(f"Failed to import protection_utils: {e}")

try:
    from .report_generator import *
except ImportError as e:
    logger.warning(f"Failed to import report_generator: {e}")

try:
    from .system_utils import *
except ImportError as e:
    logger.warning(f"Failed to import system_utils: {e}")

try:
    from .ui_utils import *
except ImportError as e:
    logger.warning(f"Failed to import ui_utils: {e}")

try:
    from .dependencies import *
except ImportError as e:
    logger.warning(f"Failed to import dependencies: {e}")

try:
    from .tool_wrappers import *
except ImportError as e:
    logger.warning(f"Failed to import tool_wrappers: {e}")

try:
    from .runner_functions import *
except ImportError as e:
    logger.warning(f"Failed to import runner_functions: {e}")

try:
    from .exception_utils import *
except ImportError as e:
    logger.warning(f"Failed to import exception_utils: {e}")

try:
    from .protection_detection import *
except ImportError as e:
    logger.warning(f"Failed to import protection_detection: {e}")

try:
    from .process_utils import *
except ImportError as e:
    logger.warning(f"Failed to import process_utils: {e}")

try:
    from .patch_verification import *
except ImportError as e:
    logger.warning(f"Failed to import patch_verification: {e}")

try:
    from .binary_analysis import *
except ImportError as e:
    logger.warning(f"Failed to import binary_analysis: {e}")

try:
    from .security_analysis import *
except ImportError as e:
    logger.warning(f"Failed to import security_analysis: {e}")

try:
    from .exploitation import *
except ImportError as e:
    logger.warning(f"Failed to import exploitation: {e}")

try:
    from .distributed_processing import *
except ImportError as e:
    logger.warning(f"Failed to import distributed_processing: {e}")

try:
    from .additional_runners import *
except ImportError as e:
    logger.warning(f"Failed to import additional_runners: {e}")

try:
    from .core_utilities import *
except ImportError as e:
    logger.warning(f"Failed to import core_utilities: {e}")

try:
    from .final_utilities import *
except ImportError as e:
    logger.warning(f"Failed to import final_utilities: {e}")

try:
    from .internal_helpers import *
except ImportError as e:
    logger.warning(f"Failed to import internal_helpers: {e}")

try:
    from .ui_setup_functions import *
except ImportError as e:
    logger.warning(f"Failed to import ui_setup_functions: {e}")

# Define package exports
__all__ = [
    # From binary_utils
    'read_binary',
    'write_binary',
    'get_file_hash',
    'analyze_binary_format',
    
    # From logger
    'setup_logger',
    'get_logger',
    'configure_logging',
    'log_message',
    
    # From misc_utils
    'format_bytes',
    'get_timestamp',
    'validate_path',
    
    # From patch_utils
    'apply_patch',
    'create_patch',
    'validate_patch',
    
    # From protection_utils
    'detect_protection',
    'analyze_protection',
    'bypass_protection',
    
    # From report_generator
    'generate_report',
    'export_report',
    'format_findings',
    
    # From system_utils
    'get_system_info',
    'check_dependencies',
    'run_command',
    
    # From ui_utils
    'show_message',
    'get_user_input',
    'update_progress',
    
    # From binary_analysis
    'analyze_binary',
    'analyze_pe',
    'analyze_elf',
    'analyze_macho',
    'analyze_patterns',
    'analyze_traffic',
    'scan_binary',
    'extract_binary_features',
    'extract_patterns_from_binary',
    
    # From security_analysis
    'check_buffer_overflow',
    'check_for_memory_leaks',
    'check_memory_usage',
    'bypass_tpm_checks',
    'scan_protectors',
    'run_tpm_bypass',
    'run_vm_bypass',
    
    # From exploitation
    'generate_bypass_script',
    'generate_exploit',
    'generate_exploit_strategy',
    'generate_license_bypass_payload',
    'generate_ca_certificate',
    'generate_key',
    'generate_chains',
    'generate_response',
    'patch_selected',
    'run_automated_patch_agent',
    'run_simulate_patch',
    
    # From distributed_processing
    'process_binary_chunks',
    'process_chunk',
    'process_distributed_results',
    'run_distributed_analysis',
    'run_distributed_entropy_analysis',
    'run_distributed_pattern_search',
    'run_gpu_accelerator',
    'run_incremental_analysis',
    'run_memory_optimized_analysis',
    'run_pdf_report_generator',
    
    # From additional_runners
    'run_comprehensive_analysis',
    'run_deep_license_analysis',
    'run_detect_packing',
    'run_analysis',
    'run_autonomous_crack',
    'run_full_autonomous_mode',
    'run_ghidra_analysis_gui',
    'run_incremental_analysis_ui',
    'run_deep_cfg_analysis',
    'run_external_tool',
    'run_windows_activator',
    'check_adobe_licensex_status',
    'run_adobe_licensex_manually',
    'validate_dataset',
    'verify_hash',
    'run_external_command',
    'compute_file_hash',
    'create_sample_plugins',
    'load_ai_model',
    'get_target_process_pid',
    'detect_hardware_dongles',
    'detect_tpm_protection',
    
    # From core_utilities
    'main',
    'dispatch_tool',
    'register_tool',
    'register_default_tools',
    'on_message',
    'register',
    'retrieve_few_shot_examples',
    'deep_runtime_monitoring',
    'run_gui_mode',
    'run_cli_mode',
    'TOOL_REGISTRY',
    
    # From final_utilities
    'add_table', 'browse_dataset', 'browse_model', 
    'show_simulation_results', 'update_training_progress',
    'update_visualization', 'center_on_screen', 'copy_to_clipboard',
    'showEvent', 'monitor_memory', 'predict_vulnerabilities',
    'accelerate_hash_calculation', 'compute_binary_hash',
    'compute_section_hashes', 'identify_changed_sections',
    'get_file_icon', 'get_resource_type', 'cache_analysis_results',
    'get_captured_requests', 'force_memory_cleanup',
    'initialize_memory_optimizer', 'sandbox_process',
    'select_backend_for_workload', 'truncate_text',
    'async_wrapper', 'hash_func', 'export_metrics', 'submit_report',
    'start_training', 'stop_training', 'on_training_finished',
    'create_dataset', 'augment_dataset', 'load_dataset_preview',
    'create_full_feature_model', 'add_code_snippet', 'add_dataset_row', 
    'add_image', 'add_recommendations', 'patches_reordered', 'do_GET',
    
    # From ui_setup_functions
    'setup_dataset_tab', 'setup_memory_monitor', 'setup_training_tab',
    
    # From internal_helpers (selected important ones)
    '_add_protocol_fingerprinter_results', '_analyze_requests',
    '_analyze_snapshot_differences', '_handle_request',
    '_get_filesystem_state', '_get_memory_regions',
    '_get_network_state', '_get_process_state',
    '_generate_mitm_script', '_perform_augmentation',
    '_run_autonomous_patching_thread', '_run_ghidra_thread',
    '_run_report_generation_thread'
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
