"""
Intellicrack Utils Package

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging

# Set up package logger
_init_logger = logging.getLogger(__name__)

# Import utility modules with error handling
try:
    from .binary.binary_utils import (
        analyze_binary_format,
        check_suspicious_pe_sections,
        compute_file_hash,
        get_file_entropy,
        get_file_hash,
        is_binary_file,
        read_binary,
        validate_binary_path,
        write_binary,
    )
except ImportError as e:
    _init_logger.warning("Failed to import binary_utils: %s", e)

try:
    from .logger import get_logger, logger, setup_logging
except ImportError as e:
    _init_logger.warning("Failed to import logger: %s", e)

try:
    from .core.misc_utils import (
        ensure_directory_exists,
        format_bytes,
        get_file_extension,
        get_timestamp,
        log_message,
        parse_size_string,
        safe_str,
        sanitize_filename,
        truncate_string,
        validate_path,
    )
except ImportError as e:
    _init_logger.warning("Failed to import misc_utils: %s", e)

try:
    from .patching.patch_utils import (
        apply_patch,
        convert_rva_to_offset,
        create_nop_patch,
        create_patch,
        get_section_info,
        parse_patch_instructions,
        validate_patch,
    )
except ImportError as e:
    _init_logger.warning("Failed to import patch_utils: %s", e)

try:
    from .protection.protection_utils import (
        analyze_protection,
        bypass_protection,
        detect_packing,
        detect_protection,
        inject_comprehensive_api_hooks,
    )
except ImportError as e:
    _init_logger.warning("Failed to import protection_utils: %s", e)

try:
    from .reporting.report_generator import ReportGenerator, export_report, generate_report
except ImportError as e:
    _init_logger.warning("Failed to import report_generator: %s", e)

try:
    from .system.system_utils import (
        check_admin_privileges,
        extract_executable_icon,
        get_process_list,
        get_system_info,
        get_target_process_pid,
    )
except ImportError as e:
    _init_logger.warning("Failed to import system_utils: %s", e)

try:
    from .ui.ui_utils import (
        format_table_data,
        get_user_input,
        select_from_list,
        show_message,
        update_progress,
    )
except ImportError as e:
    _init_logger.warning("Failed to import ui_utils: %s", e)

try:
    from .dependencies import (
        check_and_install_dependencies,
        check_weasyprint_dependencies,
        install_dependencies,
        setup_required_environment,
    )
except ImportError as e:
    _init_logger.warning("Failed to import dependencies: %s", e)

try:
    from .analysis.entropy_utils import (
        analyze_entropy_sections,
        calculate_byte_entropy,
        calculate_entropy,
        calculate_frequency_distribution,
        calculate_string_entropy,
        is_high_entropy,
    )
except ImportError as e:
    _init_logger.warning("Failed to import entropy_utils: %s", e)

try:
    from .tools.tool_wrappers import log_message as tool_log_message
    from .tools.tool_wrappers import (
        run_ghidra_headless,
        wrapper_deep_license_analysis,
        wrapper_detect_protections,
        wrapper_disassemble_address,
        wrapper_find_file,
        wrapper_get_file_metadata,
        wrapper_list_relevant_files,
        wrapper_load_binary,
        wrapper_read_file_chunk,
        wrapper_run_static_analysis,
    )
except ImportError as e:
    _init_logger.warning("Failed to import tool_wrappers: %s", e)

try:
    from .runtime.runner_functions import (
        process_ghidra_analysis_results,
        run_advanced_ghidra_analysis,
        run_ai_guided_patching,
        run_autonomous_patching,
        run_cfg_explorer,
        run_cloud_license_hooker,
        run_comprehensive_analysis,
        run_concolic_execution,
        run_deep_license_analysis,
        run_distributed_processing,
        run_dynamic_instrumentation,
        run_enhanced_protection_scan,
        run_frida_analysis,
        run_frida_script,
        run_ghidra_analysis,
        run_ghidra_analysis_gui,
        run_ghidra_plugin_from_file,
        run_gpu_accelerated_analysis,
        run_incremental_analysis,
        run_memory_analysis,
        run_memory_optimized_analysis,
        run_multi_format_analysis,
        run_network_analysis,
        run_network_license_server,
        run_protocol_fingerprinter,
        run_qemu_analysis,
        run_qiling_emulation,
        run_radare2_analysis,
        run_rop_chain_generator,
        run_selected_analysis,
        run_selected_patching,
        run_ssl_tls_interceptor,
        run_symbolic_execution,
        run_taint_analysis,
        run_visual_network_traffic_analyzer,
    )
except ImportError as e:
    _init_logger.warning("Failed to import runner_functions: %s", e)

try:
    from .core.exception_utils import (
        create_sample_plugins,
        handle_exception,
        load_ai_model,
        load_config,
        save_config,
        setup_file_logging,
    )
except ImportError as e:
    _init_logger.warning("Failed to import exception_utils: %s", e)

try:
    from .protection.protection_detection import (
        detect_anti_debugging_techniques,
        detect_commercial_protections,
        detect_virtualization_protection,
        scan_for_bytecode_protectors,
    )
except ImportError as e:
    _init_logger.warning("Failed to import protection_detection: %s", e)

try:
    from .system.process_utils import (
        compute_file_hash,
        detect_hardware_dongles,
        detect_tpm_protection,
        get_system_processes,
        get_target_process_pid,
        run_command,
    )
except ImportError as e:
    _init_logger.warning("Failed to import process_utils: %s", e)

try:
    from .patching.patch_verification import (
        apply_parsed_patch_instructions_with_validation,
        rewrite_license_functions_with_parsing,
        simulate_patch_and_verify,
        verify_patches,
    )
except ImportError as e:
    _init_logger.warning("Failed to import patch_verification: %s", e)

try:
    from .analysis.binary_analysis import (
        analyze_binary,
        analyze_binary_optimized,
        analyze_elf,
        analyze_macho,
        analyze_patterns,
        analyze_pe,
        analyze_traffic,
        extract_binary_features,
        extract_patterns_from_binary,
        identify_binary_format,
        scan_binary,
    )
except ImportError as e:
    _init_logger.warning("Failed to import binary_analysis: %s", e)

try:
    from .analysis.security_analysis import (
        bypass_tpm_checks,
        check_buffer_overflow,
        check_for_memory_leaks,
        check_memory_usage,
        run_tpm_bypass,
        run_vm_bypass,
        scan_protectors,
    )
except ImportError as e:
    _init_logger.warning("Failed to import security_analysis: %s", e)

try:
    from .exploitation.exploitation import (
        generate_bypass_script,
        generate_ca_certificate,
        generate_chains,
        generate_exploit,
        generate_exploit_strategy,
        generate_key,
        generate_license_bypass_payload,
        generate_response,
        patch_selected,
        run_automated_patch_agent,
        run_simulate_patch,
    )
except ImportError as e:
    _init_logger.warning("Failed to import exploitation: %s", e)

try:
    from .runtime.distributed_processing import (
        extract_binary_info,
        process_binary_chunks,
        process_chunk,
        process_distributed_results,
        run_distributed_analysis,
        run_distributed_entropy_analysis,
        run_distributed_pattern_search,
        run_gpu_accelerator,
        run_incremental_analysis,
        run_memory_optimized_analysis,
        run_pdf_report_generator,
    )
except ImportError as e:
    _init_logger.warning("Failed to import distributed_processing: %s", e)

try:
    from .runtime.additional_runners import (
        check_adobe_licensex_status,
        compute_file_hash,
        create_sample_plugins,
        get_target_process_pid,
        load_ai_model,
        run_adobe_licensex_manually,
        run_analysis,
        run_autonomous_crack,
        run_comprehensive_analysis,
        run_deep_cfg_analysis,
        run_deep_license_analysis,
        run_detect_packing,
        run_external_command,
        run_external_tool,
        run_full_autonomous_mode,
        run_ghidra_analysis_gui,
        run_incremental_analysis_ui,
        run_windows_activator,
        validate_dataset,
        verify_hash,
    )
except ImportError as e:
    _init_logger.warning("Failed to import additional_runners: %s", e)

try:
    from .system.os_detection_mixin import OSDetectionMixin
except ImportError as e:
    _init_logger.warning("Failed to import os_detection_mixin: %s", e)

try:
    from .core.core_utilities import (
        TOOL_REGISTRY,
        deep_runtime_monitoring,
        dispatch_tool,
        main,
        on_message,
        register,
        register_default_tools,
        register_tool,
        retrieve_few_shot_examples,
        run_cli_mode,
        run_gui_mode,
    )
except ImportError as e:
    _init_logger.warning("Failed to import core_utilities: %s", e)

try:
    from .core.final_utilities import (
        accelerate_hash_calculation,
        add_code_snippet,
        add_dataset_row,
        add_image,
        add_recommendations,
        add_table,
        async_wrapper,
        augment_dataset,
        browse_dataset,
        browse_model,
        cache_analysis_results,
        center_on_screen,
        compute_binary_hash,
        compute_section_hashes,
        copy_to_clipboard,
        create_dataset,
        create_full_feature_model,
        do_GET,
        export_metrics,
        force_memory_cleanup,
        get_captured_requests,
        get_file_icon,
        get_resource_type,
        hash_func,
        identify_changed_sections,
        initialize_memory_optimizer,
        load_dataset_preview,
        monitor_memory,
        on_training_finished,
        patches_reordered,
        predict_vulnerabilities,
        sandbox_process,
        select_backend_for_workload,
        show_simulation_results,
        showEvent,
        start_training,
        stop_training,
        submit_report,
        truncate_text,
        update_training_progress,
        update_visualization,
    )
except ImportError as e:
    _init_logger.warning("Failed to import final_utilities: %s", e)

# internal_helpers imports are already included earlier in the file

try:
    from .ui.ui_setup_functions import setup_dataset_tab, setup_memory_monitor, setup_training_tab
except ImportError as e:
    _init_logger.warning("Failed to import ui_setup_functions: %s", e)

try:
    from .tools.pcapy_compat import PCAP_AVAILABLE, create_pcap_reader, get_packet_capture_interface
except ImportError as e:
    _init_logger.warning("Failed to import pcapy_compat: %s", e)

try:
    from .core.internal_helpers import (
        _add_protocol_fingerprinter_results,
        _analyze_requests,
        _analyze_snapshot_differences,
        _generate_mitm_script,
        _get_filesystem_state,
        _get_memory_regions,
        _get_network_state,
        _get_process_state,
        _handle_request,
        _perform_augmentation,
        _run_autonomous_patching_thread,
        _run_ghidra_thread,
        _run_report_generation_thread,
    )
except ImportError as e:
    _init_logger.warning("Failed to import internal_helpers functions: %s", e)

# Import path discovery functions
try:
    from .core.path_discovery import (
        PathDiscovery,
        ensure_tool_available,
        find_tool,
        get_path_discovery,
        get_system_path,
    )
except ImportError as e:
    _init_logger.warning("Failed to import path_discovery functions: %s", e)

# Import GPU autoloader functions
try:
    from .gpu_autoloader import (
        get_device,
        get_gpu_info,
        gpu_autoloader,
        optimize_for_gpu,
        to_device,
    )
except ImportError as e:
    _init_logger.warning("Failed to import gpu_autoloader functions: %s", e)

# Import exploit common functions
try:
    from .exploitation.exploit_common import (
        create_analysis_button,
        handle_exploit_payload_generation,
        handle_exploit_strategy_generation,
    )
except ImportError as e:
    _init_logger.warning("Failed to import exploit_common functions: %s", e)

# Import UI button common functions
try:
    from .ui.ui_button_common import add_extra_buttons, get_button_style
except ImportError as e:
    _init_logger.warning("Failed to import ui_button_common functions: %s", e)

# Import network API common functions
try:
    from .templates.network_api_common import (
        analyze_network_apis,
        get_network_api_categories,
        summarize_network_capabilities,
    )
except ImportError as e:
    _init_logger.warning("Failed to import network_api_common functions: %s", e)

# Import common utility modules
try:
    from .system.windows_common import (
        WINDOWS_AVAILABLE,
        WindowsConstants,
        get_windows_kernel32,
        get_windows_ntdll,
        is_windows_available,
    )
except ImportError as e:
    _init_logger.warning("Failed to import windows_common functions: %s", e)

try:
    from .binary.pe_analysis_common import analyze_pe_imports, get_pe_sections_info
except ImportError as e:
    _init_logger.warning("Failed to import pe_analysis_common functions: %s", e)

try:
    from .system.process_common import create_popen_safely, run_subprocess_safely
except ImportError as e:
    _init_logger.warning("Failed to import process_common functions: %s", e)

try:
    from .protection.certificate_common import create_certificate_builder
except ImportError as e:
    _init_logger.warning("Failed to import certificate_common functions: %s", e)

try:
    from .analysis.pattern_search import (
        find_function_prologues,
        find_license_patterns,
        search_patterns_in_binary,
    )
except ImportError as e:
    _init_logger.warning("Failed to import pattern_search functions: %s", e)

try:
    from .analysis.severity_levels import (
        SecurityRelevance,
        SeverityLevel,
        VulnerabilityLevel,
    )
except ImportError as e:
    _init_logger.warning("Failed to import severity_levels: %s", e)

__all__ = [
    # From binary_utils
    'compute_file_hash', 'get_file_hash', 'read_binary',
    'write_binary', 'analyze_binary_format', 'is_binary_file',
    'get_file_entropy', 'check_suspicious_pe_sections', 'validate_binary_path',

    # From logger
    'get_logger', 'setup_logging', 'logger',

    # From os_detection_mixin
    'OSDetectionMixin',

    # From misc_utils
    'log_message', 'get_timestamp', 'format_bytes', 'validate_path',
    'sanitize_filename', 'truncate_string', 'safe_str', 'parse_size_string',
    'get_file_extension', 'ensure_directory_exists',

    # From patch_utils
    'parse_patch_instructions', 'create_patch', 'apply_patch',
    'validate_patch', 'convert_rva_to_offset', 'get_section_info',
    'create_nop_patch',

    # From protection_utils
    'detect_packing', 'inject_comprehensive_api_hooks',
    'detect_protection', 'analyze_protection', 'bypass_protection',

    # From report_generator
    'ReportGenerator', 'generate_report', 'export_report',

    # From system_utils
    'get_system_info', 'check_admin_privileges', 'get_process_list',
    'extract_executable_icon', 'get_target_process_pid',

    # From ui_utils
    'format_table_data', 'select_from_list', 'show_message',
    'get_user_input', 'update_progress',

    # From dependencies
    'check_and_install_dependencies', 'install_dependencies',
    'setup_required_environment', 'check_weasyprint_dependencies',

    # From entropy_utils
    'calculate_entropy', 'calculate_byte_entropy', 'calculate_string_entropy',
    'calculate_frequency_distribution', 'is_high_entropy', 'analyze_entropy_sections',

    # From tool_wrappers
    'tool_log_message', 'wrapper_find_file', 'wrapper_load_binary',
    'wrapper_list_relevant_files', 'wrapper_read_file_chunk', 'wrapper_get_file_metadata',
    'wrapper_run_static_analysis', 'wrapper_deep_license_analysis', 'wrapper_detect_protections',
    'wrapper_disassemble_address', 'run_ghidra_headless',

    # From runner_functions
    'run_network_license_server', 'run_ssl_tls_interceptor', 'run_protocol_fingerprinter',
    'run_cloud_license_hooker', 'run_cfg_explorer', 'run_concolic_execution',
    'run_enhanced_protection_scan', 'run_visual_network_traffic_analyzer',
    'run_multi_format_analysis', 'run_distributed_processing', 'run_gpu_accelerated_analysis',
    'run_ai_guided_patching', 'run_advanced_ghidra_analysis', 'run_ghidra_plugin_from_file',
    'process_ghidra_analysis_results', 'run_symbolic_execution', 'run_incremental_analysis',
    'run_memory_optimized_analysis', 'run_taint_analysis', 'run_rop_chain_generator',
    'run_qemu_analysis', 'run_qiling_emulation', 'run_selected_analysis',
    'run_selected_patching', 'run_memory_analysis', 'run_network_analysis',
    'run_frida_analysis', 'run_dynamic_instrumentation',
    'run_frida_script', 'run_comprehensive_analysis', 'run_ghidra_analysis',
    'run_radare2_analysis', 'run_autonomous_patching', 'run_ghidra_analysis_gui',

    # From exception_utils
    'handle_exception', 'load_config', 'save_config',
    'setup_file_logging', 'create_sample_plugins', 'load_ai_model',

    # From protection_detection
    'detect_anti_debugging_techniques', 'detect_commercial_protections',
    'detect_virtualization_protection', 'scan_for_bytecode_protectors',

    # From process_utils
    'detect_hardware_dongles',
    'detect_tpm_protection', 'get_system_processes', 'run_command',

    # From patch_verification
    'verify_patches', 'simulate_patch_and_verify',
    'apply_parsed_patch_instructions_with_validation',
    'rewrite_license_functions_with_parsing',

    # From binary_analysis
    'analyze_binary', 'analyze_binary_optimized', 'identify_binary_format',
    'analyze_pe', 'analyze_elf', 'analyze_macho', 'analyze_patterns',
    'analyze_traffic', 'scan_binary', 'extract_patterns_from_binary',
    'extract_binary_features',

    # From security_analysis
    'scan_protectors', 'bypass_tpm_checks', 'check_memory_usage',
    'check_for_memory_leaks', 'check_buffer_overflow', 'run_tpm_bypass',
    'run_vm_bypass',

    # From exploitation
    'generate_bypass_script', 'generate_exploit', 'generate_exploit_strategy',
    'generate_license_bypass_payload', 'generate_ca_certificate', 'generate_key',
    'generate_chains', 'generate_response', 'patch_selected', 'run_automated_patch_agent',
    'run_simulate_patch',

    # From distributed_processing
    'process_binary_chunks', 'process_chunk', 'process_distributed_results',
    'run_distributed_analysis', 'run_distributed_entropy_analysis',
    'run_distributed_pattern_search', 'extract_binary_info',
    'run_gpu_accelerator',
    'run_pdf_report_generator',

    # From additional_runners
    'run_detect_packing',
    'run_analysis', 'run_autonomous_crack', 'run_full_autonomous_mode',
    'run_incremental_analysis_ui', 'run_deep_cfg_analysis',
    'run_external_tool', 'run_windows_activator', 'check_adobe_licensex_status',
    'run_adobe_licensex_manually', 'validate_dataset', 'verify_hash',
    'run_external_command',

    # From core_utilities
    'main', 'dispatch_tool', 'register_tool', 'register_default_tools',
    'on_message', 'register', 'retrieve_few_shot_examples', 'deep_runtime_monitoring',
    'run_gui_mode', 'run_cli_mode', 'TOOL_REGISTRY',

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

    # From pcapy_compat
    'get_packet_capture_interface', 'create_pcap_reader', 'PCAP_AVAILABLE',

    # From internal_helpers
    '_add_protocol_fingerprinter_results', '_analyze_requests',
    '_analyze_snapshot_differences', '_handle_request',
    '_get_filesystem_state', '_get_memory_regions',
    '_get_network_state', '_get_process_state',
    '_generate_mitm_script', '_perform_augmentation',
    '_run_autonomous_patching_thread', '_run_ghidra_thread',
    '_run_report_generation_thread',

    # From path_discovery
    'find_tool',
    'get_system_path',
    'ensure_tool_available',
    'PathDiscovery',
    'get_path_discovery',

    # From exploit_common
    'handle_exploit_strategy_generation',
    'handle_exploit_payload_generation',
    'create_analysis_button',

    # From ui_button_common
    'add_extra_buttons',
    'get_button_style',

    # From network_api_common
    'analyze_network_apis',
    'get_network_api_categories',
    'summarize_network_capabilities',

    # From windows_common
    'is_windows_available',
    'get_windows_kernel32',
    'get_windows_ntdll',
    'WindowsConstants',
    'WINDOWS_AVAILABLE',

    # From pe_analysis_common
    'analyze_pe_imports',
    'get_pe_sections_info',

    # From process_common
    'run_subprocess_safely',
    'create_popen_safely',

    # From certificate_common
    'create_certificate_builder',

    # From pattern_search
    'search_patterns_in_binary',
    'find_function_prologues',
    'find_license_patterns',

    # From severity_levels
    'SeverityLevel',
    'SecurityRelevance',
    'VulnerabilityLevel',

    # From gpu_autoloader
    'gpu_autoloader',
    'get_device',
    'get_gpu_info',
    'to_device',
    'optimize_for_gpu',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
