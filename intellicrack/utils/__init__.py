"""Intellicrack Utils Package.

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

import logging


_init_logger = logging.getLogger(__name__)

_lazy_imports = {}

_MOD_BINARY_UTILS = "binary.binary_utils"
_MOD_PATCHING_UTILS = "patching.patch_utils"
_MOD_SYSTEM_UTILS = "system.system_utils"
_MOD_UI_UTILS = "ui.ui_utils"
_MOD_ENTROPY_UTILS = "analysis.entropy_utils"
_MOD_TOOL_WRAPPERS = "tools.tool_wrappers"
_MOD_RUNNER_FUNCTIONS = "runtime.runner_functions"
_MOD_EXCEPTION_UTILS = "core.exception_utils"
_MOD_PROCESS_UTILS = "system.process_utils"
_MOD_PATCH_VERIFICATION = "patching.patch_verification"
_MOD_BINARY_ANALYSIS = "analysis.binary_analysis"
_MOD_SECURITY_ANALYSIS = "analysis.security_analysis"
_MOD_EXPLOITATION = "exploitation.exploitation"
_MOD_DISTRIBUTED_PROCESSING = "runtime.distributed_processing"
_MOD_ADDITIONAL_RUNNERS = "runtime.additional_runners"
_MOD_CORE_UTILITIES = "core.core_utilities"
_MOD_FINAL_UTILITIES = "core.final_utilities"
_MOD_UI_SETUP_FUNCTIONS = "ui.ui_setup_functions"
_MOD_PCAPY_COMPAT = "tools.pcapy_compat"
_MOD_INTERNAL_HELPERS = "core.internal_helpers"
_MOD_PATH_DISCOVERY = "core.path_discovery"
_MOD_NETWORK_API_ANALYSIS = "binary.network_api_analysis"
_MOD_WINDOWS_COMMON = "system.windows_common"
_MOD_PATTERN_SEARCH = "analysis.pattern_search"
_MOD_LOGGER = "logger"
_MOD_PROTECTION_UTILS = "protection_utils"
_MOD_REPORT_GENERATOR = "report_generator"
_MOD_DEPENDENCIES = "dependencies"
_MOD_GPU_AUTOLOADER = "gpu_autoloader"
_MOD_UI_BUTTON_COMMON = "ui.ui_button_common"
_MOD_PE_ANALYSIS_COMMON = "binary.pe_analysis_common"
_MOD_PROCESS_COMMON = "system.process_common"
_MOD_CERTIFICATE_COMMON = "protection.certificate_common"
_MOD_JSON_UTILS = "json_utils"
_MOD_OS_DETECTION_MIXIN = "system.os_detection_mixin"


def __getattr__(name: str) -> object:
    """Lazy load utility module attributes to prevent circular imports.

    This function implements lazy loading for module-level attributes,
    enabling deferred imports of utility functions and classes to avoid
    circular dependency issues within the intellicrack.utils package.

    Args:
        name: The attribute name being accessed on the module.

    Returns:
        The requested module attribute or None if import fails.

    Raises:
        AttributeError: If the requested attribute is not found in the import map.

    """
    if name in _lazy_imports:
        cached_value: object = _lazy_imports[name]
        return cached_value

    import_map = {
        "analyze_binary_format": (_MOD_BINARY_UTILS, "analyze_binary_format"),
        "check_suspicious_pe_sections": (_MOD_BINARY_UTILS, "check_suspicious_pe_sections"),
        "compute_file_hash": (_MOD_BINARY_UTILS, "compute_file_hash"),
        "get_file_entropy": (_MOD_BINARY_UTILS, "get_file_entropy"),
        "get_file_hash": (_MOD_BINARY_UTILS, "get_file_hash"),
        "is_binary_file": (_MOD_BINARY_UTILS, "is_binary_file"),
        "read_binary": (_MOD_BINARY_UTILS, "read_binary"),
        "validate_binary_path": (_MOD_BINARY_UTILS, "validate_binary_path"),
        "write_binary": (_MOD_BINARY_UTILS, "write_binary"),
        "get_logger": (_MOD_LOGGER, "get_logger"),
        "logger": (_MOD_LOGGER, "logger"),
        "setup_logging": (_MOD_LOGGER, "setup_logging"),
        "apply_patch": (_MOD_PATCHING_UTILS, "apply_patch"),
        "convert_rva_to_offset": (_MOD_PATCHING_UTILS, "convert_rva_to_offset"),
        "create_nop_patch": (_MOD_PATCHING_UTILS, "create_nop_patch"),
        "create_patch": (_MOD_PATCHING_UTILS, "create_patch"),
        "get_section_info": (_MOD_PATCHING_UTILS, "get_section_info"),
        "parse_patch_instructions": (_MOD_PATCHING_UTILS, "parse_patch_instructions"),
        "validate_patch": (_MOD_PATCHING_UTILS, "validate_patch"),
        "calculate_entropy": (_MOD_PROTECTION_UTILS, "calculate_entropy"),
        "detect_protection_mechanisms": (_MOD_PROTECTION_UTILS, "detect_protection_mechanisms"),
        "generate_bypass_strategy": (_MOD_PROTECTION_UTILS, "generate_bypass_strategy"),
        "generate_hwid_spoof_config": (_MOD_PROTECTION_UTILS, "generate_hwid_spoof_config"),
        "inject_comprehensive_api_hooks": (_MOD_PROTECTION_UTILS, "inject_comprehensive_api_hooks"),
        "ReportGenerator": (_MOD_REPORT_GENERATOR, "ReportGenerator"),
        "export_report": (_MOD_REPORT_GENERATOR, "export_report"),
        "generate_report": (_MOD_REPORT_GENERATOR, "generate_report"),
        "check_admin_privileges": (_MOD_SYSTEM_UTILS, "check_admin_privileges"),
        "extract_executable_icon": (_MOD_SYSTEM_UTILS, "extract_executable_icon"),
        "get_process_list": (_MOD_SYSTEM_UTILS, "get_process_list"),
        "get_system_info": (_MOD_SYSTEM_UTILS, "get_system_info"),
        "get_target_process_pid": (_MOD_SYSTEM_UTILS, "get_target_process_pid"),
        "format_table_data": (_MOD_UI_UTILS, "format_table_data"),
        "get_user_input": (_MOD_UI_UTILS, "get_user_input"),
        "select_from_list": (_MOD_UI_UTILS, "select_from_list"),
        "show_message": (_MOD_UI_UTILS, "show_message"),
        "update_progress": (_MOD_UI_UTILS, "update_progress"),
        "check_and_install_dependencies": (_MOD_DEPENDENCIES, "check_and_install_dependencies"),
        "check_weasyprint_dependencies": (_MOD_DEPENDENCIES, "check_weasyprint_dependencies"),
        "install_dependencies": (_MOD_DEPENDENCIES, "install_dependencies"),
        "setup_required_environment": (_MOD_DEPENDENCIES, "setup_required_environment"),
        "analyze_entropy_sections": (_MOD_ENTROPY_UTILS, "analyze_entropy_sections"),
        "calculate_byte_entropy": (_MOD_ENTROPY_UTILS, "calculate_byte_entropy"),
        "calculate_frequency_distribution": (
            _MOD_ENTROPY_UTILS,
            "calculate_frequency_distribution",
        ),
        "calculate_string_entropy": (_MOD_ENTROPY_UTILS, "calculate_string_entropy"),
        "is_high_entropy": (_MOD_ENTROPY_UTILS, "is_high_entropy"),
        "tool_log_message": (_MOD_TOOL_WRAPPERS, "log_message"),
        "run_ghidra_headless": (_MOD_TOOL_WRAPPERS, "run_ghidra_headless"),
        "wrapper_deep_license_analysis": (_MOD_TOOL_WRAPPERS, "wrapper_deep_license_analysis"),
        "wrapper_detect_protections": (_MOD_TOOL_WRAPPERS, "wrapper_detect_protections"),
        "wrapper_disassemble_address": (_MOD_TOOL_WRAPPERS, "wrapper_disassemble_address"),
        "wrapper_find_file": (_MOD_TOOL_WRAPPERS, "wrapper_find_file"),
        "wrapper_get_file_metadata": (_MOD_TOOL_WRAPPERS, "wrapper_get_file_metadata"),
        "wrapper_list_relevant_files": (_MOD_TOOL_WRAPPERS, "wrapper_list_relevant_files"),
        "wrapper_load_binary": (_MOD_TOOL_WRAPPERS, "wrapper_load_binary"),
        "wrapper_read_file_chunk": (_MOD_TOOL_WRAPPERS, "wrapper_read_file_chunk"),
        "wrapper_run_static_analysis": (_MOD_TOOL_WRAPPERS, "wrapper_run_static_analysis"),
        "process_ghidra_analysis_results": (
            _MOD_RUNNER_FUNCTIONS,
            "process_ghidra_analysis_results",
        ),
        "run_advanced_ghidra_analysis": (
            _MOD_RUNNER_FUNCTIONS,
            "run_advanced_ghidra_analysis",
        ),
        "run_ai_guided_patching": (_MOD_RUNNER_FUNCTIONS, "run_ai_guided_patching"),
        "run_autonomous_patching": (_MOD_RUNNER_FUNCTIONS, "run_autonomous_patching"),
        "run_cfg_explorer": (_MOD_RUNNER_FUNCTIONS, "run_cfg_explorer"),
        "run_cloud_license_hooker": (_MOD_RUNNER_FUNCTIONS, "run_cloud_license_hooker"),
        "run_comprehensive_analysis": (_MOD_RUNNER_FUNCTIONS, "run_comprehensive_analysis"),
        "run_concolic_execution": (_MOD_RUNNER_FUNCTIONS, "run_concolic_execution"),
        "run_deep_license_analysis": (_MOD_RUNNER_FUNCTIONS, "run_deep_license_analysis"),
        "run_distributed_processing": (_MOD_RUNNER_FUNCTIONS, "run_distributed_processing"),
        "run_dynamic_instrumentation": (_MOD_RUNNER_FUNCTIONS, "run_dynamic_instrumentation"),
        "run_enhanced_protection_scan": (
            _MOD_RUNNER_FUNCTIONS,
            "run_enhanced_protection_scan",
        ),
        "run_frida_analysis": (_MOD_RUNNER_FUNCTIONS, "run_frida_analysis"),
        "run_frida_script": (_MOD_RUNNER_FUNCTIONS, "run_frida_script"),
        "run_ghidra_analysis": (_MOD_RUNNER_FUNCTIONS, "run_ghidra_analysis"),
        "run_ghidra_analysis_gui": (_MOD_RUNNER_FUNCTIONS, "run_ghidra_analysis_gui"),
        "run_ghidra_plugin_from_file": (_MOD_RUNNER_FUNCTIONS, "run_ghidra_plugin_from_file"),
        "run_gpu_accelerated_analysis": (
            _MOD_RUNNER_FUNCTIONS,
            "run_gpu_accelerated_analysis",
        ),
        "run_incremental_analysis": (_MOD_RUNNER_FUNCTIONS, "run_incremental_analysis"),
        "run_memory_analysis": (_MOD_RUNNER_FUNCTIONS, "run_memory_analysis"),
        "run_memory_optimized_analysis": (
            _MOD_RUNNER_FUNCTIONS,
            "run_memory_optimized_analysis",
        ),
        "run_multi_format_analysis": (_MOD_RUNNER_FUNCTIONS, "run_multi_format_analysis"),
        "run_network_analysis": (_MOD_RUNNER_FUNCTIONS, "run_network_analysis"),
        "run_network_license_server": (_MOD_RUNNER_FUNCTIONS, "run_network_license_server"),
        "run_protocol_fingerprinter": (_MOD_RUNNER_FUNCTIONS, "run_protocol_fingerprinter"),
        "run_qemu_analysis": (_MOD_RUNNER_FUNCTIONS, "run_qemu_analysis"),
        "run_qiling_emulation": (_MOD_RUNNER_FUNCTIONS, "run_qiling_emulation"),
        "run_radare2_analysis": (_MOD_RUNNER_FUNCTIONS, "run_radare2_analysis"),
        "run_rop_chain_generator": (_MOD_RUNNER_FUNCTIONS, "run_rop_chain_generator"),
        "run_selected_analysis": (_MOD_RUNNER_FUNCTIONS, "run_selected_analysis"),
        "run_selected_patching": (_MOD_RUNNER_FUNCTIONS, "run_selected_patching"),
        "run_ssl_tls_interceptor": (_MOD_RUNNER_FUNCTIONS, "run_ssl_tls_interceptor"),
        "run_symbolic_execution": (_MOD_RUNNER_FUNCTIONS, "run_symbolic_execution"),
        "run_taint_analysis": (_MOD_RUNNER_FUNCTIONS, "run_taint_analysis"),
        "run_visual_network_traffic_analyzer": (
            _MOD_RUNNER_FUNCTIONS,
            "run_visual_network_traffic_analyzer",
        ),
        "create_sample_plugins": (_MOD_EXCEPTION_UTILS, "create_sample_plugins"),
        "handle_exception": (_MOD_EXCEPTION_UTILS, "handle_exception"),
        "load_ai_model": (_MOD_EXCEPTION_UTILS, "load_ai_model"),
        "load_config": (_MOD_EXCEPTION_UTILS, "load_config"),
        "save_config": (_MOD_EXCEPTION_UTILS, "save_config"),
        "setup_file_logging": (_MOD_EXCEPTION_UTILS, "setup_file_logging"),
        "detect_hardware_dongles": (_MOD_PROCESS_UTILS, "detect_hardware_dongles"),
        "detect_tpm_protection": (_MOD_PROCESS_UTILS, "detect_tpm_protection"),
        "get_system_processes": (_MOD_PROCESS_UTILS, "get_system_processes"),
        "run_command": (_MOD_PROCESS_UTILS, "run_command"),
        "apply_parsed_patch_instructions_with_validation": (
            _MOD_PATCH_VERIFICATION,
            "apply_parsed_patch_instructions_with_validation",
        ),
        "rewrite_license_functions_with_parsing": (
            _MOD_PATCH_VERIFICATION,
            "rewrite_license_functions_with_parsing",
        ),
        "test_patch_and_verify": (_MOD_PATCH_VERIFICATION, "test_patch_and_verify"),
        "verify_patches": (_MOD_PATCH_VERIFICATION, "verify_patches"),
        "analyze_binary": (_MOD_BINARY_ANALYSIS, "analyze_binary"),
        "analyze_binary_optimized": (_MOD_BINARY_ANALYSIS, "analyze_binary_optimized"),
        "analyze_elf": (_MOD_BINARY_ANALYSIS, "analyze_elf"),
        "analyze_macho": (_MOD_BINARY_ANALYSIS, "analyze_macho"),
        "analyze_patterns": (_MOD_BINARY_ANALYSIS, "analyze_patterns"),
        "analyze_pe": (_MOD_BINARY_ANALYSIS, "analyze_pe"),
        "analyze_traffic": (_MOD_BINARY_ANALYSIS, "analyze_traffic"),
        "extract_binary_features": (_MOD_BINARY_ANALYSIS, "extract_binary_features"),
        "extract_patterns_from_binary": (
            _MOD_BINARY_ANALYSIS,
            "extract_patterns_from_binary",
        ),
        "identify_binary_format": (_MOD_BINARY_ANALYSIS, "identify_binary_format"),
        "scan_binary": (_MOD_BINARY_ANALYSIS, "scan_binary"),
        "bypass_tpm_checks": (_MOD_SECURITY_ANALYSIS, "bypass_tpm_checks"),
        "check_buffer_overflow": (_MOD_SECURITY_ANALYSIS, "check_buffer_overflow"),
        "check_for_memory_leaks": (_MOD_SECURITY_ANALYSIS, "check_for_memory_leaks"),
        "check_memory_usage": (_MOD_SECURITY_ANALYSIS, "check_memory_usage"),
        "run_tpm_bypass": (_MOD_SECURITY_ANALYSIS, "run_tpm_bypass"),
        "run_vm_bypass": (_MOD_SECURITY_ANALYSIS, "run_vm_bypass"),
        "scan_protectors": (_MOD_SECURITY_ANALYSIS, "scan_protectors"),
        "generate_bypass_script": (_MOD_EXPLOITATION, "generate_bypass_script"),
        "generate_ca_certificate": (_MOD_EXPLOITATION, "generate_ca_certificate"),
        "generate_key": (_MOD_EXPLOITATION, "generate_key"),
        "generate_license_bypass_payload": (
            _MOD_EXPLOITATION,
            "generate_license_bypass_payload",
        ),
        "generate_response": (_MOD_EXPLOITATION, "generate_response"),
        "patch_selected": (_MOD_EXPLOITATION, "patch_selected"),
        "run_automated_patch_agent": (_MOD_EXPLOITATION, "run_automated_patch_agent"),
        "run_patch_validation": (_MOD_EXPLOITATION, "run_patch_validation"),
        "extract_binary_info": (_MOD_DISTRIBUTED_PROCESSING, "extract_binary_info"),
        "process_binary_chunks": (_MOD_DISTRIBUTED_PROCESSING, "process_binary_chunks"),
        "process_chunk": (_MOD_DISTRIBUTED_PROCESSING, "process_chunk"),
        "process_distributed_results": (
            _MOD_DISTRIBUTED_PROCESSING,
            "process_distributed_results",
        ),
        "run_distributed_analysis": (_MOD_DISTRIBUTED_PROCESSING, "run_distributed_analysis"),
        "run_distributed_entropy_analysis": (
            _MOD_DISTRIBUTED_PROCESSING,
            "run_distributed_entropy_analysis",
        ),
        "run_distributed_pattern_search": (
            _MOD_DISTRIBUTED_PROCESSING,
            "run_distributed_pattern_search",
        ),
        "run_gpu_accelerator": (_MOD_DISTRIBUTED_PROCESSING, "run_gpu_accelerator"),
        "run_pdf_report_generator": (_MOD_DISTRIBUTED_PROCESSING, "run_pdf_report_generator"),
        "run_analysis": (_MOD_ADDITIONAL_RUNNERS, "run_analysis"),
        "run_autonomous_crack": (_MOD_ADDITIONAL_RUNNERS, "run_autonomous_crack"),
        "run_deep_cfg_analysis": (_MOD_ADDITIONAL_RUNNERS, "run_deep_cfg_analysis"),
        "run_detect_packing": (_MOD_ADDITIONAL_RUNNERS, "run_detect_packing"),
        "run_external_command": (_MOD_ADDITIONAL_RUNNERS, "run_external_command"),
        "run_external_tool": (_MOD_ADDITIONAL_RUNNERS, "run_external_tool"),
        "run_full_autonomous_mode": (_MOD_ADDITIONAL_RUNNERS, "run_full_autonomous_mode"),
        "run_incremental_analysis_ui": (
            _MOD_ADDITIONAL_RUNNERS,
            "run_incremental_analysis_ui",
        ),
        "run_windows_activator": (_MOD_ADDITIONAL_RUNNERS, "run_windows_activator"),
        "validate_dataset": (_MOD_ADDITIONAL_RUNNERS, "validate_dataset"),
        "verify_hash": (_MOD_ADDITIONAL_RUNNERS, "verify_hash"),
        "OSDetectionMixin": (_MOD_OS_DETECTION_MIXIN, "OSDetectionMixin"),
        "TOOL_REGISTRY": (_MOD_CORE_UTILITIES, "TOOL_REGISTRY"),
        "deep_runtime_monitoring": (_MOD_CORE_UTILITIES, "deep_runtime_monitoring"),
        "dispatch_tool": (_MOD_CORE_UTILITIES, "dispatch_tool"),
        "main": (_MOD_CORE_UTILITIES, "main"),
        "on_message": (_MOD_CORE_UTILITIES, "on_message"),
        "register": (_MOD_CORE_UTILITIES, "register"),
        "register_default_tools": (_MOD_CORE_UTILITIES, "register_default_tools"),
        "register_tool": (_MOD_CORE_UTILITIES, "register_tool"),
        "retrieve_few_shot_examples": (_MOD_CORE_UTILITIES, "retrieve_few_shot_examples"),
        "run_cli_mode": (_MOD_CORE_UTILITIES, "run_cli_mode"),
        "run_gui_mode": (_MOD_CORE_UTILITIES, "run_gui_mode"),
        "accelerate_hash_calculation": (_MOD_FINAL_UTILITIES, "accelerate_hash_calculation"),
        "add_code_snippet": (_MOD_FINAL_UTILITIES, "add_code_snippet"),
        "add_dataset_row": (_MOD_FINAL_UTILITIES, "add_dataset_row"),
        "add_image": (_MOD_FINAL_UTILITIES, "add_image"),
        "add_recommendations": (_MOD_FINAL_UTILITIES, "add_recommendations"),
        "add_table": (_MOD_FINAL_UTILITIES, "add_table"),
        "async_wrapper": (_MOD_FINAL_UTILITIES, "async_wrapper"),
        "augment_dataset": (_MOD_FINAL_UTILITIES, "augment_dataset"),
        "browse_dataset": (_MOD_FINAL_UTILITIES, "browse_dataset"),
        "browse_model": (_MOD_FINAL_UTILITIES, "browse_model"),
        "cache_analysis_results": (_MOD_FINAL_UTILITIES, "cache_analysis_results"),
        "center_on_screen": (_MOD_FINAL_UTILITIES, "center_on_screen"),
        "compute_binary_hash": (_MOD_FINAL_UTILITIES, "compute_binary_hash"),
        "compute_section_hashes": (_MOD_FINAL_UTILITIES, "compute_section_hashes"),
        "copy_to_clipboard": (_MOD_FINAL_UTILITIES, "copy_to_clipboard"),
        "create_dataset": (_MOD_FINAL_UTILITIES, "create_dataset"),
        "create_full_feature_model": (_MOD_FINAL_UTILITIES, "create_full_feature_model"),
        "do_GET": (_MOD_FINAL_UTILITIES, "do_GET"),
        "export_metrics": (_MOD_FINAL_UTILITIES, "export_metrics"),
        "force_memory_cleanup": (_MOD_FINAL_UTILITIES, "force_memory_cleanup"),
        "get_captured_requests": (_MOD_FINAL_UTILITIES, "get_captured_requests"),
        "get_file_icon": (_MOD_FINAL_UTILITIES, "get_file_icon"),
        "get_resource_type": (_MOD_FINAL_UTILITIES, "get_resource_type"),
        "hash_func": (_MOD_FINAL_UTILITIES, "hash_func"),
        "identify_changed_sections": (_MOD_FINAL_UTILITIES, "identify_changed_sections"),
        "initialize_memory_optimizer": (_MOD_FINAL_UTILITIES, "initialize_memory_optimizer"),
        "load_dataset_preview": (_MOD_FINAL_UTILITIES, "load_dataset_preview"),
        "monitor_memory": (_MOD_FINAL_UTILITIES, "monitor_memory"),
        "on_training_finished": (_MOD_FINAL_UTILITIES, "on_training_finished"),
        "patches_reordered": (_MOD_FINAL_UTILITIES, "patches_reordered"),
        "predict_vulnerabilities": (_MOD_FINAL_UTILITIES, "predict_vulnerabilities"),
        "sandbox_process": (_MOD_FINAL_UTILITIES, "sandbox_process"),
        "select_backend_for_workload": (_MOD_FINAL_UTILITIES, "select_backend_for_workload"),
        "show_analysis_results": (_MOD_FINAL_UTILITIES, "show_analysis_results"),
        "showEvent": (_MOD_FINAL_UTILITIES, "showEvent"),
        "start_training": (_MOD_FINAL_UTILITIES, "start_training"),
        "stop_training": (_MOD_FINAL_UTILITIES, "stop_training"),
        "submit_report": (_MOD_FINAL_UTILITIES, "submit_report"),
        "truncate_text": (_MOD_FINAL_UTILITIES, "truncate_text"),
        "update_training_progress": (_MOD_FINAL_UTILITIES, "update_training_progress"),
        "update_visualization": (_MOD_FINAL_UTILITIES, "update_visualization"),
        "setup_dataset_tab": (_MOD_UI_SETUP_FUNCTIONS, "setup_dataset_tab"),
        "setup_memory_monitor": (_MOD_UI_SETUP_FUNCTIONS, "setup_memory_monitor"),
        "setup_training_tab": (_MOD_UI_SETUP_FUNCTIONS, "setup_training_tab"),
        "PCAP_AVAILABLE": (_MOD_PCAPY_COMPAT, "PCAP_AVAILABLE"),
        "create_pcap_reader": (_MOD_PCAPY_COMPAT, "create_pcap_reader"),
        "get_packet_capture_interface": (_MOD_PCAPY_COMPAT, "get_packet_capture_interface"),
        "_add_protocol_fingerprinter_results": (
            _MOD_INTERNAL_HELPERS,
            "_add_protocol_fingerprinter_results",
        ),
        "_analyze_requests": (_MOD_INTERNAL_HELPERS, "_analyze_requests"),
        "_analyze_snapshot_differences": (_MOD_INTERNAL_HELPERS, "_analyze_snapshot_differences"),
        "_generate_mitm_script": (_MOD_INTERNAL_HELPERS, "_generate_mitm_script"),
        "_get_filesystem_state": (_MOD_INTERNAL_HELPERS, "_get_filesystem_state"),
        "_get_memory_regions": (_MOD_INTERNAL_HELPERS, "_get_memory_regions"),
        "_get_network_state": (_MOD_INTERNAL_HELPERS, "_get_network_state"),
        "_get_process_state": (_MOD_INTERNAL_HELPERS, "_get_process_state"),
        "_handle_request": (_MOD_INTERNAL_HELPERS, "_handle_request"),
        "_perform_augmentation": (_MOD_INTERNAL_HELPERS, "_perform_augmentation"),
        "_run_autonomous_patching_thread": (
            _MOD_INTERNAL_HELPERS,
            "_run_autonomous_patching_thread",
        ),
        "_run_ghidra_thread": (_MOD_INTERNAL_HELPERS, "_run_ghidra_thread"),
        "_run_report_generation_thread": (_MOD_INTERNAL_HELPERS, "_run_report_generation_thread"),
        "PathDiscovery": (_MOD_PATH_DISCOVERY, "PathDiscovery"),
        "ensure_tool_available": (_MOD_PATH_DISCOVERY, "ensure_tool_available"),
        "find_tool": (_MOD_PATH_DISCOVERY, "find_tool"),
        "get_path_discovery": (_MOD_PATH_DISCOVERY, "get_path_discovery"),
        "get_system_path": (_MOD_PATH_DISCOVERY, "get_system_path"),
        "get_device": (_MOD_GPU_AUTOLOADER, "get_device"),
        "get_gpu_info": (_MOD_GPU_AUTOLOADER, "get_gpu_info"),
        "gpu_autoloader": (_MOD_GPU_AUTOLOADER, "gpu_autoloader"),
        "optimize_for_gpu": (_MOD_GPU_AUTOLOADER, "optimize_for_gpu"),
        "to_device": (_MOD_GPU_AUTOLOADER, "to_device"),
        "add_extra_buttons": (_MOD_UI_BUTTON_COMMON, "add_extra_buttons"),
        "get_button_style": (_MOD_UI_BUTTON_COMMON, "get_button_style"),
        "analyze_network_apis": (_MOD_NETWORK_API_ANALYSIS, "analyze_network_apis"),
        "get_network_api_categories": (_MOD_NETWORK_API_ANALYSIS, "get_network_api_categories"),
        "summarize_network_capabilities": (
            _MOD_NETWORK_API_ANALYSIS,
            "summarize_network_capabilities",
        ),
        "WINDOWS_AVAILABLE": (_MOD_WINDOWS_COMMON, "WINDOWS_AVAILABLE"),
        "WindowsConstants": (_MOD_WINDOWS_COMMON, "WindowsConstants"),
        "get_windows_kernel32": (_MOD_WINDOWS_COMMON, "get_windows_kernel32"),
        "get_windows_ntdll": (_MOD_WINDOWS_COMMON, "get_windows_ntdll"),
        "is_windows_available": (_MOD_WINDOWS_COMMON, "is_windows_available"),
        "analyze_pe_imports": (_MOD_PE_ANALYSIS_COMMON, "analyze_pe_imports"),
        "get_pe_sections_info": (_MOD_PE_ANALYSIS_COMMON, "get_pe_sections_info"),
        "create_popen_safely": (_MOD_PROCESS_COMMON, "create_popen_safely"),
        "run_subprocess_safely": (_MOD_PROCESS_COMMON, "run_subprocess_safely"),
        "create_certificate_builder": (
            _MOD_CERTIFICATE_COMMON,
            "create_certificate_builder",
        ),
        "find_function_prologues": (_MOD_PATTERN_SEARCH, "find_function_prologues"),
        "find_license_patterns": (_MOD_PATTERN_SEARCH, "find_license_patterns"),
        "search_patterns_in_binary": (_MOD_PATTERN_SEARCH, "search_patterns_in_binary"),
        "DateTimeEncoder": (_MOD_JSON_UTILS, "DateTimeEncoder"),
        "datetime_decoder": (_MOD_JSON_UTILS, "datetime_decoder"),
        "dump": (_MOD_JSON_UTILS, "dump"),
        "dumps": (_MOD_JSON_UTILS, "dumps"),
        "load": (_MOD_JSON_UTILS, "load"),
        "loads": (_MOD_JSON_UTILS, "loads"),
        "safe_deserialize": (_MOD_JSON_UTILS, "safe_deserialize"),
        "safe_serialize": (_MOD_JSON_UTILS, "safe_serialize"),
    }

    if name in import_map:
        module_path, attr_name = import_map[name]
        try:
            module = __import__(f"{__name__}.{module_path}", fromlist=[attr_name])
            result = getattr(module, attr_name)
            _lazy_imports[name] = result
            return result
        except (ImportError, AttributeError) as e:
            _init_logger.warning(f"Failed to import {name} from {module_path}: {e}")
            _lazy_imports[name] = None
            return None

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
