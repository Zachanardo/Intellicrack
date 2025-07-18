# Intellicrack Linter Report
Generated: 2025-06-06 14:28:08

## Summary

- **Total Files**: 977
- **Total Lines**: 353,617
- **Total Functions**: 8044
- **Total Classes**: 1836
- **Total Issues**: 5047

### Issues by Severity

- **Error**: 312
- **Warning**: 4735

### Issues by Type

- **Bare Except**: 71
- **High Complexity**: 272
- **Missing Docstring**: 4392
- **Syntax Error**: 312

## Top Problematic Files

- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_fixers.py`: 511 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/ast.py`: 234 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/infinite_recursion.py`: 179 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_setups.py`: 135 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/py3_test_grammar.py`: 108 issues
- `intellicrack/ui/main_app.py`: 92 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_pyio.py`: 92 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_io.py`: 84 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_parser.py`: 68 issues
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_suite.py`: 58 issues

## Detailed Issues

### `dependencies/fix_tool_paths.py`

- **Line 17** ⚠️ Function 'find_ghidra_installation' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 65** ⚠️ Function 'find_radare2_installation' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 76** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 252** ⚠️ Function 'update_config_file' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `final_verification_report.py`

- **Line 19** ⚠️ Function 'generate_final_report' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 486** ⚠️ Function 'generate_recommendations' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `fix_try_except.py`

- **Line 6** ⚠️ Function 'fix_try_except_imbalance' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 6** ⚠️ Function 'fix_try_except_imbalance' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/ai/ai_assistant_enhanced.py`

- **Line 789** ⚠️ Function 'send_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ai/enhanced_training_interface.py`

- **Line 783** ⚠️ Function 'create_colored_pixmap' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ai/model_manager_module.py`

- **Line 652** ⚠️ Function 'load_worker' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 668** ⚠️ Function 'predict_worker' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 896** ⚠️ Class 'ProgressCallback' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 897** ⚠️ Function 'on_epoch_end' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ai/orchestrator.py`

- **Line 172** ⚠️ Function 'call_subscriber' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 224** ⚠️ Function '_initialize_components' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 438** ⚠️ Function '_execute_vulnerability_scan' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/ai/training_thread.py`

- **Line 288** ⚠️ Class 'SimpleTransformer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 299** ⚠️ Function 'forward' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/core/analysis/binary_similarity_search.py`

- **Line 114** ⚠️ Function '_extract_binary_features' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/cfg_explorer.py`

- **Line 75** ⚠️ Function 'load_binary' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 442** ⚠️ Function 'run_deep_cfg_analysis' has high complexity (23)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/concolic_executor.py`

- **Line 36** ⚠️ Class 'Manticore' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Class 'Plugin' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `intellicrack/core/analysis/core_analysis.py`

- **Line 87** ⚠️ Function 'analyze_binary_internal' has high complexity (33)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 234** ⚠️ Function 'enhanced_deep_license_analysis' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 337** ⚠️ Function 'detect_packing' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 463** ⚠️ Function 'decrypt_embedded_script' has high complexity (21)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/dynamic_analyzer.py`

- **Line 119** ⚠️ Function '_frida_runtime_analysis' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 460** ⚠️ Function 'on_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 563** ⚠️ Function 'run_dynamic_analysis' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/incremental_manager.py`

- **Line 445** ⚠️ Function 'run_analysis_manager' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/multi_format_analyzer.py`

- **Line 161** ⚠️ Function 'analyze_pe' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 496** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 527** ⚠️ Function 'run_multi_format_analysis' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/rop_generator.py`

- **Line 141** ⚠️ Function '_simulate_gadget_finding' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 286** ⚠️ Function '_simulate_chain_generation' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 519** ⚠️ Function 'run_rop_chain_generator' has high complexity (35)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/symbolic_executor.py`

- **Line 55** ⚠️ Function 'discover_vulnerabilities' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/analysis/taint_analyzer.py`

- **Line 402** ⚠️ Function 'run_taint_analysis' has high complexity (21)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/network/cloud_license_hooker.py`

- **Line 278** ⚠️ Function '_determine_response_format' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 417** ⚠️ Function '_customize_template' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 452** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `intellicrack/core/network/license_server_emulator.py`

- **Line 409** ⚠️ Function '_start_ssl_interceptor' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 605** ⚠️ Function '_start_traffic_recorder' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 694** ⚠️ Function 'auto_save_thread' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 737** ⚠️ Function 'log_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/core/network/protocol_fingerprinter.py`

- **Line 226** ⚠️ Function 'analyze_traffic' has high complexity (31)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 358** ⚠️ Function 'parse_packet' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/network/traffic_analyzer.py`

- **Line 177** ⚠️ Function '_capture_with_socket' has high complexity (27)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 315** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 375** ⚠️ Function '_capture_with_pyshark' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 520** ⚠️ Function '_process_pyshark_packet' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 738** ⚠️ Function '_generate_visualizations' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/patching/memory_patcher.py`

- **Line 266** ⚠️ Function 'setup_memory_patching' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/patching/payload_generator.py`

- **Line 371** ⚠️ Function 'generate_complete_api_hooking_script' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/processing/distributed_manager.py`

- **Line 851** ⚠️ Function 'stop_processing' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/processing/gpu_accelerator.py`

- **Line 54** ⚠️ Function '__init__' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 297** ⚠️ Function '_check_available_backends' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 391** ⚠️ Function '_select_preferred_backend' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/processing/qiling_emulator.py`

- **Line 296** ⚠️ Function '_analyze_results' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 367** ⚠️ Function 'apply_patches' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/core/protection_bypass/vm_bypass.py`

- **Line 429** ⚠️ Function 'detect' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 528** ⚠️ Function 'analyze' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/core/reporting/pdf_generator.py`

- **Line 219** ⚠️ Function '_generate_comprehensive_report' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 655** ⚠️ Function 'run_report_generation' has high complexity (24)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/hexview/advanced_search.py`

- **Line 246** ⚠️ Function '_compile_pattern' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/hexview/ai_bridge.py`

- **Line 156** ⚠️ Function '_extract_strings' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 347** ⚠️ Function '_interpret_common_types' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 907** ⚠️ Function '_parse_analysis_response' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/hexview/data_inspector.py`

- **Line 71** ⚠️ Function 'interpret' has high complexity (74)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 706** ⚠️ Function 'apply_modification' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/hexview/file_handler.py`

- **Line 222** ⚠️ Function '__init__' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 404** ⚠️ Function 'read' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/hexview/hex_dialog.py`

- **Line 410** ⚠️ Function 'update_status_bar' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/hexview/hex_renderer.py`

- **Line 320** ⚠️ Function '_format_field_value' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 334** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `intellicrack/hexview/hex_widget.py`

- **Line 391** ⚠️ Function 'viewportPaintEvent' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 986** ⚠️ Function 'search' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1612** ⚠️ Function 'handle_navigation_key' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1696** ⚠️ Function 'get_offset_from_position' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/hexview/integration.py`

- **Line 27** ⚠️ Function 'wrapper_ai_binary_analyze' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 29** ⚠️ Function 'wrapper_ai_binary_pattern_search' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Function 'wrapper_ai_binary_edit_suggest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 323** ⚠️ Function 'wrapper' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/plugins/__init__.py`

- **Line 102** ⚠️ Function 'load_plugins' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'run_plugin' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'run_custom_plugin' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 105** ⚠️ Function 'run_frida_plugin_from_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'run_ghidra_plugin_from_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 107** ⚠️ Function 'create_sample_plugins' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Function 'run_plugin_in_sandbox' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 109** ⚠️ Function 'run_plugin_remotely' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/plugins/plugin_system.py`

- **Line 50** ⚠️ Function 'load_plugins' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 211** ⚠️ Function 'run_custom_plugin' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 281** ⚠️ Function 'run_frida_plugin_from_file' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 428** ⚠️ Function 'run_ghidra_plugin_from_file' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 779** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `intellicrack/plugins/remote_executor.py`

- **Line 122** ⚠️ Function 'start_server' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 132** ⚠️ Function 'handle_client' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/ui/adobe_injector_src/adobe_full_auto_injector.py`

- **Line 32** ⚠️ Function 'inject' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'get_running_adobe_apps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Function 'monitor_loop' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ui/common_imports.py`

- **Line 24** ⚠️ Class 'MockQtClass' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 105** ⚠️ Function 'pyqtSignal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ui/dialogs/distributed_config_dialog.py`

- **Line 227** ⚠️ Function 'set_defaults' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/ui/dialogs/guided_workflow_wizard.py`

- **Line 690** ⚠️ Function 'update_summary' has high complexity (52)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 898** ⚠️ Function 'on_finished' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/ui/dialogs/keygen_dialog.py`

- **Line 623** ⚠️ Function 'save_single_key' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/ui/dialogs/model_finetuning_dialog.py`

- **Line 247** ⚠️ Class 'DummyModel' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 257** ⚠️ Function 'forward' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 265** ⚠️ Function '_load_dataset' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1115** ⚠️ Function '_load_dataset_preview' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1313** ⚠️ Function '_validate_dataset' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1479** ⚠️ Function '_apply_augmentation_technique' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1530** ⚠️ Function '_apply_augmentation' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1650** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `intellicrack/ui/dialogs/plugin_manager_dialog.py`

- **Line 37** ⚠️ Class 'PluginInstallThread' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 39** ⚠️ Class 'PluginManagerDialog' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 43** ⚠️ Function 'show' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'exec_' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Function 'exec' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ui/dialogs/report_manager_dialog.py`

- **Line 757** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `intellicrack/ui/dialogs/system_utilities_dialog.py`

- **Line 44** ⚠️ Class 'QDialog' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Function 'pyqtSignal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ui/main_app.py`

- **Line 95** ⚠️ Class 'MockWindll' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 97** ⚠️ Class 'MockFunc' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 102** ⚠️ Function 'byref' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'c_int' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'sizeof' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 146** ⚠️ Class 'QMainWindow' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 148** ⚠️ Function 'pyqtSignal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 149** ⚠️ Function 'dummy_signal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 162** ⚠️ Class 'SplashScreen' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 163** ⚠️ Function 'show' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 164** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 289** ⚠️ Function 'run_rop_chain_generator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 291** ⚠️ Function 'run_automated_patch_agent' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 294** ⚠️ Function 'analyze_binary_internal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 296** ⚠️ Function 'enhanced_deep_license_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 298** ⚠️ Function 'deep_runtime_monitoring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 300** ⚠️ Function 'run_ssl_tls_interceptor' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 302** ⚠️ Function 'run_protocol_fingerprinter' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 304** ⚠️ Function 'run_cloud_license_hooker' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 306** ⚠️ Function 'run_cfg_explorer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 308** ⚠️ Function 'run_concolic_execution' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 310** ⚠️ Function 'run_enhanced_protection_scan' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 312** ⚠️ Function 'run_visual_network_traffic_analyzer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 314** ⚠️ Function 'run_multi_format_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 316** ⚠️ Function 'run_distributed_processing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 318** ⚠️ Function 'run_gpu_accelerated_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 320** ⚠️ Function 'run_symbolic_execution' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 322** ⚠️ Function 'run_incremental_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 324** ⚠️ Function 'run_memory_optimized_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 326** ⚠️ Function 'run_qemu_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 328** ⚠️ Function 'run_selected_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 330** ⚠️ Function 'run_network_license_server' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 332** ⚠️ Function 'run_frida_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 334** ⚠️ Function 'run_dynamic_instrumentation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 336** ⚠️ Function 'run_frida_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 338** ⚠️ Function 'run_deep_cfg_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 340** ⚠️ Function 'detect_packing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 342** ⚠️ Function 'decrypt_embedded_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 344** ⚠️ Function 'scan_for_bytecode_protectors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 346** ⚠️ Class 'AdvancedVulnerabilityEngine' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 348** ⚠️ Function 'scan_binary' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 350** ⚠️ Function 'bypass_tpm_protection' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 352** ⚠️ Function 'bypass_vm_detection' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 606** ⚠️ Function 'start' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 614** ⚠️ Function 'exec_' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 622** ⚠️ Function 'exec_' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 811** ⚠️ Function '__init__' has high complexity (37)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1451** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 4601** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 4637** ⚠️ Function 'setup_settings_tab' has high complexity (32)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 6728** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 7310** ⚠️ Function 'setup_dashboard_content' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 7635** ⚠️ Function 'handle_deep_analysis_mode' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 7860** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 8176** ⚠️ Function '_import_from_api' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 8682** ⚠️ Function 'verify_hash' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 8933** ⚠️ Function 'save_config' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 9047** ⚠️ Function 'load_analysis_config' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 9094** ⚠️ Function 'apply_config_preset' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 9210** ⚠️ Function 'scan_protectors' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 9271** ⚠️ Function 'select_program' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 9830** ⚠️ Function '_run_analysis_thread' has high complexity (63)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 10423** ⚠️ Function '_preview_patch_thread' has high complexity (26)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 10806** ⚠️ Function '_extract_patterns_from_pe' has high complexity (34)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 11219** ⚠️ Function 'run_automated_patch_agent' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 11319** ⚠️ Function '_run_full_autonomous_mode_thread' has high complexity (22)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 12267** ⚠️ Function '_run_model_inference_thread' has high complexity (24)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 12784** ⚠️ Function 'run_selected_patching' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 12824** ⚠️ Function 'run_memory_analysis' has high complexity (40)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 13045** ⚠️ Function 'run_network_analysis' has high complexity (47)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 13307** ⚠️ Function 'run_patching' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 13641** ⚠️ Function 'view_report' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 13797** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 13839** ⚠️ Function 'import_report' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 14697** ⚠️ Function '_generate_general_report_section' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 14967** ⚠️ Function 'launch' has high complexity (142)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15148** ⚠️ Function 'run_static_vulnerability_scan' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15200** ⚠️ Function 'run_ml_vulnerability_prediction' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15215** ⚠️ Function 'handle_ai_result' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15215** ⚠️ Function 'handle_ai_result' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15319** ⚠️ Function 'run_comprehensive_ai_analysis' has high complexity (22)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15332** ⚠️ Function 'handle_comprehensive_result' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15332** ⚠️ Function 'handle_comprehensive_result' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15475** ⚠️ Function 'analyze_process_behavior' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15579** ⚠️ Function 'analyze_captured_traffic' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15684** ⚠️ Function 'run_comprehensive_protection_scan' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 15867** ⚠️ Function 'log_after_start' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15886** ⚠️ Function 'force_show_window' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16136** ⚠️ Function 'install_worker' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16159** ⚠️ Function 'on_training_progress' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16292** ⚠️ Class 'WorkerThread' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16304** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/ui/widgets/__init__.py`

- **Line 38** ⚠️ Class 'HexViewer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 39** ⚠️ Class 'AssemblyView' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 40** ⚠️ Class 'CFGWidget' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Class 'CallGraphWidget' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 42** ⚠️ Class 'SearchBar' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 43** ⚠️ Class 'FilterPanel' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 44** ⚠️ Class 'ToolPanel' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 45** ⚠️ Class 'HeatmapWidget' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Class 'GraphWidget' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 47** ⚠️ Class 'TimelineWidget' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 48** ⚠️ Class 'ProgressWidget' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 49** ⚠️ Class 'StatusBar' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 50** ⚠️ Class 'LogViewer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `intellicrack/utils/additional_runners.py`

- **Line 20** ⚠️ Function 'run_comprehensive_analysis' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/binary_analysis.py`

- **Line 212** ⚠️ Function 'analyze_pe' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 692** ⚠️ Function 'walk_resources' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/utils/binary_utils.py`

- **Line 162** ⚠️ Function 'analyze_binary_format' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/dependencies.py`

- **Line 16** ⚠️ Function 'check_weasyprint_dependencies' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/distributed_processing.py`

- **Line 911** ⚠️ Function '_gpu_pattern_matching' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/exploitation.py`

- **Line 742** ⚠️ Function 'run_automated_patch_agent' has high complexity (23)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 906** ⚠️ Function 'run_simulate_patch' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1415** ⚠️ Function '_detect_license_algorithm' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1533** ⚠️ Function '_generate_key_by_algorithm' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/final_utilities.py`

- **Line 459** ⚠️ Function 'wrapped' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/utils/internal_helpers.py`

- **Line 956** ⚠️ Function 'run_ghidra' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/utils/logger.py`

- **Line 44** ⚠️ Function 'log_function_call' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 59** ⚠️ Function 'wrapper' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'safe_repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 125** ⚠️ Function 'safe_repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/utils/patch_utils.py`

- **Line 149** ⚠️ Function 'apply_patch' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/patch_verification.py`

- **Line 120** ⚠️ Function 'simulate_patch_and_verify' has high complexity (21)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 276** ⚠️ Function 'apply_parsed_patch_instructions_with_validation' has high complexity (22)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 479** ⚠️ Function 'rewrite_license_functions_with_parsing' has high complexity (34)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/performance_optimizer.py`

- **Line 490** ⚠️ Function 'analyze_chunk' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `intellicrack/utils/process_utils.py`

- **Line 82** ⚠️ Function 'detect_hardware_dongles' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 197** ⚠️ Function 'detect_tpm_protection' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/protection_detection.py`

- **Line 17** ⚠️ Function 'detect_virtualization_protection' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 93** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 110** ⚠️ Function 'detect_commercial_protections' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 423** ⚠️ Function 'detect_anti_debugging_techniques' has high complexity (29)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 612** ⚠️ Function 'scan_for_bytecode_protectors' has high complexity (25)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/protection_utils.py`

- **Line 49** ⚠️ Function 'detect_packing' has high complexity (24)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 333** ⚠️ Function 'inject_comprehensive_api_hooks' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/runner_functions.py`

- **Line 259** ⚠️ Function 'run_gpu_accelerated_analysis' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 403** ⚠️ Function 'run_advanced_ghidra_analysis' has high complexity (21)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 526** ⚠️ Function 'process_ghidra_analysis_results' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 711** ⚠️ Function 'run_symbolic_execution' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1147** ⚠️ Function 'run_memory_analysis' has high complexity (21)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1281** ⚠️ Function 'run_network_analysis' has high complexity (31)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1464** ⚠️ Function 'run_ghidra_plugin_from_file' has high complexity (23)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1578** ⚠️ Function '_run_ghidra_thread' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1655** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1659** ⚠️ Function 'run_deep_license_analysis' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1730** ⚠️ Function 'run_frida_analysis' has high complexity (21)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1877** ⚠️ Function 'on_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1921** ⚠️ Function 'run_dynamic_instrumentation' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 2172** ⚠️ Function 'on_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2265** ⚠️ Function 'run_ghidra_analysis_gui' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/security_analysis.py`

- **Line 34** ⚠️ Function 'check_buffer_overflow' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 127** ⚠️ Function 'check_for_memory_leaks' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 247** ⚠️ Function 'check_memory_usage' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 322** ⚠️ Function 'bypass_tpm_checks' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 408** ⚠️ Function 'scan_protectors' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions

### `intellicrack/utils/system_utils.py`

- **Line 389** ⚠️ Function 'extract_executable_icon' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 560** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `intellicrack/utils/tool_wrappers.py`

- **Line 855** ⚠️ Function 'run_ghidra_headless' has high complexity (33)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 958** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1079** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1086** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1352** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1360** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1369** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `intellicrack/utils/ui_utils.py`

- **Line 235** ⚠️ Function 'format_table_data' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `launch_intellicrack.py`

- **Line 52** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `lint_intellicrack.py`

- **Line 274** ⚠️ Function '_create_markdown_report' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 410** ⚠️ Function 'visit_Module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 418** ⚠️ Function 'visit_FunctionDef' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 456** ⚠️ Function 'visit_ClassDef' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 478** ⚠️ Function 'visit_Import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 482** ⚠️ Function 'visit_ImportFrom' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 492** ⚠️ Function 'visit_If' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 509** ⚠️ Function 'visit_Try' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 530** ⚠️ Class 'ComplexityVisitor' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 534** ⚠️ Function 'visit_If' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 538** ⚠️ Function 'visit_For' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 542** ⚠️ Function 'visit_While' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 546** ⚠️ Function 'visit_Try' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `models/create_ml_model.py`

- **Line 502** ⚠️ Function 'generate_synthetic_data' has high complexity (57)
  - Suggestion: Consider breaking this function into smaller functions

### `models/repositories/base.py`

- **Line 473** ⚠️ Function 'download_model' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions

### `plugins/custom_modules/demo_plugin.py`

- **Line 30** ⚠️ Function 'register' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `scripts/cli/ai_wrapper.py`

- **Line 273** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `scripts/cli/main.py`

- **Line 254** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 299** ⚠️ Function 'run_core_analysis' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 640** ⚠️ Function 'run_advanced_features' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 926** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 932** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1463** ⚠️ Function 'handle_batch_processing' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1866** ⚠️ Function 'main' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions

### `scripts/simconcolic.py`

- **Line 145** ⚠️ Function 'run' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/loaders/xmlldr.py`

- **Line 80** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 80)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/plugins/xmlexp.py`

- **Line 79** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 79)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/plugins/xmlldr.py`

- **Line 80** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 80)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/loaders/xml_loader.py`

- **Line 99** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/plugins/xml_exporter.py`

- **Line 82** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 92** ⚠️ Function 'term' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 96** ⚠️ Function 'PLUGIN_ENTRY' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/plugins/xml_importer.py`

- **Line 85** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 94** ⚠️ Function 'term' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 98** ⚠️ Function 'PLUGIN_ENTRY' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/python/idaxml.py`

- **Line 92** ⚠️ Class 'Cancelled' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 96** ⚠️ Class 'FileError' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 100** ⚠️ Class 'MultipleAddressSpacesNotSupported' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 104** ⚠️ Class 'IdaXml' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 215** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 281** ⚠️ Function 'export_xml' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 380** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 598** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 602** ⚠️ Function 'export_code' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 714** ⚠️ Function 'export_data' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 904** ⚠️ Function 'export_enums' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 971** ⚠️ Function 'export_functions' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1300** ⚠️ Function 'export_program' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1399** ⚠️ Function 'export_register_values' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1531** ⚠️ Function 'export_stack_vars' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1794** ⚠️ Function 'get_datatype' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1994** ⚠️ Function 'get_type' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 2059** ⚠️ Function 'is_signed_data' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2269** ⚠️ Function 'import_xml' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 2469** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 2485** ⚠️ Function 'get_datatype_flags' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 2512** ⚠️ Function 'get_string_type' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2553** ⚠️ Function 'is_int' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2557** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 2676** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 2930** ⚠️ Function 'import_equate_reference' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2956** ⚠️ Function 'import_function' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 3010** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 3015** ⚠️ Function 'import_function_def' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3439** ⚠️ Function 'import_stack_reference' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3538** ⚠️ Function 'import_typedef' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/kernel-dbgeng.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-dbgeng-attach.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-dbgeng-ext.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-dbgeng.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-ttd.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/remote-dbgeng.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/arch.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/commands.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/__init__.py`

- **Line 19** ⚠️ Function 'module_locator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/idatamodelmanager.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/idebughost.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/ihostdatamodelaccess.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/iiterableconcept.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/ikeyenumerator.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/imodeliterator.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/imodelobject.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/irawenumerator.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/istringdisplayableconcept.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/exdi/exdi_commands.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/exdi/exdi_methods.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/hooks.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/libraries.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/methods.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/util.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/arch.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/commands.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/hooks.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/libraries.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/methods.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/util.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/data/scripts/remote-proc-mappings.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/arch.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/commands.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/hooks.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/methods.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/parameters.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/util.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/wine.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/arch.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/commands.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/hooks.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/methods.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/util.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/data/support/raw-python3.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/client.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/sch.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/trace_rmi_pb2.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/util.py`

- **Line 1** ❌ source code string cannot contain null bytes

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/DumpBSimDebugSignaturesScript.py`

- **Line 32** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 32)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/DumpBSimSignaturesScript.py`

- **Line 37** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 37)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/ExampleOverviewQueryScript.py`

- **Line 44** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 44)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/GenerateSignatures.py`

- **Line 26** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/QueryFunction.py`

- **Line 33** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 33)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/LocateMemoryAddressesForFileOffset.py`

- **Line 31** ⚠️ Function 'getFileOffset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'processAddress' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/RecursiveStringFinder.py`

- **Line 88** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 88)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/RunYARAFromGhidra.py`

- **Line 43** ⚠️ Function 'getYaraRulePath' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'getYaraTargetOnDisk' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'getYaraTargetFromGhidra' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'createYaraDictionary' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 118** ⚠️ Function 'launchYaraProcess' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 135** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 149** ⚠️ Function 'setGhidraComment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 189** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/mark_in_out.py`

- **Line 34** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 34)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/BaseHTTPServer.py`

- **Line 341** ❌ multiple exception types must be parenthesized (<unknown>, line 341)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/CGIHTTPServer.py`

- **Line 369** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 369)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ConfigParser.py`

- **Line 261** ❌ invalid syntax (<unknown>, line 261)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/Cookie.py`

- **Line 232** ⚠️ Class 'CookieError' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 408** ⚠️ Class 'Morsel' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 448** ⚠️ Function 'isReservedKey' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 452** ⚠️ Function 'set' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 468** ⚠️ Function 'output' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 477** ⚠️ Function 'js_output' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 488** ⚠️ Function 'OutputString' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 554** ⚠️ Class 'BaseCookie' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 677** ⚠️ Function 'value_decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 679** ⚠️ Function 'value_encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 703** ⚠️ Function 'value_decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 706** ⚠️ Function 'value_encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 728** ⚠️ Function 'value_decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 732** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 734** ⚠️ Function 'value_encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/DocXMLRPCServer.py`

- **Line 272** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 272)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/HTMLParser.py`

- **Line 120** ⚠️ Function 'error' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Function 'set_cdata_mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 133** ⚠️ Function 'clear_cdata_mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'goahead' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'goahead' has high complexity (28)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 234** ⚠️ Function 'parse_html_declaration' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 255** ⚠️ Function 'parse_bogus_comment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 267** ⚠️ Function 'parse_pi' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 279** ⚠️ Function 'parse_starttag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 279** ⚠️ Function 'parse_starttag' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 331** ⚠️ Function 'check_for_whole_start_tag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 363** ⚠️ Function 'parse_endtag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 403** ⚠️ Function 'handle_startendtag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 408** ⚠️ Function 'handle_starttag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 412** ⚠️ Function 'handle_endtag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 416** ⚠️ Function 'handle_charref' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 420** ⚠️ Function 'handle_entityref' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 424** ⚠️ Function 'handle_data' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 428** ⚠️ Function 'handle_comment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 432** ⚠️ Function 'handle_decl' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 436** ⚠️ Function 'handle_pi' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 439** ⚠️ Function 'unknown_decl' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 444** ⚠️ Function 'unescape' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 447** ⚠️ Function 'replaceEntities' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SimpleHTTPServer.py`

- **Line 95** ❌ multiple exception types must be parenthesized (<unknown>, line 95)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SimpleXMLRPCServer.py`

- **Line 265** ❌ multiple exception types must be parenthesized (<unknown>, line 265)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SocketServer.py`

- **Line 350** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 350)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/StringIO.py`

- **Line 40** ❌ invalid syntax (<unknown>, line 40)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserDict.py`

- **Line 134** ❌ invalid syntax (<unknown>, line 134)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserList.py`

- **Line 5** ⚠️ Class 'UserList' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 76** ⚠️ Function 'append' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'insert' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'pop' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 79** ⚠️ Function 'remove' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'count' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'index' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 82** ⚠️ Function 'reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 83** ⚠️ Function 'sort' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 84** ⚠️ Function 'extend' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserString.py`

- **Line 170** ❌ invalid syntax (<unknown>, line 170)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_LWPCookieJar.py`

- **Line 20** ⚠️ Function 'lwp_cookie_str' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 78** ⚠️ Function 'save' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function '_really_load' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_MozillaCookieJar.py`

- **Line 47** ⚠️ Function '_really_load' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 113** ⚠️ Function 'save' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/__future__.py`

- **Line 74** ⚠️ Class '_Feature' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_abcoll.py`

- **Line 33** ⚠️ Class 'Hashable' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 56** ⚠️ Class 'Iterable' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 74** ⚠️ Class 'Iterator' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 77** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 91** ⚠️ Class 'Sized' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 106** ⚠️ Class 'Container' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 121** ⚠️ Class 'Callable' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 197** ⚠️ Function 'isdisjoint' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 262** ⚠️ Class 'MutableSet' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 335** ⚠️ Class 'Mapping' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 341** ⚠️ Function 'get' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 355** ⚠️ Function 'iterkeys' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 358** ⚠️ Function 'itervalues' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 362** ⚠️ Function 'iteritems' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 366** ⚠️ Function 'keys' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 369** ⚠️ Function 'items' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 372** ⚠️ Function 'values' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 386** ⚠️ Class 'MappingView' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 398** ⚠️ Class 'KeysView' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 412** ⚠️ Class 'ItemsView' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 432** ⚠️ Class 'ValuesView' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 445** ⚠️ Class 'MutableMapping' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 457** ⚠️ Function 'pop' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 468** ⚠️ Function 'popitem' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 477** ⚠️ Function 'clear' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 484** ⚠️ Function 'update' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 505** ⚠️ Function 'setdefault' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 549** ⚠️ Function 'index' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 555** ⚠️ Function 'count' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 564** ⚠️ Class 'MutableSequence' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 575** ⚠️ Function 'insert' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 578** ⚠️ Function 'append' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 581** ⚠️ Function 'reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 586** ⚠️ Function 'extend' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 590** ⚠️ Function 'pop' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 595** ⚠️ Function 'remove' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_google_ipaddr_r234.py`

- **Line 1468** ❌ invalid decimal literal (<unknown>, line 1468)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_io.py`

- **Line 170** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 176** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 182** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 196** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 210** ⚠️ Function 'detach' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Function 'seekable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 224** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 228** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 233** ⚠️ Function 'raw' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 237** ⚠️ Function 'closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 250** ⚠️ Function 'name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 254** ⚠️ Function 'mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 268** ⚠️ Function 'fileno' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 271** ⚠️ Function 'isatty' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 336** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 358** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 376** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 395** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 400** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 415** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 419** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 423** ⚠️ Function 'seekable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 471** ⚠️ Function '_read_unlocked' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 569** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 572** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 610** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 642** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 649** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 675** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 678** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 720** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 725** ⚠️ Function 'readinto' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 728** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 731** ⚠️ Function 'peek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 734** ⚠️ Function 'read1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 737** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 740** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 743** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 746** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 750** ⚠️ Function 'isatty' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 754** ⚠️ Function 'closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 775** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 792** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 798** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 804** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 810** ⚠️ Function 'readinto' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 814** ⚠️ Function 'peek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 818** ⚠️ Function 'read1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 822** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 909** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 940** ⚠️ Function 'getstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 951** ⚠️ Function 'setstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 957** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 968** ⚠️ Function 'newlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1020** ⚠️ Function '__init__' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1091** ⚠️ Function 'encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1095** ⚠️ Function 'errors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1099** ⚠️ Function 'line_buffering' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1103** ⚠️ Function 'buffer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1106** ⚠️ Function 'seekable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1111** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1115** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1119** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1124** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1134** ⚠️ Function 'closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1147** ⚠️ Function 'name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1150** ⚠️ Function 'fileno' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1153** ⚠️ Function 'isatty' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1156** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1270** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1332** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1338** ⚠️ Function 'detach' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1347** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1347** ⚠️ Function 'seek' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1422** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1451** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1460** ⚠️ Function 'readline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1460** ⚠️ Function 'readline' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1549** ⚠️ Function 'newlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1633** ⚠️ Function 'getvalue' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1643** ⚠️ Function 'errors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1647** ⚠️ Function 'encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1650** ⚠️ Function 'detach' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_pyio.py`

- **Line 43** ⚠️ Function 'open' has high complexity (26)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 252** ⚠️ Class 'UnsupportedOperation' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 256** ⚠️ Class 'IOBase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 357** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 464** ⚠️ Function 'nreadahead' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 473** ⚠️ Function 'nreadahead' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 493** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 519** ⚠️ Function 'writelines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 693** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 699** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 705** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 719** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 724** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 732** ⚠️ Function 'detach' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 742** ⚠️ Function 'seekable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 745** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 748** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 752** ⚠️ Function 'raw' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 756** ⚠️ Function 'closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 760** ⚠️ Function 'name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 764** ⚠️ Function 'mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 778** ⚠️ Function 'fileno' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 781** ⚠️ Function 'isatty' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 808** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 830** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 848** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 867** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 872** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 887** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 892** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 897** ⚠️ Function 'seekable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 944** ⚠️ Function '_read_unlocked' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1041** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1044** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1080** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1108** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1115** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1140** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1143** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1185** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1190** ⚠️ Function 'readinto' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1193** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1196** ⚠️ Function 'peek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1199** ⚠️ Function 'read1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1202** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1205** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1208** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1211** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1215** ⚠️ Function 'isatty' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1219** ⚠️ Function 'closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1240** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1257** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1263** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1269** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1275** ⚠️ Function 'readinto' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1279** ⚠️ Function 'peek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1283** ⚠️ Function 'read1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1287** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1376** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1407** ⚠️ Function 'getstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1418** ⚠️ Function 'setstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1424** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1435** ⚠️ Function 'newlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1473** ⚠️ Function '__init__' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1541** ⚠️ Function 'encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1545** ⚠️ Function 'errors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1549** ⚠️ Function 'line_buffering' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1553** ⚠️ Function 'buffer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1556** ⚠️ Function 'seekable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1561** ⚠️ Function 'readable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1564** ⚠️ Function 'writable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1567** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1571** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1579** ⚠️ Function 'closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1583** ⚠️ Function 'name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1586** ⚠️ Function 'fileno' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1589** ⚠️ Function 'isatty' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1592** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1701** ⚠️ Function 'tell' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1763** ⚠️ Function 'truncate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1769** ⚠️ Function 'detach' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1777** ⚠️ Function 'seek' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1777** ⚠️ Function 'seek' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1849** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1874** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1883** ⚠️ Function 'readline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1883** ⚠️ Function 'readline' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1972** ⚠️ Function 'newlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1998** ⚠️ Function 'getvalue' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2008** ⚠️ Function 'errors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2012** ⚠️ Function 'encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2015** ⚠️ Function 'detach' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_rawffi.py`

- **Line 3** ⚠️ Function 'get_libc' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 8** ⚠️ Class 'Array' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Class 'ArrayInstance' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Class 'FuncPtr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Class 'CDLL' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Function 'ptr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_socket.py`

- **Line 384** ❌ multiple exception types must be parenthesized (<unknown>, line 384)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_sslcerts.py`

- **Line 109** ⚠️ Function '_get_openssl_key_manager' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 247** ⚠️ Function '_read_pem_cert_from_data' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 249** ⚠️ Function 'PEM_SSLError' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 325** ⚠️ Class 'CompositeX509KeyManager' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 330** ⚠️ Function 'chooseClientAlias' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 337** ⚠️ Function 'chooseServerAlias' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 344** ⚠️ Function 'getPrivateKey' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 351** ⚠️ Function 'getCertificateChain' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 358** ⚠️ Function 'getClientAliases' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 367** ⚠️ Function 'getServerAliases' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 377** ⚠️ Class 'CompositeX509TrustManager' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 382** ⚠️ Function 'checkClientTrusted' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 398** ⚠️ Function 'checkServerTrusted' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 414** ⚠️ Function 'getAcceptedIssuers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 421** ⚠️ Class 'CompositeX509TrustManagerFactory' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 426** ⚠️ Function 'engineInit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 429** ⚠️ Function 'engineGetTrustManagers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_strptime.py`

- **Line 110** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 110)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_threading_local.py`

- **Line 148** ⚠️ Class '_localbase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 186** ⚠️ Class 'local' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 232** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_weakrefset.py`

- **Line 12** ⚠️ Class 'WeakSet' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/abc.py`

- **Line 11** ⚠️ Class '_C' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 148** ⚠️ Function '__subclasscheck__' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/aifc.py`

- **Line 145** ❌ invalid hexadecimal literal (<unknown>, line 145)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/anydbm.py`

- **Line 57** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 57)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/argparse.py`

- **Line 197** ⚠️ Class '_Section' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 205** ⚠️ Function 'format_help' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 236** ⚠️ Function 'start_section' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 242** ⚠️ Function 'end_section' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 246** ⚠️ Function 'add_text' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 250** ⚠️ Function 'add_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 255** ⚠️ Function 'add_argument' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 273** ⚠️ Function 'add_arguments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 280** ⚠️ Function 'format_help' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 292** ⚠️ Function '_format_usage' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 336** ⚠️ Function 'get_lines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 384** ⚠️ Function '_format_actions_usage' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 566** ⚠️ Function 'format' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 805** ⚠️ Class '_StoreAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 840** ⚠️ Class '_StoreConstAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 863** ⚠️ Class '_StoreTrueAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 880** ⚠️ Class '_StoreFalseAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 897** ⚠️ Class '_AppendAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 934** ⚠️ Class '_AppendConstAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 960** ⚠️ Class '_CountAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 981** ⚠️ Class '_HelpAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1000** ⚠️ Class '_VersionAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1025** ⚠️ Class '_SubParsersAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1027** ⚠️ Class '_ChoicesPseudoAction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1054** ⚠️ Function 'add_parser' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1180** ⚠️ Class '_ActionsContainer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1234** ⚠️ Function 'register' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1244** ⚠️ Function 'set_defaults' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1253** ⚠️ Function 'get_default' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1310** ⚠️ Function 'add_argument_group' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1315** ⚠️ Function 'add_mutually_exclusive_group' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1484** ⚠️ Class '_ArgumentGroup' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1518** ⚠️ Class '_MutuallyExclusiveGroup' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1602** ⚠️ Function 'identity' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1649** ⚠️ Function 'add_subparsers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1700** ⚠️ Function 'parse_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1707** ⚠️ Function 'parse_known_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1707** ⚠️ Function 'parse_known_args' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1742** ⚠️ Function '_parse_known_args' has high complexity (34)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1789** ⚠️ Function 'take_action' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1810** ⚠️ Function 'consume_optional' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1887** ⚠️ Function 'consume_positionals' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2017** ⚠️ Function 'convert_arg_line_to_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2055** ⚠️ Function '_parse_optional' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 2200** ⚠️ Function '_get_values' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 2287** ⚠️ Function 'format_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2293** ⚠️ Function 'format_help' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2316** ⚠️ Function 'format_version' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2332** ⚠️ Function 'print_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2337** ⚠️ Function 'print_help' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2342** ⚠️ Function 'print_version' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2359** ⚠️ Function 'exit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ast.py`

- **Line 40** ⚠️ Function 'literal_eval' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 290** ⚠️ Function 'generic_visit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/asynchat.py`

- **Line 111** ❌ multiple exception types must be parenthesized (<unknown>, line 111)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/asyncore.py`

- **Line 115** ❌ multiple exception types must be parenthesized (<unknown>, line 115)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/atexit.py`

- **Line 34** ❌ invalid syntax (<unknown>, line 34)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/base64.py`

- **Line 74** ❌ multiple exception types must be parenthesized (<unknown>, line 74)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/bdb.py`

- **Line 62** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 62)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/binhex.py`

- **Line 192** ❌ invalid syntax (<unknown>, line 192)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/calendar.py`

- **Line 269** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 269)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cgi.py`

- **Line 155** ❌ invalid syntax (<unknown>, line 155)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cgitb.py`

- **Line 47** ⚠️ Function 'small' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Function 'strong' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 59** ⚠️ Function 'grey' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 102** ⚠️ Function 'html' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 133** ⚠️ Function 'reader' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 193** ⚠️ Function 'text' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 217** ⚠️ Function 'reader' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 273** ⚠️ Function 'handle' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 282** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 304** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 313** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/chunk.py`

- **Line 93** ❌ invalid syntax (<unknown>, line 93)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cmd.py`

- **Line 362** ❌ invalid syntax (<unknown>, line 362)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/code.py`

- **Line 103** ❌ Missing parentheses in call to 'exec'. Did you mean exec(...)? (<unknown>, line 103)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/codecs.py`

- **Line 16** ❌ multiple exception types must be parenthesized (<unknown>, line 16)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/codeop.py`

- **Line 86** ❌ invalid syntax (<unknown>, line 86)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/collections.py`

- **Line 355** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 355)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/colorsys.py`

- **Line 37** ⚠️ Function 'rgb_to_yiq' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Function 'yiq_to_rgb' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 67** ⚠️ Function 'rgb_to_hls' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 90** ⚠️ Function 'hls_to_rgb' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 116** ⚠️ Function 'rgb_to_hsv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 135** ⚠️ Function 'hsv_to_rgb' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/commands.py`

- **Line 69** ⚠️ Function 'mk2arg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'mkarg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compileall.py`

- **Line 35** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 35)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/ast.py`

- **Line 7** ⚠️ Function 'flatten' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Function 'flatten_nodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Function 'asList' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 32** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 35** ⚠️ Class 'EmptyNode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Class 'Expression' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 44** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Class 'Add' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 59** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Class 'And' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 73** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 76** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 84** ⚠️ Class 'AssAttr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 91** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 94** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Class 'AssList' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 105** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 116** ⚠️ Class 'AssName' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 122** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 125** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 131** ⚠️ Class 'AssTuple' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 136** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 139** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 147** ⚠️ Class 'Assert' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 153** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 159** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 169** ⚠️ Class 'Assign' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 175** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 181** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 190** ⚠️ Class 'AugAssign' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 197** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 200** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 206** ⚠️ Class 'Backquote' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 211** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 214** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Class 'Bitand' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 225** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 228** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 236** ⚠️ Class 'Bitor' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 241** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 244** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 252** ⚠️ Class 'Bitxor' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 257** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 260** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 268** ⚠️ Class 'Break' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 272** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 275** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 281** ⚠️ Class 'CallFunc' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 289** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 297** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 310** ⚠️ Class 'Class' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 319** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 328** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 339** ⚠️ Class 'Compare' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 345** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 351** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 360** ⚠️ Class 'Const' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 365** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 368** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 374** ⚠️ Class 'Continue' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 378** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 381** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 387** ⚠️ Class 'Decorators' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 392** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 395** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 403** ⚠️ Class 'Dict' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 408** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 411** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 419** ⚠️ Class 'Discard' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 424** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 427** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 433** ⚠️ Class 'Div' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 439** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 442** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 448** ⚠️ Class 'Ellipsis' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 452** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 455** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 461** ⚠️ Class 'Exec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 468** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 475** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 487** ⚠️ Class 'FloorDiv' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 493** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 496** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 502** ⚠️ Class 'For' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 510** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 518** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 530** ⚠️ Class 'From' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 537** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 540** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 546** ⚠️ Class 'Function' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 563** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 574** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 585** ⚠️ Class 'GenExpr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 593** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 596** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 602** ⚠️ Class 'GenExprFor' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 610** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 617** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 627** ⚠️ Class 'GenExprIf' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 632** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 635** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 641** ⚠️ Class 'GenExprInner' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 647** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 653** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 662** ⚠️ Class 'Getattr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 668** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 671** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 677** ⚠️ Class 'Global' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 682** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 685** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 691** ⚠️ Class 'If' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 697** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 703** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 713** ⚠️ Class 'IfExp' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 720** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 723** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 729** ⚠️ Class 'Import' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 734** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 737** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 743** ⚠️ Class 'Invert' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 748** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 751** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 757** ⚠️ Class 'Keyword' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 763** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 766** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 772** ⚠️ Class 'Lambda' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 786** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 794** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 803** ⚠️ Class 'LeftShift' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 809** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 812** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 818** ⚠️ Class 'List' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 823** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 826** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 834** ⚠️ Class 'ListComp' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 840** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 846** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 855** ⚠️ Class 'ListCompFor' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 862** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 869** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 879** ⚠️ Class 'ListCompIf' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 884** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 887** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 893** ⚠️ Class 'SetComp' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 899** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 905** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 914** ⚠️ Class 'DictComp' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 921** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 928** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 938** ⚠️ Class 'Mod' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 944** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 947** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 953** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 959** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 962** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 968** ⚠️ Class 'Mul' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 974** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 977** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 983** ⚠️ Class 'Name' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 988** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 991** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 997** ⚠️ Class 'Not' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1002** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1005** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1011** ⚠️ Class 'Or' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1016** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1019** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1027** ⚠️ Class 'Pass' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1031** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1034** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1040** ⚠️ Class 'Power' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1046** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1049** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1055** ⚠️ Class 'Print' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1061** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1067** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1077** ⚠️ Class 'Printnl' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1083** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1089** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1099** ⚠️ Class 'Raise' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1106** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1113** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1126** ⚠️ Class 'Return' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1131** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1134** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1140** ⚠️ Class 'RightShift' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1146** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1149** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1155** ⚠️ Class 'Set' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1160** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1163** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1171** ⚠️ Class 'Slice' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1179** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1187** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1199** ⚠️ Class 'Sliceobj' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1204** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1207** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1215** ⚠️ Class 'Stmt' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1220** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1223** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1231** ⚠️ Class 'Sub' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1237** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1240** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1246** ⚠️ Class 'Subscript' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1253** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1260** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1269** ⚠️ Class 'TryExcept' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1276** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1283** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1294** ⚠️ Class 'TryFinally' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1300** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1303** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1309** ⚠️ Class 'Tuple' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1314** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1317** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1325** ⚠️ Class 'UnaryAdd' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1330** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1333** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1339** ⚠️ Class 'UnarySub' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1344** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1347** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1353** ⚠️ Class 'While' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1360** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1367** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1378** ⚠️ Class 'With' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1385** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1392** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1403** ⚠️ Class 'Yield' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1408** ⚠️ Function 'getChildren' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1411** ⚠️ Function 'getChildNodes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/future.py`

- **Line 37** ❌ invalid syntax (<unknown>, line 37)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/misc.py`

- **Line 2** ⚠️ Function 'flatten' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 11** ⚠️ Class 'Set' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'add' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 20** ⚠️ Function 'elements' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Function 'has_elt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Function 'remove' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Function 'copy' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Class 'Stack' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 37** ⚠️ Function 'push' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'top' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'mangle' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/pyassem.py`

- **Line 22** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 22)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/pycodegen.py`

- **Line 62** ❌ invalid syntax (<unknown>, line 62)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/symbols.py`

- **Line 56** ❌ invalid syntax (<unknown>, line 56)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/syntax.py`

- **Line 35** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 35)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/transformer.py`

- **Line 90** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 90)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/visitor.py`

- **Line 82** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 82)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/contextlib.py`

- **Line 37** ❌ multiple exception types must be parenthesized (<unknown>, line 37)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cookielib.py`

- **Line 123** ⚠️ Function 'offset_from_tz_string' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 137** ⚠️ Function '_str2time' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 444** ⚠️ Function 'parse_ns_headers' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 619** ⚠️ Function 'request_port' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 637** ⚠️ Function 'uppercase_escaped_char' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 767** ⚠️ Function 'has_nonstandard_attr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 769** ⚠️ Function 'get_nonstandard_attr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 771** ⚠️ Function 'set_nonstandard_attr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 774** ⚠️ Function 'is_expired' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 888** ⚠️ Function 'is_blocked' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 903** ⚠️ Function 'is_not_allowed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 930** ⚠️ Function 'set_ok_version' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 945** ⚠️ Function 'set_ok_verifiability' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 957** ⚠️ Function 'set_ok_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 966** ⚠️ Function 'set_ok_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 977** ⚠️ Function 'set_ok_domain' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 977** ⚠️ Function 'set_ok_domain' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1036** ⚠️ Function 'set_ok_port' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1075** ⚠️ Function 'return_ok_version' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1084** ⚠️ Function 'return_ok_verifiability' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1096** ⚠️ Function 'return_ok_secure' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1102** ⚠️ Function 'return_ok_expires' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1108** ⚠️ Function 'return_ok_port' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1122** ⚠️ Function 'return_ok_domain' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1144** ⚠️ Function 'domain_return_ok' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1166** ⚠️ Function 'path_return_ok' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1175** ⚠️ Function 'vals_sorted_by_key' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1199** ⚠️ Class 'Absent' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1225** ⚠️ Function 'set_policy' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1253** ⚠️ Function '_cookie_attrs' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1345** ⚠️ Function '_normalized_cookie_tuples' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1442** ⚠️ Function '_cookie_from_cookie_tuple' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 1599** ⚠️ Function 'no_matching_rfc2965' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1731** ⚠️ Class 'LoadError' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1746** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/copy.py`

- **Line 370** ❌ invalid decimal literal (<unknown>, line 370)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/copy_reg.py`

- **Line 70** ❌ invalid syntax (<unknown>, line 70)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/crypt.py`

- **Line 9** ⚠️ Function 'crypt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/csv.py`

- **Line 53** ❌ multiple exception types must be parenthesized (<unknown>, line 53)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ctypes/__init__.py`

- **Line 266** ❌ invalid syntax (<unknown>, line 266)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/datetime.py`

- **Line 225** ⚠️ Function '_wrap_strftime' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 402** ⚠️ Class '_tmxxx' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 406** ⚠️ Function '__init__' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 601** ⚠️ Function 'plural' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1707** ⚠️ Function 'astimezone' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dbexts.py`

- **Line 678** ❌ Function parameters cannot be parenthesized (<unknown>, line 678)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/decimal.py`

- **Line 2108** ❌ invalid decimal literal (<unknown>, line 2108)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/difflib.py`

- **Line 920** ❌ invalid syntax (<unknown>, line 920)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dis.py`

- **Line 92** ❌ invalid decimal literal (<unknown>, line 92)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/archive_util.py`

- **Line 73** ❌ invalid syntax (<unknown>, line 73)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/bcppcompiler.py`

- **Line 114** ❌ multiple exception types must be parenthesized (<unknown>, line 114)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/ccompiler.py`

- **Line 880** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 880)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/cmd.py`

- **Line 351** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 351)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist.py`

- **Line 115** ❌ invalid syntax (<unknown>, line 115)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_dumb.py`

- **Line 76** ❌ invalid syntax (<unknown>, line 76)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_msi.py`

- **Line 154** ❌ invalid syntax (<unknown>, line 154)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_rpm.py`

- **Line 193** ❌ invalid syntax (<unknown>, line 193)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_wininst.py`

- **Line 101** ❌ invalid syntax (<unknown>, line 101)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build.py`

- **Line 13** ⚠️ Function 'show_compilers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'build' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 55** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 70** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 70** ⚠️ Function 'finalize_options' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 120** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 131** ⚠️ Function 'has_pure_modules' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 134** ⚠️ Function 'has_c_libraries' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 137** ⚠️ Function 'has_ext_modules' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'has_scripts' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_clib.py`

- **Line 130** ❌ invalid syntax (<unknown>, line 130)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_ext.py`

- **Line 350** ❌ invalid syntax (<unknown>, line 350)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_py.py`

- **Line 16** ⚠️ Class 'build_py' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 184** ⚠️ Function 'check_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 211** ⚠️ Function 'check_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 218** ⚠️ Function 'find_package_modules' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 301** ⚠️ Function 'get_source_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 304** ⚠️ Function 'get_module_outfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 308** ⚠️ Function 'get_outputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 329** ⚠️ Function 'build_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 344** ⚠️ Function 'build_modules' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 354** ⚠️ Function 'build_packages' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 375** ⚠️ Function 'byte_compile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_scripts.py`

- **Line 125** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 125)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/check.py`

- **Line 19** ⚠️ Class 'SilentReporter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'system_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/clean.py`

- **Line 14** ⚠️ Class 'clean' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/config.py`

- **Line 24** ⚠️ Class 'config' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 54** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install.py`

- **Line 569** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 569)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_data.py`

- **Line 14** ⚠️ Class 'install_data' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 44** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'get_inputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'get_outputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_egg_info.py`

- **Line 19** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 32** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'get_outputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_headers.py`

- **Line 12** ⚠️ Class 'install_headers' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 29** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 35** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'get_inputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'get_outputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_lib.py`

- **Line 88** ❌ invalid syntax (<unknown>, line 88)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_scripts.py`

- **Line 54** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 54)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/register.py`

- **Line 153** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 153)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/sdist.py`

- **Line 137** ❌ invalid syntax (<unknown>, line 137)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/upload.py`

- **Line 181** ❌ multiple exception types must be parenthesized (<unknown>, line 181)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/config.py`

- **Line 45** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 45)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/core.py`

- **Line 112** ❌ multiple exception types must be parenthesized (<unknown>, line 112)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/cygwinccompiler.py`

- **Line 159** ❌ multiple exception types must be parenthesized (<unknown>, line 159)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dep_util.py`

- **Line 40** ❌ invalid syntax (<unknown>, line 40)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dir_util.py`

- **Line 19** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 19)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dist.py`

- **Line 418** ❌ multiple exception types must be parenthesized (<unknown>, line 418)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/emxccompiler.py`

- **Line 82** ❌ multiple exception types must be parenthesized (<unknown>, line 82)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/extension.py`

- **Line 139** ⚠️ Function 'read_setup_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 139** ⚠️ Function 'read_setup_file' has high complexity (25)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/fancy_getopt.py`

- **Line 100** ❌ invalid syntax (<unknown>, line 100)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/file_util.py`

- **Line 33** ❌ multiple exception types must be parenthesized (<unknown>, line 33)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/filelist.py`

- **Line 48** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 48)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/log.py`

- **Line 14** ⚠️ Class 'Log' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'log' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'debug' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'info' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'warn' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'error' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'fatal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 59** ⚠️ Function 'set_threshold' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'set_verbosity' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/msvc9compiler.py`

- **Line 507** ❌ multiple exception types must be parenthesized (<unknown>, line 507)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/msvccompiler.py`

- **Line 132** ❌ invalid syntax (<unknown>, line 132)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/spawn.py`

- **Line 46** ❌ invalid syntax (<unknown>, line 46)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/sysconfig.py`

- **Line 31** ⚠️ Function 'getJythonBinDir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 160** ⚠️ Function 'customize_compiler' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 294** ⚠️ Function 'parse_makefile' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/__init__.py`

- **Line 24** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/setuptools_build_ext.py`

- **Line 34** ⚠️ Function 'if_dl' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 44** ⚠️ Class 'build_ext' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 53** ⚠️ Function 'copy_extensions_to_source' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'swig_sources' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Function 'get_ext_filename' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 97** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'setup_shlib_compiler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'setup_shlib_compiler' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 167** ⚠️ Function 'get_export_symbols' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 172** ⚠️ Function 'build_extension' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 196** ⚠️ Function 'get_outputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 208** ⚠️ Function 'write_stub' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 252** ⚠️ Function 'link_shared_object' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 266** ⚠️ Function 'link_shared_object' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/support.py`

- **Line 16** ⚠️ Function 'capture_warnings' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'LoggingSilencer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 26** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'get_logs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'clear_logs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 64** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'ensure_finalized' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 130** ⚠️ Class 'EnvironGuard' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 132** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 136** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_archive_util.py`

- **Line 51** ⚠️ Class 'ArchiveUtilTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 56** ⚠️ Function 'test_make_tarball' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'test_tarfile_vs_tar' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 175** ⚠️ Function 'test_compress_deprecated' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 207** ⚠️ Function 'test_make_zipfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Function 'test_check_archive_formats' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 225** ⚠️ Function 'test_make_archive' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 231** ⚠️ Function 'test_make_archive_owner_group' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 259** ⚠️ Function 'test_tarfile_root_owner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 283** ⚠️ Function 'test_make_archive_cwd' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 291** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 324** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_bdist.py`

- **Line 11** ⚠️ Class 'BuildTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 14** ⚠️ Function 'test_formats' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 29** ⚠️ Function 'test_skip_build' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_bdist_dumb.py`

- **Line 29** ⚠️ Class 'BuildDumbTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'test_simple_built' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 94** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 109** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_bdist_msi.py`

- **Line 9** ⚠️ Class 'BDistMSITestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'test_minimal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_bdist_rpm.py`

- **Line 27** ⚠️ Class 'BuildRpmTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 31** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'test_quiet' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 86** ⚠️ Function 'test_no_optimize_flag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 132** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_bdist_wininst.py`

- **Line 9** ⚠️ Class 'BuildWinInstTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'test_get_exe_bytes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_build.py`

- **Line 11** ⚠️ Class 'BuildTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 15** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_build_clib.py`

- **Line 13** ⚠️ Class 'BuildCLibTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'test_check_library_dist' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'test_get_source_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'test_build_libraries' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Class 'FakeCompiler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 74** ⚠️ Function 'compile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 90** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 105** ⚠️ Function 'test_run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 142** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_build_ext.py`

- **Line 21** ⚠️ Class 'BuildExtTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 44** ⚠️ Function 'test_build_ext' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 86** ⚠️ Function 'test_solaris_enable_shared' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 107** ⚠️ Function 'test_user_site' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 137** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 200** ⚠️ Function 'test_check_extensions_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 247** ⚠️ Function 'test_get_source_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 254** ⚠️ Function 'test_compiler_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 265** ⚠️ Function 'test_get_outputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 328** ⚠️ Function 'test_ext_fullpath' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 362** ⚠️ Function 'test_build_ext_inplace' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 377** ⚠️ Function 'test_setuptools_compat' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 407** ⚠️ Function 'test_build_ext_path_with_os_sep' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 417** ⚠️ Function 'test_build_ext_path_cross_platform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 431** ⚠️ Function 'test_deployment_target_default' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 438** ⚠️ Function 'test_deployment_target_too_low' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 445** ⚠️ Function 'test_deployment_target_higher_ok' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 507** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_build_py.py`

- **Line 15** ⚠️ Class 'BuildPyTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'test_package_data' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'test_empty_package_dir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 96** ⚠️ Function 'test_dont_write_bytecode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 112** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_build_scripts.py`

- **Line 14** ⚠️ Class 'BuildScriptsTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'test_default_settings' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Function 'test_build' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Function 'get_build_scripts_cmd' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'write_sample_scripts' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'write_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'test_version_int' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_ccompiler.py`

- **Line 12** ⚠️ Class 'FakeCompiler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'library_dir_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16** ⚠️ Function 'runtime_library_dir_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Function 'find_library_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Function 'library_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'CCompilerTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'test_gen_lib_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 38** ⚠️ Function 'test_debug_print' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Class 'MyCCompiler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 58** ⚠️ Function 'test_customize_compiler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Class 'compiler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 71** ⚠️ Function 'set_executables' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_check.py`

- **Line 10** ⚠️ Class 'CheckTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 26** ⚠️ Function 'test_check_metadata' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 59** ⚠️ Function 'test_check_document' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Function 'test_check_restructuredtext' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 98** ⚠️ Function 'test_check_all' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 105** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_clean.py`

- **Line 11** ⚠️ Class 'cleanTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 15** ⚠️ Function 'test_simple_run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_cmd.py`

- **Line 11** ⚠️ Class 'MyCmd' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 12** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15** ⚠️ Class 'CommandTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'test_ensure_string_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'test_make_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 52** ⚠️ Function 'test_dump_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'test_ensure_string' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'test_ensure_string_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function 'test_ensure_filename' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'test_ensure_dirname' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 107** ⚠️ Function 'test_debug_print' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 123** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_config.py`

- **Line 51** ⚠️ Class 'PyPIRCCommandTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 64** ⚠️ Class 'command' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 67** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 79** ⚠️ Function 'test_server_registration' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'test_server_empty_registration' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 119** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_config_cmd.py`

- **Line 11** ⚠️ Class 'ConfigTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 29** ⚠️ Function 'test_dump_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Function 'test_search_cpp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 67** ⚠️ Function 'test_clean' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 86** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_core.py`

- **Line 32** ⚠️ Class 'CoreTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'cleanup_testfn' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'write_setup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'test_run_setup_provides_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'test_run_setup_uses_current_dir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 86** ⚠️ Function 'test_debug_mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_dep_util.py`

- **Line 11** ⚠️ Class 'DepUtilTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'test_newer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 32** ⚠️ Function 'test_newer_pairwise' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Function 'test_newer_group' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_dir_util.py`

- **Line 15** ⚠️ Class 'DirUtilTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 33** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'test_mkpath_remove_tree_verbosity' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'test_mkpath_with_custom_mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 67** ⚠️ Function 'test_create_tree_verbosity' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'test_copy_tree_verbosity' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'test_copy_tree_skips_nfs_temp_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'test_ensure_relative' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 130** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_dist.py`

- **Line 25** ⚠️ Function 'initialize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'find_config_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Class 'DistributionTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'create_distribution' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 63** ⚠️ Function 'test_debug_mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 84** ⚠️ Function 'test_command_packages_unspecified' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'test_command_packages_cmdline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'test_command_packages_configfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 130** ⚠️ Function 'test_write_pkg_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 157** ⚠️ Function 'test_empty_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 176** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 187** ⚠️ Function 'test_get_command_packages' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 199** ⚠️ Function 'test_announce' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 206** ⚠️ Function 'test_find_config_files_disable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 236** ⚠️ Class 'MetadataTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 239** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 243** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 248** ⚠️ Function 'test_classifier' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 255** ⚠️ Function 'test_download_url' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 262** ⚠️ Function 'test_long_description' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 277** ⚠️ Function 'test_simple_metadata' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 287** ⚠️ Function 'test_provides' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 301** ⚠️ Function 'test_provides_illegal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 307** ⚠️ Function 'test_requires' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 323** ⚠️ Function 'test_requires_illegal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 329** ⚠️ Function 'test_obsoletes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 345** ⚠️ Function 'test_obsoletes_illegal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 351** ⚠️ Function 'format_metadata' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 356** ⚠️ Function 'test_custom_pydistutils' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 391** ⚠️ Function 'test_fix_help_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 397** ⚠️ Function 'test_show_help' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 410** ⚠️ Function 'test_read_metadata' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 438** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_file_util.py`

- **Line 11** ⚠️ Class 'FileUtilTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 29** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 33** ⚠️ Function 'test_move_file_verbosity' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 61** ⚠️ Function 'test_write_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'test_copy_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_filelist.py`

- **Line 34** ⚠️ Class 'FileListTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 37** ⚠️ Function 'assertNoWarnings' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Function 'assertWarnings' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'test_glob_to_re' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 63** ⚠️ Function 'test_process_template_line' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'test_debug_print' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 117** ⚠️ Function 'test_set_allfiles' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 123** ⚠️ Function 'test_remove_duplicates' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 131** ⚠️ Function 'test_translate_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 152** ⚠️ Function 'test_exclude_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 168** ⚠️ Function 'test_include_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 186** ⚠️ Function 'test_process_template' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 295** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_install.py`

- **Line 28** ⚠️ Class 'InstallTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 32** ⚠️ Function 'test_home_installation_scheme' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'check_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'test_user_site' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'cleanup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'test_handle_extra_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 154** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 175** ⚠️ Function 'test_record' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'test_record_extensions' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 231** ⚠️ Function 'test_debug_mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 243** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_install_data.py`

- **Line 11** ⚠️ Class 'InstallDataTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'test_simple_run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_install_headers.py`

- **Line 11** ⚠️ Class 'InstallHeadersTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'test_simple_run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_install_lib.py`

- **Line 12** ⚠️ Class 'InstallLibTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'test_byte_compile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Function 'test_get_outputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 70** ⚠️ Function 'test_get_inputs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 87** ⚠️ Function 'test_dont_write_bytecode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_install_scripts.py`

- **Line 13** ⚠️ Class 'InstallScriptsTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'test_default_settings' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'test_installation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Function 'write_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_msvc9compiler.py`

- **Line 103** ⚠️ Class 'msvc9compilerTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 106** ⚠️ Function 'test_no_compiler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 123** ⚠️ Function 'test_reg_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 141** ⚠️ Function 'test_remove_visual_c_ref' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 165** ⚠️ Function 'test_remove_entire_manifest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 180** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_register.py`

- **Line 62** ⚠️ Function 'open' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Class 'RegisterTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 71** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 94** ⚠️ Function 'test_create_pypirc' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 149** ⚠️ Function 'test_password_not_in_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 161** ⚠️ Function 'test_registering' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 179** ⚠️ Function 'test_password_reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 198** ⚠️ Function 'test_strict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 264** ⚠️ Function 'test_register_invalid_long_description' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 278** ⚠️ Function 'test_check_metadata_deprecated' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 286** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_sdist.py`

- **Line 57** ⚠️ Class 'SDistTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 59** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function 'test_prune_file_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 136** ⚠️ Function 'test_make_distribution' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 193** ⚠️ Function 'test_add_defaults' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 266** ⚠️ Function 'test_metadata_check_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 288** ⚠️ Function 'test_check_metadata_deprecated' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 296** ⚠️ Function 'test_show_formats' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 306** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 328** ⚠️ Function 'test_make_distribution_owner_group' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 389** ⚠️ Function 'test_invalid_template_unknown_command' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 392** ⚠️ Function 'test_invalid_template_wrong_arguments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 397** ⚠️ Function 'test_invalid_template_wrong_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 403** ⚠️ Function 'test_get_file_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 445** ⚠️ Function 'test_manifest_marker' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 462** ⚠️ Function 'test_manifest_comments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 479** ⚠️ Function 'test_manual_manifest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 508** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_spawn.py`

- **Line 36** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 36)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_sysconfig.py`

- **Line 11** ⚠️ Class 'SysconfigTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Function 'cleanup_testfn' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Function 'test_get_python_lib' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Function 'test_get_python_inc' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'test_parse_makefile_base' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'test_parse_makefile_literal_dollar' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Function 'test_sysconfig_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'test_sysconfig_compiler_vars' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_text_file.py`

- **Line 15** ⚠️ Class 'TextFileTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'test_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'test_input' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_unixccompiler.py`

- **Line 9** ⚠️ Class 'UnixCCompilerTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Class 'CompilerWrapper' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 15** ⚠️ Function 'rpath_foo' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Function 'test_runtime_libdir_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Function 'test_runtime_libdir_option' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 41** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 110** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 120** ⚠️ Function 'gcv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_upload.py`

- **Line 42** ⚠️ Class 'FakeOpen' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 52** ⚠️ Function 'getcode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Class 'uploadTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 58** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 64** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Function 'test_finalize_options' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 84** ⚠️ Function 'test_saved_password' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 101** ⚠️ Function 'test_upload' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 127** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_util.py`

- **Line 9** ⚠️ Class 'UtilTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'test_dont_write_bytecode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_version.py`

- **Line 7** ⚠️ Class 'VersionTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 9** ⚠️ Function 'test_prerelease' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Function 'test_cmp_strict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'test_cmp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 67** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_versionpredicate.py`

- **Line 9** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/text_file.py`

- **Line 85** ❌ invalid syntax (<unknown>, line 85)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/unixccompiler.py`

- **Line 110** ❌ multiple exception types must be parenthesized (<unknown>, line 110)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/util.py`

- **Line 201** ❌ invalid syntax (<unknown>, line 201)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/version.py`

- **Line 107** ❌ invalid syntax (<unknown>, line 107)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/doctest.py`

- **Line 367** ❌ invalid syntax (<unknown>, line 367)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dumbdbm.py`

- **Line 225** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 225)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dummy_thread.py`

- **Line 50** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 130** ⚠️ Function 'locked' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/__init__.py`

- **Line 74** ⚠️ Class 'LazyImporter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/_parseaddr.py`

- **Line 45** ⚠️ Function 'parsedate_tz' has high complexity (25)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 225** ⚠️ Function 'getaddress' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/feedparser.py`

- **Line 61** ⚠️ Function 'push_eof_matcher' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 64** ⚠️ Function 'pop_eof_matcher' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 67** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'readline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 91** ⚠️ Function 'unreadline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 119** ⚠️ Function 'pushlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 123** ⚠️ Function 'is_closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 195** ⚠️ Function '_parsegen' has high complexity (54)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 431** ⚠️ Function '_parse_headers' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/generator.py`

- **Line 63** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 185** ⚠️ Function '_handle_multipart' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/header.py`

- **Line 61** ⚠️ Function 'decode_header' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 144** ⚠️ Class 'Header' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 418** ⚠️ Function '_split_ascii' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/message.py`

- **Line 147** ⚠️ Function 'set_unixfrom' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 150** ⚠️ Function 'get_unixfrom' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/mime/nonmultipart.py`

- **Line 17** ⚠️ Function 'attach' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/parser.py`

- **Line 17** ⚠️ Class 'Parser' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 86** ⚠️ Class 'HeaderParser' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 87** ⚠️ Function 'parse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 90** ⚠️ Function 'parsestr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/quoprimime.py`

- **Line 109** ⚠️ Function 'quote' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 178** ⚠️ Function 'encode' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email.py`

- **Line 61** ❌ invalid syntax (<unknown>, line 61)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_codecs.py`

- **Line 22** ⚠️ Class 'TestEmailAsianCodecs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'test_japanese_codecs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 55** ⚠️ Function 'test_payload_encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'test_main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_codecs_renamed.py`

- **Line 22** ⚠️ Class 'TestEmailAsianCodecs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'test_japanese_codecs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 55** ⚠️ Function 'test_payload_encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'test_main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_renamed.py`

- **Line 61** ❌ invalid syntax (<unknown>, line 61)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_torture.py`

- **Line 22** ⚠️ Function 'openfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 35** ⚠️ Class 'TortureBase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Class 'TestCrispinTorture' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 48** ⚠️ Function 'test_mondo_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Function 'test_main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/utils.py`

- **Line 202** ⚠️ Function 'parsedate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 208** ⚠️ Function 'parsedate_tz' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 214** ⚠️ Function 'parseaddr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 313** ⚠️ Function 'collapse_rfc2231_value' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/__init__.py`

- **Line 133** ❌ invalid syntax (<unknown>, line 133)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/_java.py`

- **Line 47** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 52** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 94** ⚠️ Class 'NonfinalCodec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 96** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 109** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 130** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 140** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 163** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 167** ⚠️ Function 'getstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 171** ⚠️ Function 'setstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 177** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 184** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/ascii.py`

- **Line 13** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 31** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Class 'StreamConverter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/base64_codec.py`

- **Line 45** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 47** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 52** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 53** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 58** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 65** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 70** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/big5.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/big5hkscs.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/bz2_codec.py`

- **Line 47** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 49** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 60** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 67** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 70** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 76** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 82** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 88** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 93** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/charmap.py`

- **Line 17** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 32** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 37** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 55** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 60** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp037.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1006.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1026.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1140.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1250.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1251.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1252.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1253.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1254.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1255.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1256.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1257.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1258.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp424.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp437.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp500.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp720.py`

- **Line 11** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 35** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp737.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp775.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp850.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp852.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp855.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp856.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp857.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp858.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp860.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp861.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp862.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp863.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp864.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp865.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp866.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp869.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp874.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp875.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp932.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp949.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp950.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_jis_2004.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_jisx0213.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_jp.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_kr.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/gb18030.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/gb2312.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/gbk.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/hex_codec.py`

- **Line 45** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 47** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 52** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 53** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 58** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 65** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 70** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/hp_roman8.py`

- **Line 14** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/hz.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/idna.py`

- **Line 20** ❌ multiple exception types must be parenthesized (<unknown>, line 20)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_1.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_2.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_2004.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_3.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_ext.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_kr.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_1.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_10.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_11.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_13.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_14.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_15.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_16.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_2.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_3.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_4.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_5.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_6.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_7.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_8.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_9.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/johab.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/koi8_r.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/koi8_u.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/latin_1.py`

- **Line 13** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 31** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Class 'StreamConverter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_arabic.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_centeuro.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_croatian.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_cyrillic.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_farsi.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_greek.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_iceland.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_latin2.py`

- **Line 14** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_roman.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_romanian.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_turkish.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mbcs.py`

- **Line 20** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 27** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/palmos.py`

- **Line 11** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 12** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/ptcp154.py`

- **Line 14** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/punycode.py`

- **Line 140** ❌ invalid syntax (<unknown>, line 140)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/quopri_codec.py`

- **Line 43** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 45** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 51** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 55** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 61** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 66** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/raw_unicode_escape.py`

- **Line 13** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 31** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 36** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/rot_13.py`

- **Line 14** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 113** ⚠️ Function 'rot13' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/shift_jis.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/shift_jis_2004.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/shift_jisx0213.py`

- **Line 12** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/string_escape.py`

- **Line 10** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 15** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 26** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/tis_620.py`

- **Line 9** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/undefined.py`

- **Line 16** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 32** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 35** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 40** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/unicode_escape.py`

- **Line 13** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 31** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 36** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/unicode_internal.py`

- **Line 13** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 31** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 36** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_16.py`

- **Line 112** ❌ invalid syntax (<unknown>, line 112)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_16_be.py`

- **Line 15** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_16_le.py`

- **Line 15** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_32.py`

- **Line 136** ❌ invalid syntax (<unknown>, line 136)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_32_be.py`

- **Line 10** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 13** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 14** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_32_le.py`

- **Line 10** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 13** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 14** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_7.py`

- **Line 11** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 15** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_8.py`

- **Line 15** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_8_sig.py`

- **Line 14** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Function 'getstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 44** ⚠️ Function 'setstate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 68** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 73** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 84** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 85** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 92** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/uu_codec.py`

- **Line 15** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 15)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/zlib_codec.py`

- **Line 46** ⚠️ Class 'Codec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 48** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Class 'IncrementalEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 59** ⚠️ Function 'encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Class 'IncrementalDecoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 75** ⚠️ Function 'decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 82** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Class 'StreamWriter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 88** ⚠️ Class 'StreamReader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 93** ⚠️ Function 'getregentry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/filecmp.py`

- **Line 150** ❌ multiple exception types must be parenthesized (<unknown>, line 150)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fileinput.py`

- **Line 102** ❌ invalid syntax (<unknown>, line 102)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fnmatch.py`

- **Line 81** ⚠️ Function 'translate' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/formatter.py`

- **Line 327** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 327)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fpformat.py`

- **Line 42** ❌ invalid syntax (<unknown>, line 42)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fractions.py`

- **Line 68** ⚠️ Function '__new__' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 262** ⚠️ Function 'numerator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 266** ⚠️ Function 'denominator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 360** ⚠️ Function 'forward' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 372** ⚠️ Function 'reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ftplib.py`

- **Line 145** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 145)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/functools.py`

- **Line 82** ⚠️ Class 'K' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/future_builtins.py`

- **Line 25** ⚠️ Function 'hex' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Function 'oct' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/getopt.py`

- **Line 210** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 210)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/getpass.py`

- **Line 30** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 49** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 89** ⚠️ Function 'default_getpass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/gettext.py`

- **Line 259** ❌ invalid hexadecimal literal (<unknown>, line 259)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/glob.py`

- **Line 13** ⚠️ Class '_unicode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 66** ⚠️ Function 'glob1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'glob0' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 94** ⚠️ Function 'has_magic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/grp.py`

- **Line 24** ❌ invalid syntax (<unknown>, line 24)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/gzip.py`

- **Line 158** ❌ invalid hexadecimal literal (<unknown>, line 158)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/heapq.py`

- **Line 477** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 477)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/htmllib.py`

- **Line 471** ❌ multiple exception types must be parenthesized (<unknown>, line 471)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/httplib.py`

- **Line 408** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 408)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ihooks.py`

- **Line 92** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 92)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imaplib.py`

- **Line 870** ❌ multiple exception types must be parenthesized (<unknown>, line 870)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imghdr.py`

- **Line 147** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 147)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imp.py`

- **Line 11** ⚠️ Class 'NullImporter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'find_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/inspect.py`

- **Line 478** ⚠️ Function 'getmodule' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 524** ⚠️ Function 'findsource' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 591** ⚠️ Function 'getcomments' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 636** ⚠️ Class 'EndOfBlock' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 647** ⚠️ Function 'tokeneater' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 647** ⚠️ Function 'tokeneater' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 843** ⚠️ Function 'joinseq' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 894** ⚠️ Function 'convert' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 906** ⚠️ Function 'getcallargs' has high complexity (24)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 918** ⚠️ Function 'assign' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 937** ⚠️ Function 'is_assigned' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/io.py`

- **Line 87** ⚠️ Class 'IOBase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 90** ⚠️ Class 'RawIOBase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 93** ⚠️ Class 'BufferedIOBase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 96** ⚠️ Class 'TextIOBase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/isql.py`

- **Line 50** ❌ invalid syntax (<unknown>, line 50)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/javapath.py`

- **Line 32** ❌ invalid syntax (<unknown>, line 32)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/javashell.py`

- **Line 30** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 30)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/__init__.py`

- **Line 125** ❌ (unicode error) 'unicodeescape' codec can't decode bytes in position 421-422: truncated \uXXXX escape (<unknown>, line 125)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/decoder.py`

- **Line 27** ⚠️ Function 'linecol' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'errmsg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'py_scanstring' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 149** ⚠️ Function 'JSONObject' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 149** ⚠️ Function 'JSONObject' has high complexity (24)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 237** ⚠️ Function 'JSONArray' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 237** ⚠️ Function 'JSONArray' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/encoder.py`

- **Line 104** ❌ (unicode error) 'unicodeescape' codec can't decode bytes in position 362-363: truncated \uXXXX escape (<unknown>, line 104)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/scanner.py`

- **Line 15** ⚠️ Function 'py_make_scanner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15** ⚠️ Function 'py_make_scanner' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 28** ⚠️ Function '_scan_once' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/__init__.py`

- **Line 14** ⚠️ Class 'PyTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Class 'CTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Class 'TestPyTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Function 'test_pyjson' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Class 'TestCTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 37** ⚠️ Function 'test_cjson' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'test_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Function 'additional_tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_check_circular.py`

- **Line 4** ⚠️ Function 'default_iterable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 7** ⚠️ Class 'TestCheckCircular' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 8** ⚠️ Function 'test_circular_dict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 13** ⚠️ Function 'test_circular_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Function 'test_circular_composite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Function 'test_circular_default' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 28** ⚠️ Function 'test_circular_off_default' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 33** ⚠️ Class 'TestPyCheckCircular' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Class 'TestCCheckCircular' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_decode.py`

- **Line 7** ⚠️ Class 'TestDecode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 8** ⚠️ Function 'test_decimal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 13** ⚠️ Function 'test_float' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Function 'test_decoder_optimizations' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Function 'test_empty_objects' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Function 'test_object_pairs_hook' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'test_extra_data' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Function 'test_invalid_escape' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Class 'TestPyDecode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 59** ⚠️ Class 'TestCDecode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_default.py`

- **Line 4** ⚠️ Class 'TestDefault' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 5** ⚠️ Function 'test_default' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 11** ⚠️ Class 'TestPyDefault' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 12** ⚠️ Class 'TestCDefault' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_dump.py`

- **Line 19** ❌ invalid decimal literal (<unknown>, line 19)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_dunderdict.py`

- **Line 32** ❌ invalid decimal literal (<unknown>, line 32)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_encode_basestring_ascii.py`

- **Line 24** ⚠️ Class 'TestEncodeBasestringAscii' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'test_encode_basestring_ascii' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 33** ⚠️ Function 'test_ordered_dict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Class 'TestPyEncodeBasestringAscii' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Class 'TestCEncodeBasestringAscii' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_fail.py`

- **Line 80** ⚠️ Class 'TestFail' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 81** ⚠️ Function 'test_failures' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 94** ⚠️ Function 'test_non_string_keys_dict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Class 'TestPyFail' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 105** ⚠️ Class 'TestCFail' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_float.py`

- **Line 14** ❌ invalid decimal literal (<unknown>, line 14)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_indent.py`

- **Line 6** ⚠️ Class 'TestIndent' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 7** ⚠️ Function 'test_indent' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Function 'test_indent0' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'check' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 59** ⚠️ Class 'TestPyIndent' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 60** ⚠️ Class 'TestCIndent' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_pass1.py`

- **Line 66** ⚠️ Class 'TestPass1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 67** ⚠️ Function 'test_parse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 74** ⚠️ Class 'TestPyPass1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 75** ⚠️ Class 'TestCPass1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_pass2.py`

- **Line 9** ⚠️ Class 'TestPass2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 10** ⚠️ Function 'test_parse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Class 'TestPyPass2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Class 'TestCPass2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_pass3.py`

- **Line 15** ⚠️ Class 'TestPass3' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'test_parse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Class 'TestPyPass3' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Class 'TestCPass3' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_recursion.py`

- **Line 6** ⚠️ Class 'JSONTestObject' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 10** ⚠️ Class 'TestRecursion' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'test_listrecursion' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 34** ⚠️ Function 'test_dictrecursion' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'test_defaultrecursion' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Class 'RecursiveJSONEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 51** ⚠️ Function 'default' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'test_highly_nested_objects_decoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 90** ⚠️ Function 'test_highly_nested_objects_encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 101** ⚠️ Function 'test_endless_recursion' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Class 'EndlessJSONEncoder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 116** ⚠️ Class 'TestPyRecursion' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 117** ⚠️ Class 'TestCRecursion' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_scanstring.py`

- **Line 5** ⚠️ Class 'TestScanstring' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 6** ⚠️ Function 'test_scanstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 97** ⚠️ Function 'test_issue3623' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'test_overflow' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Class 'TestPyScanstring' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 109** ⚠️ Class 'TestCScanstring' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_separators.py`

- **Line 5** ⚠️ Class 'TestSeparators' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 6** ⚠️ Function 'test_separators' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Class 'TestPySeparators' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 44** ⚠️ Class 'TestCSeparators' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_speedups.py`

- **Line 4** ⚠️ Class 'TestSpeedups' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 5** ⚠️ Function 'test_scanstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 9** ⚠️ Function 'test_encode_basestring_ascii' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15** ⚠️ Class 'TestDecode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'test_make_scanner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 19** ⚠️ Function 'test_make_encoder' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_tool.py`

- **Line 9** ⚠️ Class 'TestTool' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Function 'test_stdin_stdout' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 61** ⚠️ Function 'test_infile_stdout' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 67** ⚠️ Function 'test_infile_outfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_unicode.py`

- **Line 5** ⚠️ Class 'TestUnicode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 6** ⚠️ Function 'test_encoding1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'test_encoding2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'test_encoding3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Function 'test_encoding4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Function 'test_encoding5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'test_encoding6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Function 'test_big_unicode_encode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'test_big_unicode_decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'test_unicode_decode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Function 'test_object_pairs_hook_with_unicode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Function 'test_default_encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 76** ⚠️ Function 'test_unicode_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 83** ⚠️ Function 'test_bad_encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 88** ⚠️ Class 'TestPyUnicode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 89** ⚠️ Class 'TestCUnicode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tool.py`

- **Line 31** ❌ multiple exception types must be parenthesized (<unknown>, line 31)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/keyword.py`

- **Line 53** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/btm_matcher.py`

- **Line 83** ⚠️ Function 'run' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 147** ⚠️ Function 'print_node' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 160** ⚠️ Function 'type_repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/btm_utils.py`

- **Line 104** ⚠️ Function 'reduce_tree' has high complexity (35)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixer_base.py`

- **Line 119** ⚠️ Function 'log_message' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 178** ⚠️ Function 'start_tree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 182** ⚠️ Function 'should_skip' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixer_util.py`

- **Line 17** ⚠️ Function 'KeywordArg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'LParen' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Function 'RParen' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 76** ⚠️ Function 'Number' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 163** ⚠️ Function 'parenthesize' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 264** ⚠️ Function 'make_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 297** ⚠️ Function 'is_import_stmt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 340** ⚠️ Function 'find_binding' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 393** ⚠️ Function '_is_import_binding' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_apply.py`

- **Line 14** ⚠️ Class 'FixApply' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 31** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_basestring.py`

- **Line 8** ⚠️ Class 'FixBasestring' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_buffer.py`

- **Line 11** ⚠️ Class 'FixBuffer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_callable.py`

- **Line 13** ⚠️ Class 'FixCallable' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 30** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_dict.py`

- **Line 42** ⚠️ Class 'FixDict' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 55** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 91** ⚠️ Function 'in_special_context' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_except.py`

- **Line 30** ⚠️ Function 'find_excepts' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Class 'FixExcept' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 47** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_exec.py`

- **Line 18** ⚠️ Class 'FixExec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_execfile.py`

- **Line 15** ⚠️ Class 'FixExecfile' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_exitfunc.py`

- **Line 11** ⚠️ Class 'FixExitfunc' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 33** ⚠️ Function 'start_tree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_filter.py`

- **Line 21** ⚠️ Class 'FixFilter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 53** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_funcattrs.py`

- **Line 9** ⚠️ Class 'FixFuncattrs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_future.py`

- **Line 11** ⚠️ Class 'FixFuture' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_getcwdu.py`

- **Line 10** ⚠️ Class 'FixGetcwdu' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_has_key.py`

- **Line 39** ⚠️ Class 'FixHasKey' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 72** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_idioms.py`

- **Line 37** ⚠️ Class 'FixIdioms' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 79** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 90** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'transform_isinstance' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 112** ⚠️ Function 'transform_while' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 116** ⚠️ Function 'transform_sort' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_import.py`

- **Line 38** ⚠️ Class 'FixImport' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 47** ⚠️ Function 'start_tree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Function 'probably_a_local_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_imports.py`

- **Line 61** ⚠️ Function 'alternates' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'build_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Class 'FixImports' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 96** ⚠️ Function 'build_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 99** ⚠️ Function 'compile_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 118** ⚠️ Function 'start_tree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_imports2.py`

- **Line 12** ⚠️ Class 'FixImports2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_input.py`

- **Line 13** ⚠️ Class 'FixInput' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_intern.py`

- **Line 14** ⚠️ Class 'FixIntern' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_isinstance.py`

- **Line 16** ⚠️ Class 'FixIsinstance' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 29** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_itertools.py`

- **Line 14** ⚠️ Class 'FixItertools' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 28** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_itertools_imports.py`

- **Line 8** ⚠️ Class 'FixItertoolsImports' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 14** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'transform' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_long.py`

- **Line 12** ⚠️ Class 'FixLong' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 16** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_map.py`

- **Line 28** ⚠️ Class 'FixMap' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 59** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_metaclass.py`

- **Line 95** ⚠️ Function 'remove_trailing_newline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'find_metas' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 145** ⚠️ Class 'FixMetaclass' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 152** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_methodattrs.py`

- **Line 15** ⚠️ Class 'FixMethodattrs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_ne.py`

- **Line 12** ⚠️ Class 'FixNe' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_next.py`

- **Line 17** ⚠️ Class 'FixNext' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 36** ⚠️ Function 'start_tree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'is_assign_target' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function 'find_assign' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'is_subtree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_nonzero.py`

- **Line 8** ⚠️ Class 'FixNonzero' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_numliterals.py`

- **Line 12** ⚠️ Class 'FixNumliterals' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_operator.py`

- **Line 17** ⚠️ Function 'invocation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Function 'dec' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'FixOperator' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_paren.py`

- **Line 12** ⚠️ Class 'FixParen' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 37** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_print.py`

- **Line 29** ⚠️ Class 'FixPrint' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 37** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'add_kwarg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_raise.py`

- **Line 31** ⚠️ Class 'FixRaise' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_raw_input.py`

- **Line 8** ⚠️ Class 'FixRawInput' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 15** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_reduce.py`

- **Line 15** ⚠️ Class 'FixReduce' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_renames.py`

- **Line 17** ⚠️ Function 'alternates' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'build_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Class 'FixRenames' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 49** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_repr.py`

- **Line 11** ⚠️ Class 'FixRepr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_set_literal.py`

- **Line 12** ⚠️ Class 'FixSetLiteral' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_standarderror.py`

- **Line 11** ⚠️ Class 'FixStandarderror' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 17** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_sys_exc.py`

- **Line 14** ⚠️ Class 'FixSysExc' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 22** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_throw.py`

- **Line 16** ⚠️ Class 'FixThrow' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 26** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_tuple_params.py`

- **Line 27** ⚠️ Function 'is_docstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Class 'FixTupleParams' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'transform' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 67** ⚠️ Function 'handle_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 110** ⚠️ Function 'transform_lambda' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 139** ⚠️ Function 'simplify_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 150** ⚠️ Function 'find_params' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 157** ⚠️ Function 'map_to_index' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 168** ⚠️ Function 'tuple_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_types.py`

- **Line 54** ⚠️ Class 'FixTypes' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 58** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_unicode.py`

- **Line 10** ❌ invalid syntax (<unknown>, line 10)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_urllib.py`

- **Line 49** ⚠️ Function 'build_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Class 'FixUrllib' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 74** ⚠️ Function 'build_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function 'transform_member' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 141** ⚠️ Function 'handle_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 186** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_ws_comma.py`

- **Line 12** ⚠️ Class 'FixWsComma' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_xrange.py`

- **Line 12** ⚠️ Class 'FixXrange' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Function 'start_tree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Function 'finish_tree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 27** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'transform_xrange' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'transform_range' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 63** ⚠️ Function 'in_special_context' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_xreadlines.py`

- **Line 11** ⚠️ Class 'FixXreadlines' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_zip.py`

- **Line 14** ⚠️ Class 'FixZip' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/main.py`

- **Line 93** ❌ multiple exception types must be parenthesized (<unknown>, line 93)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/patcomp.py`

- **Line 29** ⚠️ Class 'PatternSyntaxError' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 43** ⚠️ Class 'PatternCompiler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 68** ⚠️ Function 'compile_node' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 139** ⚠️ Function 'compile_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 139** ⚠️ Function 'compile_basic' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 174** ⚠️ Function 'get_int' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 204** ⚠️ Function 'compile_pattern' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/conv.py`

- **Line 63** ❌ multiple exception types must be parenthesized (<unknown>, line 63)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/driver.py`

- **Line 126** ❌ multiple exception types must be parenthesized (<unknown>, line 126)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/grammar.py`

- **Line 116** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 116)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/literals.py`

- **Line 56** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 56)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/pgen.py`

- **Line 206** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 206)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/token.py`

- **Line 75** ⚠️ Function 'ISTERMINAL' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'ISNONTERMINAL' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'ISEOF' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/tokenize.py`

- **Line 157** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 157)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pygram.py`

- **Line 20** ⚠️ Class 'Symbols' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pytree.py`

- **Line 22** ⚠️ Function 'type_repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 164** ⚠️ Function 'changed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 215** ⚠️ Function 'leaves' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Function 'depth' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 406** ⚠️ Function 'leaves' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 534** ⚠️ Class 'LeafPattern' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 578** ⚠️ Class 'NodePattern' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 722** ⚠️ Function 'generate_matches' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 827** ⚠️ Class 'NegatedPattern' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 842** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 846** ⚠️ Function 'match_seq' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 850** ⚠️ Function 'generate_matches' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/refactor.py`

- **Line 46** ⚠️ Class '_EveryNode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 130** ⚠️ Function '_detect_future_features' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 133** ⚠️ Function 'advance' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 174** ⚠️ Class 'RefactoringTool' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 284** ⚠️ Function 'log_debug' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 389** ⚠️ Function 'refactor_stdin' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 405** ⚠️ Function 'refactor_tree' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 624** ⚠️ Function 'summarize' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 691** ⚠️ Class 'MultiprocessingUnsupported' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 695** ⚠️ Class 'MultiprocessRefactoringTool' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 702** ⚠️ Function 'refactor' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 742** ⚠️ Function 'refactor_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/bom.py`

- **Line 1** ❌ invalid non-printable character U+FEFF (<unknown>, line 1)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/crlf.py`

- **Line 1** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 1)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/different_encoding.py`

- **Line 3** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 3)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/bad_order.py`

- **Line 3** ⚠️ Class 'FixBadOrder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_explicit.py`

- **Line 3** ⚠️ Class 'FixExplicit' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 6** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_first.py`

- **Line 3** ⚠️ Class 'FixFirst' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 6** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_last.py`

- **Line 3** ⚠️ Class 'FixLast' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 7** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_parrot.py`

- **Line 11** ⚠️ Function 'transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_preorder.py`

- **Line 3** ⚠️ Class 'FixPreorder' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 6** ⚠️ Function 'match' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/parrot_example.py`

- **Line 1** ⚠️ Function 'parrot' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/infinite_recursion.py`

- **Line 33** ⚠️ Class '__mbstate_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 54** ⚠️ Class 'sigcontext' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 94** ⚠️ Class 'aes_key_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 103** ⚠️ Class 'asn1_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 121** ⚠️ Class 'asn1_object_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 134** ⚠️ Class 'asn1_string_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 145** ⚠️ Class 'ASN1_ENCODING_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 155** ⚠️ Class 'asn1_string_table_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 167** ⚠️ Class 'ASN1_TEMPLATE_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 172** ⚠️ Class 'ASN1_ITEM_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 177** ⚠️ Class 'ASN1_TLC_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 182** ⚠️ Class 'ASN1_VALUE_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 188** ⚠️ Class 'asn1_type_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 190** ⚠️ Class 'N12asn1_type_st4DOLLAR_11E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 238** ⚠️ Class 'asn1_method_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 249** ⚠️ Class 'asn1_header_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 259** ⚠️ Class 'BIT_STRING_BITNAME_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 269** ⚠️ Class 'bio_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 273** ⚠️ Class 'bio_method_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 290** ⚠️ Class 'crypto_ex_data_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 292** ⚠️ Class 'stack_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 321** ⚠️ Class 'bio_f_buffer_ctx_struct' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 336** ⚠️ Class 'hostent' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 340** ⚠️ Class 'bf_key_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 349** ⚠️ Class 'bignum_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 361** ⚠️ Class 'bignum_ctx' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 366** ⚠️ Class 'bn_blinding_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 378** ⚠️ Class 'bn_mont_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 391** ⚠️ Class 'bn_recp_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 403** ⚠️ Class 'buf_mem_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 413** ⚠️ Class 'cast_key_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 422** ⚠️ Class 'comp_method_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 437** ⚠️ Class 'comp_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 450** ⚠️ Class 'CRYPTO_dynlock_value' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 454** ⚠️ Class 'CRYPTO_dynlock' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 466** ⚠️ Class 'crypto_ex_data_func_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 478** ⚠️ Class 'st_CRYPTO_EX_DATA_IMPL' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 486** ⚠️ Class 'DES_ks' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 488** ⚠️ Class 'N6DES_ks3DOLLAR_9E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 503** ⚠️ Class '_ossl_old_des_ks_struct' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 505** ⚠️ Class 'N23_ossl_old_des_ks_struct4DOLLAR_10E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 519** ⚠️ Class 'dh_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 522** ⚠️ Class 'dh_method' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 537** ⚠️ Class 'engine_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 562** ⚠️ Class 'dsa_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 565** ⚠️ Class 'DSA_SIG_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 574** ⚠️ Class 'dsa_method' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 611** ⚠️ Class 'evp_pkey_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 613** ⚠️ Class 'N11evp_pkey_st4DOLLAR_12E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 615** ⚠️ Class 'rsa_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 635** ⚠️ Class 'env_md_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 637** ⚠️ Class 'env_md_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 667** ⚠️ Class 'evp_cipher_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 669** ⚠️ Class 'evp_cipher_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 689** ⚠️ Class 'evp_cipher_info_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 718** ⚠️ Class 'evp_Encode_Ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 731** ⚠️ Class 'lhash_node_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 745** ⚠️ Class 'lhash_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 776** ⚠️ Class 'MD2state_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 787** ⚠️ Class 'MD4state_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 802** ⚠️ Class 'MD5state_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 817** ⚠️ Class 'mdc2_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 829** ⚠️ Class 'obj_name_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 843** ⚠️ Class 'x509_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 846** ⚠️ Class 'X509_algor_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 849** ⚠️ Class 'X509_crl_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 852** ⚠️ Class 'X509_name_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 855** ⚠️ Class 'x509_store_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 858** ⚠️ Class 'x509_store_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 863** ⚠️ Class 'PEM_Encode_Seal_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 873** ⚠️ Class 'pem_recip_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 884** ⚠️ Class 'pem_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 886** ⚠️ Class 'N10pem_ctx_st4DOLLAR_16E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 894** ⚠️ Class 'N10pem_ctx_st4DOLLAR_17E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 925** ⚠️ Class 'pkcs7_issuer_and_serial_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 934** ⚠️ Class 'pkcs7_signer_info_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 949** ⚠️ Class 'pkcs7_recip_info_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 961** ⚠️ Class 'pkcs7_signed_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 963** ⚠️ Class 'pkcs7_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 976** ⚠️ Class 'pkcs7_enc_content_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 987** ⚠️ Class 'pkcs7_enveloped_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 997** ⚠️ Class 'pkcs7_signedandenveloped_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1011** ⚠️ Class 'pkcs7_digest_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1022** ⚠️ Class 'pkcs7_encrypted_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1031** ⚠️ Class 'N8pkcs7_st4DOLLAR_15E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1056** ⚠️ Class 'rc2_key_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1064** ⚠️ Class 'rc4_key_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1074** ⚠️ Class 'rc5_key_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1083** ⚠️ Class 'RIPEMD160state_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1100** ⚠️ Class 'rsa_meth_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1145** ⚠️ Class 'SHAstate_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1161** ⚠️ Class 'ssl_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1164** ⚠️ Class 'ssl_cipher_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1182** ⚠️ Class 'ssl_ctx_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1185** ⚠️ Class 'ssl_method_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1187** ⚠️ Class 'ssl3_enc_method' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1221** ⚠️ Class 'ssl_session_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1223** ⚠️ Class 'sess_cert_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1256** ⚠️ Class 'ssl_comp_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1266** ⚠️ Class 'N10ssl_ctx_st4DOLLAR_18E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1283** ⚠️ Class 'cert_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1335** ⚠️ Class 'ssl2_state_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1337** ⚠️ Class 'ssl3_state_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1402** ⚠️ Class 'N13ssl2_state_st4DOLLAR_19E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1458** ⚠️ Class 'ssl3_record_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1471** ⚠️ Class 'ssl3_buffer_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1483** ⚠️ Class 'N13ssl3_state_st4DOLLAR_20E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1560** ⚠️ Class 'ui_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1565** ⚠️ Class 'ui_method_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1570** ⚠️ Class 'ui_string_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1578** ⚠️ Class 'X509_objects_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1594** ⚠️ Class 'X509_val_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1603** ⚠️ Class 'X509_pubkey_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1613** ⚠️ Class 'X509_sig_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1622** ⚠️ Class 'X509_name_entry_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1641** ⚠️ Class 'X509_extension_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1651** ⚠️ Class 'x509_attributes_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1653** ⚠️ Class 'N18x509_attributes_st4DOLLAR_13E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1670** ⚠️ Class 'X509_req_info_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1682** ⚠️ Class 'X509_req_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1693** ⚠️ Class 'x509_cinf_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1710** ⚠️ Class 'x509_cert_aux_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1722** ⚠️ Class 'AUTHORITY_KEYID_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1746** ⚠️ Class 'x509_trust_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1759** ⚠️ Class 'X509_revoked_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1770** ⚠️ Class 'X509_crl_info_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1793** ⚠️ Class 'private_key_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1809** ⚠️ Class 'X509_info_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1823** ⚠️ Class 'Netscape_spkac_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1832** ⚠️ Class 'Netscape_spki_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1842** ⚠️ Class 'Netscape_certificate_sequence' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1851** ⚠️ Class 'PBEPARAM_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1860** ⚠️ Class 'PBE2PARAM_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1869** ⚠️ Class 'PBKDF2PARAM_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1880** ⚠️ Class 'pkcs8_priv_key_info_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1892** ⚠️ Class 'x509_hash_dir_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1903** ⚠️ Class 'x509_file_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1914** ⚠️ Class 'x509_object_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1916** ⚠️ Class 'N14x509_object_st4DOLLAR_14E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1933** ⚠️ Class 'x509_lookup_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1936** ⚠️ Class 'x509_lookup_method_st' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2020** ⚠️ Class '__sbuf' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2028** ⚠️ Class '__sFILEX' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2032** ⚠️ Class '__sFILE' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2062** ⚠️ Class 'div_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2070** ⚠️ Class 'ldiv_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2078** ⚠️ Class 'lldiv_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2091** ⚠️ Class 'mcontext' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2095** ⚠️ Class 'mcontext64' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2099** ⚠️ Class '__darwin_pthread_handler_rec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2108** ⚠️ Class '_opaque_pthread_attr_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2116** ⚠️ Class '_opaque_pthread_cond_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2124** ⚠️ Class '_opaque_pthread_condattr_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2132** ⚠️ Class '_opaque_pthread_mutex_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2140** ⚠️ Class '_opaque_pthread_mutexattr_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2148** ⚠️ Class '_opaque_pthread_once_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2156** ⚠️ Class '_opaque_pthread_rwlock_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2164** ⚠️ Class '_opaque_pthread_rwlockattr_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2172** ⚠️ Class '_opaque_pthread_t' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2208** ⚠️ Class 'sigaltstack' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2218** ⚠️ Class 'ucontext' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2231** ⚠️ Class 'ucontext64' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2244** ⚠️ Class 'timeval' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2253** ⚠️ Class 'rusage' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2275** ⚠️ Class 'rlimit' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2291** ⚠️ Class 'sigval' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2299** ⚠️ Class 'sigevent' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2310** ⚠️ Class '__siginfo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2328** ⚠️ Class '__sigaction_u' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2336** ⚠️ Class '__sigaction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2346** ⚠️ Class 'sigaction' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2357** ⚠️ Class 'sigvec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2366** ⚠️ Class 'sigstack' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2402** ⚠️ Class 'fd_set' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2424** ⚠️ Class 'wait' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2426** ⚠️ Class 'N4wait3DOLLAR_3E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2436** ⚠️ Class 'N4wait3DOLLAR_4E' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2452** ⚠️ Class 'timespec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2460** ⚠️ Class 'tm' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/py2_test_grammar.py`

- **Line 31** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 31)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/py3_test_grammar.py`

- **Line 17** ⚠️ Class 'TokenTests' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 19** ⚠️ Function 'testBackslash' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 29** ⚠️ Function 'testPlainIntegers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'testLongIntegers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Function 'testFloats' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'testStringLiterals' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Function 'testEllipsis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 134** ⚠️ Class 'GrammarTests' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 145** ⚠️ Function 'testEvalInput' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 149** ⚠️ Function 'testFuncdef' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 162** ⚠️ Function 'f1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 166** ⚠️ Function 'f2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 167** ⚠️ Function 'f3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 170** ⚠️ Function 'a1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 171** ⚠️ Function 'a2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 172** ⚠️ Function 'v0' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 173** ⚠️ Function 'v1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 174** ⚠️ Function 'v2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 196** ⚠️ Function 'd01' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'd11' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 205** ⚠️ Function 'd21' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 212** ⚠️ Function 'd02' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Function 'd12' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 224** ⚠️ Function 'd22' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 228** ⚠️ Function 'd01v' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 235** ⚠️ Function 'd11v' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 239** ⚠️ Function 'd21v' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 245** ⚠️ Function 'd02v' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 252** ⚠️ Function 'd12v' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 260** ⚠️ Function 'd22v' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 277** ⚠️ Function 'pos0key1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 279** ⚠️ Function 'pos2key2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 283** ⚠️ Function 'pos2key2dict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 288** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 296** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 298** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 300** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 302** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 304** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 306** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 308** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 311** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 317** ⚠️ Function 'null' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 319** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 324** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 325** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 326** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 327** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 333** ⚠️ Function 'testLambdef' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 355** ⚠️ Function 'testSimpleStmt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 358** ⚠️ Function 'foo' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 379** ⚠️ Function 'testDelStmt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 388** ⚠️ Function 'testPassStmt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 395** ⚠️ Function 'testBreakStmt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 399** ⚠️ Function 'testContinueStmt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 410** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 425** ⚠️ Function 'test_break_continue_loop' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 435** ⚠️ Function 'test_inner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 445** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 451** ⚠️ Function 'testReturn' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 453** ⚠️ Function 'g1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 454** ⚠️ Function 'g2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 459** ⚠️ Function 'testYield' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 462** ⚠️ Function 'testRaise' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 469** ⚠️ Function 'testImport' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 482** ⚠️ Function 'testGlobal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 488** ⚠️ Function 'testNonlocal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 492** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 496** ⚠️ Function 'testAssert' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 513** ⚠️ Function 'testIf' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 526** ⚠️ Function 'testWhile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 541** ⚠️ Function 'testFor' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 546** ⚠️ Class 'Squares' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 568** ⚠️ Function 'testTry' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 582** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 591** ⚠️ Function 'testSuite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 606** ⚠️ Function 'testTest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 617** ⚠️ Function 'testComparison' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 617** ⚠️ Function 'testComparison' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 634** ⚠️ Function 'testBinaryMaskOps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 639** ⚠️ Function 'testShiftOps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 644** ⚠️ Function 'testAdditiveOps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 650** ⚠️ Function 'testMultiplicativeOps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 656** ⚠️ Function 'testUnaryOps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 663** ⚠️ Function 'testSelectors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 693** ⚠️ Function 'testAtoms' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 728** ⚠️ Function 'testClassdef' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 730** ⚠️ Class 'B' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 731** ⚠️ Class 'B2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 732** ⚠️ Class 'C1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 733** ⚠️ Class 'C2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 734** ⚠️ Class 'D' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 735** ⚠️ Class 'C' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 736** ⚠️ Function 'meth1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 737** ⚠️ Function 'meth2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 738** ⚠️ Function 'meth3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 743** ⚠️ Function 'class_decorator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 745** ⚠️ Class 'G' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 747** ⚠️ Function 'testDictcomps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 754** ⚠️ Function 'testListcomps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 776** ⚠️ Function 'test_in_func' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 781** ⚠️ Function 'test_nested_front' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 817** ⚠️ Function 'testGenexps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 852** ⚠️ Function 'testComprehensionSpecials' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 871** ⚠️ Function 'test_with_statement' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 872** ⚠️ Class 'manager' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 891** ⚠️ Function 'testIfElseExpr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 919** ⚠️ Function 'test_main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/pytree_idempotency.py`

- **Line 31** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 31)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/support.py`

- **Line 22** ⚠️ Function 'parse_string' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Function 'run_all_tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Function 'reformat' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'all_project_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_all_fixers.py`

- **Line 16** ⚠️ Class 'Test_all' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'test_all_project_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_fixers.py`

- **Line 14** ⚠️ Class 'FixerTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 18** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'check' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'warns' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'warns_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'assert_runs_after' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Class 'Test_ne' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 74** ⚠️ Function 'test_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 82** ⚠️ Function 'test_no_spaces' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 90** ⚠️ Function 'test_chained' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 98** ⚠️ Class 'Test_has_key' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 101** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 111** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 116** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 121** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'test_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 131** ⚠️ Function 'test_7' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 136** ⚠️ Function 'test_8' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 141** ⚠️ Function 'test_9' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 146** ⚠️ Function 'test_10' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 151** ⚠️ Function 'test_11' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 156** ⚠️ Class 'Test_apply' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 159** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 164** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 169** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 174** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 179** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 184** ⚠️ Function 'test_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 191** ⚠️ Function 'test_complex_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 196** ⚠️ Function 'test_complex_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'test_complex_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 208** ⚠️ Function 'test_dotted_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 213** ⚠️ Function 'test_subscript' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 218** ⚠️ Function 'test_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 224** ⚠️ Function 'test_extreme' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 230** ⚠️ Function 'test_weird_comments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 239** ⚠️ Function 'test_unchanged_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 243** ⚠️ Function 'test_unchanged_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 247** ⚠️ Function 'test_unchanged_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 251** ⚠️ Function 'test_unchanged_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 255** ⚠️ Function 'test_unchanged_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 259** ⚠️ Function 'test_unchanged_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 263** ⚠️ Function 'test_unchanged_7' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 267** ⚠️ Function 'test_unchanged_8' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 271** ⚠️ Function 'test_unchanged_9' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 275** ⚠️ Function 'test_space_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 280** ⚠️ Function 'test_space_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 285** ⚠️ Class 'Test_intern' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 288** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 303** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 318** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 334** ⚠️ Class 'Test_reduce' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 337** ⚠️ Function 'test_simple_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 342** ⚠️ Function 'test_bug_7253' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 348** ⚠️ Function 'test_call_with_lambda' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 353** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 369** ⚠️ Class 'Test_print' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 372** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 377** ⚠️ Function 'test_idempotency' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 384** ⚠️ Function 'test_idempotency_print_as_function' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 395** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 400** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 405** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 410** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 416** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 421** ⚠️ Function 'test_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 428** ⚠️ Function 'test_trailing_comma_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 433** ⚠️ Function 'test_trailing_comma_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 438** ⚠️ Function 'test_trailing_comma_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 445** ⚠️ Function 'test_vargs_without_trailing_comma' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 450** ⚠️ Function 'test_with_trailing_comma' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 455** ⚠️ Function 'test_no_trailing_comma' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 460** ⚠️ Function 'test_spaces_before_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 465** ⚠️ Function 'test_with_future_print_function' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 475** ⚠️ Class 'Test_exec' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 478** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 483** ⚠️ Function 'test_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 488** ⚠️ Function 'test_with_globals' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 493** ⚠️ Function 'test_with_globals_locals' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 498** ⚠️ Function 'test_complex_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 503** ⚠️ Function 'test_complex_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 510** ⚠️ Function 'test_unchanged_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 514** ⚠️ Function 'test_unchanged_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 518** ⚠️ Function 'test_unchanged_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 522** ⚠️ Function 'test_unchanged_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 526** ⚠️ Class 'Test_repr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 529** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 534** ⚠️ Function 'test_simple_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 539** ⚠️ Function 'test_simple_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 544** ⚠️ Function 'test_complex' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 549** ⚠️ Function 'test_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 554** ⚠️ Function 'test_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 559** ⚠️ Function 'test_nested_tuples' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 564** ⚠️ Class 'Test_except' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 567** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 580** ⚠️ Function 'test_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 593** ⚠️ Function 'test_simple_no_space_before_target' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 606** ⚠️ Function 'test_tuple_unpack' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 627** ⚠️ Function 'test_multi_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 641** ⚠️ Function 'test_list_unpack' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 656** ⚠️ Function 'test_weird_target_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 671** ⚠️ Function 'test_weird_target_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 686** ⚠️ Function 'test_weird_target_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 701** ⚠️ Function 'test_bare_except' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 719** ⚠️ Function 'test_bare_except_and_else_finally' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 745** ⚠️ Function 'test_multi_fixed_excepts_before_bare_except' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 767** ⚠️ Function 'test_one_line_suites' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 815** ⚠️ Function 'test_unchanged_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 823** ⚠️ Function 'test_unchanged_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 831** ⚠️ Function 'test_unchanged_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 839** ⚠️ Class 'Test_raise' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 842** ⚠️ Function 'test_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 847** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 856** ⚠️ Function 'test_with_comments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 871** ⚠️ Function 'test_None_value' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 876** ⚠️ Function 'test_tuple_value' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 881** ⚠️ Function 'test_tuple_detection' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 886** ⚠️ Function 'test_tuple_exc_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 891** ⚠️ Function 'test_tuple_exc_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 898** ⚠️ Function 'test_string_exc' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 902** ⚠️ Function 'test_string_exc_val' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 906** ⚠️ Function 'test_string_exc_val_tb' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 912** ⚠️ Function 'test_tb_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 919** ⚠️ Function 'test_tb_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 930** ⚠️ Function 'test_tb_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 937** ⚠️ Function 'test_tb_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 948** ⚠️ Function 'test_tb_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 955** ⚠️ Function 'test_tb_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 966** ⚠️ Class 'Test_throw' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 969** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 974** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 979** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 984** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 991** ⚠️ Function 'test_warn_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 995** ⚠️ Function 'test_warn_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 999** ⚠️ Function 'test_warn_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1005** ⚠️ Function 'test_untouched_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1009** ⚠️ Function 'test_untouched_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1013** ⚠️ Function 'test_untouched_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1019** ⚠️ Function 'test_tb_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1026** ⚠️ Function 'test_tb_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1037** ⚠️ Function 'test_tb_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1044** ⚠️ Function 'test_tb_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1055** ⚠️ Function 'test_tb_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1062** ⚠️ Function 'test_tb_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1073** ⚠️ Function 'test_tb_7' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1080** ⚠️ Function 'test_tb_8' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1091** ⚠️ Class 'Test_long' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1094** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1099** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1104** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1109** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1131** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1137** ⚠️ Class 'Test_execfile' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1140** ⚠️ Function 'test_conversion' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1165** ⚠️ Function 'test_spacing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1175** ⚠️ Class 'Test_isinstance' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1178** ⚠️ Function 'test_remove_multiple_items' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1195** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1200** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1203** ⚠️ Class 'Test_dict' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1206** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1231** ⚠️ Function 'test_trailing_comment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1260** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1271** ⚠️ Function 'test_01' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1280** ⚠️ Function 'test_02' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1285** ⚠️ Function 'test_03' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1290** ⚠️ Function 'test_04' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1295** ⚠️ Function 'test_05' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1300** ⚠️ Function 'test_06' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1305** ⚠️ Function 'test_07' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1309** ⚠️ Function 'test_08' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1313** ⚠️ Function 'test_09' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1318** ⚠️ Function 'test_10' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1323** ⚠️ Function 'test_11' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1328** ⚠️ Function 'test_12' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1333** ⚠️ Function 'test_13' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1338** ⚠️ Function 'test_14' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1343** ⚠️ Function 'test_15' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1348** ⚠️ Function 'test_16' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1353** ⚠️ Function 'test_17' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1358** ⚠️ Function 'test_18' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1363** ⚠️ Function 'test_19' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1368** ⚠️ Function 'test_20' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1373** ⚠️ Function 'test_21' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1378** ⚠️ Function 'test_22' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1383** ⚠️ Function 'test_23' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1388** ⚠️ Function 'test_24' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1393** ⚠️ Function 'test_25' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1398** ⚠️ Function 'test_26' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1403** ⚠️ Function 'test_27' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1408** ⚠️ Function 'test_14' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1413** ⚠️ Function 'test_15' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1418** ⚠️ Function 'test_17' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1423** ⚠️ Function 'test_18' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1428** ⚠️ Function 'test_19' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1433** ⚠️ Class 'Test_xrange' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1436** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1449** ⚠️ Function 'test_single_arg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1454** ⚠️ Function 'test_two_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1459** ⚠️ Function 'test_three_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1464** ⚠️ Function 'test_wrap_in_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1485** ⚠️ Function 'test_xrange_in_for' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1494** ⚠️ Function 'test_range_in_for' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1498** ⚠️ Function 'test_in_contains_test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1501** ⚠️ Function 'test_in_consuming_context' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1505** ⚠️ Class 'Test_xrange_with_reduce' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1507** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1510** ⚠️ Function 'test_double_transform' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1516** ⚠️ Class 'Test_raw_input' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1519** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1528** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1533** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1538** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1543** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1548** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1553** ⚠️ Function 'test_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1558** ⚠️ Function 'test_8' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1563** ⚠️ Class 'Test_funcattrs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1568** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1578** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1589** ⚠️ Class 'Test_xreadlines' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1592** ⚠️ Function 'test_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1605** ⚠️ Function 'test_attr_ref' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1618** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1632** ⚠️ Class 'ImportsFixerTests' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1634** ⚠️ Function 'test_import_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1644** ⚠️ Function 'test_import_from' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1658** ⚠️ Function 'test_import_module_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1668** ⚠️ Function 'test_import_from_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1674** ⚠️ Function 'test_star' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1680** ⚠️ Function 'test_import_module_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1730** ⚠️ Class 'Test_imports' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1734** ⚠️ Function 'test_multiple_imports' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1739** ⚠️ Function 'test_multiple_imports_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1751** ⚠️ Class 'Test_imports2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1756** ⚠️ Class 'Test_imports_fixer_order' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1758** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1766** ⚠️ Function 'test_after_local_imports_refactoring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1772** ⚠️ Class 'Test_urllib' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1776** ⚠️ Function 'test_import_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1782** ⚠️ Function 'test_import_from' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1808** ⚠️ Function 'test_import_module_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1813** ⚠️ Function 'test_import_from_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1824** ⚠️ Function 'test_star' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1829** ⚠️ Function 'test_indented' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1856** ⚠️ Function 'test_import_module_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1882** ⚠️ Class 'Test_input' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1885** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1894** ⚠️ Function 'test_trailing_comment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1899** ⚠️ Function 'test_idempotency' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1909** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1914** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1919** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1924** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1929** ⚠️ Class 'Test_tuple_params' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 1932** ⚠️ Function 'test_unchanged_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1936** ⚠️ Function 'test_unchanged_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1940** ⚠️ Function 'test_unchanged_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1944** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1955** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1966** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1977** ⚠️ Function 'test_semicolon' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1985** ⚠️ Function 'test_keywords' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1996** ⚠️ Function 'test_varargs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2007** ⚠️ Function 'test_multi_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2019** ⚠️ Function 'test_multi_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2031** ⚠️ Function 'test_docstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2045** ⚠️ Function 'test_lambda_no_change' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2049** ⚠️ Function 'test_lambda_parens_single_arg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2066** ⚠️ Function 'test_lambda_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2083** ⚠️ Function 'test_lambda_one_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2092** ⚠️ Function 'test_lambda_simple_multi_use' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2097** ⚠️ Function 'test_lambda_simple_reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2102** ⚠️ Function 'test_lambda_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2111** ⚠️ Function 'test_lambda_nested_multi_use' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2116** ⚠️ Class 'Test_methodattrs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2121** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2137** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2148** ⚠️ Class 'Test_next' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2151** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2156** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2161** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2166** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2171** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2176** ⚠️ Function 'test_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2181** ⚠️ Function 'test_prefix_preservation_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2194** ⚠️ Function 'test_prefix_preservation_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2209** ⚠️ Function 'test_prefix_preservation_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2224** ⚠️ Function 'test_prefix_preservation_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2241** ⚠️ Function 'test_prefix_preservation_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2256** ⚠️ Function 'test_prefix_preservation_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2269** ⚠️ Function 'test_method_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2282** ⚠️ Function 'test_method_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2295** ⚠️ Function 'test_method_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2308** ⚠️ Function 'test_method_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2333** ⚠️ Function 'test_method_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2341** ⚠️ Function 'test_shadowing_assign_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2351** ⚠️ Function 'test_shadowing_assign_tuple_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2361** ⚠️ Function 'test_shadowing_assign_tuple_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2371** ⚠️ Function 'test_shadowing_assign_list_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2381** ⚠️ Function 'test_shadowing_assign_list_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2391** ⚠️ Function 'test_builtin_assign' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2402** ⚠️ Function 'test_builtin_assign_in_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2413** ⚠️ Function 'test_builtin_assign_in_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2424** ⚠️ Function 'test_assign_to_next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2435** ⚠️ Function 'test_assign_to_next_in_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2446** ⚠️ Function 'test_assign_to_next_in_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2457** ⚠️ Function 'test_shadowing_import_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2467** ⚠️ Function 'test_shadowing_import_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2477** ⚠️ Function 'test_shadowing_import_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2487** ⚠️ Function 'test_shadowing_import_from_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2497** ⚠️ Function 'test_shadowing_import_from_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2507** ⚠️ Function 'test_shadowing_import_from_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2517** ⚠️ Function 'test_shadowing_import_from_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2527** ⚠️ Function 'test_shadowing_funcdef_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2538** ⚠️ Function 'test_shadowing_funcdef_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2561** ⚠️ Function 'test_shadowing_global_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2569** ⚠️ Function 'test_shadowing_global_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2577** ⚠️ Function 'test_shadowing_for_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2587** ⚠️ Function 'test_shadowing_for_tuple_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2597** ⚠️ Function 'test_shadowing_for_tuple_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2607** ⚠️ Function 'test_noncall_access_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2612** ⚠️ Function 'test_noncall_access_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2617** ⚠️ Function 'test_noncall_access_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2622** ⚠️ Class 'Test_nonzero' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2625** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2638** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2651** ⚠️ Function 'test_unchanged_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2659** ⚠️ Function 'test_unchanged_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2667** ⚠️ Function 'test_unchanged_func' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2674** ⚠️ Class 'Test_numliterals' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2677** ⚠️ Function 'test_octal_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2682** ⚠️ Function 'test_long_int_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2687** ⚠️ Function 'test_long_int_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2692** ⚠️ Function 'test_long_hex' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2697** ⚠️ Function 'test_comments_and_spacing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2706** ⚠️ Function 'test_unchanged_int' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2710** ⚠️ Function 'test_unchanged_float' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2714** ⚠️ Function 'test_unchanged_octal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2718** ⚠️ Function 'test_unchanged_hex' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2722** ⚠️ Function 'test_unchanged_exp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2726** ⚠️ Function 'test_unchanged_complex_int' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2730** ⚠️ Function 'test_unchanged_complex_float' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2734** ⚠️ Function 'test_unchanged_complex_bare' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2740** ⚠️ Class 'Test_renames' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2746** ⚠️ Function 'test_import_from' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2755** ⚠️ Function 'test_import_from_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2761** ⚠️ Function 'test_import_module_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2773** ⚠️ Function 'XXX_test_from_import_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2786** ⚠️ Class 'Test_unicode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2789** ⚠️ Function 'test_whitespace' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2802** ⚠️ Function 'test_unicode_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2807** ⚠️ Function 'test_unichr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2812** ⚠️ Function 'test_unicode_literal_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2817** ⚠️ Function 'test_unicode_literal_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2822** ⚠️ Function 'test_unicode_literal_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2827** ⚠️ Class 'Test_callable' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2830** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2840** ⚠️ Function 'test_callable_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2845** ⚠️ Function 'test_global_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2907** ⚠️ Function 'test_callable_should_not_change' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2920** ⚠️ Class 'Test_filter' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 2923** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2932** ⚠️ Function 'test_filter_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2955** ⚠️ Function 'test_filter_nochange' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 2995** ⚠️ Function 'test_future_builtins' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3006** ⚠️ Class 'Test_map' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3009** ⚠️ Function 'check' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3013** ⚠️ Function 'test_prefix_preservation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3018** ⚠️ Function 'test_trailing_comment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3023** ⚠️ Function 'test_None_with_multiple_arguments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3028** ⚠️ Function 'test_map_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3067** ⚠️ Function 'test_map_nochange' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3107** ⚠️ Function 'test_future_builtins' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3118** ⚠️ Class 'Test_zip' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3121** ⚠️ Function 'check' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3125** ⚠️ Function 'test_zip_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3134** ⚠️ Function 'test_zip_nochange' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3174** ⚠️ Function 'test_future_builtins' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3185** ⚠️ Class 'Test_standarderror' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3188** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3201** ⚠️ Class 'Test_types' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3204** ⚠️ Function 'test_basic_types_convert' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3229** ⚠️ Class 'Test_idioms' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3232** ⚠️ Function 'test_while' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3251** ⚠️ Function 'test_while_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3264** ⚠️ Function 'test_eq_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3273** ⚠️ Function 'test_eq_reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3282** ⚠️ Function 'test_eq_expression' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3291** ⚠️ Function 'test_is_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3300** ⚠️ Function 'test_is_reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3309** ⚠️ Function 'test_is_expression' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3318** ⚠️ Function 'test_is_not_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3327** ⚠️ Function 'test_is_not_reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3336** ⚠️ Function 'test_is_not_expression' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3345** ⚠️ Function 'test_ne_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3354** ⚠️ Function 'test_ne_reverse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3363** ⚠️ Function 'test_ne_expression' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3372** ⚠️ Function 'test_type_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3376** ⚠️ Function 'test_sort_list_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3476** ⚠️ Function 'test_sort_simple_expr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3558** ⚠️ Function 'test_sort_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3573** ⚠️ Class 'Test_basestring' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3576** ⚠️ Function 'test_basestring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3581** ⚠️ Class 'Test_buffer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3584** ⚠️ Function 'test_buffer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3589** ⚠️ Function 'test_slicing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3594** ⚠️ Class 'Test_future' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3597** ⚠️ Function 'test_future' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3610** ⚠️ Function 'test_run_order' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3613** ⚠️ Class 'Test_itertools' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3616** ⚠️ Function 'checkall' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3626** ⚠️ Function 'test_0' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3633** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3638** ⚠️ Function 'test_qualified' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3647** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3656** ⚠️ Function 'test_space_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3661** ⚠️ Function 'test_space_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3670** ⚠️ Function 'test_run_order' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3674** ⚠️ Class 'Test_itertools_imports' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3677** ⚠️ Function 'test_reduced' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3690** ⚠️ Function 'test_comments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3695** ⚠️ Function 'test_none' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3704** ⚠️ Function 'test_import_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3724** ⚠️ Function 'test_ifilter_and_zip_longest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3738** ⚠️ Function 'test_import_star' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3743** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3748** ⚠️ Class 'Test_import' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3751** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3758** ⚠️ Function 'fake_exists' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3765** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3769** ⚠️ Function 'check_both' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3775** ⚠️ Function 'test_files_checked' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3776** ⚠️ Function 'p' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3799** ⚠️ Function 'test_not_in_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3805** ⚠️ Function 'test_with_absolute_import_enabled' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3811** ⚠️ Function 'test_in_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3818** ⚠️ Function 'test_import_from_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3825** ⚠️ Function 'test_already_relative_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3829** ⚠️ Function 'test_comments_and_indent' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3834** ⚠️ Function 'test_from' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3847** ⚠️ Function 'test_dotted_from' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3852** ⚠️ Function 'test_from_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3857** ⚠️ Function 'test_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3874** ⚠️ Function 'test_import_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3883** ⚠️ Function 'test_local_and_absolute' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3890** ⚠️ Function 'test_dotted_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3895** ⚠️ Function 'test_dotted_import_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3900** ⚠️ Function 'test_prefix' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3912** ⚠️ Class 'Test_set_literal' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 3916** ⚠️ Function 'test_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3951** ⚠️ Function 'test_listcomps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 3968** ⚠️ Function 'test_whitespace' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4000** ⚠️ Function 'test_comments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4018** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4039** ⚠️ Class 'Test_sys_exc' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 4042** ⚠️ Function 'test_0' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4047** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4052** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4057** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4062** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4067** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4073** ⚠️ Class 'Test_paren' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 4076** ⚠️ Function 'test_0' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4081** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4086** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4091** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4096** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4101** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4106** ⚠️ Function 'test_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4111** ⚠️ Function 'test_unchanged_0' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4115** ⚠️ Function 'test_unchanged_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4119** ⚠️ Function 'test_unchanged_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4123** ⚠️ Function 'test_unchanged_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4127** ⚠️ Function 'test_unchanged_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4131** ⚠️ Class 'Test_metaclass' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 4135** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4156** ⚠️ Function 'test_comments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4181** ⚠️ Function 'test_meta' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4296** ⚠️ Class 'Test_getcwdu' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 4300** ⚠️ Function 'test_basic' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4317** ⚠️ Function 'test_comment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4322** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4332** ⚠️ Function 'test_indentation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4343** ⚠️ Function 'test_multilation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4357** ⚠️ Class 'Test_operator' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 4361** ⚠️ Function 'test_operator_isCallable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4366** ⚠️ Function 'test_operator_sequenceIncludes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4379** ⚠️ Function 'test_operator_isSequenceType' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4384** ⚠️ Function 'test_operator_isMappingType' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4389** ⚠️ Function 'test_operator_isNumberType' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4394** ⚠️ Function 'test_operator_repeat' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4407** ⚠️ Function 'test_operator_irepeat' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4420** ⚠️ Function 'test_bare_isCallable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4425** ⚠️ Function 'test_bare_sequenceIncludes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4430** ⚠️ Function 'test_bare_operator_isSequenceType' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4435** ⚠️ Function 'test_bare_operator_isMappingType' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4440** ⚠️ Function 'test_bare_operator_isNumberType' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4445** ⚠️ Function 'test_bare_operator_repeat' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4450** ⚠️ Function 'test_bare_operator_irepeat' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4456** ⚠️ Class 'Test_exitfunc' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 4460** ⚠️ Function 'test_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4472** ⚠️ Function 'test_names_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4483** ⚠️ Function 'test_complex_expression' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4495** ⚠️ Function 'test_comments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4517** ⚠️ Function 'test_in_a_function' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4531** ⚠️ Function 'test_no_sys_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 4539** ⚠️ Function 'test_unchanged' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_main.py`

- **Line 20** ⚠️ Class 'TestMain' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 24** ⚠️ Function 'assertNotRegex' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 34** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Function 'run_2to3_capture' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'test_unencodable_diff' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_parser.py`

- **Line 36** ⚠️ Class 'TestDriver' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'test_formfeed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Class 'TestPgen2Caching' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 46** ⚠️ Function 'test_load_grammar_from_txt_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'test_load_grammar_from_pickle' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 70** ⚠️ Function 'test_load_grammar_from_subprocess' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 111** ⚠️ Function 'test_load_packaged_grammar' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 113** ⚠️ Class 'MyLoader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 114** ⚠️ Function 'get_data' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 116** ⚠️ Class 'MyModule' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 125** ⚠️ Class 'GrammarTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 126** ⚠️ Function 'validate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Function 'invalid_syntax' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 138** ⚠️ Class 'TestMatrixMultiplication' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 140** ⚠️ Function 'test_matrix_multiplication_operator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 145** ⚠️ Class 'TestYieldFrom' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 147** ⚠️ Function 'test_matrix_multiplication_operator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 153** ⚠️ Class 'TestRaiseChanges' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 154** ⚠️ Function 'test_2x_style_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 157** ⚠️ Function 'test_2x_style_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 160** ⚠️ Function 'test_2x_style_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 163** ⚠️ Function 'test_2x_style_invalid_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 166** ⚠️ Function 'test_3x_style' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 169** ⚠️ Function 'test_3x_style_invalid_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 172** ⚠️ Function 'test_3x_style_invalid_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 175** ⚠️ Function 'test_3x_style_invalid_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 178** ⚠️ Function 'test_3x_style_invalid_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 184** ⚠️ Class 'TestUnpackingGeneralizations' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 185** ⚠️ Function 'test_mid_positional_star' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 188** ⚠️ Function 'test_double_star_dict_literal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 191** ⚠️ Function 'test_double_star_dict_literal_after_keywords' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 194** ⚠️ Function 'test_list_display' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 198** ⚠️ Function 'test_set_display' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 202** ⚠️ Function 'test_dict_display_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 206** ⚠️ Function 'test_dict_display_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 210** ⚠️ Function 'test_argument_unpacking_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 214** ⚠️ Function 'test_argument_unpacking_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 218** ⚠️ Function 'test_argument_unpacking_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 223** ⚠️ Class 'TestFunctionAnnotations' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 224** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 227** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 230** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 233** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 236** ⚠️ Function 'test_5' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 239** ⚠️ Function 'test_6' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 242** ⚠️ Function 'test_7' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 245** ⚠️ Function 'test_8' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 251** ⚠️ Class 'TestExcept' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 252** ⚠️ Function 'test_new' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 260** ⚠️ Function 'test_old' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 270** ⚠️ Class 'TestSetLiteral' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 271** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 274** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 277** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 280** ⚠️ Function 'test_4' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 284** ⚠️ Class 'TestNumericLiterals' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 285** ⚠️ Function 'test_new_octal_notation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 289** ⚠️ Function 'test_new_binary_notation' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 294** ⚠️ Class 'TestClassDef' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 295** ⚠️ Function 'test_new_syntax' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 307** ⚠️ Function 'test_all_project_files' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 323** ⚠️ Function 'test_extended_unpacking' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 330** ⚠️ Class 'TestLiterals' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 332** ⚠️ Function 'validate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 335** ⚠️ Function 'test_multiline_bytes_literals' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 344** ⚠️ Function 'test_multiline_bytes_tripquote_literals' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 353** ⚠️ Function 'test_multiline_str_literals' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 380** ⚠️ Function 'diffLine' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_pytree.py`

- **Line 25** ⚠️ Function 'sorted' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'test_deprecated_prefix_methods' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'test_instantiate_base' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'test_leaf' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 61** ⚠️ Function 'test_leaf_repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'test_leaf_str' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'test_leaf_str_numeric_value' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'test_leaf_equality' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 87** ⚠️ Function 'test_leaf_prefix' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 95** ⚠️ Function 'test_node' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 102** ⚠️ Function 'test_node_repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 109** ⚠️ Function 'test_node_str' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 115** ⚠️ Function 'test_node_prefix' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 124** ⚠️ Function 'test_get_suffix' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'test_node_equality' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 147** ⚠️ Function 'test_node_recursive_equality' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 157** ⚠️ Function 'test_replace' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 171** ⚠️ Function 'test_replace_with_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 181** ⚠️ Function 'test_leaves' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 191** ⚠️ Function 'test_depth' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 202** ⚠️ Function 'test_post_order' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 210** ⚠️ Function 'test_pre_order' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 218** ⚠️ Function 'test_changed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 244** ⚠️ Function 'test_leaf_constructor_prefix' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 250** ⚠️ Function 'test_node_constructor_prefix' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 260** ⚠️ Function 'test_remove' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 283** ⚠️ Function 'test_remove_parentless' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 292** ⚠️ Function 'test_node_set_child' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 313** ⚠️ Function 'test_node_insert_child' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 329** ⚠️ Function 'test_node_append_child' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 345** ⚠️ Function 'test_node_next_sibling' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 354** ⚠️ Function 'test_leaf_next_sibling' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 363** ⚠️ Function 'test_node_prev_sibling' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 372** ⚠️ Function 'test_leaf_prev_sibling' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 386** ⚠️ Function 'test_basic_patterns' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 422** ⚠️ Function 'test_wildcard' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 453** ⚠️ Function 'test_generate_matches' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 483** ⚠️ Function 'test_has_key_example' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_refactor.py`

- **Line 34** ⚠️ Class 'TestRefactoringTool' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 36** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'check_instances' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'rt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'test_print_function_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'test_write_unchanged_files_option' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'test_fixer_loading_helpers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Function 'test_detect_future_features' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 117** ⚠️ Function 'test_get_headnode_dict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 118** ⚠️ Class 'NoneFix' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 121** ⚠️ Class 'FileInputFix' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 124** ⚠️ Class 'SimpleFix' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 138** ⚠️ Function 'test_fixer_loading' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 150** ⚠️ Function 'test_naughty_fixers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 155** ⚠️ Function 'test_refactor_string' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 165** ⚠️ Function 'test_refactor_stdin' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 167** ⚠️ Class 'MyRT' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 169** ⚠️ Function 'print_output' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 185** ⚠️ Function 'check_file_refactoring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 195** ⚠️ Function 'read_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 214** ⚠️ Function 'test_refactor_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 218** ⚠️ Function 'test_refactor_file_write_unchanged_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 221** ⚠️ Function 'recording_log_debug' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 238** ⚠️ Function 'test_refactor_dir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 239** ⚠️ Function 'check' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 240** ⚠️ Function 'mock_refactor_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 270** ⚠️ Function 'test_file_encoding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 274** ⚠️ Function 'test_bom' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 279** ⚠️ Function 'test_crlf_newlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 289** ⚠️ Function 'test_refactor_docstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 306** ⚠️ Function 'test_explicit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_util.py`

- **Line 15** ⚠️ Function 'parse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Class 'MacroTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 25** ⚠️ Function 'assertStr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Class 'Test_is_tuple' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 32** ⚠️ Function 'is_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 35** ⚠️ Function 'test_valid' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'test_invalid' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Class 'Test_is_list' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 48** ⚠️ Function 'is_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'test_valid' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Function 'test_invalid' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Class 'Test_Attr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 63** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'test_returns' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 74** ⚠️ Class 'Test_Name' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 75** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Class 'Test_Call' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 92** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Class 'Test_does_tree_import' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 116** ⚠️ Function 'does_tree_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'try_with' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 147** ⚠️ Function 'test_in_function' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 150** ⚠️ Class 'Test_find_binding' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 151** ⚠️ Function 'find_binding' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 154** ⚠️ Function 'test_simple_assignment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 162** ⚠️ Function 'test_tuple_assignment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 170** ⚠️ Function 'test_list_assignment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 178** ⚠️ Function 'test_invalid_assignments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 184** ⚠️ Function 'test_simple_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 190** ⚠️ Function 'test_from_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 200** ⚠️ Function 'test_import_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 206** ⚠️ Function 'test_from_import_as' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 215** ⚠️ Function 'test_simple_import_with_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 221** ⚠️ Function 'test_from_import_with_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 234** ⚠️ Function 'test_import_as_with_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 239** ⚠️ Function 'test_from_import_as_with_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 251** ⚠️ Function 'test_function_def' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 266** ⚠️ Function 'test_class_def' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 284** ⚠️ Function 'test_for' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 293** ⚠️ Function 'test_for_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 342** ⚠️ Function 'test_if' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 346** ⚠️ Function 'test_if_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 359** ⚠️ Function 'test_while' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 363** ⚠️ Function 'test_while_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 376** ⚠️ Function 'test_try_except' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 407** ⚠️ Function 'test_try_except_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 484** ⚠️ Function 'test_try_except_finally' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 517** ⚠️ Function 'test_try_except_finally_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 552** ⚠️ Class 'Test_touch_import' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 554** ⚠️ Function 'test_after_docstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 559** ⚠️ Function 'test_after_imports' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 564** ⚠️ Function 'test_beginning' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 569** ⚠️ Function 'test_from_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 574** ⚠️ Function 'test_name_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 579** ⚠️ Class 'Test_find_indentation' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 581** ⚠️ Function 'test_nothing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 588** ⚠️ Function 'test_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/linecache.py`

- **Line 13** ⚠️ Function 'getline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'updatecache' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/locale.py`

- **Line 88** ❌ invalid syntax (<unknown>, line 88)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/logging/__init__.py`

- **Line 80** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 670** ⚠️ Function 'get_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 673** ⚠️ Function 'set_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 880** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1662** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1683** ⚠️ Function 'handle' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1686** ⚠️ Function 'emit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 1689** ⚠️ Function 'createLock' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/logging/config.py`

- **Line 523** ❌ multiple exception types must be parenthesized (<unknown>, line 523)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/logging/handlers.py`

- **Line 81** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 317** ⚠️ Function 'doRollover' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 582** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 844** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 922** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1009** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 1084** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/macpath.py`

- **Line 147** ❌ invalid syntax (<unknown>, line 147)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/macurl2path.py`

- **Line 18** ❌ invalid syntax (<unknown>, line 18)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mailbox.py`

- **Line 259** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 259)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mailcap.py`

- **Line 222** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 222)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/markupbase.py`

- **Line 33** ⚠️ Function 'error' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Function 'updatepos' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'parse_declaration' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'parse_declaration' has high complexity (18)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 147** ⚠️ Function 'parse_marked_section' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 169** ⚠️ Function 'parse_comment' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 183** ⚠️ Function '_parse_doctype_subset' has high complexity (21)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 261** ⚠️ Function '_parse_doctype_attlist' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 341** ⚠️ Function '_parse_doctype_entity' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 395** ⚠️ Function 'unknown_decl' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/marshal.py`

- **Line 11** ⚠️ Function 'dump' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15** ⚠️ Function 'load' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'dumps' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Function 'loads' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mhlib.py`

- **Line 74** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 74)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimetools.py`

- **Line 173** ❌ invalid syntax (<unknown>, line 173)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimetypes.py`

- **Line 565** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 565)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimify.py`

- **Line 441** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 441)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy.py`

- **Line 77** ❌ multiple exception types must be parenthesized (<unknown>, line 77)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_exceptions.py`

- **Line 81** ❌ multiple exception types must be parenthesized (<unknown>, line 81)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_impl.py`

- **Line 59** ❌ multiple exception types must be parenthesized (<unknown>, line 59)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_input.py`

- **Line 27** ⚠️ Class 'modjy_input_object' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 34** ⚠️ Function 'istream_read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Function 'readline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 85** ⚠️ Function 'readline' has high complexity (14)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 145** ⚠️ Function 'readlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 163** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_log.py`

- **Line 37** ⚠️ Class 'modjy_logger' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 54** ⚠️ Function 'debug' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Function 'info' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 60** ⚠️ Function 'warn' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 63** ⚠️ Function 'error' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'fatal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'set_log_level' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Function 'set_log_format' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_params.py`

- **Line 52** ⚠️ Class 'modjy_param_mgr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_publish.py`

- **Line 108** ❌ multiple exception types must be parenthesized (<unknown>, line 108)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_response.py`

- **Line 59** ❌ multiple exception types must be parenthesized (<unknown>, line 59)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_write.py`

- **Line 42** ❌ multiple exception types must be parenthesized (<unknown>, line 42)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_wsgi.py`

- **Line 131** ❌ multiple exception types must be parenthesized (<unknown>, line 131)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/multifile.py`

- **Line 67** ❌ invalid syntax (<unknown>, line 67)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mutex.py`

- **Line 20** ⚠️ Class 'mutex' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/netrc.py`

- **Line 122** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 122)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/nntplib.py`

- **Line 136** ❌ multiple exception types must be parenthesized (<unknown>, line 136)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ntpath.py`

- **Line 63** ⚠️ Function 'join' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 189** ⚠️ Function 'splitext' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 317** ⚠️ Function 'expandvars' has high complexity (17)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 398** ⚠️ Function 'normpath' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/nturl2path.py`

- **Line 26** ❌ invalid syntax (<unknown>, line 26)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/numbers.py`

- **Line 276** ⚠️ Function 'numerator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 280** ⚠️ Function 'denominator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/opcode.py`

- **Line 27** ⚠️ Function 'def_op' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Function 'name_op' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 35** ⚠️ Function 'jrel_op' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'jabs_op' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/optparse.py`

- **Line 249** ❌ invalid syntax (<unknown>, line 249)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/os.py`

- **Line 153** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 153)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pawt/__init__.py`

- **Line 4** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16** ⚠️ Class 'GridBag' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'addRow' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 27** ⚠️ Function 'add' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pawt/swing.py`

- **Line 7** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pdb.py`

- **Line 219** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 219)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pickle.py`

- **Line 1288** ❌ invalid decimal literal (<unknown>, line 1288)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pickletools.py`

- **Line 1770** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 1770)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pipes.py`

- **Line 111** ❌ invalid syntax (<unknown>, line 111)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pkgutil.py`

- **Line 557** ❌ multiple exception types must be parenthesized (<unknown>, line 557)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/platform.py`

- **Line 387** ❌ invalid syntax (<unknown>, line 387)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/plistlib.py`

- **Line 301** ❌ invalid syntax (<unknown>, line 301)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/popen2.py`

- **Line 162** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 162)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/poplib.py`

- **Line 96** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 96)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/posixfile.py`

- **Line 83** ❌ invalid syntax (<unknown>, line 83)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/posixpath.py`

- **Line 25** ⚠️ Class '_unicode' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 104** ⚠️ Function 'splitext' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 372** ⚠️ Function '_joinrealpath' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pprint.py`

- **Line 346** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 346)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/profile.py`

- **Line 88** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 88)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pstats.py`

- **Line 75** ❌ invalid syntax (<unknown>, line 75)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pty.py`

- **Line 58** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 58)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pwd.py`

- **Line 21** ❌ invalid syntax (<unknown>, line 21)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/py_compile.py`

- **Line 97** ❌ multiple exception types must be parenthesized (<unknown>, line 97)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pycimport.py`

- **Line 25** ❌ Missing parentheses in call to 'exec'. Did you mean exec(...)? (<unknown>, line 25)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pyclbr.py`

- **Line 335** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 335)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pydoc.py`

- **Line 343** ❌ invalid syntax (<unknown>, line 343)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/quopri.py`

- **Line 197** ❌ multiple exception types must be parenthesized (<unknown>, line 197)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/random.py`

- **Line 174** ❌ invalid decimal literal (<unknown>, line 174)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/re.py`

- **Line 238** ❌ invalid syntax (<unknown>, line 238)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/readline.py`

- **Line 42** ⚠️ Function 'parse_and_bind' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'get_line_buffer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 48** ⚠️ Function 'insert_text' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'read_init_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'read_history_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 59** ⚠️ Function 'write_history_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'clear_history' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'add_history' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Function 'get_history_length' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Function 'set_history_length' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'get_current_history_length' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'get_history_item' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 88** ⚠️ Function 'remove_history_item' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 91** ⚠️ Function 'replace_history_item' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 94** ⚠️ Function 'redisplay' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 97** ⚠️ Function 'set_startup_hook' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'set_pre_input_hook' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 115** ⚠️ Function 'complete_handler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 148** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 159** ⚠️ Function 'get_completer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 170** ⚠️ Function 'get_begidx' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 173** ⚠️ Function 'get_endidx' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 176** ⚠️ Function 'set_completer_delims' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 181** ⚠️ Function 'get_completer_delims' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/repr.py`

- **Line 8** ⚠️ Class 'Repr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Function 'repr1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'repr_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Function 'repr_list' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 60** ⚠️ Function 'repr_array' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 64** ⚠️ Function 'repr_set' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'repr_frozenset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'repr_deque' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 76** ⚠️ Function 'repr_dict' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 91** ⚠️ Function 'repr_str' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'repr_long' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Function 'repr_instance' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/rfc822.py`

- **Line 119** ❌ invalid syntax (<unknown>, line 119)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/rlcompleter.py`

- **Line 60** ❌ invalid syntax (<unknown>, line 60)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/robotparser.py`

- **Line 78** ⚠️ Function 'parse' has high complexity (15)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 177** ⚠️ Function 'applies_to' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Class 'URLopener' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 225** ⚠️ Function 'prompt_user_passwd' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 230** ⚠️ Function 'http_error_default' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/runpy.py`

- **Line 72** ❌ Missing parentheses in call to 'exec'. Did you mean exec(...)? (<unknown>, line 72)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sched.py`

- **Line 38** ⚠️ Class 'scheduler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sets.py`

- **Line 76** ❌ invalid syntax (<unknown>, line 76)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sgmllib.py`

- **Line 390** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 390)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shelve.py`

- **Line 78** ⚠️ Function 'closed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Function 'keys' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'has_key' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 112** ⚠️ Function 'get' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 142** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 161** ⚠️ Function 'sync' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 188** ⚠️ Function 'set_location' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 193** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 198** ⚠️ Function 'previous' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 203** ⚠️ Function 'first' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 208** ⚠️ Function 'last' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shlex.py`

- **Line 56** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 56)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shutil.py`

- **Line 104** ❌ multiple exception types must be parenthesized (<unknown>, line 104)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/signal.py`

- **Line 37** ❌ multiple exception types must be parenthesized (<unknown>, line 37)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/site.py`

- **Line 186** ❌ Missing parentheses in call to 'exec'. Did you mean exec(...)? (<unknown>, line 186)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/smtpd.py`

- **Line 123** ❌ multiple exception types must be parenthesized (<unknown>, line 123)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/smtplib.py`

- **Line 311** ❌ invalid syntax (<unknown>, line 311)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sndhdr.py`

- **Line 211** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 211)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/socket.py`

- **Line 132** ⚠️ Function 'supports' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_compile.py`

- **Line 22** ❌ invalid hexadecimal literal (<unknown>, line 22)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_constants.py`

- **Line 259** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 259)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_parse.py`

- **Line 145** ❌ invalid decimal literal (<unknown>, line 145)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ssl.py`

- **Line 80** ❌ invalid hexadecimal literal (<unknown>, line 80)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/stat.py`

- **Line 22** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 22)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/string.py`

- **Line 70** ❌ invalid syntax (<unknown>, line 70)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/subprocess.py`

- **Line 489** ❌ multiple exception types must be parenthesized (<unknown>, line 489)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/symbol.py`

- **Line 106** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sysconfig.py`

- **Line 165** ❌ multiple exception types must be parenthesized (<unknown>, line 165)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tabnanny.py`

- **Line 46** ❌ multiple exception types must be parenthesized (<unknown>, line 46)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tarfile.py`

- **Line 136** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 136)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/telnetlib.py`

- **Line 241** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 241)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tempfile.py`

- **Line 250** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 250)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/textwrap.py`

- **Line 425** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 425)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/this.py`

- **Line 28** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 28)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/threading.py`

- **Line 415** ❌ invalid syntax (<unknown>, line 415)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/timeit.py`

- **Line 137** ❌ Missing parentheses in call to 'exec'. Did you mean exec(...)? (<unknown>, line 137)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/token.py`

- **Line 97** ❌ multiple exception types must be parenthesized (<unknown>, line 97)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tokenize.py`

- **Line 152** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 152)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/trace.py`

- **Line 244** ❌ multiple exception types must be parenthesized (<unknown>, line 244)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/types.py`

- **Line 52** ⚠️ Class '_C' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unicodedata.py`

- **Line 45** ⚠️ Function 'name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'lookup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 63** ⚠️ Function 'digit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'decimal' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 83** ⚠️ Function 'numeric' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'decomposition' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 187** ⚠️ Function 'category' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 217** ⚠️ Function 'bidirectional' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 221** ⚠️ Function 'combining' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 225** ⚠️ Function 'mirrored' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 240** ⚠️ Function 'east_asian_width' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 258** ⚠️ Function 'get_icu_version' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/case.py`

- **Line 773** ❌ multiple exception types must be parenthesized (<unknown>, line 773)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/loader.py`

- **Line 72** ❌ multiple exception types must be parenthesized (<unknown>, line 72)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/main.py`

- **Line 99** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 99)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/result.py`

- **Line 14** ⚠️ Function 'failfast' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16** ⚠️ Function 'inner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/runner.py`

- **Line 22** ⚠️ Function 'writeln' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Function 'getDescription' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'startTest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Function 'addSuccess' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'addError' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'addFailure' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'addSkip' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'addExpectedFailure' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 97** ⚠️ Function 'addUnexpectedSuccess' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 105** ⚠️ Function 'printErrors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 111** ⚠️ Function 'printErrorList' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'run' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/signals.py`

- **Line 9** ⚠️ Class '_InterruptHandler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Function 'default_handler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'registerResult' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'removeResult' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Function 'installHandler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Function 'removeHandler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 60** ⚠️ Function 'inner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/suite.py`

- **Line 183** ❌ multiple exception types must be parenthesized (<unknown>, line 183)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/__init__.py`

- **Line 9** ⚠️ Function 'suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/support.py`

- **Line 15** ❌ multiple exception types must be parenthesized (<unknown>, line 15)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_assertions.py`

- **Line 73** ❌ multiple exception types must be parenthesized (<unknown>, line 73)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_break.py`

- **Line 17** ⚠️ Class 'TestBreak' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 20** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Function 'testInstallHandler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 44** ⚠️ Function 'testRegisterResult' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 57** ⚠️ Function 'testInterruptCaught' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 79** ⚠️ Function 'testSecondInterrupt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 88** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 105** ⚠️ Function 'testTwoResults' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 118** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 132** ⚠️ Function 'testHandlerReplacedButCalled' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 143** ⚠️ Function 'new_handler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 155** ⚠️ Function 'testRunner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 163** ⚠️ Function 'testWeakReferences' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 176** ⚠️ Function 'testRemoveResult' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 194** ⚠️ Function 'testMainInstallsHandler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Class 'FakeRunner' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 206** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 210** ⚠️ Class 'Program' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 244** ⚠️ Function 'testRemoveHandler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 254** ⚠️ Function 'testRemoveHandlerAsDecorator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 259** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 269** ⚠️ Class 'TestBreakDefaultIntHandler' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 276** ⚠️ Class 'TestBreakSignalIgnored' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 283** ⚠️ Class 'TestBreakSignalDefault' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_case.py`

- **Line 923** ❌ multiple exception types must be parenthesized (<unknown>, line 923)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_discovery.py`

- **Line 8** ⚠️ Class 'TestDiscovery' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'test_get_name_from_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Function 'test_find_tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 29** ⚠️ Function 'restore_listdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 32** ⚠️ Function 'restore_isfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 35** ⚠️ Function 'restore_isdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 44** ⚠️ Function 'isdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 49** ⚠️ Function 'isfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'test_find_tests_with_package' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Function 'restore_listdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Function 'restore_isfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'restore_isdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 92** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 100** ⚠️ Function 'load_tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 112** ⚠️ Function 'loadTestsFromModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 133** ⚠️ Function 'test_discover' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 138** ⚠️ Function 'restore_isfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 145** ⚠️ Function 'restore_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 159** ⚠️ Function 'restore_isdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 179** ⚠️ Function 'test_discover_with_modules_that_fail_to_import' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 187** ⚠️ Function 'restore' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'test_command_line_handling_parseArgs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 206** ⚠️ Function 'do_discovery' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 215** ⚠️ Function 'test_command_line_handling_do_discovery_too_many_arguments' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 216** ⚠️ Class 'Stop' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 218** ⚠️ Function 'usageExit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 230** ⚠️ Function 'test_command_line_handling_do_discovery_uses_default_loader' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 233** ⚠️ Class 'Loader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 235** ⚠️ Function 'discover' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 243** ⚠️ Function 'test_command_line_handling_do_discovery_calls_loader' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 246** ⚠️ Class 'Loader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 248** ⚠️ Function 'discover' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 317** ⚠️ Function 'test_detect_module_clash' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 318** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 326** ⚠️ Function 'cleanup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 335** ⚠️ Function 'listdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 337** ⚠️ Function 'isfile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 339** ⚠️ Function 'isdir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 358** ⚠️ Function 'test_discovery_from_dotted_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_functiontestcase.py`

- **Line 6** ⚠️ Class 'Test_FunctionTestCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 10** ⚠️ Function 'test_countTestCases' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 22** ⚠️ Function 'test_run_call_order__error_in_setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 26** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 33** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 47** ⚠️ Function 'test_run_call_order__error_in_test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'test_run_call_order__failure_in_test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 84** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 99** ⚠️ Function 'test_run_call_order__error_in_tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 103** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 109** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 124** ⚠️ Function 'test_id' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 132** ⚠️ Function 'test_shortDescription__no_docstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'test_shortDescription__singleline_docstring' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_loader.py`

- **Line 208** ❌ multiple exception types must be parenthesized (<unknown>, line 208)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_program.py`

- **Line 8** ⚠️ Class 'Test_TestProgram' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 10** ⚠️ Function 'test_discovery_from_dotted_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 27** ⚠️ Function 'testNoExit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 31** ⚠️ Class 'FakeRunner' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 32** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'restoreParseArgs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 44** ⚠️ Function 'removeTest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 55** ⚠️ Class 'FooBar' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 56** ⚠️ Function 'testPass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Function 'testFail' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 63** ⚠️ Function 'loadTestsFromModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 68** ⚠️ Function 'test_NonExit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 76** ⚠️ Function 'test_Exit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 86** ⚠️ Function 'test_ExitAsDefault' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 95** ⚠️ Class 'InitialisableProgram' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 109** ⚠️ Class 'FakeRunner' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 120** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 124** ⚠️ Class 'TestCommandLineArgs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 126** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 133** ⚠️ Function 'testHelpAndUnknown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 135** ⚠️ Function 'usageExit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 150** ⚠️ Function 'testVerbosity' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 163** ⚠️ Function 'testBufferCatchFailfast' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 185** ⚠️ Function 'testRunTestsRunnerClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'testRunTestsRunnerInstance' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 215** ⚠️ Function 'testRunTestsOldRunnerClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 233** ⚠️ Function 'testCatchBreakInstallsHandler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 236** ⚠️ Function 'restore' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 241** ⚠️ Function 'fakeInstallHandler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_result.py`

- **Line 425** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 425)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_runner.py`

- **Line 9** ⚠️ Class 'TestCleanUp' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Function 'testCleanUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 12** ⚠️ Class 'TestableTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 13** ⚠️ Function 'testNothing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 21** ⚠️ Function 'cleanup1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 24** ⚠️ Function 'cleanup2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Function 'testCleanUpWithErrors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Class 'TestableTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 42** ⚠️ Function 'testNothing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Class 'MockResult' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 47** ⚠️ Function 'addError' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'cleanup1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 59** ⚠️ Function 'cleanup2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'testCleanupInRun' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Class 'TestableTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 76** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'testNothing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 84** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'cleanup1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 91** ⚠️ Function 'cleanup2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 96** ⚠️ Function 'success' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 114** ⚠️ Function 'testTestCaseDebugExecutesCleanups' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 117** ⚠️ Class 'TestableTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 118** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'testNothing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 125** ⚠️ Function 'tearDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 130** ⚠️ Function 'cleanup1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 133** ⚠️ Function 'cleanup2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 143** ⚠️ Function 'test_init' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 152** ⚠️ Function 'test_multiple_inheritance' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 153** ⚠️ Class 'AResult' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 157** ⚠️ Class 'ATextResult' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 165** ⚠️ Function 'testBufferAndFailfast' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 166** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 167** ⚠️ Function 'testFoo' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 179** ⚠️ Function 'testRunnerRegistersResult' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 180** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 181** ⚠️ Function 'testFoo' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 184** ⚠️ Function 'cleanup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 194** ⚠️ Function 'fakeRegisterResult' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 202** ⚠️ Function 'test_works_with_result_without_startTestRun_stopTestRun' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 203** ⚠️ Class 'OldTextResult' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 205** ⚠️ Function 'printErrors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 208** ⚠️ Class 'Runner' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 218** ⚠️ Function 'test_startTestRun_stopTestRun_called' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 219** ⚠️ Class 'LoggingTextResult' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 221** ⚠️ Function 'printErrors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 224** ⚠️ Class 'LoggingRunner' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 238** ⚠️ Function 'test_pickle_unpickle' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 251** ⚠️ Function 'test_resultclass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 252** ⚠️ Function 'MockResultClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_setups.py`

- **Line 8** ⚠️ Function 'resultFactory' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 12** ⚠️ Class 'TestSetups' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 14** ⚠️ Function 'getRunner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 17** ⚠️ Function 'runTests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 33** ⚠️ Function 'test_setup_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 34** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 37** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 40** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 42** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 51** ⚠️ Function 'test_teardown_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 52** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 55** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 60** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'test_teardown_class_two_classes' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 70** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 73** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 76** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 78** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Class 'Test2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 84** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 87** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 99** ⚠️ Function 'test_error_in_setupclass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Class 'BrokenTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 102** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 117** ⚠️ Function 'test_error_in_teardown_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 118** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 121** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 124** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Class 'Test2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 132** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 135** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 137** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 150** ⚠️ Function 'test_class_not_torndown_when_setup_fails' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 151** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 154** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 157** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 160** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 166** ⚠️ Function 'test_class_not_setup_or_torndown_when_skipped' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 167** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 171** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 174** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 176** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 184** ⚠️ Function 'test_setup_teardown_order_with_pathological_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 187** ⚠️ Class 'Module1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 189** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 192** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 195** ⚠️ Class 'Module2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 197** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 200** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 203** ⚠️ Class 'Test1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 205** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 208** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 210** ⚠️ Function 'testOne' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 212** ⚠️ Function 'testTwo' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 215** ⚠️ Class 'Test2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 217** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 222** ⚠️ Function 'testOne' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 224** ⚠️ Function 'testTwo' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 227** ⚠️ Class 'Test3' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 229** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 232** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 234** ⚠️ Function 'testOne' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 236** ⚠️ Function 'testTwo' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 266** ⚠️ Function 'test_setup_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 267** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 270** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 273** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 274** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 276** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 286** ⚠️ Function 'test_error_in_setup_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 287** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 291** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 295** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 298** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 302** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 305** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 307** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 309** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 312** ⚠️ Class 'Test2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 313** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 315** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 331** ⚠️ Function 'test_testcase_with_missing_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 332** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 333** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 335** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 343** ⚠️ Function 'test_teardown_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 344** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 347** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 350** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 351** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 353** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 363** ⚠️ Function 'test_error_in_teardown_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 364** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 367** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 371** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 375** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 378** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 380** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 382** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 385** ⚠️ Class 'Test2' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 386** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 388** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 403** ⚠️ Function 'test_skiptest_in_setupclass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 404** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 406** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 408** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 410** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 420** ⚠️ Function 'test_skiptest_in_setupmodule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 421** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 422** ⚠️ Function 'test_one' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 424** ⚠️ Function 'test_two' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 427** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 429** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 442** ⚠️ Function 'test_suite_debug_executes_setups_and_teardowns' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 445** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 447** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 450** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 453** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 455** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 458** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 460** ⚠️ Function 'test_something' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 471** ⚠️ Function 'test_suite_debug_propagates_exceptions' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 472** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 474** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 478** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 482** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 484** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 488** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 491** ⚠️ Function 'test_something' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_skipping.py`

- **Line 6** ⚠️ Class 'Test_TestSkipping' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 8** ⚠️ Function 'test_skipping' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 9** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 10** ⚠️ Function 'test_skip_me' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 20** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 21** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Function 'test_nothing' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 32** ⚠️ Function 'test_skipping_decorators' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'test_skip' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Function 'test_dont_skip' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 56** ⚠️ Function 'test_skip_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 59** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'test_skip_non_unittest_class_old_style' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Class 'Mixin' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 72** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 74** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 84** ⚠️ Function 'test_skip_non_unittest_class_new_style' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 86** ⚠️ Class 'Mixin' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 87** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 99** ⚠️ Function 'test_expected_failure' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 100** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 102** ⚠️ Function 'test_die' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 113** ⚠️ Function 'test_unexpected_success' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 114** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 116** ⚠️ Function 'test_die' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 128** ⚠️ Function 'test_skip_doesnt_run_setup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 132** ⚠️ Function 'setUp' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 134** ⚠️ Function 'tornDown' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 137** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 148** ⚠️ Function 'test_decorated_skip' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 149** ⚠️ Function 'decorator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 150** ⚠️ Function 'inner' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 154** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 157** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_suite.py`

- **Line 10** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 11** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 12** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 13** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 14** ⚠️ Function 'test_3' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 15** ⚠️ Function 'runTest' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 23** ⚠️ Class 'Test_TestSuite' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 48** ⚠️ Function 'test_init__tests_optional' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 60** ⚠️ Function 'test_init__empty_tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'test_init__tests_from_any_iterable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 72** ⚠️ Function 'tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 92** ⚠️ Function 'test_init__TestSuite_instances_in_tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function 'tests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 105** ⚠️ Function 'test_iter' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 117** ⚠️ Function 'test_countTestCases_zero_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 128** ⚠️ Function 'test_countTestCases_zero_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Class 'Test1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 130** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'test_countTestCases_simple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 152** ⚠️ Function 'test_countTestCases_nested' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 153** ⚠️ Class 'Test1' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 154** ⚠️ Function 'test1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 155** ⚠️ Function 'test2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 168** ⚠️ Function 'test_run__empty_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 180** ⚠️ Function 'test_run__requires_result' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 192** ⚠️ Function 'test_run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 196** ⚠️ Class 'LoggingCase' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 197** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 200** ⚠️ Function 'test1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'test2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 210** ⚠️ Function 'test_addTest__TestCase' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 211** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 212** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 223** ⚠️ Function 'test_addTest__TestSuite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 224** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 225** ⚠️ Function 'test' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 240** ⚠️ Function 'test_addTests' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 241** ⚠️ Class 'Foo' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 242** ⚠️ Function 'test_1' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 243** ⚠️ Function 'test_2' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 249** ⚠️ Function 'gen' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 271** ⚠️ Function 'test_addTest__noniterable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 281** ⚠️ Function 'test_addTest__noncallable' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 285** ⚠️ Function 'test_addTest__casesuiteclass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 290** ⚠️ Function 'test_addTests__string' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 294** ⚠️ Function 'test_function_in_suite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 295** ⚠️ Function 'f' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 305** ⚠️ Function 'test_basetestsuite' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 306** ⚠️ Class 'Test' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 310** ⚠️ Function 'setUpClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 313** ⚠️ Function 'tearDownClass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 315** ⚠️ Function 'testPass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 317** ⚠️ Function 'testFail' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 319** ⚠️ Class 'Module' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 323** ⚠️ Function 'setUpModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 326** ⚠️ Function 'tearDownModule' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 348** ⚠️ Function 'test_overriding_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 349** ⚠️ Class 'MySuite' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/util.py`

- **Line 8** ⚠️ Function 'safe_repr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 18** ⚠️ Function 'strclass' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'unorderable_list_difference' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 100** ⚠️ Function '_count_diff_all_purpose' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urllib.py`

- **Line 222** ❌ multiple exception types must be parenthesized (<unknown>, line 222)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urllib2.py`

- **Line 254** ❌ invalid syntax (<unknown>, line 254)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urlparse.py`

- **Line 392** ❌ invalid syntax (<unknown>, line 392)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/uu.py`

- **Line 75** ❌ leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers (<unknown>, line 75)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/uuid.py`

- **Line 151** ❌ invalid decimal literal (<unknown>, line 151)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/warnings.py`

- **Line 106** ❌ multiple exception types must be parenthesized (<unknown>, line 106)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/webbrowser.py`

- **Line 58** ❌ multiple exception types must be parenthesized (<unknown>, line 58)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/whichdb.py`

- **Line 117** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 117)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/handlers.py`

- **Line 167** ❌ invalid syntax (<unknown>, line 167)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/simple_server.py`

- **Line 152** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 152)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/util.py`

- **Line 29** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/validate.py`

- **Line 127** ⚠️ Function 'assert_' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 143** ⚠️ Function 'lint_app' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 154** ⚠️ Function 'start_response_wrapper' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 186** ⚠️ Class 'InputWrapper' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 191** ⚠️ Function 'read' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 197** ⚠️ Function 'readline' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 202** ⚠️ Function 'readlines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 217** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Class 'ErrorWrapper' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 225** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 229** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 232** ⚠️ Function 'writelines' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 236** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 239** ⚠️ Class 'WriteWrapper' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 248** ⚠️ Class 'PartialIteratorWrapper' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 257** ⚠️ Class 'IteratorWrapper' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 268** ⚠️ Function 'next' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 278** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 290** ⚠️ Function 'check_environ' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 355** ⚠️ Function 'check_input' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 361** ⚠️ Function 'check_errors' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 367** ⚠️ Function 'check_status' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 382** ⚠️ Function 'check_headers' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 407** ⚠️ Function 'check_content_type' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 421** ⚠️ Function 'check_exc_info' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 426** ⚠️ Function 'check_iterator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xdrlib.py`

- **Line 66** ❌ invalid hexadecimal literal (<unknown>, line 66)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/FtCore.py`

- **Line 8** ⚠️ Class 'FtException' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 41** ⚠️ Function 'get_translator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'get_translator' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/Uri.py`

- **Line 182** ⚠️ Function 'MakeUrllibSafe' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 294** ⚠️ Function 'RemoveDotSegments' has high complexity (13)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/NodeFilter.py`

- **Line 12** ❌ invalid hexadecimal literal (<unknown>, line 12)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/__init__.py`

- **Line 75** ⚠️ Class 'IndexSizeErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 78** ⚠️ Class 'DomstringSizeErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 81** ⚠️ Class 'HierarchyRequestErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 84** ⚠️ Class 'WrongDocumentErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 87** ⚠️ Class 'InvalidCharacterErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 90** ⚠️ Class 'NoDataAllowedErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 93** ⚠️ Class 'NoModificationAllowedErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 96** ⚠️ Class 'NotFoundErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 99** ⚠️ Class 'NotSupportedErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 102** ⚠️ Class 'InuseAttributeErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 105** ⚠️ Class 'InvalidStateErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 108** ⚠️ Class 'SyntaxErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 111** ⚠️ Class 'InvalidModificationErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 114** ⚠️ Class 'NamespaceErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 117** ⚠️ Class 'InvalidAccessErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 120** ⚠️ Class 'ValidationErr' missing docstring
  - Suggestion: Add a docstring describing the class's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/domreg.py`

- **Line 80** ❌ invalid syntax (<unknown>, line 80)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/expatbuilder.py`

- **Line 479** ❌ invalid syntax (<unknown>, line 479)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/minicompat.py`

- **Line 51** ⚠️ Class 'NodeList' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 54** ⚠️ Function 'item' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 75** ⚠️ Class 'EmptyNodeList' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 88** ⚠️ Function 'item' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 102** ⚠️ Function 'defproperty' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'set' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/minidom.py`

- **Line 537** ❌ invalid syntax (<unknown>, line 537)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/pulldom.py`

- **Line 203** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 203)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/xmlbuilder.py`

- **Line 337** ❌ invalid syntax (<unknown>, line 337)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementInclude.py`

- **Line 62** ⚠️ Class 'FatalIncludeError' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 77** ⚠️ Function 'default_loader' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 98** ⚠️ Function 'include' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 98** ⚠️ Function 'include' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementPath.py`

- **Line 73** ⚠️ Function 'xpath_tokenizer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 87** ⚠️ Function 'get_parent_map' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 96** ⚠️ Function 'prepare_child' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 98** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 105** ⚠️ Function 'prepare_star' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 112** ⚠️ Function 'prepare_self' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 113** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 118** ⚠️ Function 'prepare_descendant' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 133** ⚠️ Function 'prepare_parent' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 134** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 146** ⚠️ Function 'prepare_predicate' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 146** ⚠️ Function 'prepare_predicate' has high complexity (25)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 165** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 174** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 182** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 191** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 212** ⚠️ Function 'select' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 237** ⚠️ Class '_SelectorContext' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 247** ⚠️ Function 'iterfind' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 283** ⚠️ Function 'find' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 292** ⚠️ Function 'findall' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 298** ⚠️ Function 'findtext' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementTree.py`

- **Line 1654** ❌ multiple exception types must be parenthesized (<unknown>, line 1654)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/parsers/expat.py`

- **Line 205** ❌ multiple exception types must be parenthesized (<unknown>, line 205)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/__init__.py`

- **Line 83** ❌ multiple exception types must be parenthesized (<unknown>, line 83)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/drivers2/drv_javasax.py`

- **Line 163** ❌ multiple exception types must be parenthesized (<unknown>, line 163)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/handler.py`

- **Line 42** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 42)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/saxutils.py`

- **Line 554** ❌ multiple exception types must be parenthesized (<unknown>, line 554)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/xmlreader.py`

- **Line 298** ❌ invalid syntax (<unknown>, line 298)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xmllib.py`

- **Line 813** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 813)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xmlrpclib.py`

- **Line 194** ❌ invalid decimal literal (<unknown>, line 194)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/zipfile.py`

- **Line 406** ❌ invalid hexadecimal literal (<unknown>, line 406)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/zlib.py`

- **Line 55** ❌ invalid hexadecimal literal (<unknown>, line 55)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/ghidradoc.py`

- **Line 62** ❌ invalid decimal literal (<unknown>, line 62)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/introspect.py`

- **Line 25** ❌ cannot assign to True (<unknown>, line 25)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/jintrospect.py`

- **Line 51** ⚠️ Function 'getCallTipJava' has high complexity (20)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 67** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 121** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/AskScriptPy.py`

- **Line 45** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 45)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/CallAnotherScriptForAllProgramsPy.py`

- **Line 38** ⚠️ Function 'recurseProjectFolder' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'processDomainFile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ChooseDataTypeScriptPy.py`

- **Line 37** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 37)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ExampleColorScriptPy.py`

- **Line 33** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 33)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/FormatExampleScriptPy.py`

- **Line 28** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 28)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/PrintNonZeroPurge.py`

- **Line 21** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 21)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/external_module_callee.py`

- **Line 24** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 24)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ghidra_basics.py`

- **Line 22** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 22)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/jython_basics.py`

- **Line 23** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 23)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/python_basics.py`

- **Line 22** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 22)

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/__init__.py`

- **Line 40** ⚠️ Function 'wrapper' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/__main__.py`

- **Line 115** ⚠️ Function 'script_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 119** ⚠️ Function 'script_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 127** ⚠️ Function 'jvm_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/converters.py`

- **Line 22** ⚠️ Function 'pathToString' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 27** ⚠️ Function 'pathToFile' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/core.py`

- **Line 78** ⚠️ Function '_setup_project' has high complexity (19)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/ghidra_launch.py`

- **Line 25** ⚠️ Class 'GhidraLauncher' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 50** ⚠️ Class 'ParsedArgs' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 61** ⚠️ Function 'jvm_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 70** ⚠️ Function 'get_parser' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/ghidradoc.py`

- **Line 31** ⚠️ Class '_Helper' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 56** ⚠️ Function '__call__' has high complexity (31)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 58** ⚠️ Function 'get_class_and_method' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 74** ⚠️ Function 'get_jsondoc' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 92** ⚠️ Function 'format_class' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 102** ⚠️ Function 'format_field' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 113** ⚠️ Function 'format_method' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/gui.py`

- **Line 29** ⚠️ Class '_GuiOutput' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 35** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 41** ⚠️ Class '_GuiArgumentParser' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 42** ⚠️ Function 'exit' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 45** ⚠️ Function 'print_usage' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'print_help' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 157** ⚠️ Function 'get_current_interpreter' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/internal/plugin/completions.py`

- **Line 119** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/internal/plugin/plugin.py`

- **Line 51** ⚠️ Class 'ThreadState' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 95** ⚠️ Function 'run' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 107** ⚠️ Function 'interrupt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 115** ⚠️ Function 'clear_interrupted' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 118** ⚠️ Function 'kill' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 127** ⚠️ Function 'interrupted' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 131** ⚠️ Function 'killed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 135** ⚠️ Class 'ConsoleState' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 171** ⚠️ Function 'raw_input' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 186** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 211** ⚠️ Function 'close' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 228** ⚠️ Function 'reset' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 239** ⚠️ Function 'name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 243** ⚠️ Function 'restart' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 252** ⚠️ Function 'interrupt' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 260** ⚠️ Function 'interact' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 276** ⚠️ Function 'redirect_writer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 283** ⚠️ Function 'showsyntaxerror' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 287** ⚠️ Function 'showtraceback' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 316** ⚠️ Function 'runcode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 321** ⚠️ Function 'getCompletions' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 337** ⚠️ Function 'setup_plugin' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/javac.py`

- **Line 46** ⚠️ Class '_CompilerDiagnosticListener' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 53** ⚠️ Function 'report' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/launcher.py`

- **Line 97** ⚠️ Function 'find_spec' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 106** ⚠️ Function 'create_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 109** ⚠️ Function 'exec_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 115** ⚠️ Function 'find_spec' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 149** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 276** ⚠️ Function 'extension_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 286** ⚠️ Function 'java_home' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 300** ⚠️ Function 'java_home' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 304** ⚠️ Function 'install_dir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 440** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 551** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 626** ⚠️ Class '_PyGhidraStdOut' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 637** ⚠️ Function 'flush' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 647** ⚠️ Function 'write' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 664** ⚠️ Function 'popup_error' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 708** ⚠️ Function 'get_function' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 741** ⚠️ Function 'dummy_timer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/properties.py`

- **Line 25** ⚠️ Class '_JavaObject' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 27** ⚠️ Function '__jclass_init__' has high complexity (11)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 59** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/script.py`

- **Line 36** ⚠️ Class '_StaticMap' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 59** ⚠️ Function 'get' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'keys' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'items' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Class '_JavaProperty' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 88** ⚠️ Class '_PythonFieldExposer' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 99** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch
- **Line 104** ⚠️ Class '_GhidraScriptModule' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 115** ⚠️ Class '_GhidraScriptLoader' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 121** ⚠️ Function 'create_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'exec_module' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 132** ⚠️ Function 'wrapper' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 199** ⚠️ Function 'get_static' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 205** ⚠️ Function 'get_static_view' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 253** ⚠️ Bare except clause catches all exceptions
  - Suggestion: Specify the exception type(s) to catch

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/version.py`

- **Line 75** ⚠️ Function 'from_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 77** ⚠️ Function 'cast' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/data/example_script.py`

- **Line 19** ⚠️ Function 'import_test_function' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_argparser.py`

- **Line 30** ⚠️ Function 'exe_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Class 'TestArgParser' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 38** ⚠️ Function 'parse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 50** ⚠️ Function 'example_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'example_exe' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 58** ⚠️ Function 'ghost_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 62** ⚠️ Function 'ghost_exe' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 65** ⚠️ Function 'test_no_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 69** ⚠️ Function 'test_verbose_flag' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 73** ⚠️ Function 'test_project_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 80** ⚠️ Function 'test_project_path' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 88** ⚠️ Function 'test_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function 'test_non_existing_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 99** ⚠️ Function 'test_binary' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 104** ⚠️ Function 'test_non_existing_binary' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 109** ⚠️ Function 'test_non_existing_binary_plus_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 115** ⚠️ Function 'test_script_with_non_existing_binary_arg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'test_script_with_optional_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 129** ⚠️ Function 'test_script_with_positional_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 145** ⚠️ Function 'test_script_with_intermingled_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 165** ⚠️ Function 'test_binary_script_with_intermingled_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 191** ⚠️ Function 'test_skip_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 197** ⚠️ Function 'test_default_analysis' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 201** ⚠️ Function 'test_jvm_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 211** ⚠️ Class 'TestGhidraLaunchParser' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 213** ⚠️ Function 'parse' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 220** ⚠️ Function 'test_class_name' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 225** ⚠️ Function 'test_gui_mode' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 229** ⚠️ Function 'test_jvm_args' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 238** ⚠️ Function 'test_remaining' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_core.py`

- **Line 30** ⚠️ Function 'class_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 37** ⚠️ Function 'test_invalid_jpype_keyword_arg' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'test_invalid_vm_arg_succeed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 54** ⚠️ Function 'test_run_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'test_open_program' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 79** ⚠️ Function 'test_bad_language' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 90** ⚠️ Function 'test_bad_compiler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 102** ⚠️ Function 'test_no_compiler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Function 'test_no_language_with_compiler' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 114** ⚠️ Function 'test_loader' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 126** ⚠️ Function 'test_invalid_loader' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 139** ⚠️ Function 'test_invalid_loader_type' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 152** ⚠️ Function 'test_no_project' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 158** ⚠️ Function 'test_no_program' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 167** ⚠️ Function 'test_import_script' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 174** ⚠️ Function 'test_import_ghidra_base_java_packages' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 176** ⚠️ Function 'get_runtime_top_level_java_packages' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 190** ⚠️ Function 'wrap_mod' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_plugin.py`

- **Line 43** ⚠️ Class 'PluginTest' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 61** ⚠️ Function 'setup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 66** ⚠️ Function 'prelaunch' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 89** ⚠️ Function 'test_setup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 93** ⚠️ Function 'test_prelaunch' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 97** ⚠️ Class 'EntryPoint' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 103** ⚠️ Function 'load' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 111** ⚠️ Function 'entry_points' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 143** ⚠️ Class 'TestValidPlugin' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 146** ⚠️ Function 'setup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 151** ⚠️ Function 'prelaunch' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 156** ⚠️ Function 'test_extension_point' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 163** ⚠️ Class 'TestBadPlugin' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 168** ⚠️ Function 'setup' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 174** ⚠️ Function 'prelaunch' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 178** ⚠️ Function 'test_no_plugin' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py`

- **Line 26** ⚠️ Function 'get_application_properties' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 39** ⚠️ Function 'get_launch_properties' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 53** ⚠️ Function 'get_user_settings_dir' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'find_supported_python_exe' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 108** ⚠️ Function 'in_venv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 111** ⚠️ Function 'is_externally_managed' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 122** ⚠️ Function 'get_venv_exe' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 127** ⚠️ Function 'get_ghidra_venv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 130** ⚠️ Function 'create_ghidra_venv' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 134** ⚠️ Function 'version_tuple' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 140** ⚠️ Function 'get_package_version' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 151** ⚠️ Function 'get_saved_python_cmd' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 162** ⚠️ Function 'save_python_cmd' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 170** ⚠️ Function 'install' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 194** ⚠️ Function 'upgrade' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 211** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 211** ⚠️ Function 'main' has high complexity (12)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/radare2/libr/bin/d/dll/convert_dumpbin_exports_to_sdb_txt.py`

- **Line 4** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 4)

### `tools/radare2/libr/bin/format/xnu/scripts/build_mig_index.py`

- **Line 44** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 44)

### `tools/radare2/libr/bin/format/xnu/scripts/machtraps.py`

- **Line 59** ❌ Missing parentheses in call to 'print'. Did you mean print(...)? (<unknown>, line 59)

### `tools/radare2/libr/include/sflib/darwin-arm-64/ios-syscalls.py`

- **Line 4** ⚠️ Function 'chk' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/radare2/radare2-5.9.8-w64/share/scripts/r2sptrace.py`

- **Line 13** ⚠️ Function 'sp_delta_for_fcn_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 20** ⚠️ Function 'sp_delta_for_instr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Function 'block_at' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'trace_block' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/radare2/scripts/r2sptrace.py`

- **Line 13** ⚠️ Function 'sp_delta_for_fcn_call' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 20** ⚠️ Function 'sp_delta_for_instr' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 30** ⚠️ Function 'block_at' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 36** ⚠️ Function 'trace_block' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/radare2/sys/clang-format-diff.py`

- **Line 43** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 43** ⚠️ Function 'main' has high complexity (33)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 74** ⚠️ Function 'debug' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/radare2/sys/clang-format.py`

- **Line 39** ⚠️ Function 'skip' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/radare2/sys/indent.py`

- **Line 10** ⚠️ Function 'is_function' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 13** ⚠️ Function 'is_control_structure' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 16** ⚠️ Function 'fix_line' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 25** ⚠️ Function 'replacer' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/radare2/sys/lint.py`

- **Line 7** ⚠️ Class 'LintCheck' missing docstring
  - Suggestion: Add a docstring describing the class's purpose
- **Line 23** ⚠️ Function 'applies_to_file' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 33** ⚠️ Function 'check_line' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 46** ⚠️ Function 'get_checks' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 198** ⚠️ Function 'run_lint_checks' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 198** ⚠️ Function 'run_lint_checks' has high complexity (24)
  - Suggestion: Consider breaking this function into smaller functions
- **Line 271** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `tools/radare2/sys/meson.py`

- **Line 114** ⚠️ Function 'copytree' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 120** ⚠️ Function 'move' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 128** ⚠️ Function 'copy' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 136** ⚠️ Function 'makedirs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 141** ⚠️ Function 'xp_compat' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 193** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 193** ⚠️ Function 'main' has high complexity (22)
  - Suggestion: Consider breaking this function into smaller functions

### `tools/radare2/test/fuzz/scripts/fuzz_rasm2.py`

- **Line 59** ⚠️ Function 'cannonical' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 63** ⚠️ Function 'meta_cannonical' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 71** ⚠️ Function 'meta_meta_cannonical' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 81** ⚠️ Function 'gen_testcase' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 95** ⚠️ Function 'check_hexpairs' missing docstring
  - Suggestion: Add a docstring describing the function's purpose
- **Line 130** ⚠️ Function 'main' missing docstring
  - Suggestion: Add a docstring describing the function's purpose

### `utils/siphash24_replacement.py`

- **Line 74** ⚠️ Function '_siphash' has high complexity (16)
  - Suggestion: Consider breaking this function into smaller functions

## Module Quality Analysis

### Files Missing Module Docstrings

- `intellicrack/ui/adobe_injector_src/adobe_full_auto_injector.py`
- `intellicrack/ui/missing_methods.py`
- `plugins/custom_modules/demo_plugin.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/loaders/xmlldr.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/plugins/xmlexp.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/plugins/xmlldr.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/kernel-dbgeng.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-dbgeng-attach.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-dbgeng-ext.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-dbgeng.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/local-ttd.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/data/support/remote-dbgeng.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/arch.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/commands.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/idatamodelmanager.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/idebughost.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/ihostdatamodelaccess.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/iiterableconcept.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/ikeyenumerator.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/imodeliterator.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/imodelobject.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/irawenumerator.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/dbgmodel/istringdisplayableconcept.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/exdi/exdi_commands.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/exdi/exdi_methods.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/hooks.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/libraries.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/methods.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidradbg/util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/arch.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/commands.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/hooks.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/libraries.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/methods.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-dbgeng/pypkg/src/ghidrattd/util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/data/scripts/remote-proc-mappings.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/arch.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/commands.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/hooks.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/methods.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/parameters.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/wine.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/arch.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/commands.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/hooks.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/methods.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-agent-lldb/pypkg/src/ghidralldb/util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/data/support/raw-python3.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/client.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/sch.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/trace_rmi_pb2.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/DumpBSimDebugSignaturesScript.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/DumpBSimSignaturesScript.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/ExampleOverviewQueryScript.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/GenerateSignatures.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/QueryFunction.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/LocateMemoryAddressesForFileOffset.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/RecursiveStringFinder.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/RunYARAFromGhidra.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/mark_in_out.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/BaseHTTPServer.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/CGIHTTPServer.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ConfigParser.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/DocXMLRPCServer.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SimpleHTTPServer.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SimpleXMLRPCServer.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SocketServer.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/StringIO.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserDict.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserString.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_fsum.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_google_ipaddr_r234.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_rawffi.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_socket.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_sslcerts.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_strptime.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_weakrefset.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/aifc.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/anydbm.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/asynchat.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/asyncore.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/atexit.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/base64.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/bdb.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/binhex.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/calendar.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cgi.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/chunk.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cmd.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/code.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/codecs.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/codeop.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/collections.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compileall.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/consts.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/future.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/misc.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/pyassem.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/pycodegen.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/symbols.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/syntax.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/transformer.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/visitor.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/contextlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/copy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/copy_reg.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/crypt.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/csv.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ctypes/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dbexts.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/decimal.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/difflib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dis.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/archive_util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/bcppcompiler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/ccompiler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/cmd.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_dumb.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_msi.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_rpm.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_wininst.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_clib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_ext.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_scripts.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_lib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_scripts.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/register.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/sdist.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/upload.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/config.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/core.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/cygwinccompiler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/debug.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dep_util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dir_util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dist.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/emxccompiler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/fancy_getopt.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/file_util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/filelist.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/msvc9compiler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/msvccompiler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/spawn.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/setuptools_build_ext.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/setuptools_extension.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_build_ext.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_spawn.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/text_file.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/unixccompiler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/util.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/version.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/doctest.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dumbdbm.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/charset.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/mime/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_codecs.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_codecs_renamed.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_renamed.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_torture.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/_java.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/big5.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/big5hkscs.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp932.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp949.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp950.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_jis_2004.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_jisx0213.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_jp.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/euc_kr.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/gb18030.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/gb2312.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/gbk.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/hz.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/idna.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_1.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_2.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_2004.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_3.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_jp_ext.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso2022_kr.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/johab.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/punycode.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/shift_jis.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/shift_jis_2004.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/shift_jisx0213.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_16.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_32.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/uu_codec.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ensurepip/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ensurepip/__main__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/filecmp.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fileinput.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/formatter.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fpformat.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ftplib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/getopt.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/gettext.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/grp.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/gzip.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/hashlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/heapq.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/htmllib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/httplib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ihooks.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imaplib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imghdr.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imp.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/isql.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/javapath.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/javashell.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/encoder.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_check_circular.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_decode.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_default.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_dump.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_dunderdict.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_encode_basestring_ascii.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_fail.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_float.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_indent.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_pass1.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_pass2.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_pass3.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_recursion.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_scanstring.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_separators.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_speedups.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_tool.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_unicode.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tool.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/jythonlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/__main__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_unicode.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/main.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/conv.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/driver.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/grammar.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/literals.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/pgen.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/tokenize.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/bom.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/crlf.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/different_encoding.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/bad_order.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_explicit.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_first.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_last.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_parrot.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/myfixes/fix_preorder.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/no_fixer_cls.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/fixers/parrot_example.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/infinite_recursion.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/py2_test_grammar.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/py3_test_grammar.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/pytree_idempotency.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_main.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/locale.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/logging/config.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/macpath.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/macurl2path.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mailbox.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mailcap.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/md5.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mhlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimetools.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimetypes.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimify.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_exceptions.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_impl.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_input.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_log.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_params.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_publish.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_response.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_write.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_wsgi.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/multifile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/netrc.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/nntplib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/nturl2path.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/optparse.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/os.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pawt/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pawt/colors.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pdb.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pickle.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pickletools.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pipes.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pkgutil.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/platform.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/plistlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/popen2.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/poplib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/posixfile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pprint.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/profile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pstats.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pty.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pwd.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/py_compile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pycimport.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pyclbr.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pydoc.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pydoc_data/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pydoc_data/topics.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pyexpat.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/quopri.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/random.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/re.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/readline.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/rfc822.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/rlcompleter.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/runpy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/select.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sets.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sgmllib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sha.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shlex.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shutil.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/signal.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/site.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/smtpd.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/smtplib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sndhdr.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/socket.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_compile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_constants.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_parse.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ssl.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/stat.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/string.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/subprocess.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sysconfig.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tabnanny.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tarfile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/telnetlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tempfile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/textwrap.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/this.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/threading.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/timeit.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/token.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tokenize.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/trace.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unicodedata.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/case.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/loader.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/main.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/signals.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/suite.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/dummy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/support.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_assertions.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_break.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_case.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_discovery.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_functiontestcase.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_loader.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_program.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_result.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_runner.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_setups.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_skipping.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_suite.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urllib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urllib2.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urlparse.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/uu.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/uuid.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/warnings.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/webbrowser.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/whichdb.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/handlers.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/simple_server.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xdrlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/Uri.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/NodeFilter.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/domreg.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/expatbuilder.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/minidom.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/pulldom.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/xmlbuilder.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementInclude.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementPath.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementTree.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/cElementTree.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/parsers/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/parsers/expat.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/drivers2/drv_javasax.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/handler.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/saxutils.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/xmlreader.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xmllib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xmlrpclib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/zipfile.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/zlib.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/ghidradoc.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/introspect.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/AddCommentToProgramScriptPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/AskScriptPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/CallAnotherScriptForAllProgramsPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/CallAnotherScriptPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ChooseDataTypeScriptPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ExampleColorScriptPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/FormatExampleScriptPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ImportSymbolsScript.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/PrintNonZeroPurge.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ToolPropertiesExampleScriptPy.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/external_module_callee.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/external_module_caller.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ghidra_basics.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/jython_basics.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/python_basics.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/ghidra_scripts/PyGhidraBasics.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/setup.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/__main__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/converters.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/core.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/ghidra_launch.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/gui.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/internal/__init__.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/internal/plugin/completions.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/internal/plugin/plugin.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/javac.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/launcher.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/properties.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/script.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/version.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/data/example_script.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/data/import_test_script.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/data/programless_script.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/data/projectless_script.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_argparser.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_core.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_plugin.py`
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py`
- `tools/radare2/libr/bin/d/dll/convert_dumpbin_exports_to_sdb_txt.py`
- `tools/radare2/libr/bin/format/xnu/scripts/build_mig_index.py`
- `tools/radare2/libr/bin/format/xnu/scripts/machtraps.py`
- `tools/radare2/libr/flag/d/tags.py`
- `tools/radare2/libr/include/sflib/darwin-arm-64/ios-syscalls.py`
- `tools/radare2/libr/syscall/d/gen.py`
- `tools/radare2/radare2-5.9.8-w64/share/scripts/r2sptrace.py`
- `tools/radare2/scripts/r2sptrace.py`
- `tools/radare2/sys/clang-format.py`
- `tools/radare2/sys/indent.py`
- `tools/radare2/sys/lint.py`
- `tools/radare2/test/bench/r2pipe/test-example.py`
- `tools/radare2/test/fuzz/scripts/fuzz_rasm2.py`
- `tools/radare2/test/unit/legacy_unit/syscall/openbsd-gen.py`

### Large Files Missing Main Guard

- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/decimal.py` (6167 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_fixers.py` (4541 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/python/idaxml.py` (3730 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email.py` (3561 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/test/test_email_renamed.py` (3332 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/doctest.py` (2798 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/infinite_recursion.py` (2669 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tarfile.py` (2587 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/plugins/xmlexp.py` (2495 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pydoc.py` (2453 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/argparse.py` (2374 lines)
- `intellicrack/utils/runner_functions.py` (2316 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_socket.py` (2295 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pickletools.py` (2274 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/datetime.py` (2245 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mailbox.py` (2230 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/difflib.py` (2059 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/subprocess.py` (2051 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_pyio.py` (2017 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/minidom.py` (1943 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_google_ipaddr_r234.py` (1907 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/locale.py` (1891 lines)
- `intellicrack/ui/dialogs/model_finetuning_dialog.py` (1864 lines)
- `intellicrack/hexview/hex_widget.py` (1863 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/loaders/xmlldr.py` (1823 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/6xx/plugins/xmlldr.py` (1823 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cookielib.py` (1794 lines)
- `intellicrack/utils/exploitation.py` (1769 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/platform.py` (1737 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/logging/__init__.py` (1728 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/optparse.py` (1703 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urllib.py` (1681 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementTree.py` (1680 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xmlrpclib.py` (1656 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_io.py` (1652 lines)
- `intellicrack/utils/additional_runners.py` (1645 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/pycodegen.py` (1546 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imaplib.py` (1535 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/zipfile.py` (1526 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/transformer.py` (1491 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urllib2.py` (1489 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/httplib.py` (1470 lines)
- `intellicrack/hexview/ai_bridge.py` (1425 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/ast.py` (1419 lines)
- `intellicrack/utils/tool_wrappers.py` (1397 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pickle.py` (1364 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pdb.py` (1338 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ssl.py` (1323 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_loader.py` (1286 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dist.py` (1249 lines)
- `intellicrack/ai/model_manager_module.py` (1200 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/logging/handlers.py` (1198 lines)
- `intellicrack/core/processing/distributed_manager.py` (1125 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_case.py` (1124 lines)
- `intellicrack/utils/binary_analysis.py` (1120 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/codecs.py` (1098 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/ccompiler.py` (1098 lines)
- `intellicrack/ai/enhanced_training_interface.py` (1095 lines)
- `intellicrack/utils/distributed_processing.py` (1093 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/case.py` (1077 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/inspect.py` (1070 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ftplib.py` (1061 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cgi.py` (1050 lines)
- `intellicrack/utils/internal_helpers.py` (1029 lines)
- `intellicrack/hexview/advanced_search.py` (1023 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/rfc822.py` (1016 lines)
- `intellicrack/ui/dialogs/guided_workflow_wizard.py` (1014 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mhlib.py` (1005 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/expatbuilder.py` (983 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/aifc.py` (975 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/data/py2_test_grammar.py` (974 lines)
- `intellicrack/ui/dialogs/keygen_dialog.py` (939 lines)
- `intellicrack/core/network/traffic_analyzer.py` (933 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xmllib.py` (930 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/logging/config.py` (906 lines)
- `intellicrack/core/network/cloud_license_hooker.py` (904 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/random.py` (904 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pytree.py` (887 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/smtplib.py` (874 lines)
- `intellicrack/utils/protection_detection.py` (863 lines)
- `intellicrack/plugins/plugin_system.py` (857 lines)
- `intellicrack/ui/dialogs/report_manager_dialog.py` (851 lines)
- `intellicrack/ui/dialogs/system_utilities_dialog.py` (838 lines)
- `intellicrack/ui/dialogs/help_documentation_widget.py` (833 lines)
- `intellicrack/ai/ml_predictor.py` (822 lines)
- `intellicrack/utils/patch_verification.py` (819 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/trace.py` (819 lines)
- `intellicrack/core/processing/qemu_emulator.py` (814 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/saxutils.py` (813 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_parse.py` (801 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/msvc9compiler.py` (801 lines)
- `intellicrack/ai/ai_assistant_enhanced.py` (800 lines)
- `intellicrack/core/analysis/dynamic_analyzer.py` (800 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/message.py` (799 lines)
- `intellicrack/hexview/file_handler.py` (798 lines)
- `intellicrack/core/network/license_server_emulator.py` (795 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/telnetlib.py` (787 lines)
- `intellicrack/core/reporting/pdf_generator.py` (786 lines)
- `intellicrack/ai/training_thread.py` (783 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_ext.py` (766 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/pyassem.py` (763 lines)
- `intellicrack/hexview/data_inspector.py` (760 lines)
- `intellicrack/ui/widgets/hex_viewer.py` (757 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ConfigParser.py` (753 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/launcher.py` (751 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/refactor.py` (747 lines)
- `intellicrack/ai/orchestrator.py` (743 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_msi.py` (742 lines)
- `intellicrack/utils/final_utilities.py` (741 lines)
- `intellicrack/core/patching/payload_generator.py` (739 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SocketServer.py` (739 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sysconfig.py` (739 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/os.py` (737 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dbexts.py` (722 lines)
- `intellicrack/core/processing/gpu_accelerator.py` (719 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/calendar.py` (713 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SimpleXMLRPCServer.py` (707 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pstats.py` (705 lines)
- `intellicrack/core/analysis/cfg_explorer.py` (701 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp437.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp737.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp850.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp852.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp855.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp858.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp860.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp861.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp862.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp863.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp865.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp866.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_arabic.py` (698 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp775.py` (697 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/collections.py` (695 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp857.py` (694 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp864.py` (690 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp869.py` (689 lines)
- `intellicrack/core/analysis/rop_generator.py` (686 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install.py` (686 lines)
- `intellicrack/hexview/hex_dialog.py` (661 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/asyncore.py` (659 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/msvccompiler.py` (659 lines)
- `intellicrack/ui/dialogs/text_editor_dialog.py` (652 lines)
- `intellicrack/core/processing/docker_container.py` (648 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/bdb.py` (645 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/string.py` (642 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/site.py` (637 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tempfile.py` (637 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/nntplib.py` (636 lines)
- `intellicrack/hexview/large_file_handler.py` (634 lines)
- `intellicrack/core/protection_bypass/vm_bypass.py` (632 lines)
- `intellicrack/core/analysis/multi_format_analyzer.py` (631 lines)
- `intellicrack/ai/llm_backends.py` (621 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_abcoll.py` (617 lines)
- `intellicrack/utils/performance_optimizer.py` (614 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/BaseHTTPServer.py` (614 lines)
- `models/repositories/base.py` (612 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/profile.py` (610 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pkgutil.py` (607 lines)
- `intellicrack/utils/security_analysis.py` (606 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/parsers/expat.py` (606 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fractions.py` (605 lines)
- `intellicrack/ui/dialogs/script_generator_dialog.py` (603 lines)
- `intellicrack/utils/system_utils.py` (602 lines)
- `intellicrack/core/analysis/core_analysis.py` (601 lines)
- `intellicrack/core/network/protocol_fingerprinter.py` (598 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_util.py` (594 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimetypes.py` (592 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/gettext.py` (591 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_rpm.py` (588 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/util.py` (582 lines)
- `intellicrack/core/analysis/incremental_manager.py` (568 lines)
- `intellicrack/ui/dialogs/visual_patch_editor.py` (568 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_result.py` (567 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/uuid.py` (560 lines)
- `intellicrack/ai/coordination_layer.py` (559 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sets.py` (557 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shutil.py` (556 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/smtpd.py` (555 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ihooks.py` (554 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sgmllib.py` (553 lines)
- `intellicrack/utils/core_utilities.py` (552 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_compile.py` (536 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/gzip.py` (535 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ntpath.py` (533 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/introspect.py` (530 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/aliases.py` (527 lines)
- `intellicrack/hexview/hex_commands.py` (525 lines)
- `intellicrack/core/protection_bypass/tpm_bypass.py` (522 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/header.py` (520 lines)
- `intellicrack/core/protection_bypass/dongle_emulator.py` (513 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/binhex.py` (508 lines)
- `intellicrack/core/analysis/taint_analyzer.py` (507 lines)
- `intellicrack/ui/main_window.py` (506 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/sysconfig.py` (504 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/tokenize.py` (500 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/_parseaddr.py` (497 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_pytree.py` (494 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/htmllib.py` (491 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/feedparser.py` (486 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/fancy_getopt.py` (484 lines)
- `intellicrack/core/processing/memory_optimizer.py` (483 lines)
- `intellicrack/config.py` (480 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/heapq.py` (480 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/sdist.py` (478 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/plistlib.py` (474 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/HTMLParser.py` (472 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimify.py` (468 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_strptime.py` (467 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/threading.py` (463 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/cygwinccompiler.py` (463 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/symbols.py` (462 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/cmd.py` (457 lines)
- `intellicrack/core/analysis/binary_similarity_search.py` (455 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/csv.py` (451 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/handlers.py` (450 lines)
- `intellicrack/core/processing/qiling_emulator.py` (449 lines)
- `intellicrack/utils/ui_setup_functions.py` (448 lines)
- `intellicrack/utils/protection_utils.py` (447 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/encoder.py` (447 lines)
- `intellicrack/core/analysis/vulnerability_engine.py` (446 lines)
- `intellicrack/hexview/performance_monitor.py` (445 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/formatter.py` (445 lines)
- `intellicrack/ui/dialogs/similarity_search_dialog.py` (444 lines)
- `intellicrack/core/processing/distributed_analysis_manager.py` (438 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/copy.py` (433 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixer_util.py` (432 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/validate.py` (432 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/posixpath.py` (431 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_sslcerts.py` (430 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/saxlib.py` (430 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/poplib.py` (427 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tokenize.py` (426 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/textwrap.py` (425 lines)
- `intellicrack/hexview/hex_renderer.py` (424 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/warnings.py` (424 lines)
- `intellicrack/ui/protection_detection_handlers.py` (420 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/drivers2/drv_javasax.py` (417 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fileinput.py` (415 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cmd.py` (404 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/urlparse.py` (403 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/charset.py` (401 lines)
- `intellicrack/ai/ai_file_tools.py` (397 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/markupbase.py` (396 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/bcppcompiler.py` (394 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_py.py` (394 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_parser.py` (392 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/numbers.py` (391 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/pgen.py` (386 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/xmlbuilder.py` (386 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/decoder.py` (384 lines)
- `intellicrack/utils/patch_utils.py` (383 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/Uri.py` (380 lines)
- `intellicrack/core/network/ssl_interceptor.py` (379 lines)
- `intellicrack/hexview/hex_highlighter.py` (379 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/CGIHTTPServer.py` (378 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/xmlreader.py` (378 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/generator.py` (375 lines)
- `intellicrack/core/patching/memory_patcher.py` (374 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/core.py` (373 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_wininst.py` (368 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/base64.py` (365 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/javapath.py` (363 lines)
- `intellicrack/core/analysis/concolic_executor.py` (359 lines)
- `intellicrack/utils/logger.py` (357 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/config.py` (357 lines)
- `intellicrack/utils/process_utils.py` (354 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/zlib.py` (353 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/pulldom.py` (352 lines)
- `intellicrack/plugins/remote_executor.py` (351 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/__init__.py` (351 lines)
- `intellicrack/ui/dashboard_manager.py` (350 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pprint.py` (350 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/handler.py` (345 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pyclbr.py` (344 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/filelist.py` (343 lines)
- `models/model_manager.py` (341 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/quoprimime.py` (341 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/internal/plugin/plugin.py` (339 lines)
- `intellicrack/core/network/license_protocol_handler.py` (334 lines)
- `intellicrack/hexview/integration.py` (333 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/utils.py` (333 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/timeit.py` (331 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/tabnanny.py` (329 lines)
- `intellicrack/utils/ui_utils.py` (328 lines)
- `intellicrack/ui/dialogs/distributed_config_dialog.py` (325 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/re.py` (324 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/StringIO.py` (324 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/cgitb.py` (323 lines)
- `intellicrack/utils/exception_utils.py` (319 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/traceback.py` (319 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/emxccompiler.py` (319 lines)
- `models/repositories/local_repository.py` (318 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/test_refactor.py` (317 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/loader.py` (316 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/register.py` (315 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/asynchat.py` (314 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/script.py` (314 lines)
- `intellicrack/core/patching/windows_activator.py` (312 lines)
- `intellicrack/core/processing/memory_loader.py` (311 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ast.py` (311 lines)
- `intellicrack/utils/report_generator.py` (310 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/code.py` (310 lines)
- `intellicrack/utils/__init__.py` (309 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp720.py` (309 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp037.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1006.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1026.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1140.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1250.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1251.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1252.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1253.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1254.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1255.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1256.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1257.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp1258.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp424.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp500.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp856.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp874.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/cp875.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_1.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_10.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_11.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_13.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_14.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_15.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_16.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_2.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_3.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_4.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_5.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_6.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_7.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_8.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/iso8859_9.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/koi8_r.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/koi8_u.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_centeuro.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_croatian.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_cyrillic.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_farsi.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_greek.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_iceland.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_roman.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_romanian.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_turkish.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/tis_620.py` (307 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/text_file.py` (304 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/suite.py` (303 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementPath.py` (303 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/version.py` (299 lines)
- `intellicrack/utils/binary_utils.py` (296 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/filecmp.py` (296 lines)
- `intellicrack/utils/misc_utils.py` (293 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shlex.py` (292 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ctypes/__init__.py` (291 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/unixccompiler.py` (288 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/setuptools_build_ext.py` (287 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_assertions.py` (286 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/test_break.py` (284 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/btm_utils.py` (283 lines)
- `scripts/simconcolic.py` (282 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/DocXMLRPCServer.py` (279 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pipes.py` (278 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/runpy.py` (278 lines)
- `intellicrack/core/analysis/symbolic_executor.py` (276 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/htmlentitydefs.py` (273 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/main.py` (269 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unicodedata.py` (267 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sre_constants.py` (259 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/conv.py` (257 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mailcap.py` (255 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/extension.py` (255 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/signal.py` (253 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/_java.py` (252 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_threading_local.py` (251 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/spawn.py` (251 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dumbdbm.py` (250 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mimetools.py` (250 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/Queue.py` (244 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/archive_util.py` (243 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_argparser.py` (241 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/shelve.py` (239 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/core.py` (239 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/file_util.py` (239 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/punycode.py` (238 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/posixfile.py` (237 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/quopri.py` (237 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/jintrospect.py` (237 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/main.py` (236 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_core.py` (236 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/isql.py` (235 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/robotparser.py` (233 lines)
- `intellicrack/models/__init__.py` (231 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xdrlib.py` (231 lines)
- `intellicrack/core/patching/adobe_injector.py` (229 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sndhdr.py` (228 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserString.py` (228 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_metaclass.py` (228 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compileall.py` (227 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ensurepip/__init__.py` (227 lines)
- `models/repositories/google_repository.py` (226 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/SimpleHTTPServer.py` (225 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dis.py` (224 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/support.py` (221 lines)
- `intellicrack/ai/ai_tools.py` (219 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_lib.py` (219 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/macpath.py` (215 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dir_util.py` (214 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/getopt.py` (210 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_clib.py` (209 lines)
- `intellicrack/utils/dependencies.py` (208 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/patcomp.py` (205 lines)
- `models/repositories/openrouter_repository.py` (204 lines)
- `models/repositories/anthropic_repository.py` (202 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/copy_reg.py` (201 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/parse.py` (201 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_urllib.py` (197 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/uu.py` (196 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/runner.py` (196 lines)
- `models/repositories/lmstudio_repository.py` (195 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/upload.py` (194 lines)
- `models/repositories/interface.py` (193 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/result.py` (193 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/opcode.py` (192 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/popen2.py` (190 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-src/ghidradoc.py` (190 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixer_base.py` (189 lines)
- `models/repositories/openai_repository.py` (188 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/base64mime.py` (187 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/abc.py` (185 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/readline.py` (184 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/grammar.py` (184 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/mac_latin2.py` (183 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/tests/test_plugin.py` (182 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pty.py` (180 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserDict.py` (180 lines)
- `utils/siphash24_replacement.py` (179 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/idna.py` (178 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/ptcp154.py` (175 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_tuple_params.py` (175 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/ghidradoc.py` (175 lines)
- `intellicrack/ai/__init__.py` (173 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_LWPCookieJar.py` (170 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/headers.py` (169 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/btm_matcher.py` (168 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/chunk.py` (167 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/__init__.py` (167 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_input.py` (167 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/rlcompleter.py` (166 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/util.py` (165 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/versionpredicate.py` (164 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/RecursiveStringFinder.py` (163 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/gui.py` (163 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/multifile.py` (162 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/imghdr.py` (161 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build_scripts.py` (160 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/driver.py` (157 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_wsgi.py` (157 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/colorsys.py` (156 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/util.py` (156 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/wsgiref/simple_server.py` (155 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/contextlib.py` (154 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/hp_roman8.py` (152 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_idioms.py` (152 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_32.py` (150 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_MozillaCookieJar.py` (149 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/check.py` (149 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/getpass.py` (148 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist.py` (147 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/build.py` (147 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/hashlib.py` (146 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dummy_thread.py` (145 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fpformat.py` (145 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_imports.py` (145 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pawt/colors.py` (144 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_publish.py` (143 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/socket.py` (142 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/token.py` (142 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/etree/ElementInclude.py` (142 lines)
- `intellicrack/plugins/__init__.py` (141 lines)
- `intellicrack/hexview/__init__.py` (139 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/__init__.py` (139 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/weakref.py` (137 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/linecache.py` (135 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/codeop.py` (134 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/sched.py` (134 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/bdist_dumb.py` (134 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/hmac.py` (133 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/repr.py` (132 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/uu_codec.py` (129 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/py_compile.py` (128 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/__future__.py` (128 lines)
- `launch_intellicrack.py` (127 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/_exceptions.py` (127 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_16.py` (126 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/__init__.py` (125 lines)
- `intellicrack/ui/dialogs/__init__.py` (124 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/netrc.py` (122 lines)
- `intellicrack/utils/license_response_templates.py` (121 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy.py` (121 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/internal/plugin/completions.py` (120 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/test/support.py` (119 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/python_basics.py` (118 lines)
- `models/repositories/factory.py` (117 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/whichdb.py` (117 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/utf_8_sig.py` (117 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_recursion.py` (117 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/fnmatch.py` (116 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/config.py` (116 lines)
- `intellicrack/ui/dialogs/splash_screen.py` (115 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/mark_in_out.py` (115 lines)
- `intellicrack/core/analysis/__init__.py` (113 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/visitor.py` (113 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_response.py` (113 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/AskScriptPy.py` (113 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_has_key.py` (110 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/minicompat.py` (110 lines)
- `intellicrack/__init__.py` (109 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_scanstring.py` (109 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/loaders/xml_loader.py` (108 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/io.py` (107 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_dict.py` (107 lines)
- `intellicrack/ui/common_imports.py` (106 lines)
- `intellicrack/ui/dialogs/plugin_manager_dialog.py` (106 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/javac.py` (106 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/genericpath.py` (105 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_fail.py` (105 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_next.py` (103 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/bz2_codec.py` (102 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/zlib_codec.py` (102 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/sax/__init__.py` (102 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_impl.py` (101 lines)
- `intellicrack/core/patching/__init__.py` (100 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/functools.py` (100 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/plugins/xml_importer.py` (99 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_import.py` (99 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/dom/domreg.py` (99 lines)
- `intellicrack/ui/missing_methods.py` (97 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Extensions/IDAPro/Python/7xx/plugins/xml_exporter.py` (97 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/macurl2path.py` (97 lines)
- `intellicrack/core/processing/__init__.py` (96 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/stat.py` (96 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_operator.py` (96 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/glob.py` (95 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pycimport.py` (95 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/ghidra_scripts/PyGhidraBasics.py` (95 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/javashell.py` (93 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/parser.py` (93 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_except.py` (93 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/bisect.py` (92 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/pytree_idempotency.py` (92 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_map.py` (91 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_exceptions.py` (91 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/CallAnotherScriptForAllProgramsPy.py` (91 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/commands.py` (90 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_raise.py` (90 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pwd.py` (89 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/dep_util.py` (89 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_unicode.py` (89 lines)
- `tools/radare2/libr/bin/format/xnu/scripts/machtraps.py` (89 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/UserList.py` (88 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/errors.py` (88 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/version.py` (88 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/types.py` (87 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/encoders.py` (87 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_print.py` (87 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/anydbm.py` (85 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/grp.py` (85 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_params.py` (84 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/palmos.py` (83 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/token.py` (82 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_data.py` (81 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/clean.py` (80 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/modjy/modjy_log.py` (80 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/QueryFunction.py` (79 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/base64_codec.py` (79 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/hex_codec.py` (79 lines)
- `intellicrack/ui/widgets/__init__.py` (78 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/dummy_threading.py` (78 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/webbrowser.py` (78 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_egg_info.py` (78 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ghidra_basics.py` (78 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/pydoc_data/topics.py` (77 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/iterators.py` (76 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_filter.py` (76 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/mime/audio.py` (75 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/quopri_codec.py` (75 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_pass1.py` (75 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_tool.py` (75 lines)
- `intellicrack/utils/ui_helpers.py` (74 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/future.py` (74 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/compiler/misc.py` (73 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_xrange.py` (73 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_exitfunc.py` (72 lines)
- `fix_indentation.py` (71 lines)
- `intellicrack/core/protection_bypass/__init__.py` (71 lines)
- `intellicrack/utils/html_templates.py` (71 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/log.py` (71 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/signals.py` (71 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_renames.py` (70 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/encodings/charmap.py` (69 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/unittest/__init__.py` (69 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/scanner.py` (67 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/__init__.py` (67 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/nturl2path.py` (66 lines)
- `intellicrack/utils/common_imports.py` (65 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts/LocateMemoryAddressesForFileOffset.py` (65 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/atexit.py` (65 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/DumpBSimSignaturesScript.py` (64 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_scripts.py` (64 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/src/pyghidra/properties.py` (64 lines)
- `tools/radare2/libr/bin/format/xnu/scripts/build_mig_index.py` (63 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_types.py` (62 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/ImportSymbolsScript.py` (62 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/test_spawn.py` (60 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_indent.py` (60 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/pgen2/literals.py` (60 lines)
- `intellicrack/ui/__init__.py` (59 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/BSim/ghidra_scripts/GenerateSignatures.py` (59 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/email/errors.py` (59 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/json/tests/test_decode.py` (59 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_apply.py` (59 lines)
- `tools/radare2/sys/clang-format.py` (59 lines)
- `intellicrack/ui/dialog_utils.py` (58 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/xml/FtCore.py` (58 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_itertools_imports.py` (57 lines)
- `tools/radare2/libr/bin/d/dll/convert_dumpbin_exports_to_sdb_txt.py` (57 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_throw.py` (56 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/mutex.py` (55 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/_rawffi.py` (54 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/tests/support.py` (54 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/ghidra_scripts/jython_basics.py` (54 lines)
- `tools/radare2/radare2-5.9.8-w64/share/scripts/r2sptrace.py` (54 lines)
- `tools/radare2/scripts/r2sptrace.py` (54 lines)
- `tools/radare2/test/unit/legacy_unit/syscall/openbsd-gen.py` (54 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_set_literal.py` (53 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_execfile.py` (52 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/lib2to3/fixes/fix_isinstance.py` (52 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/command/install_headers.py` (51 lines)
- `tools/ghidra/ghidra_11.3.2_PUBLIC/Ghidra/Features/Jython/data/jython-2.7.4/Lib/distutils/tests/setuptools_extension.py` (51 lines)

## Recommendations

1. **Fix Syntax Errors**: Address all syntax errors before other improvements
2. **Add Docstrings**: Add module docstrings to improve code documentation
3. **Type Hints**: Add type hints to improve code clarity and catch errors
4. **Code Formatting**: Use black or similar formatter for consistent code style
5. **Import Organization**: Organize imports consistently (stdlib, third-party, local)
6. **Error Handling**: Add proper exception handling where missing
7. **Testing**: Add unit tests for modules with high complexity
