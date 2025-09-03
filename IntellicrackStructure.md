# Intellicrack Project Structure

## PROJECT: Intellicrack

Advanced binary analysis and exploitation platform with AI-driven capabilities.

### ENTRY POINT
- **main.py**
  - `main()` - Main entry point that:
    - Installs global exception handler
    - Initializes security enforcement
    - Performs startup checks
    - Launches GUI via `ui.main_app.launch()`

---

## MAIN FEATURE: Core Analysis Engine (`intellicrack/core/analysis/`)

er.py**

- `R2ErrorHandler` - Error handling for R2
- **radare2_esil.py**
  - `ESILAnalysisEngine` - ESIL emulation
- **radare2_imports.py**
  - `R2ImportExportAnalyzer` - Import/export analysis
- **radare2_json_standardizer.py**
  - `R2JSONStandardizer` - Standardize R2 output
- **radare2_performance_optimizer.py**
  - `R2PerformanceOptimizer` - Optimize R2 performance
- **radare2_realtime_analyzer.py**
  - `R2RealtimeAnalyzer` - Real-time analysis
- **radare2_scripting.py**
  - `R2ScriptingEngine` - R2 scripting interface
- **radare2_signatures.py**
  - `R2SignatureAnalyzer` - Signature matching
- **radare2_strings.py**
  - `R2StringAnalyzer` - String extraction
- **radare2_vulnerability_engine.py**
  - `R2VulnerabilityEngine` - Vulnerability detection

### ROP Generation
- **rop_generator.py**
  - `ROPChainGenerator` - ROP chain generation
    - `run_rop_chain_generator()` - Generate ROP chains

### Taint Analysis
- **taint_analyzer.py**
  - `AdvancedTaintTracker` - Advanced taint tracking
  - `TaintAnalysisEngine` - Taint analysis engine
    - `run_taint_analysis()` - Execute taint analysis

### Vulnerability Detection
- **vulnerability_engine.py**
  - `AdvancedVulnerabilityEngine` - Advanced vuln detection
  - `VulnerabilityReport` - Vulnerability report structure

### Pattern Matching
- **yara_pattern_engine.py**
  - `YaraPatternEngine` - YARA pattern matching
    - `scan_file_with_yara()` - Scan files with YARA

---

## MAIN FEATURE: AI/LLM Integration (`intellicrack/ai/`)

### Core AI Components
- **ai_script_generator.py**
  - `AIScriptGenerator` - Generate Frida/Ghidra scripts
    - `ScriptType` - Script type enumeration
    - `ProtectionType` - Protection type enumeration
    - `ScriptValidator` - Validate generated scripts
    - `ScriptTemplateEngine` - Template management
    - `PatternLibrary` - Pattern library

### AI Assistants
- **ai_assistant_enhanced.py**
  - `IntellicrackAIAssistant` - Enhanced AI assistant
    - `Tool` - Tool definition
    - `ToolCategory` - Tool categorization
- **ai_tools.py**
  - `AIAssistant` - Basic AI assistant
  - `CodeAnalyzer` - AI-powered code analysis
    - `analyze_with_ai()` - Analyze code with AI
    - `get_ai_suggestions()` - Get AI suggestions
    - `explain_code()` - Explain code functionality

### Autonomous Agents
- **autonomous_agent.py**
  - `AutonomousAgent` - Self-directed analysis agent
    - `ExecutionResult` - Execution result structure
    - `TestEnvironment` - Test environment setup
    - `WorkflowState` - Workflow state tracking

### Model Management
- **llm_backends.py**
  - `LLMManager` - Central LLM management
  - Backend implementations:
    - `OpenAIBackend` - OpenA### Analysis Orchestration
- **analysis_orchestrator.py**
  - `AnalysisOrchestrator` - Coordinates multiple analysis phases
    - `AnalysisPhase` - Enum for analysis phases
    - `OrchestrationResult` - Analysis results container

### Binary Analysis
- **binary_analyzer.py**
  - `BinaryAnalyzer` - Core binary analysis functionality

### Binary Similarity
- **binary_similarity_search.py**
  - `BinarySimilaritySearch` - Find similar binaries
    - `create_similarity_search()` - Factory function

### Control Flow Analysis
- **cfg_explorer.py**
  - `CFGExplorer` - Control flow graph exploration
    - `run_deep_cfg_analysis()` - Deep CFG analysis
    - `run_cfg_explorer()` - Run CFG exploration

### Symbolic Execution
- **concolic_executor.py**
  - `ConcolicExecutionEngine` - Concolic execution implementation
    - `__init__(binary_path, max_iterations, timeout)` - Initialize the concolic execution engine
    - `explore_paths(target_address, avoid_addresses)` - Perform concolic execution to explore program paths
    - `find_license_bypass(license_check_address)` - Find inputs that bypass license checks
    - `analyze(binary_path, **kwargs)` - Perform comprehensive concolic execution analysis on a binary
  - Private Methods:
    - `_target_hook(state)` - Hook for target address
    - `_avoid_hook(state)` - Hook for addresses to avoid
    - `_find_license_check_address()` - Attempt to automatically find license check address
    - `_native_analyze(binary_path, **kwargs)` - Native implementation of analyze without Manticore
    - `_target_reached(state, analysis_data)` - Callback when target address is reached
  - Nested Classes:
    - `NativeConcolicState`
      - `__init__(pc, memory, registers)` - Initialize a new execution state
      - `is_terminated()` - Check if state is terminated
      - `terminate(reason)` - Terminate the state
      - `fork()` - Create a copy of this state for branching
      - `add_constraint(constraint)` - Add a path constraint
      - `set_register(reg, value, symbolic)` - Set register value
      - `get_register(reg)` - Get register value
      - `write_memory(addr, value, size, symbolic)` - Write to memory
      - `read_memory(addr, size)` - Read from memory
    - `Manticore` (mock)
      - `__init__(binary_path, *args, **kwargs)` - Initialize native concolic execution engine
      - `add_hook(address, callback)` - Add execution hook at specific address
      - `register_plugin(plugin)` - Register a plugin for execution callbacks
      - `set_exec_timeout(timeout)` - Set execution timeout in seconds
      - `run(procs)` - Run concolic execution
      - `get_all_states()` - Get all execution states
      - `get_terminated_states()` - Get all terminated states
      - `get_ready_states()` - Get all ready states
      - Private Methods:
        - `_load_binary()` - Load and analyze the target binary
        - `_parse_pe_entry_point()` - Parse PE file to find entry point
        - `_parse_elf_entry_point()` - Parse ELF file to find entry point
        - `_execute_instruction(state)` - Execute a single instruction in the given state
        - `_emulate_instruction(state, instruction_bytes)` - Emulate instruction execution
        - `_check_for_branches(state)` - Check if the current state should branch into multiple states
    - `Plugin` (mock)
      - `__init__()` - Initialize native plugin
      - `will_run_callback(executor, *args, **kwargs)` - Callback before execution starts
      - `did_finish_run_callback(executor, *args, **kwargs)` - Callback after execution completes
      - `will_fork_state_callback(state, new_state, *args, **kwargs)` - Callback before state fork
      - `will_execute_instruction_callback(state, pc, insn)` - Callback before instruction execution
    - `PathExplorationPlugin`
      - `__init__()` - Initialize the path exploration plugin
      - `will_run_callback(*args, **kwargs)` - Called when path exploration is about to start
      - `did_finish_run_callback(*args, **kwargs)` - Called when path exploration has finished execution
      - `will_fork_state_callback(state, *args, **kwargs)` - Called before a state is about to be forked
    - `LicenseCheckPlugin`
      - `__init__()` - Initialize the license check plugin
      - `will_execute_instruction_callback(state, pc, insn)` - Called before executing each instruction
    - `ComprehensiveAnalysisPlugin`
      - `__init__(analysis_data)` - Initialize the comprehensive analysis plugin
      - `will_execute_instruction_callback(state, pc, insn)` - Track execution and detect interesting behaviors
      - `will_fork_state_callback(state, expression, solutions, *args, **kwargs)` - Track constraints when state forks
      - `did_run_callback()` - Finalize analysis after execution
      - Private Methods:
        - `_check_for_vulnerability(state, pc, insn)` - Check for potential vulnerabilities using execution state
- **concolic_executor_fixed.py**
  - `ConcolicExecutionEngine` - Unified concolic execution engine supporting multiple backends
    - `__init__(binary_path, max_iterations, timeout)` - Initialize the concolic execution engine
    - `explore_paths(target_address, avoid_addresses)` - Explore paths using the available symbolic execution engine
    - `find_license_bypass()` - Find license bypass using available engine
  - Properties:
    - `manticore_available` - Legacy property for backward compatibility
  - Private Methods:
    - `_explore_paths_angr(target_address, avoid_addresses)` - Explore paths using angr
    - `_explore_paths_manticore(target_address, avoid_addresses)` - Explore paths using manticore (Linux only)
    - `_explore_paths_simconcolic(target_address, avoid_addresses)` - Fallback simconcolic implementation
    - `_find_license_bypass_angr()` - Find license bypass using angr
    - `_find_license_bypass_manticore()` - Find license bypass using manticore
- **symbolic_executor.py**
  - `SymbolicExecutionEngine` - Symbolic execution engine
  - `TaintTracker` - Taint tracking functionality

### Dynamic Analysis
- **dynamic_analyzer.py**
  - `AdvancedDynamicAnalyzer` - Advanced runtime analysis
    - `run_dynamic_analysis()` - Execute dynamic analysis
    - `deep_runtime_monitoring()` - Deep runtime monitoring
    - `create_dynamic_analyzer()` - Factory function

### Entropy Analysis
- **entropy_analyzer.py**
  - `EntropyAnalyzer` - Entropy analysis engine for binary data examination
    - `__init__()` - Initialize the entropy analyzer
    - `calculate_entropy(data)` - Calculate Shannon entropy of binary data
    - `analyze_entropy(binary_path)` - Analyze entropy characteristics of a binary file
  - Private Methods:
    - `_classify_entropy(entropy)` - Classify entropy level

### Firmware Analysis
- **firmware_analyzer.py**
  - `FirmwareAnalyzer` - Firmware extraction and analysis
    - `FirmwareType` - Firmware type enumeration
    - `SecurityFinding` - Security finding structure
    - `analyze_firmware_file()` - Main analysis function

### Ghidra Integration
- **ghidra_common.py**
  - `run_ghidra_plugin()` - Run a Ghidra plugin script on a binary
  - `_build_ghidra_command()` - Build the Ghidra command line
  - `create_ghidra_analysis_script()` - Create a Ghidra analysis script (basic, license, function, string)
  - `_create_basic_analysis_script()` - Create a basic Ghidra analysis script
  - `_create_license_analysis_script()` - Create a license-focused analysis script
  - `_create_function_analysis_script()` - Create a function analysis script
  - `_create_string_analysis_script()` - Create a string analysis script
  - `save_ghidra_script()` - Save a Ghidra script to file
  - `get_ghidra_project_info()` - Get information about a Ghidra project
  - `cleanup_ghidra_project()` - Clean up a Ghidra project directory
- **ghidra_script_manager.py**
  - `GhidraScript` - Ghidra script base class
  - `GhidraScriptManager` - Ghidra script manager
  - `add_script_directory()` - Add script directory
  - `get_script_manager()` - Get script manager singleton

### Memory Forensics
- **memory_forensics_engine.py**
  - `MemoryArtifactType` (Enum): Types of memory artifacts
  - `AnalysisProfile` (Enum): Memory analysis profiles
  - `MemoryProcess` (dataclass): Information about a process in memory
  - `MemoryModule` (dataclass): Information about a loaded module
  - `NetworkConnection` (dataclass): Network connection information
  - `MemoryString` (dataclass): String found in memory
  - `MemoryAnalysisResult` (dataclass): Complete memory analysis results
    - Properties: has_suspicious_activity, hidden_process_count
  - `MemoryForensicsEngine`: Advanced memory forensics analysis engine using Volatility3
    - `__init__(cache_directory)`: Initialize the memory forensics engine
    - `analyze_memory_dump(dump_path, profile, deep_analysis)`: Analyze a memory dump file for forensic artifacts
    - `analyze_process_memory(process_id, dump_path)`: Analyze live process memory or specific process from dump
    - `generate_icp_supplemental_data(analysis_result)`: Generate supplemental data for ICP backend integration
    - `get_analysis_summary(analysis_result)`: Generate a summary of memory analysis results
    - `export_analysis_report(analysis_result, output_path)`: Export memory analysis results to JSON report
  - Private Methods:
    - `_init_volatility()`: Initialize Volatility3 framework
    - `_fallback_memory_analysis(dump_path)`: Fallback analysis when Volatility3 is not available
    - `_detect_profile(dump_path)`: Detect appropriate Volatility3 profile for memory dump
    - `_configure_volatility(dump_path, profile)`: Configure Volatility3 for analysis
    - `_run_volatility_plugin(plugin_name, plugin_config)`: Run a Volatility3 plugin and return results
    - `_analyze_processes()`: Analyze processes in memory dump
    - `_analyze_modules()`: Analyze loaded modules
    - `_analyze_network_connections()`: Analyze network connections
    - `_analyze_registry()`: Analyze registry artifacts
    - `_analyze_file_handles()`: Analyze file handles
    - `_extract_memory_strings(min_length)`: Extract strings from memory dump
    - `_extract_strings_fallback(file_path, min_length)`: Fallback string extraction using basic binary parsing
    - `_check_process_suspicious_indicators(process)`: Check for suspicious process indicators
    - `_detect_hidden_processes(processes)`: Detect hidden processes using psxview-like analysis
    - `_is_module_suspicious(module_data)`: Check if a module appears suspicious
    - `_detect_security_issues(analysis_result)`: Detect security issues based on analysis results
    - `_analyze_live_process_windows(process_id)`: Analyze live process memory on Windows
    - `_analyze_live_process_linux(process_id)`: Analyze live process memory on Linux
    - `_get_protection_string(protect)`: Convert Windows protection flags to string
    - `_get_memory_type(mem_type)`: Convert Windows memory type to string
    - `_parse_linux_addr(addr_str)`: Parse Linux /proc/net address format
  - Top-level Functions:
    - `get_memory_forensics_engine()`: Get or create the memory forensics engine singleton
    - `is_volatility3_available()`: Check if Volatility3 functionality is available
    - `analyze_memory_dump_file(dump_path)`: Quick memory dump analysis function for integration

### Network Forensics
- **network_forensics_engine.py**
  - `NetworkForensicsEngine` - Network forensics analysis engine for traffic examination
    - `__init__()` - Initialize the network forensics engine
    - `analyze_capture(capture_path)` - Analyze a network capture file for forensic artifacts
    - `analyze_live_traffic(interface, duration)` - Analyze live network traffic for forensic artifacts
    - `extract_artifacts(traffic_data)` - Extract forensic artifacts from network traffic data
    - `detect_protocols(packet_data)` - Detect network protocols in packet data

### Radare2 Integration (Multiple Components)
- **radare2_enhanced_integration.py**
  - `EnhancedR2Integration` - Enhanced radare2 integration with comprehensive error handling, recovery, performance optimization, and real-time capabilities
    - `__init__(binary_path, config)`: Initialize the enhanced Radare2 integration
    - `run_comprehensive_analysis(analysis_types)`: Run comprehensive analysis with error handling and recovery
    - `start_real_time_monitoring(callback)`: Start real-time monitoring of analysis results
    - `stop_real_time_monitoring()`: Stop real-time monitoring
    - `get_performance_stats()`: Get comprehensive performance statistics
    - `optimize_performance()`: Optimize performance based on collected metrics
    - `clear_cache()`: Clear results cache
    - `get_health_status()`: Get system health status
    - `cleanup()`: Cleanup resources
  - Private Methods:
    - `_initialize_components()`: Initialize all analysis components with error handling
    - `_run_parallel_analysis(analysis_types)`: Run analyses in parallel for performance
    - `_run_single_analysis(analysis_type)`: Run a single analysis with caching and error handling
    - `_get_cached_result(cache_key)`: Get cached result if still valid
    - `_cache_result(cache_key, result)`: Cache analysis result
    - `_record_analysis_time(analysis_type, duration, success)`: Record analysis performance
    - `_monitoring_loop(callback)`: Real-time monitoring loop
  - Top-level Functions:
    - `create_enhanced_r2_integration(binary_path, **config)`: Create enhanced radare2 integration instance
- **radare2_ai_integration.py**
  - `R2AIEngine` - Advanced AI/ML engine for radare2 analysis with pattern recognition capabilities
    - `__init__(binary_path, radare2_path)`: Initialize AI engine
    - `analyze_with_ai()`: Perform comprehensive AI-enhanced analysis
  - Private Methods:
    - `_extract_comprehensive_features()`: Extract comprehensive features for ML analysis
    - `_extract_static_features(binary_info)`: Extract static binary features
    - `_extract_function_features(functions)`: Extract function-level features
    - `_extract_string_features(string_analysis)`: Extract string-based features
    - `_extract_import_features(import_analysis)`: Extract import/export features
    - `_extract_graph_features(r2, functions)`: Extract control flow graph features
    - `_extract_entropy_features(r2)`: Extract entropy and complexity features
    - `_ai_license_detection(features)`: AI-based license validation detection
    - `_ai_vulnerability_prediction(features)`: AI-based vulnerability prediction
    - `_function_clustering_analysis(features)`: Perform function clustering analysis
    - `_anomaly_detection_analysis(features)`: Perform anomaly detection analysis
    - `_code_similarity_analysis(features)`: Perform code similarity analysis
    - `_generate_ai_bypass_suggestions(features)`: Generate AI-based bypass suggestions
    - `_train_license_detector()`: Train license detection model with synthetic data
    - `_train_vulnerability_classifier()`: Train vulnerability classification model with synthetic data
    - `_generate_license_training_data()`: Generate synthetic training data for license detection
    - `_generate_vulnerability_training_data()`: Generate synthetic training data for vulnerability classification
    - `_prepare_license_feature_vector(features)`: Prepare feature vector for license detection
    - `_prepare_vulnerability_feature_vector(features)`: Prepare feature vector for vulnerability prediction
    - `_assess_license_complexity(features)`: Assess license validation complexity
    - `_predict_bypass_difficulty(features)`: Predict license bypass difficulty
    - `_identify_validation_methods(features)`: Identify license validation methods
    - `_identify_high_risk_areas(features)`: Identify high-risk areas for vulnerabilities
    - `_predict_exploit_likelihood(features)`: Predict likelihood of successful exploitation
    - `_assess_clustering_quality(cluster_labels)`: Assess quality of clustering results
    - `_identify_anomaly_indicators(features)`: Identify indicators that make the binary anomalous
    - `_calculate_confidence_scores(results)`: Calculate confidence scores for AI predictions
    - `_get_model_performance_metrics()`: Get model performance metrics
  - Top-level Functions:
    - `analyze_binary_with_ai(binary_path, radare2_path)`: Perform AI-enhanced analysis on a binary
- **radare2_binary_diff.py**
  - `R2BinaryDiff` - Advanced binary comparison and diffing engine using radare2
    - `__init__(binary1_path, binary2_path, radare2_path)`: Initialize binary diff analyzer
    - `analyze_differences()`: Perform comprehensive binary difference analysis
  - Private Methods:
    - `_compare_metadata(r2_1, r2_2)`: Compare basic binary metadata
    - `_compare_functions(r2_1, r2_2)`: Compare functions between binaries
    - `_compare_function_details(r2_1, r2_2, func1, func2)`: Compare detailed function properties
    - `_compare_instructions(r2_1, r2_2)`: Compare instruction-level differences
    - `_compare_strings(r2_1, r2_2)`: Compare strings between binaries
    - `_compare_imports_exports(r2_1, r2_2)`: Compare imports and exports
    - `_compare_sections(r2_1, r2_2)`: Compare binary sections
    - `_compare_entry_points(r2_1, r2_2)`: Compare entry points
    - `_compare_security_features(r2_1, r2_2)`: Compare security features
    - `_analyze_patches(r2_1, r2_2)`: Analyze patches between binaries
    - `_calculate_similarity_metrics(diff_result)`: Calculate various similarity metrics
    - `_generate_change_summary(diff_result)`: Generate high-level change summary
    - `_assess_vulnerability_impact(diff_result)`: Assess vulnerability impact of changes
    - `_calculate_file_hash(file_path)`: Calculate SHA256 hash of file
    - `_extract_instructions(disasm)`: Extract instructions from disassembly
    - `_diff_instructions(instructions1, instructions2)`: Diff instruction sequences
    - `_analyze_instruction_changes(disasm1, disasm2, func_name)`: Analyze instruction-level changes
    - `_extract_opcode_distribution(r2, functions)`: Extract opcode distribution from functions
    - `_compare_opcode_distributions(opcodes1, opcodes2)`: Compare opcode distributions
    - `_analyze_license_string_changes(added, removed)`: Analyze license-related string changes
    - `_analyze_error_message_changes(added, removed)`: Analyze error message changes
    - `_analyze_debug_string_changes(added, removed)`: Analyze debug string changes
    - `_identify_significant_string_additions(added_strings)`: Identify significant string additions
    - `_identify_significant_string_removals(removed_strings)`: Identify significant string removals
    - `_assess_import_security_impact(added_imports, removed_imports)`: Assess security impact of import changes
    - `_analyze_dll_dependency_changes(imports1, imports2)`: Analyze DLL dependency changes
    - `_analyze_api_usage_changes(imports1, imports2)`: Analyze API usage pattern changes
    - `_assess_security_feature_impact(feature, old_val, new_val)`: Assess impact of security feature change
    - `_classify_patch_type(function_name, size_change)`: Classify type of patch based on function name and size change
    - `_assess_patch_impact(function_name, size_change)`: Assess impact of patch based on size change and function importance
  - Top-level Functions:
    - `compare_binaries(binary1_path, binary2_path, radare2_path)`: Perform comprehensive binary comparison
- **radare2_bypass_generator.py**
  - `R2BypassGenerator` - Advanced automated license bypass generation system using radare2 analysis
    - `__init__(binary_path, radare2_path)`: Initialize bypass generator
    - `generate_comprehensive_bypass()`: Generate comprehensive license bypass solutions
  - Private Methods:
    - `_analyze_license_mechanisms(r2)`: Analyze license validation mechanisms in detail
    - `_extract_validation_logic(decompiled, func)`: Extract license validation logic from decompiled function
    - `_extract_crypto_operations(decompiled)`: Extract cryptographic operations from decompiled code
    - `_analyze_license_strings(r2)`: Analyze license-related strings
    - `_analyze_validation_apis(r2)`: Analyze API calls used in validation
    - `_build_validation_flow(analysis)`: Build the validation flow diagram
    - `_generate_bypass_strategies(license_analysis)`: Generate bypass strategies based on analysis
    - `_generate_automated_patches(r2, license_analysis)`: Generate automated binary patches
    - `_generate_keygen_algorithms(license_analysis)`: Generate keygen algorithms based on crypto analysis
    - `_generate_registry_modifications(license_analysis)`: Generate registry modification instructions
    - `_generate_file_modifications(license_analysis)`: Generate file modification instructions
    - `_generate_memory_patches(r2, license_analysis)`: Generate runtime memory patches
    - `_generate_api_hooks(license_analysis)`: Generate API hook implementations
    - `_generate_validation_bypasses(license_analysis)`: Generate validation bypass techniques
    - `_suggest_bypass_method(pattern)`: Suggest bypass method for a validation pattern
    - `_identify_crypto_algorithm(operation)`: Identify cryptographic algorithm from operation name
    - `_identify_crypto_purpose(line)`: Identify purpose of cryptographic operation
    - `_assess_string_bypass_potential(string_content)`: Assess bypass potential for license string
    - `_assess_bypass_difficulty(func_info)`: Assess bypass difficulty for function
    - `_recommend_bypass_approach(func_info)`: Recommend bypass approach for function
    - `_generate_direct_patch_implementation(func_info)`: Generate direct patch implementation
    - `_generate_crypto_bypass_implementation(func_info)`: Generate crypto bypass implementation
    - `_generate_network_bypass_implementation(func_info)`: Generate network bypass implementation
    - `_generate_time_bypass_implementation(func_info)`: Generate time bypass implementation
    - `_generate_registry_bypass_implementation(license_analysis)`: Generate registry bypass implementation based on license analysis
    - `_create_binary_patch(r2, func_info, bypass_point)`: Create binary patch for bypass point
    - `_generate_keygen_implementation(crypto_op)`: Generate keygen implementation
    - `_assess_keygen_feasibility(crypto_op)`: Assess feasibility of keygen creation
    - `_predict_registry_path(reg_op)`: Predict registry path for license storage
    - `_generate_license_value()`: Generate realistic license key for bypass operations
    - `_predict_license_file_path(file_op)`: Predict license file path based on file operation patterns
    - `_generate_license_file_content()`: Generate realistic license file content for bypass operations
    - `_get_original_bytes(r2, func_addr)`: Get original bytes at function address
    - `_generate_patch_bytes(func_info)`: Generate patch bytes for function
    - `_generate_registry_hook_code(reg_op)`: Generate registry hook code
    - `_generate_file_hook_code(file_op)`: Generate file hook code
    - `_generate_bypass_steps(step)`: Generate step-by-step bypass instructions
    - `_get_required_tools(step)`: Get required tools for bypass
    - `_get_success_indicators(step)`: Get success indicators for bypass
    - `_generate_patch_instruction(bypass_method)`: Generate patch instruction based on method
    - `_generate_patch_bytes_for_method(bypass_method)`: Generate patch bytes for specific method
    - `_get_hash_keygen_template(algorithm)`: Get hash-based keygen template
    - `_get_aes_keygen_template()`: Get AES keygen template
    - `_get_generic_keygen_template()`: Get generic keygen template
    - `_calculate_success_probabilities(result)`: Calculate success probabilities for different approaches
    - `_generate_implementation_guide(result)`: Generate comprehensive implementation guide
    - `_assess_bypass_risks(result)`: Assess risks associated with bypass methods
    - `_calculate_risk_level(strategies, mechanisms)`: Calculate overall risk level
    - `_get_recommended_precautions(strategies)`: Get recommended precautions
  - Top-level Functions:
    - `generate_license_bypass(binary_path, radare2_path)`: Generate comprehensive license bypass for a binary
- **radare2_decompiler.py**
  - `R2DecompilationEngine` - Advanced decompilation engine using radare2's pdc and pdg commands
    - `__init__(binary_path, radare2_path)`: Initialize decompilation engine
    - `decompile_function(address, optimize)`: Decompile a single function with advanced analysis
    - `decompile_all_functions(limit)`: Decompile all functions in the binary
    - `generate_license_bypass_suggestions(function_results)`: Generate bypass suggestions based on decompilation analysis
    - `analyze_license_functions()`: Analyze all functions in the binary to identify license-related functions
    - `export_analysis_report(output_path, analysis_results)`: Export comprehensive analysis report
  - Private Methods:
    - `_extract_variables(r2, address)`: Extract function variables and their types
    - `_detect_license_patterns(pseudocode)`: Detect license-related patterns in decompiled code
    - `_detect_vulnerability_patterns(pseudocode)`: Detect vulnerability patterns in decompiled code
    - `_calculate_complexity(pseudocode, graph_data)`: Calculate complexity metrics for decompiled function
    - `_extract_api_calls(pseudocode)`: Extract API function calls from pseudocode
    - `_get_string_references(r2, address)`: Get string references used by the function
    - `_analyze_control_flow(graph_data)`: Analyze control flow from graph data
    - `_should_analyze_function(func_name)`: Determine if a function should be analyzed for license patterns
    - `_calculate_license_confidence(func_name, license_patterns)`: Calculate confidence score for license-related function
    - `_get_confidence_reason(func_name, license_patterns)`: Get human-readable reason for high confidence
  - Top-level Functions:
    - `analyze_binary_decompilation(binary_path, radare2_path, function_limit)`: Perform comprehensive decompilation analysis of a binary
- **radare2_error_handlI API
  - `AnthropicBackend` - Anthropic Claude
  - `LlamaCppBackend` - llama.cpp integration
  - `OllamaBackend` - Ollama integration
  - `LocalGGUFBackend` - Local GGUF models
  - `PyTorchLLMBackend` - PyTorch models
  - `TensorFlowLLMBackend` - TensorFlow models
  - `ONNXLLMBackend` - ONNX models
  - `SafetensorsBackend` - Safetensors format
  - `GPTQBackend` - GPTQ quantized models
  - `HuggingFaceLocalBackend` - HuggingFace local

### Configuration Management
- **llm_config_manager.py**
  - `LLMConfigManager` - LLM configuration management
- **llm_config_as_code.py**
  - `ConfigAsCodeManager` - Config as code support
- **llm_fallback_chains.py**
  - `FallbackManager` - Fallback chain management
    - `FallbackChain` - Define fallback chains
    - `ModelHealth` - Track model health

### Model Loading & Optimization
- **background_loader.py**
  - `BackgroundModelLoader` - Background model loading
  - `IntegratedBackgroundLoader` - Integrated loader
- **lazy_model_loader.py**
  - `LazyModelManager` - Lazy loading support
    - `LazyModelWrapper` - Lazy model wrapper
- **local_gguf_server.py**
  - `LocalGGUFServer` - Local GGUF model server
  - `GGUFModelManager` - GGUF model management

### Performance & Monitoring
- **performance_monitor.py**
  - `PerformanceMonitor` - Monitor AI performance
  - `AsyncPerformanceMonitor` - Async monitoring
- **performance_optimization_layer.py**
  - `PerformanceOptimizationLayer` - Optimize AI operations
    - `PerformanceOptimizer` - Performance optimization
    - `ResourceManager` - Resource allocation
    - `ParallelExecutor` - Parallel execution
    - `CacheManager` - Cache management

### Advanced AI Features
- **exploitation_orchestrator.py**
  - `ExploitationOrchestrator` - Orchestrate exploits
- **exploit_chain_builder.py**
  - `AutomatedExploitChainBuilder` - Build exploit chains
    - `ExploitPrimitiveLibrary` - Exploit primitives
    - `SafetyVerificationSystem` - Safety checks
- **intelligent_code_modifier.py**
  - `IntelligentCodeModifier` - AI code modification
    - `CodeAnalyzer` - Analyze code structure
    - `DiffGenerator` - Generate diffs
- **multi_agent_system.py**
  - `MultiAgentSystem` - Multi-agent collaboration
    - `StaticAnalysisAgent` - Static analysis
    - `DynamicAnalysisAgent` - Dynamic analysis
    - `ReverseEngineeringAgent` - Reverse engineering
    - `MessageRouter` - Route agent messages
    - `TaskDistributor` - Distribute tasks
    - `LoadBalancer` - Load balancing

### Machine Learning Features
- **learning_engine.py**
  - `AILearningEngine` - ML-based learning
    - `PatternEvolutionEngine` - Evolve patterns
    - `FailureAnalysisEngine` - Analyze failures
- **predictive_intelligence.py**
  - `PredictiveIntelligenceEngine` - Predictive analysis
    - `SuccessProbabilityPredictor` - Success prediction
    - `ExecutionTimePredictor` - Time estimation
    - `VulnerabilityPredictor` - Vuln prediction

### Visualization & Analytics
- **visualization_analytics.py**
  - `VisualizationAnalytics` - AI analytics
    - `DataCollector` - Collect metrics
    - `ChartGenerator` - Generate charts
    - `DashboardManager` - Manage dashboards
    - `AnalyticsEngine` - Analytics engine

### Integration Features
- **coordination_layer.py**
  - `AICoordinationLayer` - Coordinate AI components
- **integration_manager.py**
  - `IntegrationManager` - Manage integrations
- **orchestrator.py**
  - `AIOrchestrator` - Main AI orchestrator
    - `AIEventBus` - Event communication
    - `AISharedContext` - Shared context

### Specialized Features
- **qemu_test_manager.py**
  - `QEMUTestManager` - QEMU test management
- **realtime_adaptation_engine.py**
  - `RealTimeAdaptationEngine` - Real-time adaptation
    - `RuntimeMonitor` - Monitor runtime
    - `AnomalyDetector` - Detect anomalies
    - `DynamicHookManager` - Dynamic hooks
- **resilience_self_healing.py**
  - `ResilienceSelfHealingSystem` - Self-healing system
    - `HealthMonitor` - Monitor health
    - `RecoverySystem` - Recovery mechanisms
- **semantic_code_analyzer.py**
  - `SemanticCodeAnalyzer` - Semantic analysis
    - `NLPCodeProcessor` - NLP processing
    - `SemanticKnowledgeBase` - Knowledge base

---

## MAIN FEATURE: Exploitation Framework (`intellicrack/core/exploitation/`)

### Base Classes
- **base_exploitation.py**
  - `BaseExploitation` - Base exploitation class
- **base_persistence.py**
  - `BasePersistence` - Base persistence class

### Mitigation Bypasses
- **bypass_engine.py**
  - `BypassEngine` - Central bypass engine
- **aslr_bypass.py**
  - `ASLRBypass` - ASLR bypass techniques
- **dep_bypass.py**
  - `DEPBypass` - DEP/NX bypass techniques
- **cfi_bypass.py**
  - `CFIBypass` - Control Flow Integrity bypass
- **cet_bypass.py**
  - `CETBypass` - Intel CET bypass
- **stack_canary_bypass.py**
  - `StackCanaryBypass` - Stack canary bypass

### Payload Generation
- **payload_engine.py**
  - `PayloadEngine` - Main payload generation
- **shellcode_generator.py**
  - `ShellcodeGenerator` - Generate shellcode
- **encoder_engine.py**
  - `EncoderEngine` - Encode payloads
- **polymorphic_engine.py**
  - `PolymorphicEngine` - Polymorphic payloads
- **assembly_compiler.py**
  - `AssemblyCompiler` - Compile assembly
- **payload_templates.py**
  - `PayloadTemplates` - Payload templates

### Post-Exploitation
- **privilege_escalation.py**
  - `PrivilegeEscalation` - Privilege escalation
  - `PrivilegeEscalationManager` - Manage escalation
- **lateral_movement.py**
  - `LateralMovement` - Lateral movement
  - `LateralMovementManager` - Manage movement
- **credential_harvester.py**
  - `CredentialHarvester` - Harvest credentials

### Persistence
- **persistence_manager.py**
  - `PersistenceManager` - Manage persistence
- **windows_persistence.py**
  - `WindowsPersistence` - Windows persistence
- **linux_persistence.py**
  - `LinuxPersistence` - Linux persistence

### Reconnaissance
- **system_reconnaissance.py**
  - `SystemRecon` - System reconnaissance

---

## MAIN FEATURE: User Interface (`intellicrack/ui/`)

### Main Application
- **main_app.py**
  - `launch()` - Launch the application
  - Main window initialization
  - Tab management

### Tabs (`intellicrack/ui/tabs/`)
- **base_tab.py**
  - `BaseTab` - Base class for all tabs
- **dashboard_tab.py**
  - `DashboardTab` - Main dashboard view
- **analysis_tab.py**
  - `AnalysisTab` - Binary analysis interface
- **exploitation_tab.py**
  - `ExploitationTab` - Exploitation tools
- **ai_assistant_tab.py**
  - `AIAssistantTab` - AI assistant interface
- **tools_tab.py**
  - `ToolsTab` - Additional tools
- **settings_tab.py**
  - `SettingsTab` - Application settings
- **project_workspace_tab.py**
  - Project workspace management

### Dialogs (`intellicrack/ui/dialogs/`)
- **base_dialog.py**
  - `BaseDialog` - Base class for all dialogs
- **binary_info_dialog.py**
  - `BinaryInfoDialog` - Display binary information
- **keygen_dialog.py**
  - `KeygenDialog` - Key generation dialog
- **protection_info_dialog.py**
  - `ProtectionInfoDialog` - Protection information display
- **patch_wizard_dialog.py**
  - `PatchWizardDialog` - Patch creation wizard
- **debugger_dialog.py**
  - `DebuggerDialog` - Integrated debugger interface
- **report_manager_dialog.py**
  - `ReportManagerDialog` - Manage analysis reports
- **vulnerability_research_dialog.py**
  - `VulnerabilityResearchDialog` - Vulnerability research tools
- **model_finetuning_dialog.py**
  - `ModelFinetuningDialog` - AI model fine-tuning interface

### Widgets (`intellicrack/ui/widgets/`)
- **hex_viewer_widget.py**
  - `HexViewerWidget` - Hex editor/viewer
- **disassembly_widget.py**
  - `DisassemblyWidget` - Disassembly viewer
- **console_widget.py**
  - `ConsoleWidget` - Console output
- **file_tree_widget.py**
  - `FileTreeWidget` - File browser
- **memory_map_widget.py**
  - `MemoryMapWidget` - Memory layout viewer
- **strings_viewer_widget.py**
  - `StringsViewerWidget` - String analysis viewer
- **system_monitor_widget.py**
  - `SystemMonitorWidget` - System resource monitor
- **file_metadata_widget.py**
  - `FileMetadataWidget` - File metadata display

### UI Handlers
- **main_window_handlers.py**
  - Event handlers for main window
- **exploitation_handlers.py**

## - Exploitation-specific UI handlers

---

## MAIN FEATURE: Network Analysis (`intellicrack/core/network/`)

### Traffic Analysis
- **traffic_analyzer.py**
  - `TrafficAnalyzer` - Network traffic analysis
  - `NetworkCaptureManager` - Capture management
  - `PacketProcessor` - Process network packets
  - `ProtocolDecoder` - Decode network protocols

- **traffic_interception_engine.py**
  - `TrafficInterceptionEngine` - Intercept and modify traffic
  - `InterceptionRule` - Define interception rules
  - `PacketManipulator` - Manipulate packets

### License and Activation
- **license_server_emulator.py**
  - `LicenseServerEmulator` - Emulate license servers
  - `LicenseProtocolHandler` - Handle license protocols
  - `ActivationResponder` - Respond to activation requests

- **dynamic_response_generator.py**
  - `DynamicResponseGenerator` - Generate dynamic responses
  - `ResponseTemplate` - Response templates
  - `ProtocolEmulator` - Emulate protocols

### Command and Control
- **c2_manager.py** (`intellicrack/core/c2/`)
  - `C2Manager` - Manage C2 operations
  - `C2Server` - C2 server implementation
  - `C2Client` - C2 client implementation
  - `CommandHandler` - Handle C2 commands
  - `SessionManager` - Manage C2 sessions

---

## MAIN FEATURE: Protection Detection and Bypass (`intellicrack/core/`)

### Protection Detection
- **protection_detector.py**
  - `ProtectionDetector` - Detect protection mechanisms
  - `ProtectionIdentifier` - Identify specific protections
  - `SignatureDatabase` - Protection signatures
  - `HeuristicAnalyzer` - Heuristic detection### Protection Bypass (`intellicrack/core/protection_bypass/`)
- **vm_bypass.py**
  - `VMBypass` - Virtual machine bypass
  - `VMDetector` - Detect VM protections
  - `VMUnpacker` - Unpack VM-protected code

- **bypass_engine.py**
  - `BypassEngine` - Main bypass engine
  - `BypassStrategy` - Bypass strategies
  - `BypassPlugin` - Plugin interface

### Anti-Analysis (`intellicrack/core/anti_analysis/`)
- **sandbox_detector.py**
  - `SandboxDetector` - Detect sandbox environments
  - `EnvironmentChecker` - Check execution environment
  - `ArtifactScanner` - Scan for sandbox artifacts

- **timing_attacks.py**
  - `TimingAttackEngine` - Timing attack implementations
  - `DelayAnalyzer` - Analyze timing delays
  - `ClockManipulator` - Manipulate system clocks

---

## MAIN FEATURE: Patching System (`intellicrack/core/patching/`)

### Binary Patching
- **patch_engine.py**
  - `PatchEngine` - Main patching engine
  - `PatchBuilder` - Build patches
  - `PatchApplier` - Apply patches

- **memory_patcher.py**
  - `MemoryPatcher` - Runtime memory patching
  - `ProcessInjector` - Process injection
  - `MemoryScanner` - Scan memory patterns

- **adobe_injector.py**
  - `AdobeInjector` - Adobe-specific injector
  - `AmtlibPatcher` - Amtlib patching
  - `LicenseBypass` - License bypass---

## MAIN FEATURE: Utilities and Support Systems (`intellicrack/utils/`)

### Binary Analysis Utilities (`intellicrack/utils/binary/`)
- **binary_utils.py**
  - `compute_file_hash()` - Calculate file hashes
  - `read_binary()` - Read binary files
  - `write_binary()` - Write binary files
  - `analyze_binary_format()` - Analyze binary format
  - `get_file_entropy()` - Calculate file entropy
  - `check_suspicious_pe_sections()` - Check for suspicious PE sections

- **hex_utils.py**
  - `create_hex_dump()` - Create hex dump views
  - `hex_to_bytes()` - Convert hex to bytes
  - `bytes_to_hex()` - Convert bytes to hex
  - `find_pattern()` - Find byte patterns
  - `patch_bytes()` - Patch byte sequences
  - `nop_range()` - NOP out byte ranges

- **pe_analysis_common.py**
  - `analyze_pe_imports()` - Analyze PE imports
  - `get_pe_sections_info()` - Get PE section information
  - `extract_pe_icon()` - Extract icons from PE files
  - `extract_all_pe_icons()` - Extract all icons

- **certificate_extractor.py**
  - `CertificateExtractor` - Extract certificates
  - `extract_pe_certificates()` - Extract PE certificates
  - `get_certificate_security_assessment()` - Assess certificate security

### Core Utilities (`intellicrack/utils/core/`)
- **common_imports.py**
  - Import management and fallbacks
  - Library availability checks
  - Safe import wrappers

- **exception_utils.py**
  - `handle_exception()` - Exception handling
  - `secure_pickle_dump()` - Secure serialization
  - `secure_pickle_load()` - Secure deserialization
  - `setup_file_logging()` - Configure logging

- **misc_utils.py**
  - `log_message()` - Logging utilities
  - `format_bytes()` - Format byte sizes
  - `validate_path()` - Path validation
  - `sanitize_filename()` - Filename sanitization
  - `ensure_directory_exists()` - Directory creation### System Utilities (`intellicrack/utils/system/`)
- **system_utils.py**
  - `get_system_info()` - Get system information
  - `check_dependencies()` - Check dependencies
  - `run_command()` - Execute system commands
  - `get_process_list()` - List system processes
  - `check_admin_privileges()` - Check admin rights
  - `run_as_admin()` - Run with elevated privileges

- **process_utils.py**
  - `find_process_by_name()` - Find processes
  - `get_all_processes()` - Get all processes
  - `detect_hardware_dongles()` - Detect dongles
  - `detect_tpm_protection()` - Detect TPM

- **subprocess_utils.py**
  - `run_subprocess()` - Run subprocesses safely
  - `run_subprocess_check()` - Run with checks
  - `create_popen_with_encoding()` - Create encoded processes
  - `async_run_subprocess()` - Async subprocess execution

- **os_detection.py**
  - `detect_operating_system()` - Detect OS
  - `is_windows()` - Check for Windows
  - `is_linux_like()` - Check for Linux
  - `get_platform_details()` - Get platform info

- **file_resolution.py**
  - `FileResolver` - Resolve file types
  - File type detection
  - Extension mapping

### Patching Utilities (`intellicrack/utils/patching/`)
- **patch_generator.py**
  - `PatchGenerator` - Main patch generation
  - `generate_patch()` - Generate patches
  - `apply_patch()` - Apply patches
  - `BinaryAnalyzer` - Analyze for patching
  - `PatternDatabase` - Pattern storage
  - `IntelligentPatcher` - Smart patching

- **patch_utils.py**
  - `parse_patch_instructions()` - Parse patches
  - `create_patch()` - Create patch files
  - `validate_patch()` - Validate patches
  - `create_nop_patch()` - Create NOP patches### Protection Utilities (`intellicrack/utils/protection/`)
- **protection_detection.py**
  - `detect_virtualization_protection()` - Detect VM protection
  - `detect_commercial_protections()` - Detect commercial protectors
  - `run_comprehensive_protection_scan()` - Full protection scan
  - `detect_anti_debugging_techniques()` - Anti-debug detection
  - `detect_obfuscation()` - Obfuscation detection

- **protection_utils.py**
  - `analyze_protection()` - Analyze protection mechanisms
  - `bypass_protection()` - Generate bypass strategies
  - `inject_comprehensive_api_hooks()` - API hooking
  - `generate_bypass_strategy()` - Bypass strategy generation

- **certificate_utils.py**
  - `generate_self_signed_cert()` - Generate certificates
  - `load_certificate_from_file()` - Load certificates
  - `verify_certificate_validity()` - Verify certificates
  - `get_certificate_info()` - Certificate information

### Exploitation Utilities (`intellicrack/utils/exploitation/`)
- **exploitation.py**
  - `generate_bypass_script()` - Generate bypass scripts
  - `generate_exploit()` - Generate exploits
  - `generate_exploit_strategy()` - Exploit strategies
  - `generate_license_bypass_payload()` - License bypass
  - `analyze_for_patches()` - Patch analysis
  - `generate_keygen_batch()` - Batch key generation

- **payload_result_handler.py**
  - `PayloadResultHandler` - Handle payload results

- **exploit_common.py**
  - `handle_exploit_strategy_generation()` - Strategy generation
  - `handle_exploit_payload_generation()` - Payload generation
  - `generate_reverse_shell_payload()` - Reverse shells
  - `generate_meterpreter_payload()` - Meterpreter payloads### Runtime and Performance (`intellicrack/utils/runtime/`)
- **additional_runners.py**
  - `run_comprehensive_analysis()` - Comprehensive analysis
  - `run_deep_license_analysis()` - License analysis
  - `run_autonomous_crack()` - Autonomous cracking
  - `run_vulnerability_scan()` - Vulnerability scanning
  - `detect_hardware_dongles()` - Hardware detection

- **distributed_processing.py**
  - `process_binary_chunks()` - Chunk processing
  - `run_distributed_analysis()` - Distributed analysis
  - `run_gpu_accelerated_analysis()` - GPU acceleration
  - `extract_binary_features()` - Feature extraction

- **performance_optimizer.py**
  - `PerformanceOptimizer` - Performance optimization
  - `MemoryManager` - Memory management
  - `BinaryChunker` - Binary chunking
  - `CacheManager` - Cache management
  - `AdaptiveAnalyzer` - Adaptive analysis

### Analysis Utilities (`intellicrack/utils/analysis/`)
- **analysis_exporter.py**
  - `AnalysisExporter` - Export analysis results

- **entropy_utils.py**
  - `calculate_entropy()` - Calculate entropy
  - `calculate_byte_entropy()` - Byte entropy
  - `is_high_entropy()` - Check high entropy
  - `analyze_entropy_sections()` - Section entropy

- **pattern_search.py**
  - `find_all_pattern_occurrences()` - Find patterns
  - `search_patterns_in_binary()` - Binary pattern search
  - `find_function_prologues()` - Find prologues
  - `find_license_patterns()` - License patterns

### Reporting (`intellicrack/utils/reporting/`)
- **report_generator.py**
  - `ReportGenerator` - Generate reports
  - `generate_report()` - Create reports
  - `generate_html_report()` - HTML reports
  - `generate_text_report()` - Text reports
  - `export_report()` - Export reports---

## MAIN FEATURE: Hex Viewer (`intellicrack/hexview/`)

### Core Hex Viewer
- **hex_widget.py**
  - `HexViewerWidget` - Main hex viewer widget
  - Hex/ASCII display
  - Binary editing capabilities

- **hex_dialog.py**
  - `HexViewerDialog` - Hex viewer dialog window
  - Standalone hex viewer interface

- **hex_renderer.py**
  - `HexViewRenderer` - Render hex view
  - `ViewMode` - Display modes
  - `parse_hex_view()` - Parse hex data

### Advanced Features
- **advanced_search.py**
  - `AdvancedSearchDialog` - Advanced search dialog
  - `SearchEngine` - Search functionality
  - `FindAllDialog` - Find all occurrences
  - `ReplaceDialog` - Replace functionality
  - `SearchThread` - Threaded searching

- **data_inspector.py**
  - `DataInspector` - Inspect binary data
  - `DataInterpreter` - Interpret data types
  - `DataType` - Data type definitions

- **hex_highlighter.py**
  - `HexHighlighter` - Syntax highlighting
  - `HexHighlight` - Highlight definitions
  - `HighlightType` - Highlight types

### Large File Support
- **large_file_handler.py**
  - `LargeFileHandler` - Handle large files
  - `FileCache` - File caching
  - `MemoryMonitor` - Memory monitoring
  - `BackgroundLoader` - Background loading
  - `MemoryStrategy` - Memory strategies

- **file_handler.py**
  - `VirtualFileAccess` - Virtual file access
  - `ChunkManager` - Chunk management
  - `LRUCache` - LRU cache implementation### AI Integration
- **ai_bridge.py**
  - `AIBinaryBridge` - AI-powered binary analysis
  - `BinaryContextBuilder` - Build context for AI
  - `AIFeatureType` - AI feature types
  - `wrapper_ai_binary_analyze()` - AI analysis wrapper
  - `wrapper_ai_binary_pattern_search()` - AI pattern search
  - `wrapper_ai_binary_edit_suggest()` - AI edit suggestions

### Commands and Operations
- **hex_commands.py**
  - `CommandManager` - Command management
  - `HexCommand` - Base command class
  - `ReplaceCommand` - Replace operations
  - `InsertCommand` - Insert operations
  - `DeleteCommand` - Delete operations
  - `FillCommand` - Fill operations
  - `PasteCommand` - Paste operations

### Integration
- **integration.py**
  - `integrate_enhanced_hex_viewer()` - Integrate with main app
  - `show_enhanced_hex_viewer()` - Show hex viewer
  - `register_hex_viewer_ai_tools()` - Register AI tools
  - `add_hex_viewer_menu()` - Add menu items
  - `add_hex_viewer_toolbar_button()` - Add toolbar buttons

- **intellicrack_hex_protection_integration.py**
  - `IntellicrackHexProtectionIntegration` - Protection integration
  - `ProtectionIntegrationWidget` - Protection widget
  - `create_intellicrack_hex_integration()` - Create integration

### API and Utilities
- **api.py**
  - `open_hex_file()` - Open files
  - `read_hex_region()` - Read regions
  - `write_hex_region()` - Write regions
  - `analyze_binary_data()` - Analyze data
  - `search_binary_pattern()` - Search patterns
  - `suggest_binary_edits()` - Edit suggestions
  - `create_hex_viewer_widget()` - Create widget
  - `launch_hex_viewer()` - Launch viewer---

## MAIN FEATURE: Plugin System (`intellicrack/plugins/`)

### Core Plugin Infrastructure
- **plugin_system.py**
  - `PluginSystem` - Main plugin system
  - `load_plugins()` - Load plugins
  - `run_plugin()` - Execute plugins
  - `run_plugin_in_sandbox()` - Sandboxed execution
  - `run_plugin_remotely()` - Remote execution
  - `create_plugin_template()` - Template generation

- **plugin_base.py**
  - `BasePlugin` - Base plugin class
  - `PluginMetadata` - Plugin metadata
  - `PluginConfigManager` - Configuration management
  - `create_plugin_info()` - Plugin info creation

- **remote_executor.py**
  - `RemotePluginExecutor` - Remote execution
  - `create_remote_executor()` - Create executor
  - Sandboxed plugin execution

### Custom Modules (`intellicrack/plugins/custom_modules/`)
- **intellicrack_core_engine.py**
  - `IntellicrackcoreEngine` - Core plugin engine
  - `PluginManager` - Plugin management
  - `EventBus` - Event system
  - `WorkflowEngine` - Workflow execution
  - `AnalysisCoordinator` - Analysis coordination
  - `ResourceManager` - Resource management

- **anti_anti_debug_suite.py**
  - `AntiAntiDebugSuite` - Anti-debugging bypass
  - `WindowsAPIHooker` - API hooking
  - `PEBManipulator` - PEB manipulation
  - `HardwareDebugProtector` - Hardware debug protection
  - `TimingNormalizer` - Timing normalization
  - `MemoryPatcher` - Memory patching

- **hardware_dongle_emulator.py**
  - `HardwareDongleEmulator` - Dongle emulation
  - `HASPEmulator` - HASP dongle emulator
  - `SentinelEmulator` - Sentinel emulator
  - `USBDongleDriver` - USB dongle driver
  - `DongleAPIHooker` - Dongle API hooks- **license_server_emulator.py**
  - `LicenseServerEmulator` - License server emulation
  - `FlexLMEmulator` - FlexLM emulation
  - `HASPEmulator` - HASP license emulation
  - `MicrosoftKMSEmulator` - KMS emulation
  - `AdobeEmulator` - Adobe license emulation
  - `DatabaseManager` - License database
  - `HardwareFingerprintGenerator` - HWID generation

- **cloud_license_interceptor.py**
  - `CloudLicenseInterceptor` - Cloud license interception
  - `CertificateManager` - Certificate management
  - `RequestClassifier` - Request classification
  - `AuthenticationManager` - Auth management
  - `ResponseModifier` - Response modification
  - `LocalLicenseServer` - Local server

- **vm_protection_unwrapper.py**
  - `VMProtectionUnwrapper` - VM protection unwrapping
  - `VMProtectHandler` - VMProtect handling
  - `ThemidaHandler` - Themida handling
  - `VMEmulator` - VM emulation
  - `VMAnalyzer` - VM analysis

- **performance_optimizer.py**
  - `PerformanceOptimizer` - Performance optimization
  - `GPUOptimizer` - GPU optimization
  - `ThreadPoolOptimizer` - Thread optimization
  - `CacheManager` - Cache management
  - `AdaptiveOptimizer` - Adaptive optimization

- **success_rate_analyzer.py**
  - `SuccessRateAnalyzer` - Success rate analysis
  - `EventTracker` - Event tracking
  - `StatisticalTester` - Statistical testing
  - `MLPredictor` - ML predictions
  - `ReportGenerator` - Report generation

### Specialized Plugins
- **binary_patcher_plugin.py**
  - `BinaryPatcherPlugin` - Binary patching
  - `BinaryPatch` - Patch definitions- **network_analysis_plugin.py**
  - `NetworkAnalysisPlugin` - Network analysis

- **simple_analysis_plugin.py**
  - `SimpleAnalysisPlugin` - Simple analysis

- **demo_plugin.py**
  - `DemoPlugin` - Demo plugin template
  - Plugin metadata example

- **ui_enhancement_module.py**
  - `UIEnhancementModule` - UI enhancements
  - `RealTimeChart` - Real-time charting
  - `LogViewer` - Log viewing
  - `ProgressTracker` - Progress tracking
  - `FileExplorerPanel` - File explorer
  - `AnalysisViewerPanel` - Analysis viewer
  - `ScriptGeneratorPanel` - Script generation

- **test_suite_comprehensive.py**
  - `TestRunner` - Test execution
  - `TestProtectionClassifier` - Protection testing
  - `TestNeuralNetworkDetector` - NN detection testing
  - `TestHardwareDongleEmulator` - Dongle testing
  - `TestVMProtectionUnwrapper` - VM protection testing
  - `TestAntiAntiDebugSuite` - Anti-debug testing

### Ghidra Scripts (`intellicrack/plugins/ghidra_scripts/`)
- **AntiAnalysisDetector.py**
  - `AntiAnalysisDetector` - Detect anti-analysis
  - Anti-debugging detection
  - Anti-VM detection
  - Obfuscation detection

### Radare2 Modules (`intellicrack/plugins/radare2_modules/`)
- **radare2_license_analyzer.py**
  - `R2LicenseAnalyzer` - License analysis
  - License function detection
  - Protection level assessment

- **radare2_keygen_assistant.py**
  - `R2KeygenAssistant` - Keygen assistance
  - Crypto algorithm detection
  - Key generation templates---

## MAIN FEATURE: Scripts and Automation (`intellicrack/scripts/`)

### CLI Scripts (`intellicrack/scripts/cli/`)
- **main.py**
  - `IntellicrackCLI` - Main CLI interface
  - Command-line argument parsing
  - Batch processing
  - Server mode
  - Watch mode

- **interactive_mode.py**
  - `IntellicrackShell` - Interactive shell
  - `AdvancedProgressManager` - Progress management
  - Command completion
  - Interactive features

- **ai_integration.py**
  - `AIModelAdapter` - AI model integration
  - `ClaudeAdapter` - Claude integration
  - `OpenAIAdapter` - OpenAI integration
  - `LangChainIntegration` - LangChain support
  - `IntellicrackAIServer` - AI server

- **ai_wrapper.py**
  - `IntellicrackAIInterface` - AI interface
  - `ConfirmationManager` - Action confirmation
  - AI tool registration
  - Prompt creation

- **ai_chat_interface.py**
  - `AITerminalChat` - Terminal chat interface
  - `launch_ai_chat()` - Launch chat

- **enhanced_runner.py**
  - `EnhancedCLIRunner` - Enhanced CLI runner
  - Advanced command execution

- **hex_viewer_cli.py**
  - `TerminalHexViewer` - Terminal hex viewer
  - `launch_hex_viewer()` - Launch viewer

- **terminal_dashboard.py**
  - `TerminalDashboard` - Terminal dashboard
  - System metrics display
  - Analysis statistics
  - Session information### Configuration and Management
- **config_manager.py**
  - `ConfigManager` - Configuration management
  - `ConfigOption` - Configuration options
  - `get_config_manager()` - Get manager instance

- **config_profiles.py**
  - `ConfigProfile` - Configuration profiles
  - `ProfileManager` - Profile management
  - `create_default_profiles()` - Default profiles

- **project_manager.py**
  - `ProjectManager` - Project management
  - `IntellicrackProject` - Project representation
  - Project creation and management

- **tutorial_system.py**
  - `TutorialSystem` - Tutorial system
  - `Tutorial` - Tutorial definitions
  - `TutorialStep` - Tutorial steps
  - Interactive tutorials

### Analysis and Export
- **pipeline.py**
  - `Pipeline` - Analysis pipeline
  - `PipelineStage` - Pipeline stages
  - `AnalysisStage` - Analysis stage
  - `FilterStage` - Filter stage
  - `TransformStage` - Transform stage
  - `OutputStage` - Output stage

- **advanced_export.py**
  - `AdvancedExporter` - Advanced export functionality
  - Multiple export formats
  - Template-based export

- **ascii_charts.py**
  - `ASCIIChartGenerator` - ASCII chart generation
  - Terminal-friendly charts
  - Analysis visualization

- **progress_manager.py**
  - `ProgressManager` - Progress tracking
  - `MultiStageProgress` - Multi-stage progress
  - `AnalysisTask` - Task tracking### Utility Scripts
- **run_analysis_cli.py**
  - Command-line analysis runner
  - Custom configuration loading
  - Output formatting

- **migrate_secrets.py**
  - `migrate_llm_configs()` - Migrate LLM configs
  - `migrate_env_files()` - Migrate env files
  - `check_code_for_secrets()` - Check for secrets

- **test_integration.py**
  - Integration testing
  - Module testing
  - Package structure validation

- **simconcolic.py**
  - Symbolic/concolic execution
  - Binary analysis plugins

### Fix Scripts (`intellicrack/scripts/fixes/`)
- Exception handling fixes
- Code quality improvements
- S110 violation fixes

---

## MAIN FEATURE: Frida Scripts (`intellicrack/scripts/frida/`)

### Core Bypass Scripts
- **adobe_bypass.js** - Adobe product bypass
- **adobe_bypass_frida.js** - Enhanced Adobe bypass
- **central_orchestrator.js** - Central bypass orchestration
- **bypass_success_tracker.js** - Track bypass success

### Platform-Specific Bypasses
- **android_bypass_suite.js** - Android protection bypass
- **dotnet_bypass_suite.js** - .NET protection bypass
- **kernel_mode_bypass.js** - Kernel-mode bypass
- **kernel_bridge.js** - Kernel communication

### Anti-Analysis Bypass
- **anti_debugger.js** - Anti-debugging bypass
- **obfuscation_detector.js** - Detect obfuscation
- **realtime_protection_detector.js** - Detect protections
- **virtualization_bypass.js** - VM detection bypass### License and Protection Bypass
- **cloud_licensing_bypass.js** - Cloud license bypass
- **drm_bypass.js** - DRM protection bypass
- **code_integrity_bypass.js** - Code integrity bypass
- **memory_integrity_bypass.js** - Memory integrity bypass
- **ml_license_detector.js** - ML-based license detection

### Hardware and Environment
- **hwid_spoofer.js** - Hardware ID spoofing
- **enhanced_hardware_spoofer.js** - Enhanced hardware spoofing
- **tpm_emulator.js** - TPM chip emulation
- **registry_monitor.js** - Registry monitoring
- **registry_monitor_enhanced.js** - Enhanced registry monitoring

### Network and Communication
- **certificate_pinner_bypass.js** - Certificate pinning bypass
- **http3_quic_interceptor.js** - HTTP/3 QUIC interception
- **websocket_interceptor.js** - WebSocket interception
- **telemetry_blocker.js** - Telemetry blocking
- **ntp_blocker.js** - NTP time sync blocking

### Time and Behavior Analysis
- **time_bomb_defuser.js** - Time bomb defusing
- **time_bomb_defuser_advanced.js** - Advanced time bomb handling
- **behavioral_pattern_analyzer.js** - Behavior pattern analysis

### Dynamic Analysis
- **dynamic_script_generator.js** - Dynamic script generation
- **modular_hook_library.js** - Modular hook library
- **hook_effectiveness_monitor.js** - Hook effectiveness monitoring

---

## MAIN FEATURE: Core Components (`intellicrack/core/`)

### Application Context
- **app_context.py**
  - Application-wide context management
  - Global state management
  - Configuration handling### Logging System (`intellicrack/core/logging/`)
- **audit_logger.py**
  - `AuditLogger` - Security audit logging
  - `PerformanceMonitor` - Performance monitoring
  - `TelemetryCollector` - Telemetry collection
  - `ContextualLogger` - Context-aware logging
  - `log_exploit_attempt()` - Log exploitation attempts
  - `log_binary_analysis()` - Log analysis operations
  - `log_vm_operation()` - Log VM operations

### Resource Management (`intellicrack/core/resources/`)
- **resource_manager.py**
  - `ResourceManager` - Centralized resource management
  - Resource allocation and tracking
  - Memory management
  - File handle management

### Task Management
- **task_manager.py**
  - Task scheduling and execution
  - Asynchronous task handling
  - Task prioritization

### Security
- **security_enforcement.py**
  - Security policy enforcement
  - Access control
  - Permission validation

---

## Summary

This structural map provides a comprehensive overview of the Intellicrack project architecture, covering:
- Entry points and initialization
- Core analysis and exploitation capabilities
- AI/LLM integration across 16+ providers
- Complete UI framework with PyQt5
- Network analysis and emulation
- Protection detection and bypass mechanisms
- Extensive utility libraries
- Plugin system architecture
- Automation scripts
- Testing infrastructure

The map serves as a reference for understanding component relationships and system architecture.

## DETAILED COMPONENT MAPPING (Private Methods, Nested Classes, Exceptions, Lambdas)

### Core Analysis Components - Private Methods

#### binary_analyzer.py
- **BinaryAnalyzer**
  - `__init__()` - Initialize the binary analyzer
  - `analyze(binary_path)` - Perform comprehensive binary analysis
  - Private Methods:
    - `_get_file_info(file_path)` - Extract basic file metadata
    - `_detect_format(file_path)` - Detect file format using magic bytes
    - `_calculate_hashes(file_path)` - Calculate MD5, SHA1, SHA256, SHA512
    - `_analyze_pe(file_path)` - Analyze PE (Windows executable) file
    - `_analyze_elf(file_path)` - Analyze ELF (Linux executable) file
    - `_get_segment_flags(flags)` - Convert segment flags to readable string
    - `_analyze_macho(file_path)` - Analyze Mach-O (macOS executable) file
    - `_analyze_dex(file_path)` - Analyze Android DEX file
    - `_analyze_archive(file_path)` - Analyze ZIP/JAR/APK archives
    - `_extract_strings(file_path)` - Extract printable strings
    - `_analyze_entropy(file_path)` - Calculate file entropy
    - `_security_analysis(file_path, file_format)` - Perform security analysis            - Private Methods:
      - _get_file_info(file_path): Get file metadata using os.stat
      - _detect_format(file_path): Detect binary format using magic bytes
                -_calculate_hashes(file_path): Calculate MD5/SHA1/SHA256 hashes
      - _analyze_pe(file_path): Analyze PE file structure
                -_analyze_elf(file_path): Analyze ELF file structure
      - _get_segment_flags(flags): Convert ELF segment flags to string
                -_analyze_macho(file_path): Analyze Mach-O file structure
      - _analyze_dex(file_path): Analyze Android DEX file structure
                -_analyze_archive(file_path): Analyze archive file formats
      - _extract_strings(file_path): Extract strings from binary
                -_analyze_entropy(file_path): Calculate entropy analysis
      - _security_analysis(file_path, file_format): Perform security checks

      - analysis_orchestrator.py: Orchestrates comprehensive binary analysis
        - Classes:
          - AnalysisPhase (Enum): Analysis phase enumeration
            - PREPARATION, BASIC_INFO, STATIC_ANALYSIS
            - ENTROPY_ANALYSIS, STRUCTURE_ANALYSIS, VULNERABILITY_SCAN
            - PATTERN_MATCHING, DYNAMIC_ANALYSIS, FINALIZATION
          - OrchestrationResult (dataclass): Result container
            - Fields: binary_path, success, phases_completed, results, errors, warnings
            - Methods: add_result(), add_error(), add_warning()
          - AnalysisOrchestrator: Main orchestration class
            - Signals: phase_started, phase_completed, phase_failed, progress_updated, analysis_completed
            - **init**(): Initialize the analysis orchestrator
            - analyze_binary(binary_path, phases): Main analysis entry point
        - Private Methods:
          - _prepare_analysis(binary_path): Prepare for analysis
          - _analyze_basic_info(binary_path): Get basic binary information
          - _perform_static_analysis(binary_path): Static analysis using radare2
          - _perform_entropy_analysis(binary_path): Entropy analysis
          - _analyze_structure(binary_path): Structure analysis
          - _scan_vulnerabilities(binary_path): Vulnerability scanning
          - _match_patterns(binary_path): YARA pattern matching
          - _perform_dynamic_analysis(binary_path): Dynamic analysis
          - _finalize_analysis(result): Finalize analysis results

      - cfg_explorer.py: Control Flow Graph exploration and analysis
        - Classes:
          - _MockNetworkX: Mock networkx library when not available
            - DiGraph(): Mock DiGraph class for type annotations
          - CFGExplorer: Main CFG exploration class
            - **init**(binary_path, radare2_path): Initialize the enhanced CFG explorer
            - load_binary(binary_path): Load a binary file and extract its enhanced CFG
            - get_function_list(): Get a list of all functions in the binary
            - set_current_function(function_name): Set the current function for analysis
            - get_functions(): Get list of functions (alias for get_function_list)
            - analyze_function(function_name): Analyze a specific function (compatibility method)
            - visualize_cfg(function_name): Visualize CFG (compatibility method)
            - export_dot(output_file): Export DOT file (alias for export_dot_file)
            - analyze(binary_path): Analyze binary (compatibility method)
            - get_complexity_metrics(): Get complexity metrics for the current function
            - get_graph_layout(layout_type): Get a layout for the current function graph
            - get_graph_data(layout_type): Get graph data for visualization
            - get_advanced_analysis_results(): Get comprehensive advanced analysis results
            - get_call_graph_metrics(): Get call graph analysis metrics
            - get_vulnerability_patterns(): Get vulnerability patterns from advanced analysis
            - get_license_validation_analysis(): Get comprehensive license validation analysis
            - get_code_complexity_analysis(): Get comprehensive code complexity analysis
            - get_cross_reference_analysis(): Get cross-reference analysis between functions
            - find_license_check_patterns(): Find potential license check patterns in the CFG
            - generate_interactive_html(function_name, license_patterns, output_file): Generate an interactive HTML visualization of the CFG
            - export_graph_image(output_file, format): Export the CFG as an image file
            - export_dot_file(output_file): Export the CFG as a DOT file
            - analyze_cfg(binary_path): Perform comprehensive advanced CFG analysis on a binary
            - export_json(output_path): Export comprehensive CFG analysis to JSON format
        - Private Methods:
          - _initialize_analysis_engines(): Initialize all analysis engines with current binary path
          - _create_enhanced_function_graph(graph_data, r2, function_addr): Create enhanced function graph with comprehensive node data
          - _classify_block_type(block): Classify block type based on its characteristics
          - _calculate_block_complexity(block): Calculate complexity score for a basic block
          - _build_call_graph(r2): Build inter-function call graph
          - _find_function_by_address(address): Find function name containing the given address
          - _perform_advanced_analysis(): Perform advanced analysis using integrated engines
          - _calculate_function_similarities(): Calculate similarities between functions using graph metrics
          - _calculate_graph_similarity(graph1, graph2): Calculate similarity between two function graphs
          - _find_recursive_functions(): Find functions that call themselves directly or indirectly
          - _calculate_cyclomatic_complexity(graph): Calculate cyclomatic complexity of a function graph
          - _generate_similarity_clusters(): Generate clusters of similar functions
          - _generate_analysis_summary(results): Generate comprehensive analysis summary
          - _show_error_dialog(title, message): Show error dialog to user when in GUI mode
        - Top-level Functions:
          - run_deep_cfg_analysis(app): Run deep CFG analysis
          - run_cfg_explorer(app): Initialize and run the CFG explorer with GUI integration
          - log_message(message): Helper function for log message formatting
        - Nested Functions:
          - json_serializable(obj): Convert non-serializable objects to JSON-friendly format (nested in export_json)

      - dynamic_analyzer.py: Advanced dynamic analysis with Frida
        - Classes:
          - AdvancedDynamicAnalyzer: Main dynamic analyzer
            - **init**(binary_path): Initialize the advanced dynamic analyzer
            - run_comprehensive_analysis(payload): Execute multi-stage dynamic analysis
            - scan_memory_for_keywords(keywords, target_process): Scan process memory for specific keywords
        - Private Methods:
          - _subprocess_analysis(): Standard subprocess execution analysis
          - _frida_runtime_analysis(payload): Advanced Frida-based runtime analysis and payload injection
          - _process_behavior_analysis(): Analyze process behavior and resource interactions
          - _frida_memory_scan(keywords, target_process): Perform memory scanning using Frida instrumentation
          - _psutil_memory_scan(keywords, target_process): Perform basic memory scanning using psutil
          - _fallback_memory_scan(keywords, target_process): Fallback memory scanning using binary file analysis
        - Top-level Functions:
          - run_dynamic_analysis(app, binary_path, payload): Run dynamic analysis on a binary with app integration
          - deep_runtime_monitoring(binary_path, timeout): Monitor runtime behavior of the binary using Frida instrumentation
          - create_dynamic_analyzer(binary_path): Factory function to create a dynamic analyzer instance
          - run_quick_analysis(binary_path, payload): Run a quick comprehensive analysis on a binary
        - Nested Functions:
          - on_message(message,_data) (nested in _frida_runtime_analysis)
          - on_message(message,_data) (nested in deep_runtime_monitoring)

          - firmware_analyzer.py: Firmware extraction and analysis
        - Classes:
          - FirmwareType (Enum): Types of firmware detected
            - ROUTER_FIRMWARE, IOT_DEVICE, BOOTLOADER, KERNEL_IMAGE, FILESYSTEM, BIOS_UEFI, EMBEDDED_BINARY, UNKNOWN
          - SecurityFindingType (Enum): Types of security findings
            - HARDCODED_CREDENTIALS, PRIVATE_KEY, CERTIFICATE, BACKDOOR_BINARY, VULNERABLE_COMPONENT, WEAK_ENCRYPTION, DEBUG_INTERFACE, DEFAULT_PASSWORD
          - FirmwareSignature (dataclass): Single firmware signature detection
            - offset, signature_name, description, file_type, size, confidence
            - Properties: is_executable, is_filesystem
          - ExtractedFile (dataclass): Information about an extracted file
            - file_path, original_offset, file_type, size, hash, is_executable, permissions, extracted_strings, security_analysis
            - Class Methods: from_path(file_path, original_offset)
          - SecurityFinding (dataclass): Security-related finding in firmware
            - finding_type, description, file_path, offset, severity, confidence, evidence, remediation
            - Properties: is_critical
          - FirmwareExtraction (dataclass): Results of firmware extraction process
            - extracted_files, extraction_directory, success, errors, total_extracted, extraction_time
            - Properties: executable_files, text_files
          - FirmwareAnalysisResult (dataclass): Complete firmware analysis results
            - file_path, firmware_type, signatures, extractions, entropy_analysis, security_findings, analysis_time, error
            - Properties: has_extractions, critical_findings, embedded_executables
          - FirmwareAnalyzer: Advanced firmware analysis engine using Binwalk
            - **init**(work_directory): Initialize the firmware analyzer with working directory configuration
            - analyze_firmware(file_path, extract_files, analyze_security, extraction_depth): Perform comprehensive firmware analysis
            - generate_icp_supplemental_data(analysis_result): Generate supplemental data for ICP backend integration
            - export_analysis_report(analysis_result, output_path): Export firmware analysis results to JSON report
            - cleanup_extractions(extraction_directory): Clean up extraction directory
        - Private Methods:
          - _scan_signatures(file_path): Scan for firmware signatures using Binwalk
          - _extract_file_type(description): Extract file type from Binwalk description
          - _determine_firmware_type(file_path, signatures): Determine the type of firmware based on signatures and filename
          - _analyze_entropy(file_path): Analyze file entropy to detect encryption/compression
          - _calculate_basic_entropy(file_path): Calculate basic Shannon entropy
          - _extract_embedded_files(file_path, max_depth): Extract embedded files using Binwalk
          - _analyze_extracted_file(extracted_file): Analyze an individual extracted file
          - _extract_strings(file_path, min_length): Extract printable strings from file
          - _analyze_file_security(file_path): Perform security analysis on a file
          - _analyze_security(file_path, extractions): Perform comprehensive security analysis
          - _scan_for_credentials(file_path): Scan for hardcoded credentials
          - _scan_for_crypto_keys(file_path): Scan for cryptographic keys
          - _scan_for_backdoors(file_path): Scan for potential backdoors
          - _is_suspicious_string(string): Check if a string looks suspicious
          - _looks_like_credential(string): Check if string looks like a credential
          - _looks_like_crypto_key(string): Check if string looks like a cryptographic key
        - Top-level Functions:
          - get_firmware_analyzer(): Get or create the firmware analyzer singleton
          - is_binwalk_available(): Check if Binwalk functionality is available
          - analyze_firmware_file(file_path): Quick firmware analysis function for integration

      - ghidra_decompiler.py: Ghidra integration for decompilation
        - Classes:
          - DecompilationResult (dataclass): Decompilation results
            - Fields: success: bool, functions: List[FunctionInfo], error: Optional[str]
          - FunctionInfo (dataclass): Function information
            - Fields: name: str, address: str, signature: str, decompiled_code: str,
                      complexity: int, calls: List[str], strings: List[str]
          - AnalysisReport (dataclass): Complete analysis report
            - Fields: decompilation: DecompilationResult, crypto_operations: List[Dict],
                      licensing_functions: List[Dict], obfuscation_detected: Dict,
                      protection_mechanisms: List[Dict], anti_debugging: List[Dict],
                      network_operations: List[Dict], backdoors: List[Dict]
          - GhidraDecompiler: Main Ghidra integration class
            - **init**(): Initialize with ghidra_path
            - decompile(): Main decompilation entry point
            - analyze_advanced(): Advanced analysis features
        - Private Methods (34 methods):
          - _load_ghidra_framework(): Load Ghidra Python framework
          - _detect_ghidra_path(): Auto-detect Ghidra installation
          - _create_ghidra_project(): Create temporary Ghidra project
          - _find_executable(): Find Ghidra executable
          - _ensure_temp_dir(): Ensure temp directory exists
          - _run_headless_ghidra(): Run Ghidra in headless mode
          - _parse_ghidra_output(): Parse Ghidra output
          - _run_cli_decompilation(): Run CLI decompilation
          - _analyze_binary(): Analyze binary with Ghidra
          - _extract_functions(): Extract functions from binary
          - _decompile_function(): Decompile single function
          - _generate_report(): Generate analysis report
          - _perform_advanced_analysis(): Perform advanced analysis
          - _extract_all_strings(): Extract all strings
          - _find_crypto_operations(): Find cryptographic operations
          - _analyze_licensing(): Analyze licensing mechanisms
          - _detect_obfuscation(): Detect code obfuscation
          - _find_protection_checks(): Find protection checks
          - _analyze_anti_debugging(): Analyze anti-debugging
          - _analyze_network_operations(): Analyze network operations
          - _find_backdoors(): Find potential backdoors
          - _integrate_with_intellicrack(): Integrate with main app
          - _cleanup_temp_files(): Clean up temporary files
          - _create_analysis_script(): Create Ghidra analysis script
          - _detect_function_boundaries(): Detect function boundaries
          - _analyze_control_flow(): Analyze control flow
          - _extract_api_calls(): Extract API calls
          - _identify_key_functions(): Identify key functions
          - _generate_bypass_suggestions(): Generate bypass suggestions
          - _export_results(): Export analysis results
          - _cache_results(): Cache analysis results
          - _load_cached_results(): Load cached results
          - _validate_results(): Validate analysis results
          - _optimize_analysis(): Optimize analysis process
        - Lambda Functions:
          - Line 948: lambda x: x['confidence'] - Sort suggestions by confidence            - _analyze_live_process_windows(process_id) -> Dict[str, Any]
          - Nested class: MEMORY_BASIC_INFORMATION
        - _analyze_live_process_linux(process_id) -> Dict[str, Any]
        - _get_protection_string(protect) -> str
        - _get_memory_type(mem_type) -> str
        - _parse_linux_addr(addr_str) -> str
        - extract_strings(memory_data, min_length) -> List[str]
        - generate_icp_supplemental_data(analysis_result) -> Dict[str, Any]
        - get_analysis_summary(analysis_result) -> Dict[str, Any]
        - export_analysis_report(analysis_result, output_path) -> Tuple[bool, str]
      - get_memory_forensics_engine() -> Optional[MemoryForensicsEngine]
      - NetworkForensicsEngine:
        - **init**(self)
        - analyze_capture(capture_path) -> Dict[str, Any]
        - analyze_live_traffic(interface, duration) -> Dict[str, Any] [async]
        - extract_artifacts(traffic_data) -> List[Dict[str, Any]]
        - detect_protocols(packet_data) -> List[str]        - Radare2EnhancedIntegration:
        - **init**(binary_path, config)
        - _initialize_components()
        - run_comprehensive_analysis(analysis_types) -> Dict[str, Any]
        - _run_parallel_analysis(analysis_types) -> Dict[str, Any]
        - _run_single_analysis(analysis_type) -> Optional[Dict[str, Any]]
        - _get_cached_result(cache_key) -> Optional[Dict[str, Any]]
        - _cache_result(cache_key, result)
          - Lambda: `key=lambda x: x[1]['timestamp']`
        - _record_analysis_time(analysis_type, duration, success)
        - start_real_time_monitoring(callback)
        - stop_real_time_monitoring()
        - _monitoring_loop(callback)
        - get_performance_stats() -> Dict[str, Any]
        - optimize_performance()
        - clear_cache()
        - get_health_status() -> Dict[str, Any]
        - cleanup()
        - open_binary(binary_path) -> bool
        - get_imports() -> List[Dict[str, Any]]
        - get_exports() -> List[Dict[str, Any]]
        - get_sections() -> List[Dict[str, Any]]
        - get_strings(min_length) -> List[Dict[str, Any]]
        - get_functions() -> List[Dict[str, Any]]
        - close()        - radare2_error_handler.py:
        - ErrorSeverity (Enum)
        - RecoveryStrategy (Enum)
        - ErrorEvent (dataclass)
        - RecoveryAction (dataclass)
        - R2ErrorHandler:
          - **init**(max_errors_per_session)
          - _initialize_recovery_actions()
          - error_context(operation_name, **context) [contextmanager]
          - handle_error(error, operation_name, context) -> bool [async]
          - _create_error_event(error, operation_name, context) -> ErrorEvent
          - _classify_error_severity(error, operation_name) -> ErrorSeverity
          - _determine_recovery_strategy(error_event) -> RecoveryStrategy
          - _execute_recovery(error_event) -> bool [async]
          - _execute_retry_recovery(error_event) -> bool [async]
          - _execute_fallback_recovery(error_event) -> bool [async]
          - _execute_graceful_degradation(error_event) -> bool [async]
          - _execute_user_intervention(error_event) -> bool
          - _execute_recovery_action(action_name, error_event) -> bool [async]
          - _restart_r2_session(error_event) -> bool
          - _re_analyze_binary(error_event) -> bool
          - _retry_with_fallback(error_event) -> bool
          - _cleanup_memory(error_event) -> bool
          - _graceful_degradation(error_event) -> bool
          - _is_circuit_broken(operation_name) -> bool
          - _update_circuit_breaker(operation_name, success)
          - _record_performance(operation_name, duration, success)
          - _record_recovery_success(action_name)
          - _record_recovery_failure(action_name)
          - _record_error(error_event)
          - add_recovery_action(name, action)
          - get_error_statistics() -> Dict[str, Any]
          - _get_error_count_by_type() -> Dict[str, int]
          - _get_error_count_by_severity() -> Dict[str, int]
          - _get_performance_metrics() -> Dict[str, Any]
          - _get_recovery_rates() -> Dict[str, float]
          - is_operation_degraded(operation_name) -> bool
          - reset_circuit_breaker(operation_name)
          - clear_error_history()
        - get_error_handler() -> R2ErrorHandler
        - handle_r2_error(error, operation_name, **context) -> bool [async]
        - r2_error_context(operation_name, **context) [contextmanager]                - R2JSONStandardizer (class)
          - SCHEMA_VERSION = "2.0"
          - ANALYSIS_TYPES = {...}
          - **init**(self)
          - standardize_analysis_result(self, analysis_type, raw_data, metadata)
                    -_create_base_structure(self, analysis_type, metadata)
                    -_standardize_decompilation(self, raw_data, metadata)

- _standardize_vulnerability(self, raw_data, metadata)
                    -_standardize_strings(self, raw_data, metadata)
- _standardize_imports(self, raw_data, metadata)
                    -_standardize_cfg(self, raw_data, metadata)
- _standardize_ai(self, raw_data, metadata)
                    -_standardize_signatures(self, raw_data, metadata)
- _standardize_esil(self, raw_data, metadata)
                    -_standardize_bypass(self, raw_data, metadata)
- _standardize_binary_diff(self, raw_data, metadata)
- _standardize_scripting(self, raw_data, metadata)
                    -_standardize_comprehensive(self, raw_data, metadata)
- _standardize_generic(self, raw_data, metadata)
                    -_add_validation_data(self, result)
- _validate_schema(self, result)
- _create_error_result(self, error_msg, analysis_type, metadata)
                    -_normalize_function_list(self, functions)
- _normalize_vulnerability(self, vuln)
- _normalize_address(self, addr)
- _get_radare2_version(self)
                    -_calculate_file_hash(self, file_path)
                    -_get_file_size(self, file_path)
                    -_calculate_completeness_score(self, result)
- _calculate_quality_score(self, result)
                    -_normalize_decompiled_code(self, code)
- _normalize_patterns(self, patterns)
- _normalize_validation_routines(self, routines)
                    -_calculate_decompilation_success_rate(self, functions)
                    -_calculate_average_complexity(self, functions)
- _extract_function_features(self, functions)
                    -_extract_pattern_features(self, patterns)
- _extract_complexity_features(self, functions)
                    -_extract_vulnerability_vectors(self, vulns)
- _extract_exploitability_features(self, vulns)
                    -_extract_risk_features(self, vulns)
- _extract_string_distribution_features(self, strings)
- _extract_string_entropy_features(self, strings)
- _extract_string_pattern_features(self, patterns)
- _extract_api_usage_vectors(self, imports)
- _extract_library_features(self, imports)
                    -_extract_suspicious_behavior_features(self, imports)
                    -_extract_graph_structural_features(self, cfg_data)
- _extract_complexity_distribution(self, cfg_data)
- _extract_cfg_pattern_features(self, patterns)
- _extract_ai_prediction_features(self, predictions)
- _extract_clustering_features(self, clustering)
                    -_extract_anomaly_features(self, anomalies)
- _extract_component_correlations(self, components)
                    -_extract_meta_features(self, all_features)
                    -_extract_generic_features(self, data)
- _calculate_risk_score(self, vulns)
                    -_get_complexity_distribution(self, functions)
- _calculate_avg_cyclomatic_complexity(self, functions)
- _calculate_avg_nesting_level(self, functions)
- _count_vulns_by_severity(self, vulns)
- _count_vulns_by_type(self, vulns)
- _categorize_strings(self, strings)
- _calculate_variance(self, values)
- _categorize_apis(self, imports)
- _count_suspicious_apis(self, imports)
                    -_get_common_libraries(self, imports)
- _count_process_apis(self, imports)
                    -_count_file_apis(self, imports)
- _count_network_apis(self, imports)
                    -_count_registry_apis(self, imports)
- _count_memory_apis(self, imports)
                    -_create_histogram(self, values, bins)
                    -_calculate_percentiles(self, values, percentiles)
                    -_calculate_correlation(self, list1, list2)
                    -_calculate_component_consistency(self, components)
- _calculate_nesting_depth(self, obj, depth)
                    -_analyze_data_types(self, obj)
- _extract_numeric_values(self, obj, values)
                    -_categorize_vulnerabilities(self, vulns)
                    -_normalize_cve_matches(self, cve_data)
                    -_normalize_exploit_data(self, exploit_data)
                    -_normalize_severity_assessment(self, severity_data)
                    -_normalize_string_list(self, strings)
- _normalize_pattern_list(self, patterns)
                    -_normalize_entropy_analysis(self, entropy_data)
                    -_normalize_cross_references(self, xrefs)
- _normalize_import_list(self, imports)
                    -_normalize_export_list(self, exports)
- _normalize_api_categories(self, api_data)
- _normalize_suspicious_apis(self, suspicious_data)
- _normalize_anti_analysis_apis(self, anti_analysis_data)
- _normalize_library_dependencies(self, libraries)
                    -_calculate_api_diversity(self, imports, exports)
- _normalize_complexity_metrics(self, complexity_data)
- _normalize_cfg_patterns(self, patterns)
                    -_normalize_graph_data(self, graph_data)
                    -_normalize_call_graph(self, call_graph)
                    -_normalize_vuln_patterns(self, patterns)
- _normalize_similarity_analysis(self, similarity_data)
- _get_average_complexity(self, functions)
                    -_get_max_complexity(self, functions)
- _count_vulnerability_patterns(self, vulns)
                    -_calculate_graph_density(self, graph_data)
                    -_normalize_ai_license_detection(self, license_data)
- _normalize_ai_vuln_prediction(self, vuln_data)
                    -_normalize_function_clustering(self, clustering_data)
                    -_normalize_anomaly_detection(self, anomaly_data)
                    -_normalize_code_similarity(self, similarity_data)
                    -_normalize_bypass_suggestions(self, suggestions)
- _calculate_bypass_success_probability(self, suggestion)
- _perform_cross_component_analysis(self, all_components)
                    -_create_unified_findings(self, all_findings)
                    -_perform_correlation_analysis(self, components)
- _count_total_vulnerabilities(self, findings)
                    -_count_total_license_functions(self, findings)
                    -_calculate_overall_risk_score(self, findings)
                    -_calculate_analysis_completeness(self, components)
- _create_unified_feature_vector(self, all_features)
                    -_normalize_generic_data(self, data)
- _analyze_component_interactions(self, components)
                    -_find_shared_indicators(self, components)
- _perform_consistency_checks(self, components)
                    -_find_complementary_findings(self, components)
- _identify_conflicts(self, components)
- _aggregate_confidence_scores(self, components)
                    -_synthesize_recommendations(self, components)
                    -_calculate_correlation_matrix(self, components)
- _find_significant_correlations(self, correlation_matrix)
- _identify_causal_relationships(self, correlations)
                    -_build_dependency_graph(self, correlations)
- _analyze_temporal_correlations(self, components)
                    -_calculate_statistical_measures(self, components)
- Lambda functions:
  - Line 1107: lambda x: libraries[x]
  - Line 2411: lambda x: component_priority.get(x, 999)
- standardize_r2_result(result, analysis_type, metadata)
- batch_standardize_results(results, standardizer)
- radare2_scripting.py                - R2ScriptingEngine (class)
- **init**(self, binary_path, radare2_path)
- execute_custom_analysis(self, script_commands)
- generate_license_analysis_script(self)
- generate_vulnerability_analysis_script(self)
- execute_license_analysis_workflow(self)
- execute_vulnerability_analysis_workflow(self)
- create_custom_r2_script(self, script_name, script_content)
- execute_r2_script_file(self, script_path)
- generate_function_analysis_script(self, function_name)
- analyze_specific_function(self, function_name)
- create_automated_patcher_script(self, patches)
- create_license_validator_script(self, validation_points)
                    -_generate_analysis_summary(self, command_results)
                    -_extract_license_functions(self, command_results)
                    -_extract_license_strings(self, command_results)
                    -_extract_license_imports(self, command_results)
                    -_extract_crypto_usage(self, command_results)
                    -_identify_validation_mechanisms(self, command_results)
                    -_find_bypass_opportunities(self, workflow_result)
                    -_calculate_analysis_confidence(self, workflow_result)
                    -_analyze_buffer_overflow_risks(self, command_results)
- _analyze_format_string_risks(self, command_results)
                    -_analyze_memory_corruption_risks(self, command_results)
- _analyze_injection_risks(self, command_results)
- _analyze_privilege_escalation_risks(self, command_results)
                    -_analyze_network_security_risks(self, command_results)
- _calculate_risk_score(self, workflow_result)
- _generate_security_recommendations(self, workflow_result)
- _parse_function_info(self, function_info_output)
                    -_generate_function_insights(self, function_result)
- execute_license_analysis_script(binary_path, radare2_path)
- execute_vulnerability_analysis_script(binary_path, radare2_path)        - core/anti_analysis/
- sandbox_detector.py
- SandboxDetector (class)
            - **init**(self)
            - detect_sandbox(self)
            - generate_sandbox_evasion(self, detected_methods)
            - get_aggressive_methods(self)
            - get_detection_type(self)
            - _check_environment(self)
            - _check_behavioral(self)
            - _check_resource_limits(self)
            - _check_network(self)
            - _check_user_interaction(self)
            - _check_file_system_artifacts(self)
            - _check_process_monitoring(self)
            - _check_time_acceleration(self)
            - _check_api_hooks(self)
            - _check_mouse_movement(self)
            - _get_system_uptime(self)
            - _ip_in_network(self, ip, network)
            - _identify_sandbox_type(self, detection_details)
            - _calculate_evasion_difficulty(self, detected_methods)
            - Nested classes in _check_mouse_movement():
  - MockPOINT (class) - Mock POINT structure for Windows API
  - MockWintypes (class) - Mock wintypes implementation
    - POINT (nested class) - Mock POINT structure definition
- timing_attacks.py                - TimingAttackDefense (class)
- **init**(self)
- secure_sleep(self, duration)
- stalling_code(self, min_duration, max_duration)
- time_bomb(self, trigger_time, action)
- execution_delay(self, check_environment)
- rdtsc_timing_check(self)
- anti_acceleration_loop(self)
- generate_timing_defense_code(self, language)
- _check_rdtsc_availability(self)
                    -_get_tick_count(self)
- _quick_debugger_check(self)
- Nested functions:
  - time_bomb_thread() (nested in time_bomb method)        - ai/
- ai_script_generator.py
- ProtectionType (enum)
- ScriptMetadata (dataclass)
- GeneratedScript (class)
- ScriptGenerationResult (class)
- ScriptValidator (class)
            - **init**(self)
            - validate_script(self, script_content, script_type)
            - _validate_frida_script(self, script_content)
            - _validate_ghidra_script(self, script_content)
            - _validate_syntax(self, script_content, language)
- ScriptTemplateEngine (class)
            - **init**(self)
            - render_frida_script(self, protection_types, hooks, bypass_logic, helper_functions)
            - render_ghidra_script(self, protection_types, analysis_functions, patching_logic)
- PatternLibrary (class)
            - **init**(self)
            - get_bypass_strategy(self, protection_type)
- AIScriptGenerator (class)
            - **init**(self)
            - generate_frida_script(self, binary_path, protection_info, output_format)
            - generate_ghidra_script(self, binary_path, protection_info, script_type)
            - save_script(self, generated_script, output_dir)
            - optimize_context_for_llm(self, analysis_data, target_protections)
            - estimate_context_tokens(self, context_data)
            - compress_context_if_needed(self, analysis_data, target_protections)
            - refine_script(self, original_script, test_results, analysis_data)
            - _generate_frida_script_internal(self, analysis_results)
            - _create_frida_generation_prompt(self, protection_types, context_data)
            - _extract_hook_info_from_content(self, script_content)
            - _generate_ghidra_script_internal(self, analysis_results)
            - _create_ghidra_generation_prompt(self, protection_types, context_data)
            - _extract_entry_point_from_content(self, script_content)
            - _extract_patch_info_from_content(self, script_content)
            - _identify_protections(self, analysis_results)
            - _generate_hooks(self, analysis_results, protection_types)
            - _generate_bypass_logic(self, protection_types)
            - _generate_helper_functions(self, protection_types)
            - _generate_analysis_functions(self, analysis_results)
            - _generate_patching_logic(self, analysis_results, protection_types)
            - _generate_initialization_code(self)
            - _generate_ghidra_initialization(self)
            - _generate_script_id(self, target_binary, script_type)
            - _calculate_success_probability(self, protection_types, confidence_scores)
            - _extract_hook_info(self, hooks_code)
            - _extract_patch_info(self, patch_code)
            - _is_protection_related(self, name)
            - _is_license_string(self, string_val)
            - _generate_recommendations(self, generated_script)
            - _generate_documentation(self, generated_script, protection_types)
            - _format_hooks_documentation(self, hooks)
            - _format_patches_documentation(self, patches)
            - _get_template_for_protections(self, protection_types)
            - _extract_hooks_from_script(self, script_content)
            - _extract_entry_point(self, script_content)
            - _generate_license_bypass_frida(self, binary_path, protection_info)
            - _generate_trial_bypass_frida(self, binary_path, protection_info)
            - _generate_hardware_bypass_frida(self, binary_path, protection_info)
            - _generate_antitamper_bypass_frida(self, binary_path, protection_info)
            - _generate_generic_bypass_frida(self, binary_path, protection_info)
            - Nested functions:
  - detect_pattern() (nested in_identify_protections method)### background_loader.py Updates
- No private methods found
- MultiCallback nested class (already documented)
- No lambda functions found

## enhanced_training_interface.py### Private Methods
- _apply_button_icons() (line 1062)

### Nested Functions
- create_colored_pixmap() in _apply_button_icons (line 1065)

### Lambda Functions
- lambda v: self.train_split_label.setText(f"Train Split: {v}%") (line 545)
- lambda x: x['accuracy'] (line 931)
- lambda v: self.validation_split_spin.setValue(v / 100.0) (line 1157)
- lambda v: self.validation_split_slider.setValue(int(v * 100)) (line 1160)

## exploitation_orchestrator.py### Private Methods (43 total)
- _init_exploitation_components() (line 69)
- _execute_intelligence_phase() (line 265)
- _get_ai_strategic_insights() (line 354)
- _execute_payload_phase() (line 394)
- _execute_c2_phase() (line 551)
- _execute_exploitation_phase() (line 623)
- _execute_post_exploitation_phase() (line 719)
- _execute_learning_phase() (line 879)
- _calculate_campaign_metrics() (line 936)
- _update_global_metrics() (line 968)
- _deploy_remote_payload() (line 1009)
- _deploy_local_payload() (line 1075)
- _deploy_binary_payload() (line 1130)
- _prepare_binary_execution() (line 1203)
- _embed_c2_config() (line 1226)
- _wait_for_c2_callback() (line 1258)
- _establish_session() (line 1303)
- _verify_access() (line 1335)
- _extract_bad_chars() (line 1399)
- _determine_bypass_techniques() (line 1418)
- _select_exploit_method() (line 1438)
- _check_protection() (line 1462)
- _select_c2_protocol() (line 1480)
- _select_c2_port() (line 1501)
- _select_c2_interface() (line 1525)
- _select_encryption_method() (line 1541)
- _calculate_max_sessions() (line 1558)
- _calculate_session_timeout() (line 1573)
- _calculate_beacon_interval() (line 1585)
- _calculate_jitter() (line 1603)
- _should_use_domain_fronting() (line 1612)
- _get_proxy_settings() (line 1621)
- _generate_user_agent() (line 1637)
- _generate_callback_urls() (line 1649)
- _determine_payload_path() (line 1667)
- _determine_stealth_level() (line 1756)
- _select_persistence_methods() (line 1796)
- _select_escalation_technique() (line 1815)
- _get_escalation_options() (line 1832)
- _determine_collection_targets() (line 1841)
- _collect_file_data() (line 1883)
- _collect_registry_data() (line 1905)
- _collect_memory_data() (line 1927)

### Lambda Functions
- lambda x: x.get (line 331)

## llm_backends.py### Private Methods (3 total)
- _messages_to_prompt() in LlamaCppBackend (line 461)
- _extract_tool_calls() in LlamaCppBackend (line 479)
- _get_backend_class() in LLMManager (line 1978)

### Nested Classes
- None found

### Lambda Functions
- None found

## llm_config_manager.py### Private Methods (4 total)
- _load_all_configs() (line 63)
- _load_json_file() (line 77)
- _save_json_file() (line 89)
- _get_default_profiles() (line 113)
- _update_aggregate_metrics() (line 389)

### Nested Classes
- None found

### Lambda Functions
- None found

## local_gguf_server.py### Private Methods (8 total)
- _detect_intel_gpu() (line 117)
- _get_optimal_threads() (line 207)
- _setup_routes() (line 383)
- _messages_to_prompt() (line 530)
- _complete_response() (line 548)
- _stream_response() (line 589)
- _run_server() (line 638)
- _test_server() (line 651)

### Nested Functions (in _setup_routes)
- health() (line 387)
- list_models() (line 400)
- gpu_info() (line 408)
- chat_completions() (line 433)
- completions() (line 464)
- load_model_endpoint() (line 492)
- unload_model_endpoint() (line 521)
- generate() in _stream_response (line 593)

### Lambda Functions
- None found

## predictive_intelligence.py### Private Methods (15 total)
- _calculate_operation_complexity() in ExploitSuccessPredictor (line 154)
- _calculate_input_size() in ExploitSuccessPredictor (line 180)
- _get_historical_performance() in ExploitSuccessPredictor (line 195)
- _extract_system_features() in ExploitSuccessPredictor (line 231)
- _extract_time_features() in ExploitSuccessPredictor (line 280)
- _initialize_model() in SuccessLLMPredictor (line 533)
- _generate_success_reasoning() in SuccessLLMPredictor (line 630)
- _get_important_factors() in SuccessLLMPredictor (line 659)
- _initialize_model() in TimeLLMPredictor (line 692)
- _get_time_factors() in TimeLLMPredictor (line 783)
- _initialize_model() in VulnerabilityLLMPredictor (line 811)
- _generate_vuln_reasoning() in VulnerabilityLLMPredictor (line 909)
- _generate_cache_key() in PredictiveIntelligenceEngine (line 1051)
- _get_confidence_distribution() in PredictiveIntelligenceEngine (line 1163)
- _get_prediction_type_distribution() in PredictiveIntelligenceEngine (line 1170)

### Lambda Functions
- lambda x: x[1] (line 670)

## qemu_test_manager.py### Private Methods (28 total)
- _init_ssh_keys() (line 209)
- _find_qemu_executable() (line 287)
- _get_ssh_connection() (line 304)
- _inject_ssh_key() (line 381)
- _is_circuit_open() (line 399)
- _record_connection_failure() (line 419)
- _reset_circuit_breaker() (line 436)
- _close_ssh_connection() (line 445)
- _start_vm_for_snapshot() (line 506)
- _wait_for_vm_ready() (line 560)
- _upload_file_to_vm() (line 588)
- _upload_binary_to_vm() (line 619)
- _execute_command_in_vm() (line 652)
- _analyze_frida_output() (line 699)
- _analyze_ghidra_output() (line 737)
- _stop_vm_for_snapshot() (line 848)
- _get_windows_base_image() (line 914)
- _get_linux_base_image() (line 963)
- _detect_os_type() (line 1015)
- _create_minimal_test_image() (line 1086)
- _copy_base_image() (line 1126)
- _start_vm() (line 1163)
- _execute_in_vm_real() (line 1366)
- _determine_snapshot_relationship() (line 1539)
- _test_generic_script() (line 1817)
- _verify_all_snapshot_integrity() (line 2361)

### Lambda Functions
- lambda x: x[0] (line 2112)

## Exploitation Modules

## lateral_movement.py### Private Methods (60 total)
- _ping_sweep() (line 446)
- _port_scan() (line 476)
- _arp_scan() (line 527)
- _dns_enumeration() (line 632)
- _netbios_scan() (line 654)
- _smb_enumeration() (line 687)
- _ldap_enumeration() (line 719)
- _snmp_enumeration() (line 752)
- _detect_target_os() (line 786, 6193)
- _select_movement_techniques() (line 802)
- _execute_movement_technique() (line 832)
- _windows_psexec() (line 848)
- _windows_wmi_exec() (line 896)
- _windows_winrm() (line 940)
- _linux_ssh() (line 988)
- _linux_ssh_key() (line 1041)
- _windows_rdp() (line 1088)
- _windows_smb_relay() (line 1162)
- _windows_dcom() (line 1254)
- _windows_scheduled_task_remote() (line 1359)
- _windows_service_creation() (line 1520)
- _windows_powershell_remoting() (line 1620)
- _windows_pass_the_hash() (line 1711)
- _find_mimikatz() (line 1864)
- _windows_pass_the_ticket() (line 1882)
- _find_rubeus() (line 2054)
- _windows_golden_ticket() (line 2071)
- _linux_nfs_mount() (line 2299)
- _linux_docker_api() (line 2488)
- _linux_ansible() (line 2690)
- _linux_salt_stack() (line 2877)
- _linux_puppet() (line 3050)
- _linux_chef() (line 3272)
- _linux_kubernetes() (line 3546)
- _linux_ssh_agent_hijacking() (line 3824)
- _linux_sudo_hijacking() (line 4000)
- _linux_cron_hijacking() (line 4253)
- _execute_ssh_command() (line 4542)
- _execute_winrm_command() (line 4581)
- _execute_psexec_command() (line 4616)
- _execute_generic_command() (line 4652)
- _execute_rdp_payload() (line 4661)
- _execute_smb_payload() (line 4760)
- _harvest_memory_credentials() (line 5002)
- _harvest_registry_credentials() (line 5206)
- _harvest_file_credentials() (line 5280)
- _harvest_browser_credentials() (line 5408)
- _generate_session_id() (line 5521)
- _check_rdp_availability() (line 5571)
- _attempt_rdp_connection() (line 5589)
- _check_smb_availability() (line 5686)
- _attempt_smb_connection() (line 5721)
- _check_winrm_availability() (line 5771)
- _prepare_powershell_payload() (line 5806)
- _execute_powershell_remote() (line 5846)
- _execute_real_powershell() (line 5912)
- _execute_real_winrs() (line 5982)
- _parse_powershell_output() (line 6056)

### Nested Classes
- Anonymous **init** in _linux_docker_api (line 2510)

### Lambda Functions
- None found

## payload_engine.py### Private Methods (28 total)
- _analyze_target_environment() (line 269)
- _generate_base_shellcode() (line 321)
- _substitute_template_variables() (line 345)
- _apply_encoding() (line 428)
- _add_anti_analysis() (line 442)
- _add_sandbox_detection() (line 482)
- _add_debugger_detection() (line 521)
- _add_vm_detection() (line 553)
- _generate_metadata() (line 583)
- _find_bad_characters() (line 608)
- _calculate_compatibility_score() (line 619)
- _generate_random_key() (line 644)
- _update_statistics() (line 649)
- _add_advanced_sandbox_detection() (line 686)
- _add_advanced_debugger_detection() (line 769)
- _add_advanced_vm_detection() (line 861)
- _add_api_obfuscation() (line 959)
- _add_timing_defenses() (line 1005)
- _deploy_via_network() (line 1098)
- _deploy_via_buffer_overflow() (line 1126)
- _inject_via_process_hollowing() (line 1133)
- _inject_via_generic_method() (line 1166)
- _deploy_via_format_string() (line 1575)
- _deploy_via_rce() (line 1584)
- _inject_via_dll_injection() (line 1598)
- _inject_via_reflective_dll() (line 1633)

### Lambda Functions
- None found

## privilege_escalation.py### Private Methods (110 total)
- _check_tools_on_init() (line 284)
- _check_tool_available() (line 304)
- _ensure_tool_available() (line 334)
- _is_linux() (line 480)
- _is_windows() (line 484)
- _get_current_privileges() (line 696)
- _check_known_exploits() (line 757)
- _check_token_privilege() (line 786)
- _check_uac_bypass_availability() (line 866)
- _generate_recommendations() (line 890)
- _windows_unquoted_service_path() (line 915)
- _windows_service_permissions() (line 968)
- _windows_registry_autoruns() (line 1018)
- _linux_sudo_misconfiguration() (line 1077)
- _linux_suid_binaries() (line 1138)
- _linux_kernel_exploit() (line 1194)
- _exploit_unquoted_service_path() (line 1249)
- _exploit_service_permissions() (line 1290)
- _exploit_registry_autoruns() (line 1320)
- _exploit_sudo_misconfiguration() (line 1356)
- _exploit_suid_binary() (line 1395)
- _exploit_kernel_vulnerability() (line 1437)
- _exploit_dirty_cow() (line 1461)
- _exploit_ebpf_verifier() (line 1659)
- _exploit_pwnkit() (line 1838)
- _generic_kernel_exploit() (line 2055)
- _exploit_dirty_pipe() (line 2089)
- _exploit_generic_template() (line 2226)
- _exploit_keyring_refcount() (line 2324)
- _exploit_double_fdput() (line 2328)
- _exploit_packet_set_ring() (line 2332)
- _exploit_memory_corruption() (line 2336)
- _exploit_ptrace_kmod() (line 2340)
- _exploit_cls_route() (line 2344)
- _exploit_nftables_uaf() (line 2348)
- _windows_dll_hijacking() (line 2354)
- _windows_token_impersonation() (line 2417)
- _windows_uac_bypass() (line 2467)
- _windows_kernel_exploit() (line 2519)
- _windows_scheduled_task_permissions() (line 2571)
- _windows_always_install_elevated() (line 2638)
- _windows_weak_file_permissions() (line 2720)
- _windows_service_binary_hijacking() (line 2785)
- _windows_com_hijacking() (line 2890)
- _linux_cron_permissions() (line 2942)
- _linux_weak_file_permissions() (line 3027)
- _linux_library_hijacking() (line 3117)
- _linux_capabilities() (line 3178)
- _linux_docker_socket() (line 3252)
- _linux_environment_variables() (line 3312)
- _linux_systemd_permissions() (line 3365)
- _linux_path_hijacking() (line 3424)
- _linux_nfs_weak_permissions() (line 3479)
- _get_windows_version() (line 3539)
- _get_linux_version() (line 3556)
- _is_exploit_applicable() (line 3569)
- _is_kernel_vulnerable() (line 3579)
- _attempt_dll_hijacking() (line 3633)
- _attempt_token_impersonation() (line 3735)
- _attempt_uac_bypass() (line 3844)
- _attempt_kernel_exploit() (line 3892)
- _get_exploit_path() (line 3975)
- _parse_privileges_from_output() (line 3996)
- _select_kernel_payload() (line 4014)
- _attempt_scheduled_task_exploit() (line 4024)
- _attempt_msi_exploit() (line 4104)
- _generate_malicious_msi() (line 4211)
- _attempt_file_overwrite() (line 4263)
- _generate_binary_payload() (line 4343)
- _determine_file_privs() (line 4354)
- _attempt_service_binary_hijack() (line 4362)
- _create_hijack_dll() (line 4523, 6536)
- _restart_service() (line 4562)
- _execute_real_exploit() (line 4605)
- _create_malicious_library() (line 4745)
- _attempt_com_hijack() (line 4789)
- _attempt_cron_exploit() (line 4909)
- _generate_cron_content() (line 5035)
- _attempt_linux_file_exploit() (line 5043)
- _generate_script_payload() (line 5190)
- _attempt_library_hijack() (line 5199)
- _attempt_capability_exploit() (line 5351)
- _attempt_docker_exploit() (line 5577)
- _build_docker_command() (line 5768)
- _attempt_env_var_exploit() (line 5778)
- _attempt_systemd_exploit() (line 5948)
- _attempt_path_hijack() (line 6167)
- _attempt_nfs_exploit() (line 6345)
- _get_dll_template() (line 6559)
- _create_minimal_dll_template() (line 6574)
- _check_dll_search_order_vulnerability() (line 6640)
- _check_useful_privileges() (line 6664)
- _attempt_token_duplication() (line 6689)
- _attempt_actual_impersonation() (line 6775)
- _check_token_abuse_techniques() (line 6802)
- _can_open_process() (line 6830)
- _uac_bypass_fodhelper() (line 6859)
- _uac_bypass_computerdefaults() (line 6951)
- _uac_bypass_sdclt() (line 6987)
- _uac_bypass_eventvwr() (line 7023)
- _uac_bypass_compmgmtlauncher() (line 7059)
- _uac_bypass_auto() (line 7095)
- _execute_dll_hijacking() (line 7236)
- _execute_process_hollowing() (line 7262)
- _execute_dll_injection() (line 7313)
- _execute_shellcode_injection() (line 7369)
- _execute_generic_exploit() (line 7432)

### Nested Classes
- Anonymous **init** in _attempt_token_duplication (line 6722)

### Lambda Functions
- lambda x: x.get('success_probability', 0) (line 897)

## UI Modules

## main_app.py### Private Methods (99 total)
- _fallback_integrate_with_intellicrack() (line 489)
- _fallback_register_hex_viewer_ai_tools() (line 529)
- _start_rop_analysis() (line 821)
- _start_protocol_fingerprinting() (line 1271)
- _start_cloud_license_hooking() (line 1544)
- _generate_ssl_certificates() (line 2277)
- _create_ssl_proxy_server() (line 2414)
- _check_intercepted_traffic() (line 2443)
- _perform_real_concolic_execution() (line 3657)
- _perform_real_cfg_analysis() (line 3911)
- _handle_connections() (line 7179)
- _handle_client() (line 7197)
- _capture_packets_thread() (line 10273)
- _update_packet_display() (line 10328)
- _get_ai_response() (line 14997)
- _get_fallback_response() (line 15096)
- _create_placeholder_image() (line 15510)
- _create_icon_pixmap() (line 15553)
- _on_binary_loaded() (line 17477)
- _on_analysis_completed() (line 17486)
- _on_task_started() (line 17494)
- _on_task_progress() (line 17498)
- _on_task_completed() (line 17504)
- _on_task_failed() (line 17508)
- _on_ai_task_complete() (line 18573)
- _on_coordinated_analysis_complete() (line 18591)
- _display_directory_analysis_results() (line 18762)
- _import_from_file() (line 19581)
- _generate_ai_response() (line 19661)
- _generate_fallback_response() (line 19697)
- _prepare_ai_context() (line 19727)
- _generate_enhanced_fallback_response() (line 19773)
- _import_from_api() (line 19834)
- _verify_model_thread() (line 20498)
- _populate_file_tree() (line 20743)
- _initialize_binary_info() (line 21613)
- _extract_pe_info() (line 21640)
- _extract_pe_architecture() (line 21664)
- _extract_pe_metadata() (line 21683)
- _extract_pe_sections_and_imports() (line 21697)
- _detect_pe_protections() (line 21716)
- _extract_elf_info() (line 21752)
- _extract_elf_architecture() (line 21772)
- _extract_elf_metadata() (line 21791)
- _extract_elf_sections_and_symbols() (line 21809)
- _update_dashboard_with_binary_info() (line 21827)
- _refresh_and_show_dashboard() (line 21870)
- _log_analysis_completion() (line 21927)
- _run_analysis_thread() (line 21983)
- _run_deep_license_analysis_thread() (line 22375)
- _run_deep_runtime_monitoring_thread() (line 22466)
- _run_autonomous_patching_thread() (line 22497)
- _preview_patch_thread() (line 22539)
- _extract_patterns_from_pe() (line 22991)
- _extract_patterns_from_elf() (line 23198)
- _extract_patterns_from_macho() (line 23260)
- _generate_generic_patterns() (line 23266)
- _run_full_autonomous_mode_thread() (line 23457)
- _refresh_performance_stats() (line 23922)
- _clear_ai_cache_from_stats() (line 23950)
- _run_detect_packing_thread() (line 24004)
- _run_simulate_patch_thread() (line 24050)
- _run_tpm_bypass_thread() (line 24089)
- _run_vm_bypass_thread() (line 24135)
- _run_vm_detection_thread() (line 24181)
- _run_anti_debug_detection_thread() (line 24233)
- _run_tpm_detection_thread() (line 24298)
- _run_dongle_detection_thread() (line 24341)
- _run_checksum_detection_thread() (line 24423)
- _run_self_healing_detection_thread() (line 24472)
- _run_commercial_protection_thread() (line 24519)
- _run_commercial_protection_scan_thread() (line 24577)
- _run_external_command_thread() (line 24672)
- _run_model_inference_thread() (line 24802)
- _format_tool_result() (line 25154)
- _generate_html_report() (line 26494)
- _generate_pdf_report() (line 26653)
- _generate_text_report() (line 26718)
- _open_text_report_viewer() (line 26792)
- _generate_memory_report_section() (line 26899)
- _generate_network_report_section() (line 27006)
- _generate_patching_report_section() (line 27154)
- _generate_general_report_section() (line 27228)
- _format_memory_analysis_for_text() (line 27336)
- _format_network_analysis_for_text() (line 27384)
- _format_patching_results_for_text() (line 27453)
- _run_full_automated_exploitation_impl() (line 27838)

### Nested Classes/Functions
- **getattr** in FallbackGhidraIntegration (line 166)
- **call** in **getattr** (line 170)
- Anonymous **init** (lines 321, 327, 7145, 9802, 9833, 9945, 10434, 12633, 16463, 20037)

### Lambda Functions
- lambda n: int(n['address'], 16) (line 4171)
- lambda x: x['total_memory_mb'] (line 6097)
- lambda text: self.filter_plugin_list(frida_list, text) (line 13222)
- lambda text: self.filter_plugin_list(ghidra_list, text) (line 13275)
- lambda text: self.filter_plugin_list(custom_list, text) (line 13328)
- lambda value: self.scale_value_label.setText(f"{value}%") (line 15699)
- lambda msg: self.update_output.emit(log_message(msg)) (line 22503, 25606)
- lambda x: x.get("offset", 0) (line 22987)
- lambda x: x[1] (lines 25701, 25709, 27061, 27422)

## exploitation_handlers.py### Private Methods (1 total)
- _get_preferred_local_ip() (line 960)

### Lambda Functions
- None found

# Summary of All Private Methods, Nested Classes, and Lambda Functions

## Total Count Summary
- **Private Methods**: 421+ found across all modules
- **Nested Classes/Functions**: 45+ found
- **Lambda Functions**: 25+ found

## Key Patterns Observed
1. Heavy use of private methods for internal implementation details
2. Nested classes primarily used for callbacks and internal data structures
3. Lambda functions mostly used for sorting and UI event handling
4. Consistent naming conventions with underscore prefix for private methods

## Most Complex Modules (by private method count)
1. privilege_escalation.py (110 private methods)
2. main_app.py (99 private methods)
3. lateral_movement.py (60 private methods)
4. exploitation_orchestrator.py (43 private methods)
5. radare2_json_standardizer.py (139 private methods)

This completes the comprehensive mapping of all private methods, nested classes, exception classes, and lambda functions in the Intellicrack project structure.

## Additional Elements Found

### @property decorators
- concolic_executor_fixed.py: 1 property
- firmware_analyzer.py: 8 properties
- memory_forensics_engine.py: 2 properties
- yara_pattern_engine.py: 5 properties

### @staticmethod decorators
- vulnerability_engine.py: 5 static methods
- frida_bypass_wizard.py: 2 static methods
- bypass_config.py: 5 static methods
- tool_discovery.py: 5 static methods

### @classmethod decorators
- firmware_analyzer.py: 1 class method
- vulnerability_engine.py: 3 class methods
- payload_templates.py: 1 class method

### Dataclasses
- Multiple dataclasses found (LLMConfig, LLMMessage, LLMResponse, etc.)
