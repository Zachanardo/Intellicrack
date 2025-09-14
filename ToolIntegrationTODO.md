# Intellicrack Tool Integration TODO List

## Verification Status
Last Verified: 2024-01-13
Verification Method: Direct code inspection using Serena tools

## PHASE 1: GHIDRA INTEGRATION TASKS

### 1.1 Ghidra Output Parser Implementation
- [x] Open file: `intellicrack/core/analysis/ghidra_analyzer.py`
- [x] Navigate to line 46 (comment: "In a real implementation, you would parse Ghidra's output here")
- [x] Create new class `GhidraOutputParser` in same file
- [x] Implement method `parse_functions(self, stdout_text: str) -> List[Dict]`
  - [x] Parse function names using regex pattern `Function: (\w+) @ (0x[0-9a-fA-F]+)`
  - [x] Extract function address as integer
  - [x] Extract function size if available
  - [x] Return list of dicts with keys: name, address, size
- [x] Implement method `parse_strings(self, stdout_text: str) -> List[Dict]`
  - [x] Parse string literals from Ghidra output
  - [x] Extract string address
  - [x] Extract string value
  - [x] Return list of dicts with keys: value, address, length
- [x] Implement method `parse_imports(self, stdout_text: str) -> List[Dict]`
  - [x] Parse import table entries
  - [x] Extract DLL/library names
  - [x] Extract imported function names
  - [x] Return list of dicts with keys: library, function, address
- [x] Implement method `parse_cross_references(self, stdout_text: str) -> List[Dict]`
  - [x] Parse xref information
  - [x] Extract source address
  - [x] Extract destination address
  - [x] Extract reference type (call, jump, data)
  - [x] Return list of dicts with keys: from_addr, to_addr, ref_type
- [x] Replace line 46 comment with actual parser instantiation
- [x] Call parser methods on process.stdout
- [x] Store parsed results in structured format

### 1.2 Ghidra Results Storage
- [x] Create new file: `intellicrack/core/analysis/ghidra_results.py`
- [x] Define dataclass `GhidraAnalysisResult`
  - [x] Add field: functions: List[Dict]
  - [x] Add field: strings: List[Dict]
  - [x] Add field: imports: List[Dict]
  - [x] Add field: cross_references: List[Dict]
  - [x] Add field: timestamp: datetime
  - [x] Add field: binary_path: str
- [x] Modify `run_advanced_ghidra_analysis` to return GhidraAnalysisResult
- [x] Update all callers of `run_advanced_ghidra_analysis` to handle return value

### 1.3 Ghidra GUI Integration
- [ ] Open file: `intellicrack/ui/dialogs/ghidra_script_selector.py`
- [ ] Add new QTableWidget for displaying parsed results
- [ ] Add columns: Type, Name, Address, Details
- [ ] Connect to GhidraAnalysisResult data
- [ ] Implement double-click handler to navigate to address

## PHASE 2: FRIDA INTEGRATION TASKS

### 2.1 Memory Operations GUI
- [ ] Open file: `intellicrack/ui/dialogs/frida_manager_dialog.py`
- [ ] Navigate to line 420 (create_scripts_tab method)
- [ ] Add new QGroupBox "Memory Operations"
- [ ] Add QPushButton "Read Memory"
  - [ ] Connect to new method `read_memory_dialog()`
  - [ ] Create QDialog with address and size inputs
  - [ ] Call FridaManager._handle_memory_dump on OK
  - [ ] Display results in hex viewer widget
- [ ] Add QPushButton "Write Memory"
  - [ ] Connect to new method `write_memory_dialog()`
  - [ ] Create QDialog with address and data inputs
  - [ ] Implement memory write via Frida script injection
- [ ] Add QPushButton "Search Memory"
  - [ ] Connect to new method `search_memory_dialog()`
  - [ ] Create QDialog with pattern input
  - [ ] Implement memory search via Frida script
  - [ ] Display found addresses in table

### 2.2 Hook Effectiveness Monitoring Integration
- [x] Open file: `intellicrack/scripts/frida/hook_effectiveness_monitor.js`
- [x] Verify script exports effectiveness metrics
- [x] Open file: `intellicrack/ui/dialogs/frida_manager_dialog.py`
- [x] Navigate to line 528 (Active Hooks tree section)
- [x] Add new column "Effectiveness %" to hooks_tree
- [x] Add method `load_effectiveness_monitor()`
  - [x] Load hook_effectiveness_monitor.js script
  - [x] Parse effectiveness data from script messages
  - [x] Update hooks_tree with effectiveness percentages
- [x] Add QTimer to refresh effectiveness every 2 seconds
- [x] Add effectiveness threshold slider (0-100%)
- [x] Highlight ineffective hooks (below threshold) in red

### 2.3 Script Result Persistence
- [x] Open file: `intellicrack/core/frida_manager.py`
- [x] Navigate to line 2412 (export_analysis method)
- [x] Modify to include script outputs
- [x] Create new directory structure: `project_dir/frida_results/`
- [x] Add method `save_script_output(self, script_name: str, output: str)`
  - [x] Generate timestamp filename
  - [x] Write output to JSON file
  - [x] Include metadata: pid, process_name, script_name, timestamp
- [x] Modify _on_script_message to call save_script_output
- [x] Add method `load_previous_results(self, script_name: str) -> List[Dict]`
  - [x] Read all result files for given script
  - [x] Return sorted by timestamp

## PHASE 3: RADARE2 INTEGRATION TASKS

### 3.1 Binary Diff Implementation
- [ ] Open file: `intellicrack/core/analysis/radare2_enhanced_integration.py`
- [ ] Navigate to line 135 (Binary diff set to None)
- [ ] Import radare2_binary_diff module
- [ ] Replace None with instantiation: `BinaryDiff(self.r2_primary, self.r2_secondary)`
- [ ] Add method `set_secondary_binary(self, binary_path: str)`
  - [ ] Open secondary r2 instance
  - [ ] Store as self.r2_secondary
  - [ ] Initialize diff component
- [ ] Add method `get_function_diffs(self) -> List[Dict]`
  - [ ] Compare functions between binaries
  - [ ] Return list of added/removed/modified functions
- [ ] Add method `get_basic_block_diffs(self, function_name: str) -> List[Dict]`
  - [ ] Compare basic blocks within function
  - [ ] Return block-level differences

### 3.2 Radare2 Performance Metrics Display
- [ ] Open file: `intellicrack/ui/radare2_integration_ui.py`
- [ ] Add new QGroupBox "Performance Metrics"
- [ ] Add QLabel for "Analysis Speed: X functions/sec"
- [ ] Add QLabel for "Memory Usage: X MB"
- [ ] Add QLabel for "Cache Hit Rate: X%"
- [ ] Open file: `intellicrack/core/analysis/radare2_realtime_analyzer.py`
- [ ] Locate performance monitoring methods
- [ ] Add signal emission for performance updates
- [ ] Connect signals to UI labels
- [ ] Add QTimer to refresh every 1 second

### 3.3 Radare2 Graph View Integration
- [ ] Open file: `intellicrack/ui/cfg_explorer_inner.py`
- [ ] Verify CFG visualization exists
- [ ] Open file: `intellicrack/ui/main_app.py`
- [ ] Add menu item "View -> Function Graph"
- [ ] Connect to method `show_function_graph()`
- [ ] Create new QDockWidget for graph display
- [ ] Embed cfg_explorer_inner widget
- [ ] Connect to radare2 analysis results

## PHASE 4: CROSS-TOOL INTEGRATION TASKS

### 4.1 Create DataNormalizer Class
- [ ] Create new file: `intellicrack/core/data_normalizer.py`
- [ ] Define base class `DataNormalizer`
- [ ] Add method `normalize_function(self, tool: str, raw_data: Dict) -> Dict`
  - [ ] Define standard schema: {name, address, size, type, tool_source}
  - [ ] Handle Ghidra function format
  - [ ] Handle Frida function format
  - [ ] Handle Radare2 function format
- [ ] Add method `normalize_string(self, tool: str, raw_data: Dict) -> Dict`
  - [ ] Define standard schema: {value, address, encoding, length, tool_source}
  - [ ] Handle all three tool formats
- [ ] Add method `normalize_import(self, tool: str, raw_data: Dict) -> Dict`
  - [ ] Define standard schema: {library, function, address, tool_source}
  - [ ] Handle all three tool formats
- [ ] Write unit tests for each normalization method

### 4.2 Connect EventBus to Orchestrator
- [ ] Open file: `intellicrack/plugins/custom_modules/intellicrack_core_engine.py`
- [ ] Navigate to line 1525 (EventBus class)
- [ ] Open file: `intellicrack/core/analysis/analysis_orchestrator.py`
- [ ] Import EventBus from intellicrack_core_engine
- [ ] Add EventBus instance to AnalysisOrchestrator.__init__
- [ ] Add method `publish_analysis_event(self, event_type: str, data: Dict)`
- [ ] Add method `subscribe_to_events(self, event_type: str, callback: Callable)`
- [ ] Modify all tool analyzers to publish events via orchestrator

### 4.3 Decouple GUI from Direct Tool Calls
- [ ] Open file: `intellicrack/ui/main_app.py`
- [ ] Search for all direct calls to ghidra_analyzer
- [ ] Replace with orchestrator.submit_analysis("ghidra", config)
- [ ] Search for all direct calls to frida_analyzer
- [ ] Replace with orchestrator.submit_analysis("frida", config)
- [ ] Search for all direct calls to radare2 analyzers
- [ ] Replace with orchestrator.submit_analysis("radare2", config)
- [ ] Update all callbacks to handle normalized data

## PHASE 5: REAL-TIME DASHBOARD

### 5.1 Create Dashboard Widget
- [ ] Create new file: `intellicrack/ui/widgets/analysis_dashboard.py`
- [ ] Create class `AnalysisDashboard(QWidget)`
- [ ] Add grid layout with 4 sections
- [ ] Section 1: Tool Status (Ghidra/Frida/Radare2)
  - [ ] Add status indicator (idle/running/error)
  - [ ] Add current operation label
  - [ ] Add progress bar
- [ ] Section 2: Performance Metrics
  - [ ] Add CPU usage gauge
  - [ ] Add memory usage gauge
  - [ ] Add analysis speed label
- [ ] Section 3: Recent Findings
  - [ ] Add scrollable list of last 10 findings
  - [ ] Include timestamp and tool source
- [ ] Section 4: Statistics
  - [ ] Add total functions found
  - [ ] Add total strings found
  - [ ] Add total protections detected

### 5.2 Wire Dashboard to Main Window
- [ ] Open file: `intellicrack/ui/main_app.py`
- [ ] Import AnalysisDashboard
- [ ] Add as new tab or dock widget
- [ ] Connect to orchestrator events
- [ ] Update dashboard on each analysis event

## PHASE 6: TESTING AND VALIDATION

### 6.1 Integration Tests
- [ ] Create file: `tests/integration/test_tool_orchestration.py`
- [ ] Write test: test_ghidra_output_parsing()
- [ ] Write test: test_frida_memory_operations()
- [ ] Write test: test_radare2_binary_diff()
- [ ] Write test: test_cross_tool_correlation()
- [ ] Write test: test_event_bus_communication()
- [ ] Write test: test_data_normalization()

### 6.2 Performance Tests
- [ ] Create file: `tests/performance/test_analysis_speed.py`
- [ ] Measure orchestrator overhead
- [ ] Measure event bus latency
- [ ] Measure GUI update speed
- [ ] Ensure < 100ms latency requirement

## COMPLETION METRICS

Total Tasks: 118
- Ghidra Integration: 16 tasks **[COMPLETED: Phase 1.1 (16 items) + Phase 1.2 (8 items) = 24 tasks done]**
- Frida Integration: 20 tasks
- Radare2 Integration: 18 tasks
- Cross-tool Integration: 22 tasks
- Dashboard: 16 tasks
- Testing: 10 tasks
- Remaining setup: 16 tasks

**Progress Update (2025-09-13):**
- ✅ Phase 1.1: Ghidra Output Parser Implementation - COMPLETE
- ✅ Phase 1.2: Ghidra Results Storage - COMPLETE
- ⏳ Phase 1.3: Ghidra GUI Integration - IN PROGRESS

Estimated Time: 5-6 weeks (based on verified existing components)

## NOTES

- All line numbers have been verified as of 2024-01-13
- EventBus exists at intellicrack_core_engine.py:1525
- AnalysisOrchestrator exists at analysis_orchestrator.py:67
- FridaManager memory operations exist at lines 1823, 2330
- Hook effectiveness script exists at scripts/frida/hook_effectiveness_monitor.js
- Binary diff None assignment at radare2_enhanced_integration.py:135