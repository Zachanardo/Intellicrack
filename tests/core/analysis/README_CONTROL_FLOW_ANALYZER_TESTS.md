# Control Flow Analyzer Production Tests

## Overview

This test suite validates **REAL** control flow analysis capabilities on actual PE binaries. Every test validates genuine CFG construction, basic block extraction, dispatcher detection, and control flow deobfuscation.

**Test File:** `test_control_flow_analyzer_production.py`

**Module Under Test:** `intellicrack.core.analysis.control_flow_deobfuscation`

## Test Philosophy

### Zero Tolerance for Fake Tests

- **NO MOCKS** - All tests use real binary analysis operations
- **NO STUBS** - Every test validates actual CFG extraction from binaries
- **NO SIMULATIONS** - Tests work on real PE files with actual control flow structures
- **PRODUCTION-READY** - All code uses complete type annotations and follows PEP 8

### Test Validation Requirements

- Tests **MUST FAIL** when CFG analysis is broken
- Tests **MUST PASS** when control flow is correctly analyzed
- Tests validate actual basic blocks, edges, and control flow patterns
- All fixtures create real PE binaries with authentic x64 code

## Test Categories (40+ Tests)

### 1. Initialization Tests (4 tests)

**Purpose:** Validate ControlFlowDeobfuscator initialization and setup

**Key Tests:**

- `test_initialization_with_valid_binary` - Initializes with real PE binary
- `test_initialization_with_nonexistent_binary_fails` - Fails gracefully for missing files
- `test_initialization_detects_architecture` - Correctly identifies x86_64 architecture
- `test_initialization_with_custom_radare2_path` - Accepts custom radare2 paths

**What This Proves:**

- Binary parsing works with LIEF
- Architecture detection is accurate
- Capstone disassembler initializes correctly
- Error handling for invalid inputs

### 2. Basic Block Extraction Tests (5 tests)

**Purpose:** Validate extraction of basic blocks from binary code

**Key Tests:**

- `test_extract_basic_blocks_from_simple_function` - Extracts blocks with valid metadata
- `test_basic_block_contains_instructions` - Blocks contain actual disassembly
- `test_basic_block_has_correct_type_classification` - Blocks classified as return/call/branch/sequential
- `test_basic_block_successor_relationships` - Successor edges are valid
- `test_basic_block_predecessor_relationships` - Predecessor edges are valid

**What This Proves:**

- Radare2 integration extracts real basic blocks
- Each block has address, size, instructions, successors, predecessors
- Block classification (return/call/branch/sequential) works correctly
- CFG edge relationships are maintained correctly

### 3. Control Flow Graph Construction Tests (5 tests)

**Purpose:** Validate CFG construction with nodes and edges

**Key Tests:**

- `test_cfg_has_nodes_and_edges` - CFG contains nodes and edges
- `test_cfg_edges_have_types` - Edges labeled with types (conditional_true/false, fallthrough)
- `test_cfg_is_directed_graph` - CFG is directed with forward control flow
- `test_cfg_entry_block_identification` - Entry block (0 in-degree) identified
- `test_cfg_exit_block_identification` - Exit blocks (return/0 out-degree) identified

**What This Proves:**

- NetworkX graphs constructed correctly from binary analysis
- Control flow edges properly typed and directed
- Entry and exit points correctly identified
- Graph structure matches actual binary control flow

### 4. Branch Condition Analysis Tests (4 tests)

**Purpose:** Validate detection and analysis of conditional branches

**Key Tests:**

- `test_detect_conditional_branches` - Identifies branch blocks
- `test_branch_block_has_multiple_successors` - Branch blocks have >=2 successors
- `test_identify_true_false_branch_edges` - True/false branches distinguished
- `test_branch_complexity_calculation` - Complexity scores calculated

**What This Proves:**

- Conditional jump instructions detected
- Branch target identification works
- True/false branch differentiation
- Complexity metrics calculated correctly

### 5. Dispatcher Detection Tests (5 tests)

**Purpose:** Validate detection of control flow flattening dispatchers

**Key Tests:**

- `test_detect_control_flow_dispatcher` - Detects dispatcher blocks in flattened code
- `test_dispatcher_has_high_out_degree` - Dispatchers have many successors (>=3)
- `test_identify_state_variable_in_dispatcher` - State variable location/type identified
- `test_extract_controlled_blocks_from_dispatcher` - Blocks controlled by dispatcher extracted
- `test_extract_switch_case_mappings` - Case value to block mappings extracted

**What This Proves:**

- Control flow flattening detection works (OLLVM, Tigress, VMProtect patterns)
- Dispatcher blocks identified by high out-degree and switch patterns
- State variables (stack/global/register) correctly identified
- Controlled block analysis extracts switch case mappings

### 6. Opaque Predicate Detection Tests (4 tests)

**Purpose:** Validate detection of opaque predicates (always true/false conditions)

**Key Tests:**

- `test_detect_opaque_predicates` - Detects opaque predicates in code
- `test_opaque_predicate_self_comparison_detection` - Detects x==x patterns
- `test_opaque_predicate_has_dead_branch_info` - Identifies dead branches
- `test_opaque_predicate_confidence_scoring` - Confidence scores (0.0-1.0) calculated

**What This Proves:**

- Opaque predicates detected (self-comparison, invariant tests)
- Dead branch identification works
- Confidence scoring reflects detection certainty
- Analysis methods (symbolic, heuristic) applied correctly

### 7. Loop Detection Tests (2 tests)

**Purpose:** Validate loop (cycle) detection in CFG

**Key Tests:**

- `test_detect_loops_in_cfg` - Detects cycles in control flow graph
- `test_loop_back_edges_identification` - Identifies back-edges to loop headers

**What This Proves:**

- Cycle detection algorithms work on CFG
- Loop back-edges correctly identified
- Metrics track number of cycles

### 8. Function Call Graph Tests (1 test)

**Purpose:** Validate identification of function calls

**Key Tests:**

- `test_identify_function_calls_in_blocks` - Identifies call instructions in blocks

**What This Proves:**

- Call instruction detection in disassembly
- Call blocks correctly classified

### 9. Deobfuscation Results Tests (4 tests)

**Purpose:** Validate deobfuscation result generation and metrics

**Key Tests:**

- `test_deobfuscation_result_contains_all_fields` - Result has all required fields
- `test_deobfuscation_metrics_calculation` - Metrics (blocks/edges removed) calculated
- `test_confidence_score_calculation` - Confidence (0.0-1.0) calculated correctly
- `test_patch_information_generation` - Patch info generated for binary modification

**What This Proves:**

- DeobfuscationResult dataclass populated correctly
- Metrics accurately reflect CFG changes
- Confidence scoring considers dispatchers, opaque predicates, bogus blocks
- Patch information generated for NOP dispatchers and edge redirection

### 10. Control Flow Unflattening Tests (3 tests)

**Purpose:** Validate removal of control flow flattening

**Key Tests:**

- `test_unflatten_removes_dispatcher_blocks` - Dispatcher blocks removed from deobfuscated CFG
- `test_unflatten_recovers_original_edges` - Original control flow edges recovered
- `test_deobfuscated_cfg_simpler_than_original` - Deobfuscated CFG has lower complexity

**What This Proves:**

- Control flow unflattening removes dispatcher intermediaries
- Original control flow edges recovered from state variable analysis
- Complexity metrics show simplification

### 11. Dead Code Elimination Tests (2 tests)

**Purpose:** Validate unreachable block removal

**Key Tests:**

- `test_remove_unreachable_blocks` - Unreachable blocks removed from CFG
- `test_removed_blocks_count` - Metrics track removed block count

**What This Proves:**

- Dead code elimination removes unreachable blocks
- Bogus blocks (NOP sleds) detected and removed
- Metrics accurately track removed blocks

### 12. CFG Export Tests (1 test)

**Purpose:** Validate CFG export to DOT format

**Key Tests:**

- `test_export_deobfuscated_cfg_to_dot` - Exports CFG to GraphViz DOT format

**What This Proves:**

- CFG visualization export works
- DOT format generated correctly

### 13. Binary Patching Tests (2 tests)

**Purpose:** Validate patch information generation

**Key Tests:**

- `test_generate_patch_info_for_dispatcher_removal` - NOP patches for dispatchers
- `test_generate_patch_info_for_edge_redirection` - JMP patches for edge redirection

**What This Proves:**

- Patch information specifies addresses, types, sizes
- Dispatcher NOPing patches generated
- Edge redirection JMP patches generated

### 14. Windows System Binary Tests (2 tests)

**Purpose:** Validate analysis on real Windows binaries

**Key Tests:**

- `test_analyze_notepad_exe_cfg` - Analyzes notepad.exe control flow
- `test_analyze_calc_exe_cfg` - Analyzes calc.exe control flow

**What This Proves:**

- Real-world binary analysis works on Windows system files
- CFG extraction handles production binaries
- Skips gracefully if binaries not available

### 15. Edge Case Tests (4 tests)

**Purpose:** Validate error handling and edge cases

**Key Tests:**

- `test_analyze_function_with_no_branches` - Handles straight-line functions
- `test_analyze_function_with_single_block` - Handles single-block functions
- `test_analyze_invalid_function_address` - Fails gracefully for invalid addresses
- `test_empty_binary_handling` - Handles minimal/empty binaries

**What This Proves:**

- Edge cases handled gracefully
- Error handling for invalid inputs
- No crashes on unusual binaries

### 16. Complex Control Flow Tests (2 tests)

**Purpose:** Validate analysis of complex patterns

**Key Tests:**

- `test_analyze_nested_branches` - Handles nested conditionals
- `test_analyze_switch_statement` - Analyzes switch statements (high out-degree)

**What This Proves:**

- Complex control flow patterns analyzed correctly
- Nested branches and switches handled

## Test Fixtures

### Binary Fixtures

All fixtures create **REAL PE binaries** with actual x64 machine code:

1. **simple_pe_binary** - Basic PE with multiple functions:
    - Simple function with stack frame setup/teardown
    - Function with conditional branches and calls
    - Function with comparison and branch logic
    - Function with pointer validation and nested conditionals

2. **control_flow_flattened_binary** - PE with dispatcher pattern:
    - State variable-based dispatcher with 5+ cases
    - Controlled blocks that jump back to dispatcher
    - State variable assignments for next case selection
    - Classic OLLVM/Tigress/VMProtect flattening pattern

3. **opaque_predicate_binary** - PE with opaque predicates:
    - Self-comparison patterns (x == x, x XOR x)
    - Invariant tests (always true/false conditions)
    - Dead branch targets
    - Multiple opaque predicate types

### Fixture Architecture

- All binaries are x64 PE format (Windows)
- DOS header, PE signature, COFF header, optional header, section header
- .text section with executable code
- Real x64 instructions (not random bytes)
- Valid control flow structures

## Running the Tests

### Run All Tests

```bash
pytest tests/core/analysis/test_control_flow_analyzer_production.py -v
```

### Run Specific Test Class

```bash
pytest tests/core/analysis/test_control_flow_analyzer_production.py::TestBasicBlockExtraction -v
```

### Run Single Test

```bash
pytest tests/core/analysis/test_control_flow_analyzer_production.py::TestControlFlowDeobfuscatorInitialization::test_initialization_with_valid_binary -v
```

### Run with Coverage

```bash
pytest tests/core/analysis/test_control_flow_analyzer_production.py --cov=intellicrack.core.analysis.control_flow_deobfuscation --cov-report=html
```

## Dependencies Required

### Critical Dependencies

- **radare2** - Binary analysis and CFG extraction
- **r2pipe** - Python interface to radare2
- **networkx** - Graph data structures
- **LIEF** - PE binary parsing and manipulation
- **Capstone** - Disassembly engine
- **Keystone** - Assembly engine (for patching)

### Optional Dependencies

- **Z3** - Symbolic execution for opaque predicate analysis
- **pytest** - Test framework
- **pytest-cov** - Coverage reporting

## Expected Test Behavior

### Normal Operation (Radare2 Available)

When radare2 is available, tests will:

- Extract actual CFG from binaries using radare2
- Validate basic blocks, edges, and control flow
- Detect dispatchers, opaque predicates, and dead code
- Generate deobfuscation results with metrics

### Graceful Degradation (Radare2 Unavailable)

When radare2 is not available, tests will:

- **SKIP** tests that require CFG analysis
- **PASS** initialization and setup tests
- Report skipped tests with clear reason

This ensures tests don't fail due to missing tools while still validating what's possible.

## Coverage Goals

Target coverage for `control_flow_deobfuscation.py`:

- **Line Coverage:** 85%+
- **Branch Coverage:** 80%+
- **Critical Paths:** 100% (initialization, CFG building, dispatcher detection)

## Test Quality Validation

### How to Verify Tests Are Real

1. **Break the Implementation:**

    ```python
    # In control_flow_deobfuscation.py, break CFG construction
    def _build_control_flow_graph(self, r2, function_address):
        return nx.DiGraph()  # Return empty graph
    ```

    **Expected:** Tests MUST FAIL

2. **Remove Dispatcher Detection:**

    ```python
    def _detect_dispatchers(self, r2, cfg, function_address):
        return []  # Return no dispatchers
    ```

    **Expected:** Dispatcher detection tests MUST FAIL

3. **Break Opaque Predicate Detection:**
    ```python
    def _detect_opaque_predicates(self, r2, cfg, function_address):
        return []  # Return no opaque predicates
    ```
    **Expected:** Opaque predicate tests MUST FAIL

If tests still PASS after breaking the implementation, the tests are FAKE and must be rewritten.

## Success Criteria

Tests prove genuine control flow analysis capability when:

1. ✅ All initialization tests pass with real binaries
2. ✅ Basic block extraction returns valid blocks with addresses, sizes, instructions
3. ✅ CFG construction creates directed graphs with correct edges
4. ✅ Dispatcher detection identifies control flow flattening patterns
5. ✅ Opaque predicate detection finds always-true/false conditions
6. ✅ Deobfuscation produces simplified CFG with metrics
7. ✅ Tests FAIL when implementation is broken
8. ✅ Tests SKIP gracefully when radare2 unavailable

## Future Enhancements

### Additional Test Scenarios

- Multi-level nested dispatchers
- Exception handler CFG analysis
- Indirect call/jump target resolution
- Inter-procedural control flow analysis
- ARM/ARM64 binary CFG analysis

### Performance Tests

- Large binary CFG extraction benchmarks
- Deobfuscation speed on heavily obfuscated code
- Memory usage during CFG construction

### Integration Tests

- Full binary deobfuscation workflow
- Patch application and verification
- Deobfuscated binary execution validation

## Contribution Guidelines

When adding new tests:

1. **Use Real Operations** - No mocks for core CFG analysis
2. **Type All Code** - Complete type hints on all functions
3. **Test Real Binaries** - Create fixtures with actual PE files
4. **Validate Failures** - Ensure tests fail when code is broken
5. **Document Purpose** - Clear docstrings explaining what test proves
6. **Follow Patterns** - Match existing test structure and naming

## Test Maintenance

### When to Update Tests

- ✅ New CFG analysis features added
- ✅ Dispatcher detection patterns enhanced
- ✅ Opaque predicate analysis improved
- ✅ New obfuscation techniques supported
- ✅ Binary format support expanded (ARM, ELF, Mach-O)

### When NOT to Update Tests

- ❌ Implementation details change (tests should be black-box)
- ❌ Internal refactoring (tests validate behavior, not structure)
- ❌ Dependency versions update (tests should be version-agnostic)

---

**Total Tests:** 45+ comprehensive tests validating real control flow analysis

**Test File:** `tests/core/analysis/test_control_flow_analyzer_production.py`

**Last Updated:** 2025-12-05
