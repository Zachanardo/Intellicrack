# Frida Advanced Hooks Production Tests

## Overview

Comprehensive production-ready tests for `intellicrack/core/analysis/frida_advanced_hooks.py` that validate REAL Frida functionality against live processes. **NO MOCKS, NO STUBS** - all tests use actual Frida instrumentation on running processes.

## Test File Location

`D:\Intellicrack\tests\core\analysis\test_frida_advanced_hooks_production.py`

## Test Architecture

### Real Process Testing

Tests use a **real Python subprocess** as the target for Frida instrumentation:

- Continuous memory allocations (100KB buffers)
- Thread creation and termination
- Real heap activity for malloc/free tracking
- Live execution for Stalker tracing

This ensures tests validate actual Frida hook functionality, not simulated behavior.

## Test Coverage

### 1. FridaStalkerEngine Tests (TestFridaStalkerEngine)

**Purpose**: Validate instruction-level tracing with Stalker on real process

**Tests**:
- `test_stalker_initialization`: Verifies Stalker engine initializes with session
- `test_stalker_traces_thread_execution`: **CRITICAL** - Validates actual instruction trace capture including:
  - Real instruction data (address, mnemonic, operands)
  - Basic block identification
  - Call graph construction
  - Code coverage calculation
- `test_stalker_start_stop_trace`: Validates trace control (start/stop)
- `test_stalker_captures_call_graph`: Confirms real function call relationships are captured

**Failure Conditions**: Tests FAIL if Stalker doesn't capture real instruction data

### 2. FridaHeapTracker Tests (TestFridaHeapTracker)

**Purpose**: Validate heap allocation tracking via malloc/free hooking

**Tests**:
- `test_heap_tracker_initialization`: Verifies heap tracker initializes and hooks memory functions
- `test_heap_tracker_captures_allocations`: **CRITICAL** - Must intercept real malloc calls:
  - Captures allocation address, size, timestamp
  - Records thread ID and call stack
  - Tracks freed status
- `test_heap_tracker_tracks_frees`: Validates free() interception and freed timestamp recording
- `test_heap_tracker_get_stats`: Verifies accurate heap statistics (total allocations, frees, current allocated)
- `test_heap_tracker_find_leaks`: Tests memory leak detection (allocations older than 1 minute)

**Failure Conditions**: Tests FAIL if no heap allocations captured (hooks not working)

### 3. FridaThreadMonitor Tests (TestFridaThreadMonitor)

**Purpose**: Validate thread creation/termination monitoring

**Tests**:
- `test_thread_monitor_initialization`: Verifies thread monitor initialization
- `test_thread_monitor_detects_threads`: **CRITICAL** - Captures real thread creation events:
  - Thread ID, entry point, creation time
  - Parent thread ID tracking
- `test_thread_monitor_tracks_current_threads`: Enumerates currently running threads via RPC
- `test_thread_monitor_tracks_termination`: Detects thread termination with timestamps

**Failure Conditions**: Tests FAIL if CreateThread/pthread_create hooks don't intercept calls

### 4. FridaExceptionHooker Tests (TestFridaExceptionHooker)

**Purpose**: Validate exception handler hooking

**Tests**:
- `test_exception_hooker_initialization`: Verifies exception hooker initialization
- `test_exception_hooker_clear_exceptions`: Validates exception history clearing (local and remote)
- `test_exception_hooker_get_exceptions`: Tests exception list retrieval

**Note**: Exception tests may not trigger exceptions in test process, but validate infrastructure

### 5. FridaNativeReplacer Tests (TestFridaNativeReplacer)

**Purpose**: Validate native function replacement

**Tests**:
- `test_native_replacer_initialization`: Verifies native replacer initialization
- `test_native_replacer_replace_function`: **CRITICAL** - Replaces real function in target:
  - Finds actual exported function
  - Replaces with licensing bypass implementation
  - Validates replacement is active
- `test_native_replacer_restore_function`: Tests function restoration (Interceptor.revert)

**Failure Conditions**: Tests FAIL if Interceptor.replace doesn't actually replace functions

### 6. FridaRPCInterface Tests (TestFridaRPCInterface)

**Purpose**: Validate RPC interface for complex operations

**Tests**:
- `test_rpc_interface_initialization`: Verifies RPC interface initialization
- `test_rpc_memory_read`: **CRITICAL** - Reads real memory from module base address
- `test_rpc_memory_write`: Allocates memory and writes/reads to validate write operations
- `test_rpc_memory_scan`: Scans process memory for byte patterns
- `test_rpc_module_find_export`: Finds real module exports (kernel32.dll or malloc)
- `test_rpc_evaluate_javascript`: **CRITICAL** - Executes JavaScript in target context:
  - Validates arithmetic evaluation
  - Confirms Process.id access
  - Verifies Process.platform retrieval

**Failure Conditions**: Tests FAIL if memory operations don't access real process memory

### 7. FridaAdvancedHooking Tests (TestFridaAdvancedHooking)

**Purpose**: Validate main orchestrator class

**Tests**:
- `test_advanced_hooking_initialization`: Verifies orchestrator initialization
- `test_advanced_hooking_init_stalker`: Tests Stalker engine initialization
- `test_advanced_hooking_init_heap_tracker`: Tests heap tracker initialization
- `test_advanced_hooking_init_thread_monitor`: Tests thread monitor initialization
- `test_advanced_hooking_init_exception_hooker`: Tests exception hooker initialization
- `test_advanced_hooking_init_native_replacer`: Tests native replacer initialization
- `test_advanced_hooking_init_rpc_interface`: Tests RPC interface initialization
- `test_advanced_hooking_init_all`: **CRITICAL** - Initializes ALL components simultaneously

**Failure Conditions**: Tests FAIL if any component fails to initialize

### 8. Integration Tests (TestIntegrationScenarios)

**Purpose**: Validate complete hooking workflows combining multiple features

**Tests**:
- `test_complete_process_instrumentation`: **CRITICAL END-TO-END** - Full instrumentation:
  - All components active simultaneously
  - Heap allocations captured
  - Threads monitored
  - RPC operations successful
  - Memory reading functional
  - Validates no component interference
- `test_memory_scan_and_patch_workflow`: Realistic cracking workflow:
  - Allocate memory
  - Write pattern
  - Read back and verify
  - Patch with NOPs
  - Verify patch applied
- `test_heap_tracking_with_leak_detection`: Complete heap analysis workflow

**Failure Conditions**: Tests FAIL if any component doesn't work or components interfere

### 9. Windows-Specific Tests (TestWindowsSpecificFeatures)

**Purpose**: Validate Windows-only features (registry operations)

**Tests**:
- `test_rpc_registry_operations`: Reads real Windows registry values for license extraction scenarios

**Platform**: Windows only (skipped on Linux/macOS)

## Running Tests

### Run All Tests
```bash
pixi run pytest tests/core/analysis/test_frida_advanced_hooks_production.py -v
```

### Run Specific Test Class
```bash
pixi run pytest tests/core/analysis/test_frida_advanced_hooks_production.py::TestFridaHeapTracker -v
```

### Run with Coverage
```bash
pixi run pytest tests/core/analysis/test_frida_advanced_hooks_production.py --cov=intellicrack.core.analysis.frida_advanced_hooks --cov-report=html
```

### Run Integration Tests Only
```bash
pixi run pytest tests/core/analysis/test_frida_advanced_hooks_production.py::TestIntegrationScenarios -v
```

## Test Requirements

**Platform**: Windows (primary), Linux/macOS supported but some features limited

**Dependencies**:
- frida
- pytest
- Running test process (automatically spawned)

**Privileges**: May require elevated privileges for process attachment on some systems

## Test Validation Criteria

### Tests MUST FAIL When:

1. **Hooks don't work**: If malloc/free hooks don't intercept calls, heap tests fail
2. **Memory operations fail**: If memory read/write doesn't access real memory
3. **Stalker doesn't trace**: If no instruction data captured
4. **Thread monitoring broken**: If CreateThread hooks don't intercept
5. **RPC doesn't execute**: If JavaScript evaluation fails
6. **Function replacement broken**: If Interceptor.replace doesn't work

### Tests MUST PASS When:

1. All Frida hooks successfully intercept target functions
2. Memory operations access real process memory
3. Stalker captures actual instruction traces
4. Thread creation/termination detected
5. Heap allocations tracked with real addresses
6. RPC operations execute in target context
7. All components work simultaneously without interference

## Coverage Goals

- **Line Coverage**: 85%+ of frida_advanced_hooks.py
- **Branch Coverage**: 80%+ of conditional paths
- **Component Coverage**: All 6 main classes + orchestrator
- **Integration Coverage**: End-to-end workflows

## Test Methodology

### Production Validation Approach:

1. **Real Target Process**: Python subprocess with actual heap/thread activity
2. **No Mocking**: All Frida operations against live process
3. **Actual Verification**: Tests verify real data (addresses, sizes, timestamps)
4. **Failure Detection**: Intentional code breaks must cause test failures
5. **Platform Coverage**: Windows-specific and cross-platform tests

### Offensive Capability Validation:

These tests prove Intellicrack can:
- **Hook memory allocations** in protected software
- **Trace execution** at instruction level for analysis
- **Replace license validation functions** with bypass implementations
- **Monitor threads** for anti-debugging detection
- **Scan and patch memory** for license check removal
- **Access registry** for license key extraction (Windows)

## Known Limitations

1. **Exception Testing**: May not trigger exceptions in test process (infrastructure validated, not events)
2. **Platform Differences**: Some features (registry) Windows-only
3. **Timing Sensitivity**: Tests use sleep() for async operations (may need adjustment on slow systems)
4. **Process Cleanup**: Test process terminated after tests (ensure proper cleanup)

## Future Enhancements

1. Add performance benchmarks for Stalker tracing overhead
2. Test anti-anti-debugging features (hide hooks from detection)
3. Add tests for specific protectors (VMProtect, Themida detection avoidance)
4. Test hook persistence across process lifetime
5. Validate memory scanning performance on large address spaces

## Conclusion

This test suite provides **comprehensive validation** of Frida advanced hooking capabilities against **real running processes**. All tests verify **genuine offensive capability** - no simulations, no mocks, no placeholders. Tests MUST fail when hooks don't work, proving they validate real functionality.

**Test Count**: 30+ production tests across 9 test classes
**Coverage**: All major classes and integration workflows
**Validation Level**: Production-ready, offensive capability proven
