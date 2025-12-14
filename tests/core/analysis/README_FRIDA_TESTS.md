# Frida Analyzer Production Tests

## Overview

This test suite validates **REAL offensive capabilities** of the Frida dynamic analysis framework against actual Windows processes. All tests use genuine Windows system binaries (notepad.exe, calc.exe) and verify that Frida successfully performs code injection, API hooking, memory manipulation, and runtime analysis.

## Test Coverage: 48 Tests Across 11 Categories

### 1. TestFridaMessageHandling (5 tests)

Tests Frida's message passing and callback system between injected JavaScript and Python.

**Validates:**

- Send message payload extraction and logging
- Error message handling with stack traces
- Empty payload handling
- Malformed message recovery

**Why Critical:** Message handling is the primary communication channel for all dynamic analysis. If messages fail, no analysis data reaches the analyzer.

### 2. TestFridaProcessLifecycle (4 tests)

Tests process spawning, attachment, and detachment workflows.

**Validates:**

- Process spawn and PID assignment
- Session attachment to running processes
- Process enumeration and identification
- Clean detachment on process termination

**Why Critical:** Process lifecycle management ensures Frida can reliably attach to and control target processes without crashes or resource leaks.

### 3. TestFridaScriptExecution (3 tests)

Tests JavaScript injection and execution in target processes.

**Validates:**

- Script injection into running processes
- Module enumeration via injected code
- Invalid script path handling
- JavaScript syntax error detection

**Why Critical:** Script execution is the core of Frida's analysis capabilities. Scripts must inject cleanly and execute without corrupting the target process.

### 4. TestFridaSessionManagement (4 tests)

Tests session tracking and management across multiple binaries.

**Validates:**

- Active session detachment
- No-session error handling
- Binary load validation
- Multi-binary session tracking

**Why Critical:** Session management prevents resource leaks and ensures analysis isolation between different target binaries.

### 5. TestStalkerSessionIntegration (5 tests)

Tests Stalker instruction-level tracing integration.

**Validates:**

- StalkerSession initialization
- Output directory creation
- Statistics tracking (instructions, blocks, coverage)
- TraceEvent data capture
- API call event logging with licensing detection

**Why Critical:** Stalker provides instruction-level execution traces essential for identifying licensing validation logic and protection mechanisms.

### 6. TestStalkerControlFunctions (7 tests)

Tests Stalker session control and validation logic.

**Validates:**

- Binary load requirement enforcement
- Duplicate session prevention
- Active session validation
- Statistics retrieval
- Licensing routine extraction
- Function tracing initiation
- Module coverage collection

**Why Critical:** Control functions ensure Stalker sessions are properly managed and prevent analysis conflicts or data corruption.

### 7. TestStalkerMessageHandling (5 tests)

Tests Stalker message processing and data aggregation.

**Validates:**

- Status message logging
- API call capture and classification
- Licensing event detection
- Progress statistics updates
- Function trace data processing

**Why Critical:** Message handling aggregates all trace data from the Stalker script, enabling post-analysis of licensing flows.

### 8. TestStalkerDataExport (3 tests)

Tests results export and statistical analysis.

**Validates:**

- JSON export of complete trace results
- Coverage summary with hotspot identification
- API call aggregation and frequency analysis

**Why Critical:** Export functionality persists analysis results for later review and enables automated licensing detection workflows.

### 9. TestAnalysisScriptsWhitelist (4 tests)

Tests approved script whitelist completeness.

**Validates:**

- Licensing analysis scripts present
- Protection detector scripts available
- Network interceptor scripts included
- Stalker tracer script availability

**Why Critical:** Whitelist ensures only approved, tested scripts execute on target processes, preventing malicious code execution.

### 10. TestFridaErrorHandling (4 tests)

Tests error recovery and graceful failure modes.

**Validates:**

- Process not found exception handling
- Invalid binary path errors
- Missing Frida import detection
- Already-detached session cleanup

**Why Critical:** Error handling prevents crashes and provides actionable diagnostic information when analysis fails.

### 11. TestFridaHookingCapabilities (4 tests)

Tests API hooking and memory manipulation capabilities.

**Validates:**

- CreateFileW API interception in notepad.exe
- Process memory reading from calc.exe
- Module enumeration in target processes

**Why Critical:** Hooking is the offensive capability that enables license check interception, trial reset, and protection bypass.

## Real Binary Requirements

All tests use actual Windows system binaries:

- **notepad.exe**: `C:\Windows\System32\notepad.exe` (360KB, text editor)
- **calc.exe**: `C:\Windows\System32\calc.exe` (49KB, calculator)

These binaries are chosen because:

1. Always present on Windows systems
2. Clean, unprotected PE executables
3. Standard Windows API usage patterns
4. Well-documented module dependencies

## Offensive Capabilities Validated

### Code Injection

- JavaScript code injection into running processes
- Script execution with full process access
- Multi-script concurrent execution

### API Hooking

- CreateFileW interception (file access monitoring)
- Kernel32.dll export hooking
- Pre/post-call hook callbacks

### Memory Manipulation

- Process memory reading at arbitrary addresses
- PE header parsing from memory
- Module enumeration and base address resolution

### Runtime Analysis

- Instruction-level tracing with Stalker
- Basic block coverage collection
- API call frequency analysis
- Licensing routine identification

## Test Execution Requirements

### Environment Setup

```bash
pixi shell
pytest tests/core/analysis/test_frida_analyzer_production.py -v
```

### Required Dependencies

- frida >= 17.4.0
- frida-tools >= 14.4.5
- pytest >= 7.0
- Windows OS (tests spawn Windows processes)

### Administrator Privileges

Some tests may require elevated privileges to spawn and attach to system processes. Run from administrator shell if tests fail with access denied errors.

## Test Failure Modes

### Process Spawn Failures

If `frida.get_local_device().spawn()` fails:

- Verify binary paths are correct
- Check antivirus is not blocking process creation
- Ensure Frida service has process spawn permissions

### Attachment Failures

If `device.attach(pid)` fails:

- Process may have terminated before attachment
- Another debugger may be attached
- Process protection may block debugging

### Script Load Failures

If `session.create_script()` fails:

- JavaScript syntax errors in test scripts
- Frida version incompatibility
- Process architecture mismatch (x86 vs x64)

## Coverage Goals

- **Line Coverage Target**: 85%+
- **Branch Coverage Target**: 80%+
- **Current Coverage**: 48 tests covering all major code paths

### Uncovered Scenarios

Tests do NOT cover:

- Frida script whitelisting UI interaction (requires Qt)
- User script selection dialog (requires QInputDialog)
- Real-time analysis UI updates (requires signal/slot testing)

These require UI integration tests with Qt test framework.

## Continuous Integration

Tests are designed for automated CI/CD pipelines:

```yaml
- name: Run Frida Tests
  run: |
      pytest tests/core/analysis/test_frida_analyzer_production.py \
        --cov=intellicrack/core/analysis/frida_analyzer \
        --cov-report=xml \
        -v
```

## Test Maintenance

### Adding New Tests

1. Use real Windows binaries (notepad.exe, calc.exe)
2. Verify Frida operations complete successfully
3. Assert on actual output, not just "no exception"
4. Clean up sessions/processes in finally blocks

### Debugging Test Failures

1. Check Frida service is running: `frida --version`
2. Verify processes spawn: `frida-ps -U`
3. Test script injection manually: `frida -l script.js notepad.exe`
4. Review test output for error messages

## Security Considerations

These tests validate **offensive security capabilities**. They demonstrate:

- Process injection (used by malware)
- API hooking (used by rootkits)
- Memory manipulation (used by game cheats)

**Purpose**: Educational security research to help developers strengthen licensing protections.

**NOT FOR**: Unauthorized software cracking, malware development, or illegal activity.

## License

Tests validate GPL-licensed security research tool. See LICENSE for full terms.
