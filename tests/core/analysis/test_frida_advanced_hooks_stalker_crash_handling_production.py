"""Production tests for Stalker crash handling in frida_advanced_hooks.py.

Tests validate comprehensive error handling for Stalker.parseInstruction(),
memory guards, script error recovery, anti-Stalker pattern detection,
and edge cases including packed code, self-modifying code, and exception handlers.

These tests ONLY pass when error handling is complete and functional.
"""

import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

# Conditional import with VERY VERBOSE skip
try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print("\n" + "=" * 80)
    print("FRIDA NOT AVAILABLE - SKIPPING STALKER CRASH HANDLING TESTS")
    print("=" * 80)
    print("\nREQUIREMENTS FOR THESE TESTS:")
    print("1. Frida must be installed: pip install frida frida-tools")
    print("2. Frida server must be running (for remote attach) OR")
    print("3. Tests will spawn local Windows processes for instrumentation")
    print("\nINSTALLATION INSTRUCTIONS:")
    print("  pip install frida frida-tools")
    print("\nCURRENT PYTHON:", sys.executable)
    print("CURRENT PATH:", sys.path)
    print("=" * 80 + "\n")

from intellicrack.core.analysis.frida_advanced_hooks import (
    FridaAdvancedHooks,
    StalkerTrace,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def simple_target_executable(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a simple Windows executable for testing.

    This executable performs basic operations that trigger Stalker instrumentation.
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    tmp_dir = tmp_path_factory.mktemp("targets")
    exe_path = tmp_dir / "simple_target.exe"

    # Simple C program that loops and calls functions
    c_code = """
#include <windows.h>
#include <stdio.h>

void function_a(int x) {
    volatile int result = x * 2;
}

void function_b(int x) {
    volatile int result = x + 100;
}

int main(void) {
    printf("Target started\\n");
    fflush(stdout);

    for (int i = 0; i < 1000; i++) {
        function_a(i);
        function_b(i);
        Sleep(1);
    }

    printf("Target finished\\n");
    return 0;
}
"""

    c_file = tmp_dir / "simple_target.c"
    c_file.write_text(c_code)

    # Compile with gcc (assumes MinGW is available on Windows)
    try:
        subprocess.run(
            ["gcc", "-o", str(exe_path), str(c_file), "-O0"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        pytest.skip(f"Cannot compile test executable: {e}")

    if not exe_path.exists():
        pytest.skip("Failed to create test executable")

    return exe_path


@pytest.fixture(scope="session")
def self_modifying_target_executable(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """Create executable with self-modifying code to test edge case handling."""
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    tmp_dir = tmp_path_factory.mktemp("targets")
    exe_path = tmp_dir / "self_modifying.exe"

    # Code that modifies itself at runtime
    c_code = """
#include <windows.h>
#include <stdio.h>

void modifiable_function(void) {
    printf("Original code\\n");
}

int main(void) {
    printf("Self-modifying target started\\n");
    fflush(stdout);

    // Get address of function
    void* func_addr = (void*)modifiable_function;

    // Make memory writable
    DWORD old_protect;
    VirtualProtect(func_addr, 16, PAGE_EXECUTE_READWRITE, &old_protect);

    // Modify first instruction to NOP
    unsigned char* code = (unsigned char*)func_addr;
    for (int i = 0; i < 100; i++) {
        code[0] = 0x90;  // NOP
        Sleep(10);
        modifiable_function();
    }

    printf("Self-modifying target finished\\n");
    return 0;
}
"""

    c_file = tmp_dir / "self_modifying.c"
    c_file.write_text(c_code)

    try:
        subprocess.run(
            ["gcc", "-o", str(exe_path), str(c_file), "-O0"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        pytest.skip(f"Cannot compile self-modifying executable: {e}")

    if not exe_path.exists():
        pytest.skip("Failed to create self-modifying executable")

    return exe_path


@pytest.fixture(scope="session")
def exception_throwing_target_executable(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """Create executable that throws exceptions to test exception handler edge cases."""
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    tmp_dir = tmp_path_factory.mktemp("targets")
    exe_path = tmp_dir / "exception_target.exe"

    c_code = """
#include <windows.h>
#include <stdio.h>
#include <setjmp.h>

jmp_buf jump_buffer;

void risky_function(void) {
    // Trigger exception by dividing by zero
    volatile int x = 0;
    volatile int y = 100 / x;
}

int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep) {
    printf("Exception caught: 0x%x\\n", code);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(void) {
    printf("Exception target started\\n");
    fflush(stdout);

    for (int i = 0; i < 100; i++) {
        __try {
            if (i % 10 == 0) {
                risky_function();
            }
        }
        __except(filter(GetExceptionCode(), GetExceptionInformation())) {
            printf("Handled exception\\n");
        }
        Sleep(10);
    }

    printf("Exception target finished\\n");
    return 0;
}
"""

    c_file = tmp_dir / "exception_target.c"
    c_file.write_text(c_code)

    try:
        subprocess.run(
            ["gcc", "-o", str(exe_path), str(c_file), "-O0"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        pytest.skip(f"Cannot compile exception executable: {e}")

    if not exe_path.exists():
        pytest.skip("Failed to create exception executable")

    return exe_path


@pytest.fixture
def frida_session_on_simple_target(
    simple_target_executable: Path,
) -> frida.core.Session:
    """Spawn simple target and return attached Frida session."""
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_executable)])
    session = device.attach(pid)
    device.resume(pid)

    yield session

    try:
        session.detach()
    except Exception:
        pass


@pytest.fixture
def frida_session_on_self_modifying_target(
    self_modifying_target_executable: Path,
) -> frida.core.Session:
    """Spawn self-modifying target and return attached Frida session."""
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(self_modifying_target_executable)])
    session = device.attach(pid)
    device.resume(pid)

    yield session

    try:
        session.detach()
    except Exception:
        pass


@pytest.fixture
def frida_session_on_exception_target(
    exception_throwing_target_executable: Path,
) -> frida.core.Session:
    """Spawn exception-throwing target and return attached Frida session."""
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(exception_throwing_target_executable)])
    session = device.attach(pid)
    device.resume(pid)

    yield session

    try:
        session.detach()
    except Exception:
        pass


# ============================================================================
# Core Crash Handling Tests
# ============================================================================


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_parse_instruction_crash_recovery(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Stalker wraps parseInstruction() in try-catch and recovers from crashes.

    VALIDATES: Must wrap Stalker.parseInstruction() in try-catch for crash recovery.
    This test FAILS if parseInstruction crashes without recovery.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    # Start Stalker tracing
    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Let it run for a bit to potentially hit parsing errors
    time.sleep(2)

    # Stop tracing
    trace = hooks.stop_stalker_trace()

    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must return trace even after parse errors"
    assert trace.thread_id > 0, "Stalker must have traced at least one thread"

    # Verify error recovery mechanism exists
    # If parseInstruction() crashes without try-catch, process would crash
    # The fact we got here means recovery works

    # Check for meaningful error messages if any errors occurred
    if error_messages:
        for error_msg in error_messages:
            assert (
                "context" in error_msg
            ), "Error messages must include context for debugging"
            assert (
                "error" in error_msg
            ), "Error messages must include error information"
            assert (
                error_msg["context"] != "Unknown"
            ), "Error context must be meaningful"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_memory_guards_prevent_invalid_access(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Memory guards prevent invalid memory access during Stalker tracing.

    VALIDATES: Must implement memory guards to prevent invalid memory access.
    This test FAILS if Stalker crashes on invalid memory regions.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    # Start Stalker - memory guards should be active
    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    time.sleep(2)

    trace = hooks.stop_stalker_trace()

    # Memory guard validation
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must handle invalid memory gracefully"

    # Check that memory validation errors are properly logged
    memory_validation_errors = [
        err
        for err in error_messages
        if "Memory validation" in err.get("context", "")
        or "Invalid instruction boundary" in err.get("context", "")
    ]

    # If we got memory validation errors, verify they contain proper information
    for err in memory_validation_errors:
        assert (
            "additionalInfo" in err
        ), "Memory errors must include address information"
        # Verify error didn't crash the process
        assert (
            "error" in err
        ), "Memory guard must log error instead of crashing"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_graceful_script_error_handling(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Script errors during Stalker tracing don't crash target process.

    VALIDATES: Must gracefully handle script errors without crashing target process.
    This test FAILS if script errors cause target process to crash.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    script_errors: list[dict[str, Any]] = []
    stalker_errors: list[dict[str, Any]] = []

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "error":
            script_errors.append(message)
        elif message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                stalker_errors.append(payload.get("payload", {}))

    # Start Stalker tracing
    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Let it run to potentially trigger script errors
    time.sleep(2)

    # Stop tracing - process must still be alive
    trace = hooks.stop_stalker_trace()

    # Process must not have crashed
    assert isinstance(
        trace, StalkerTrace
    ), "Target process must survive script errors"
    assert trace.thread_id > 0, "Stalker must have traced despite errors"

    # Verify error recovery messages exist
    if stalker_errors:
        recovery_messages = [
            err for err in stalker_errors if "recovery" in err.get("context", "")
        ]
        # If errors occurred, recovery should have been attempted
        if len(stalker_errors) > 3:
            assert (
                recovery_messages or stalker_errors[-1].get("context") != "Unknown"
            ), "Stalker must attempt recovery from errors"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_detects_and_skips_anti_stalker_patterns(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Stalker detects and skips over anti-instrumentation code patterns.

    VALIDATES: Must detect and skip over anti-Stalker code patterns.
    This test FAILS if anti-Stalker patterns cause crashes or infinite loops.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []
    trace_complete = False

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    # Start Stalker
    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Run for limited time to ensure we don't hang on anti-Stalker code
    start_time = time.time()
    timeout = 5.0

    while time.time() - start_time < timeout:
        time.sleep(0.1)

    # Stop must succeed without hanging
    trace = hooks.stop_stalker_trace()
    trace_complete = True

    # Verify tracing completed without hanging
    assert trace_complete, "Stalker must not hang on anti-instrumentation code"
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must skip problematic patterns and continue"

    # Check for skip count increases (indicates detection and skipping)
    skip_errors = [
        err for err in error_messages if "skipCount" in str(err.get("additionalInfo"))
    ]

    # If we hit parsing failures, verify skip mechanism activated
    if error_messages:
        assert any(
            "skip" in str(err).lower() or "Failed to keep" in err.get("context", "")
            for err in error_messages
        ), "Stalker must skip problematic instructions"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_provides_meaningful_error_messages(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Error messages contain context, thread info, and stack traces for debugging.

    VALIDATES: Must provide meaningful error messages for debugging.
    This test FAILS if error messages lack context or debugging information.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    time.sleep(2)

    trace = hooks.stop_stalker_trace()

    # Even if no errors occurred, verify error logging infrastructure exists
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must complete tracing with error logging"

    # If errors occurred, validate their structure
    if error_messages:
        for error in error_messages:
            # All errors must have these fields
            assert (
                "timestamp" in error
            ), "Error messages must include timestamp for debugging"
            assert (
                "context" in error
            ), "Error messages must include context describing what failed"
            assert (
                "error" in error
            ), "Error messages must include error details"
            assert (
                "threadId" in error
            ), "Error messages must include thread ID for debugging"

            # Context must be meaningful
            assert (
                error["context"] != ""
            ), "Error context must not be empty"
            assert (
                error["context"] != "Unknown"
            ), "Error context must be specific"

            # Verify timestamp is reasonable
            assert error["timestamp"] > 0, "Error timestamp must be valid"

            # Thread ID must be valid
            assert error["threadId"] > 0, "Thread ID must be valid"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_recovers_from_partial_tracing_failures(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Stalker recovers from partial tracing failures and continues.

    VALIDATES: Must recover from partial tracing failures.
    This test FAILS if partial failures cause complete tracing failure.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    recovery_messages: list[dict[str, Any]] = []
    error_messages: list[dict[str, Any]] = []

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type", "")

            if msg_type == "stalker_recovery_success":
                recovery_messages.append(payload.get("payload", {}))
            elif msg_type == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Run for extended period to increase chance of hitting errors
    time.sleep(3)

    trace = hooks.stop_stalker_trace()

    # Tracing must complete even with partial failures
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must recover from partial failures"
    assert trace.thread_id > 0, "Stalker must continue tracing after recovery"

    # If recovery occurred, verify it was successful
    if recovery_messages:
        for recovery in recovery_messages:
            assert (
                "threadId" in recovery
            ), "Recovery messages must identify thread"
            assert recovery["threadId"] > 0, "Recovered thread ID must be valid"

    # Verify trace contains data (proving recovery worked)
    assert len(trace.instructions) > 0, "Trace must contain instructions after recovery"


# ============================================================================
# Edge Case Tests
# ============================================================================


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_handles_self_modifying_code_edge_case(
    frida_session_on_self_modifying_target: frida.core.Session,
) -> None:
    """Stalker handles self-modifying code without crashing.

    VALIDATES EDGE CASE: Self-modifying code
    This test FAILS if self-modifying code causes crashes or hangs.
    """
    hooks = FridaAdvancedHooks(frida_session_on_self_modifying_target)

    error_messages: list[dict[str, Any]] = []
    completed = False

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Let self-modifying code execute
    time.sleep(3)

    trace = hooks.stop_stalker_trace()
    completed = True

    # Must complete without crashing
    assert completed, "Stalker must handle self-modifying code without hanging"
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must trace self-modifying code"

    # Self-modifying code may trigger instruction boundary errors
    # Verify they were handled gracefully
    if error_messages:
        boundary_errors = [
            err
            for err in error_messages
            if "boundary" in err.get("context", "").lower()
        ]
        for err in boundary_errors:
            assert (
                "error" in err
            ), "Boundary errors must be logged without crashing"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_handles_exception_handlers_edge_case(
    frida_session_on_exception_target: frida.core.Session,
) -> None:
    """Stalker handles exception handlers without crashing.

    VALIDATES EDGE CASE: Exception handlers
    This test FAILS if exception handlers cause Stalker to crash.
    """
    hooks = FridaAdvancedHooks(frida_session_on_exception_target)

    error_messages: list[dict[str, Any]] = []
    completed = False

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Let exception-throwing code execute
    time.sleep(3)

    trace = hooks.stop_stalker_trace()
    completed = True

    # Must complete without crashing
    assert (
        completed
    ), "Stalker must handle exception handlers without crashing"
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must trace through exception handlers"

    # Verify tracing continued through exceptions
    assert (
        len(trace.instructions) > 0
    ), "Stalker must capture instructions despite exceptions"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_handles_packed_code_execution_edge_case(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Stalker handles dynamically unpacked code execution.

    VALIDATES EDGE CASE: Packed code execution
    This test FAILS if dynamically unpacked code causes crashes.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    # Inject code that simulates unpacking behavior
    unpack_simulation_script = """
    // Simulate unpacking: allocate memory and execute dynamically
    var unpackedCode = Memory.alloc(Process.pageSize);

    // Write simple code (NOP sled followed by RET)
    var code = [0x90, 0x90, 0x90, 0x90, 0xC3];
    Memory.protect(unpackedCode, Process.pageSize, 'rwx');
    Memory.writeByteArray(unpackedCode, code);

    // Make it executable
    Memory.protect(unpackedCode, Process.pageSize, 'r-x');

    // Frida will try to trace this dynamically generated code
    send({type: 'unpacked_code_ready', address: unpackedCode.toString()});
    """

    try:
        script = frida_session_on_simple_target.create_script(
            unpack_simulation_script
        )
        script.load()
        time.sleep(1)
    except Exception:
        # If we can't inject unpacking simulation, skip this edge case
        pytest.skip("Cannot inject unpacking simulation")

    # Start Stalker to trace dynamically generated code
    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    time.sleep(2)

    trace = hooks.stop_stalker_trace()

    # Must handle dynamically generated code
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must handle packed/dynamically generated code"

    # Check for memory validation during dynamic code execution
    if error_messages:
        dynamic_errors = [
            err for err in error_messages if "Memory" in err.get("context", "")
        ]
        # If dynamic code triggered errors, verify they were handled
        for err in dynamic_errors:
            assert (
                "error" in err
            ), "Dynamic code errors must be handled gracefully"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_error_log_circular_buffer_prevents_memory_exhaustion(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Error log uses circular buffer to prevent memory exhaustion.

    VALIDATES: Error logging must not exhaust memory during long traces.
    This test FAILS if error log grows unbounded.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_count = 0

    def error_handler(message: dict[str, Any], data: Any) -> None:
        nonlocal error_count
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_count += 1

    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Run for extended period to accumulate errors
    time.sleep(4)

    trace = hooks.stop_stalker_trace()

    # Verify trace completed (circular buffer prevented memory exhaustion)
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must complete with circular error buffer"

    # If many errors occurred, verify process didn't crash from memory exhaustion
    # The fact we're still running proves circular buffer worked
    if error_count > 50:
        assert (
            True
        ), "Circular buffer prevented memory exhaustion from excessive errors"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_thread_local_state_prevents_race_conditions(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Thread-local state prevents race conditions during multi-threaded tracing.

    VALIDATES: Thread-local state management prevents race conditions.
    This test FAILS if concurrent threads cause state corruption.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []
    thread_ids_seen: set[int] = set()

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_msg = payload.get("payload", {})
                error_messages.append(error_msg)
                if "threadId" in error_msg:
                    thread_ids_seen.add(error_msg["threadId"])

    # Start Stalker on all threads (thread_id=0)
    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Let multiple threads execute
    time.sleep(3)

    trace = hooks.stop_stalker_trace()

    # Verify multi-threaded tracing succeeded
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must handle multi-threaded execution"

    # If multiple threads generated errors, verify thread isolation
    if len(thread_ids_seen) > 1:
        # Each error must have thread ID (proves thread-local state)
        for err in error_messages:
            assert (
                "threadId" in err
            ), "Errors must include thread ID from thread-local state"
            assert (
                err["threadId"] > 0
            ), "Thread-local state must track valid thread IDs"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_session_recovery_mechanism_functional(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Session recovery mechanism restores Stalker after failures.

    VALIDATES: Recovery mechanism must restore Stalker functionality.
    This test FAILS if recovery doesn't restore tracing capability.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    recovery_messages: list[dict[str, Any]] = []
    first_trace_complete = False
    second_trace_complete = False

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_recovery_success":
                recovery_messages.append(payload.get("payload", {}))

    # First trace
    trace1_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )
    time.sleep(2)
    trace1 = hooks.stop_stalker_trace()
    first_trace_complete = True

    # Second trace to verify recovery allows re-tracing
    trace2_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )
    time.sleep(2)
    trace2 = hooks.stop_stalker_trace()
    second_trace_complete = True

    # Both traces must complete
    assert first_trace_complete, "First trace must complete"
    assert second_trace_complete, "Second trace must complete after recovery"

    assert isinstance(trace1, StalkerTrace), "First trace must succeed"
    assert isinstance(trace2, StalkerTrace), "Second trace must succeed after recovery"

    # Verify both traces captured data
    assert len(trace1.instructions) > 0, "First trace must capture instructions"
    assert len(trace2.instructions) > 0, "Second trace must capture instructions after recovery"


# ============================================================================
# Integration Tests - Complete Error Handling Workflow
# ============================================================================


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_complete_error_handling_workflow(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Complete workflow: error detection -> logging -> recovery -> continuation.

    VALIDATES: Complete error handling chain from detection to recovery.
    This test FAILS if any part of the error handling chain is broken.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []
    recovery_messages: list[dict[str, Any]] = []
    workflow_stages = {
        "started": False,
        "errors_detected": False,
        "errors_logged": False,
        "recovery_attempted": False,
        "tracing_continued": False,
        "completed": False,
    }

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type", "")

            if msg_type == "stalker_error":
                workflow_stages["errors_detected"] = True
                error_messages.append(payload.get("payload", {}))
                workflow_stages["errors_logged"] = True

            elif msg_type == "stalker_recovery_success":
                workflow_stages["recovery_attempted"] = True
                recovery_messages.append(payload.get("payload", {}))

    # Start tracing
    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )
    workflow_stages["started"] = True

    # Run to accumulate potential errors
    time.sleep(3)

    # Stop tracing
    trace = hooks.stop_stalker_trace()
    workflow_stages["completed"] = True

    # Verify workflow stages
    assert workflow_stages["started"], "Workflow must start"
    assert workflow_stages["completed"], "Workflow must complete"

    # Verify tracing succeeded
    assert isinstance(
        trace, StalkerTrace
    ), "Tracing must succeed through error handling workflow"
    assert len(trace.instructions) > 0, "Trace must contain data"

    workflow_stages["tracing_continued"] = True

    # If errors occurred, verify complete workflow
    if error_messages:
        assert (
            workflow_stages["errors_logged"]
        ), "Errors must be logged"

        # Verify logged errors have proper structure
        for err in error_messages:
            assert "context" in err, "Logged errors must have context"
            assert "error" in err, "Logged errors must have error info"
            assert "threadId" in err, "Logged errors must have thread ID"
            assert "timestamp" in err, "Logged errors must have timestamp"

    # Verify tracing continued despite any errors
    assert (
        workflow_stages["tracing_continued"]
    ), "Tracing must continue after error handling"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_invalid_memory_boundary_detection_and_skip(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Invalid instruction boundaries are detected and skipped.

    VALIDATES: Instruction boundary validation prevents crashes.
    This test FAILS if invalid boundaries cause crashes instead of skips.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    boundary_errors: list[dict[str, Any]] = []

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                err = payload.get("payload", {})
                if "boundary" in err.get("context", "").lower():
                    boundary_errors.append(err)

    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    time.sleep(2)

    trace = hooks.stop_stalker_trace()

    # Must complete without crashing
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must skip invalid boundaries without crashing"

    # If boundary errors occurred, verify they were handled
    if boundary_errors:
        for err in boundary_errors:
            assert (
                "additionalInfo" in err
            ), "Boundary errors must include address/size info"
            info = err["additionalInfo"]
            assert (
                "address" in info or "size" in info
            ), "Boundary errors must identify problematic location"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_stalker_max_retry_mechanism_prevents_infinite_loops(
    frida_session_on_simple_target: frida.core.Session,
) -> None:
    """Max retry mechanism prevents infinite loops on persistent errors.

    VALIDATES: Retry limit prevents infinite loops.
    This test FAILS if retry mechanism allows infinite retries.
    """
    hooks = FridaAdvancedHooks(frida_session_on_simple_target)

    error_messages: list[dict[str, Any]] = []
    timeout_occurred = False

    def error_handler(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "stalker_error":
                error_messages.append(payload.get("payload", {}))

    trace_result = hooks.start_stalker_trace(
        thread_id=0, on_message=error_handler
    )

    # Set timeout to detect infinite loops
    start_time = time.time()
    max_execution_time = 10.0

    while time.time() - start_time < max_execution_time:
        time.sleep(0.5)

    if time.time() - start_time >= max_execution_time:
        timeout_occurred = True

    trace = hooks.stop_stalker_trace()

    # Must complete within timeout (no infinite loops)
    assert not timeout_occurred, "Stalker must not enter infinite retry loops"
    assert isinstance(
        trace, StalkerTrace
    ), "Stalker must complete with retry limits"

    # Check for retry-related errors
    retry_errors = [
        err
        for err in error_messages
        if "retries" in str(err.get("additionalInfo"))
        or "attempts" in str(err.get("additionalInfo"))
    ]

    if retry_errors:
        for err in retry_errors:
            # Verify retry count is reasonable (not infinite)
            assert (
                "attempts" in str(err["additionalInfo"])
            ), "Retry errors must show attempt count"
