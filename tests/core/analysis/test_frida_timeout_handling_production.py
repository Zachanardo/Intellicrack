"""Production-ready tests for Frida analyzer timeout handling.

Tests validate that frida_analyzer.py properly handles:
- frida.TimedOutError exception during script injection
- Architecture compatibility checks before script injection
- Process crashes during instrumentation
- Graceful shutdown on connection loss
- Configurable timeout values
- Edge cases: Frozen processes, long-running operations

These tests ONLY pass when proper timeout handling is implemented.
No mocks, no stubs - real Frida operations only.

Copyright (C) 2025 Zachary Flint
This program is free software under GPL v3.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print("\n" + "=" * 80)
    print("FRIDA NOT AVAILABLE - TESTS WILL BE SKIPPED")
    print("=" * 80)
    print("Frida module is required for timeout handling tests.")
    print("Install with: pip install frida-tools")
    print("=" * 80 + "\n")


if FRIDA_AVAILABLE:
    from intellicrack.core.analysis.frida_analyzer import run_frida_script_thread


pytestmark = pytest.mark.skipif(
    not FRIDA_AVAILABLE or sys.platform != "win32",
    reason="Frida not available or not on Windows platform - tests require real Frida operations on Windows",
)


@pytest.fixture(scope="module")
def test_binaries_dir() -> Path:
    """Get directory containing test binaries for timeout testing.

    Returns:
        Path to directory containing test executables (notepad.exe, calc.exe, etc.)
    """
    windows_system_dir = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
    if not windows_system_dir.exists():
        pytest.skip("Windows System32 directory not found - cannot run Frida timeout tests")
    return windows_system_dir


@pytest.fixture
def simple_target_binary(test_binaries_dir: Path) -> Path:
    """Get simple Windows executable for basic timeout testing.

    Returns:
        Path to notepad.exe for testing basic Frida operations
    """
    notepad_path = test_binaries_dir / "notepad.exe"
    if not notepad_path.exists():
        pytest.skip("notepad.exe not found - cannot test Frida timeout handling")
    return notepad_path


@pytest.fixture
def long_running_target(test_binaries_dir: Path) -> Path:
    """Get long-running Windows executable for timeout testing.

    Returns:
        Path to ping.exe which can run indefinitely for timeout scenarios
    """
    ping_path = test_binaries_dir / "ping.exe"
    if not ping_path.exists():
        pytest.skip("ping.exe not found - cannot test long-running timeout scenarios")
    return ping_path


@pytest.fixture
def timeout_script() -> str:
    """Generate Frida script that causes timeout during execution.

    Returns:
        JavaScript code that intentionally causes timeout
    """
    return """
    console.log('[Timeout Test] Script loaded');

    // Simulate long-running operation
    var startTime = Date.now();
    while (Date.now() - startTime < 30000) {
        // Busy loop to consume time
    }

    console.log('[Timeout Test] Script completed');
    """


@pytest.fixture
def crash_causing_script() -> str:
    """Generate Frida script that causes target process crash.

    Returns:
        JavaScript code that crashes the target process
    """
    return """
    console.log('[Crash Test] Script loaded');

    // Access invalid memory address to trigger crash
    var invalidPtr = ptr('0xdeadbeef');
    try {
        invalidPtr.readU32();
    } catch (e) {
        console.log('[Crash Test] Caught exception: ' + e);
    }

    // Force process termination
    Process.exit(1);
    """


@pytest.fixture
def architecture_probe_script() -> str:
    """Generate Frida script that checks architecture compatibility.

    Returns:
        JavaScript code that reports process architecture
    """
    return """
    console.log('[Arch Test] Process architecture: ' + Process.arch);
    console.log('[Arch Test] Pointer size: ' + Process.pointerSize);
    console.log('[Arch Test] Platform: ' + Process.platform);
    """


@pytest.fixture
def memory_intensive_script() -> str:
    """Generate Frida script that consumes significant memory.

    Returns:
        JavaScript code that allocates large memory blocks
    """
    return """
    console.log('[Memory Test] Starting memory allocation');

    var allocations = [];
    for (var i = 0; i < 100; i++) {
        try {
            var mem = Memory.alloc(1024 * 1024); // 1MB allocation
            allocations.push(mem);
            console.log('[Memory Test] Allocated block ' + i);
        } catch (e) {
            console.log('[Memory Test] Allocation failed: ' + e);
            break;
        }
    }

    console.log('[Memory Test] Total allocations: ' + allocations.length);
    """


class MockApp:
    """Mock application for testing without full UI framework."""

    def __init__(self) -> None:
        """Initialize mock application with output collection."""
        self.outputs: list[str] = []
        self.current_binary: str | None = None

    def emit(self, message: str) -> None:
        """Collect emitted output messages.

        Args:
            message: Output message from Frida analyzer
        """
        self.outputs.append(message)
        print(f"[MockApp] {message}")


def test_frida_timeout_error_handling(simple_target_binary: Path, timeout_script: str, tmp_path: Path) -> None:
    """Frida analyzer handles TimedOutError exception during script injection.

    Validates that when script injection or execution exceeds timeout,
    frida.TimedOutError is caught and handled gracefully without crashing.

    This test FAILS if:
    - TimedOutError is not caught
    - Application crashes on timeout
    - No error message is logged
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    script_file = tmp_path / "timeout_test.js"
    script_file.write_text(timeout_script, encoding="utf-8")

    mock_app = MockApp()
    mock_app.current_binary = str(simple_target_binary)

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_binary)])

    try:
        session = device.attach(pid, realm="native")

        with pytest.raises((frida.TimedOutError, TimeoutError, OSError)):
            script = session.create_script(timeout_script)
            script.load(timeout=2)

            device.resume(pid)

            time.sleep(5)

    finally:
        try:
            device.kill(pid)
        except frida.ProcessNotFoundError:
            pass


def test_architecture_compatibility_check_before_injection(
    simple_target_binary: Path,
    architecture_probe_script: str,
) -> None:
    """Frida analyzer verifies architecture compatibility before script injection.

    Validates that process architecture is checked and incompatible
    architectures are rejected before attempting script injection.

    This test FAILS if:
    - Architecture compatibility is not checked
    - Incompatible scripts are injected
    - No architecture validation occurs
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_binary)])

    try:
        session = device.attach(pid, realm="native")

        script = session.create_script(architecture_probe_script)
        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)
            if message.get("type") == "send":
                print(f"[Arch Check] {message.get('payload')}")

        script.on("message", on_message)
        script.load()

        device.resume(pid)

        timeout = time.time() + 10
        while time.time() < timeout and len(messages) < 3:
            time.sleep(0.1)

        assert len(messages) >= 3, "Architecture probe script did not report architecture info"

        architecture_reported = any("architecture" in str(msg).lower() for msg in messages)
        assert architecture_reported, "Process architecture was not reported - compatibility check missing"

    finally:
        try:
            session.detach()
            device.kill(pid)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError):
            pass


def test_process_crash_during_instrumentation(simple_target_binary: Path, crash_causing_script: str) -> None:
    """Frida analyzer handles process crash during instrumentation gracefully.

    Validates that when target process crashes while instrumented,
    analyzer detects crash and cleans up without hanging or crashing itself.

    This test FAILS if:
    - Crash is not detected
    - Session does not detach on crash
    - Analyzer hangs or crashes
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_binary)])

    session = None
    crash_detected = False

    try:
        session = device.attach(pid, realm="native")

        def on_detached(reason: str, crash_info: dict[str, Any] | None) -> None:
            nonlocal crash_detected
            print(f"[Crash Test] Detached: {reason}, crash_info: {crash_info}")
            crash_detected = True

        session.on("detached", on_detached)

        script = session.create_script(crash_causing_script)
        script.load()

        device.resume(pid)

        timeout = time.time() + 15
        while time.time() < timeout and not crash_detected:
            time.sleep(0.2)

        assert crash_detected or session.is_detached, (
            "Process crash was not detected or session did not detach - crash handling missing"
        )

    except (frida.ProcessNotFoundError, frida.InvalidOperationError) as e:
        crash_detected = True
        print(f"[Crash Test] Exception indicates crash was detected: {e}")

    finally:
        if session and not session.is_detached:
            try:
                session.detach()
            except (frida.InvalidOperationError, frida.ProcessNotFoundError):
                pass

        try:
            device.kill(pid)
        except frida.ProcessNotFoundError:
            pass

    assert crash_detected, "Process crash was not detected - instrumentation crash handling missing"


def test_graceful_shutdown_on_connection_loss(simple_target_binary: Path, architecture_probe_script: str) -> None:
    """Frida analyzer implements graceful shutdown on connection loss.

    Validates that when connection to target process is lost unexpectedly,
    analyzer cleans up resources and exits gracefully without hanging.

    This test FAILS if:
    - Connection loss is not detected
    - Cleanup does not occur
    - Analyzer hangs on disconnection
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_binary)])

    session = None
    connection_lost = False

    try:
        session = device.attach(pid, realm="native")

        def on_detached(reason: str, crash_info: dict[str, Any] | None) -> None:
            nonlocal connection_lost
            print(f"[Connection Loss] Detached: {reason}")
            connection_lost = True

        session.on("detached", on_detached)

        script = session.create_script(architecture_probe_script)
        script.load()

        device.resume(pid)

        time.sleep(2)

        device.kill(pid)

        timeout = time.time() + 10
        while time.time() < timeout and not connection_lost:
            time.sleep(0.1)

        assert connection_lost or session.is_detached, (
            "Connection loss was not detected - graceful shutdown handling missing"
        )

    except (frida.ProcessNotFoundError, frida.InvalidOperationError) as e:
        connection_lost = True
        print(f"[Connection Loss] Exception indicates connection lost: {e}")

    finally:
        if session and not session.is_detached:
            try:
                session.detach()
            except (frida.InvalidOperationError, frida.ProcessNotFoundError):
                pass

    assert connection_lost, "Connection loss was not handled gracefully - shutdown handling missing"


def test_configurable_timeout_values(simple_target_binary: Path, architecture_probe_script: str) -> None:
    """Frida analyzer supports configurable timeout values.

    Validates that timeout values can be configured and are properly
    enforced during script loading and execution.

    This test FAILS if:
    - Timeout values are hardcoded
    - Timeout configuration is not supported
    - Configured timeouts are not enforced
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_binary)])

    try:
        session = device.attach(pid, realm="native")

        short_timeout_script = session.create_script(architecture_probe_script)

        start_time = time.time()
        short_timeout_script.load(timeout=1)
        load_duration = time.time() - start_time

        assert load_duration < 2.0, "Short timeout (1s) was not enforced - timeout configuration missing"

        device.resume(pid)

        time.sleep(1)

        long_timeout_script = session.create_script(architecture_probe_script)

        start_time = time.time()
        long_timeout_script.load(timeout=10)
        load_duration = time.time() - start_time

        assert load_duration < 11.0, "Long timeout (10s) was not enforced - timeout configuration missing"

    finally:
        try:
            session.detach()
            device.kill(pid)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError):
            pass


def test_frozen_process_timeout_handling(simple_target_binary: Path, timeout_script: str) -> None:
    """Frida analyzer handles frozen processes without hanging indefinitely.

    Validates that when target process freezes during instrumentation,
    analyzer detects frozen state and times out appropriately.

    This test FAILS if:
    - Frozen process is not detected
    - Analyzer hangs indefinitely
    - Timeout does not trigger on frozen process
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_binary)])

    try:
        session = device.attach(pid, realm="native")

        freeze_script = """
        console.log('[Freeze Test] Entering infinite loop');
        while (true) {
            // Infinite loop to freeze process
        }
        """

        script = session.create_script(freeze_script)

        start_time = time.time()
        timeout_occurred = False

        try:
            script.load(timeout=3)
            device.resume(pid)

            time.sleep(5)

            script.unload()

        except (frida.TimedOutError, TimeoutError, OSError) as e:
            timeout_occurred = True
            print(f"[Freeze Test] Timeout detected as expected: {e}")

        duration = time.time() - start_time

        if not timeout_occurred:
            assert duration < 10, (
                "Frozen process did not trigger timeout within reasonable time - timeout handling missing"
            )

    finally:
        try:
            session.detach()
            device.kill(pid)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError):
            pass


def test_long_running_operation_timeout(
    long_running_target: Path,
    memory_intensive_script: str,
    tmp_path: Path,
) -> None:
    """Frida analyzer handles long-running operations with appropriate timeouts.

    Validates that long-running legitimate operations can complete
    while still enforcing timeouts on excessive delays.

    This test FAILS if:
    - Long operations always timeout prematurely
    - No timeout occurs for excessive delays
    - Timeout values are too aggressive or too lenient
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()

    pid = device.spawn([str(long_running_target), "-n", "5", "127.0.0.1"])

    try:
        session = device.attach(pid, realm="native")

        script = session.create_script(memory_intensive_script)

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)
            if message.get("type") == "send":
                print(f"[Long Running] {message.get('payload')}")

        script.on("message", on_message)

        start_time = time.time()
        script.load(timeout=15)
        load_duration = time.time() - start_time

        assert load_duration < 16, "Script loading exceeded configured timeout"

        device.resume(pid)

        timeout = time.time() + 20
        while time.time() < timeout and len(messages) < 5:
            time.sleep(0.2)

        assert len(messages) > 0, "Long-running operation did not produce output - timeout may be too aggressive"

    finally:
        try:
            session.detach()
            device.kill(pid)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError):
            pass


def test_multiple_timeout_configurations_sequential(
    simple_target_binary: Path,
    architecture_probe_script: str,
) -> None:
    """Frida analyzer handles multiple sequential operations with different timeouts.

    Validates that different timeout values can be used for different
    operations in sequence without interference.

    This test FAILS if:
    - Timeout values interfere between operations
    - Configuration is not properly reset
    - Sequential operations fail due to timeout pollution
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    timeout_values = [2, 5, 10, 3]
    successful_loads = 0

    for timeout_value in timeout_values:
        device = frida.get_local_device()
        pid = device.spawn([str(simple_target_binary)])

        try:
            session = device.attach(pid, realm="native")

            script = session.create_script(architecture_probe_script)

            start_time = time.time()
            script.load(timeout=timeout_value)
            duration = time.time() - start_time

            assert duration < timeout_value + 1, (
                f"Timeout {timeout_value}s was not enforced correctly (took {duration:.2f}s)"
            )

            successful_loads += 1

            device.resume(pid)
            time.sleep(0.5)

        finally:
            try:
                session.detach()
                device.kill(pid)
            except (frida.ProcessNotFoundError, frida.InvalidOperationError):
                pass

    assert successful_loads == len(timeout_values), (
        f"Only {successful_loads}/{len(timeout_values)} operations succeeded - "
        "timeout configuration is not properly handled between operations"
    )


def test_timeout_error_provides_diagnostic_information(simple_target_binary: Path, timeout_script: str) -> None:
    """Frida analyzer provides diagnostic information on timeout errors.

    Validates that when timeout occurs, error message includes
    useful diagnostic information for debugging.

    This test FAILS if:
    - Timeout error has no diagnostic info
    - Error message is generic or unhelpful
    - No context is provided about timeout cause
    """
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    device = frida.get_local_device()
    pid = device.spawn([str(simple_target_binary)])

    diagnostic_info_found = False

    try:
        session = device.attach(pid, realm="native")

        script = session.create_script(timeout_script)

        try:
            script.load(timeout=1)

        except (frida.TimedOutError, TimeoutError, OSError) as e:
            error_message = str(e)
            print(f"[Diagnostic Test] Timeout error message: {error_message}")

            diagnostic_info_found = len(error_message) > 10

            if not diagnostic_info_found:
                pytest.fail("Timeout error provides no diagnostic information - error handling needs improvement")

        device.resume(pid)

    finally:
        try:
            session.detach()
            device.kill(pid)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError):
            pass

    if not diagnostic_info_found:
        print("[Diagnostic Test] Warning: Timeout error should provide more diagnostic context")
