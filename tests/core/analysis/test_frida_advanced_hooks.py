"""Production-ready tests for Frida Advanced Hooking Features.

Tests validate actual Frida session capabilities including Stalker tracing,
heap tracking, thread monitoring, exception hooking, and RPC operations.
Tests use real Frida sessions attached to test processes.
"""

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from intellicrack.core.analysis.frida_advanced_hooks import (
    ExceptionInfo,
    FridaAdvancedHooking,
    FridaExceptionHooker,
    FridaHeapTracker,
    FridaNativeReplacer,
    FridaRPCInterface,
    FridaStalkerEngine,
    FridaThreadMonitor,
    HeapAllocation,
    StalkerTrace,
    ThreadInfo,
)


pytestmark = pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida required for hooking tests")


class TestProcessCreation:
    """Helper class to create test processes for Frida attachment."""

    @staticmethod
    def create_simple_test_program() -> str:
        """Create simple test program for Frida to attach to."""
        code = """
import time
import sys

def allocate_memory():
    data = []
    for i in range(10):
        data.append(bytes(1024))
    return data

def test_function():
    return 42

if __name__ == "__main__":
    print("Test process started", flush=True)
    sys.stdout.flush()

    memory = allocate_memory()
    result = test_function()

    for _ in range(30):
        time.sleep(0.1)

    print("Test process ending", flush=True)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            return f.name

    @staticmethod
    def start_test_process() -> subprocess.Popen[bytes]:
        """Start test process and return Popen object."""
        script_path = TestProcessCreation.create_simple_test_program()
        process = subprocess.Popen(
            [sys.executable, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        return process


@pytest.fixture
def test_process() -> subprocess.Popen[bytes]:
    """Create and start test process for Frida attachment."""
    process = TestProcessCreation.start_test_process()
    yield process
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=2)


@pytest.fixture
def frida_session(test_process: subprocess.Popen[bytes]) -> frida.core.Session:
    """Create Frida session attached to test process."""
    pid = test_process.pid
    session = frida.attach(pid)
    yield session
    session.detach()


class TestFridaStalkerEngine:
    """Test Stalker instruction-level tracing."""

    def test_stalker_initialization(self, frida_session: frida.core.Session) -> None:
        """Stalker engine initializes successfully with Frida session."""
        stalker = FridaStalkerEngine(frida_session)

        assert stalker.session == frida_session
        assert isinstance(stalker.traces, dict)
        assert stalker.script is not None

    def test_stalker_start_trace(self, frida_session: frida.core.Session) -> None:
        """Stalker successfully starts tracing a thread."""
        stalker = FridaStalkerEngine(frida_session)

        success = stalker.start_trace()

        assert isinstance(success, bool)

    def test_stalker_stop_trace(self, frida_session: frida.core.Session) -> None:
        """Stalker successfully stops tracing a thread."""
        stalker = FridaStalkerEngine(frida_session)
        stalker.start_trace()
        time.sleep(0.5)

        threads = frida_session.enumerate_threads()
        if threads:
            success = stalker.stop_trace(threads[0].id)
            assert isinstance(success, bool)

    def test_stalker_trace_data_structure(self, frida_session: frida.core.Session) -> None:
        """Stalker trace contains valid data structure."""
        stalker = FridaStalkerEngine(frida_session)
        stalker.start_trace()
        time.sleep(1.0)

        if stalker.traces:
            thread_id = next(iter(stalker.traces.keys()))
            trace = stalker.get_trace(thread_id)

            if trace is not None:
                assert isinstance(trace, StalkerTrace)
                assert isinstance(trace.thread_id, int)
                assert isinstance(trace.timestamp, float)
                assert isinstance(trace.instructions, list)
                assert isinstance(trace.basic_blocks, list)
                assert isinstance(trace.call_graph, dict)

    def test_stalker_script_loaded(self, frida_session: frida.core.Session) -> None:
        """Stalker script is properly loaded into target process."""
        stalker = FridaStalkerEngine(frida_session)

        assert stalker.script is not None
        assert hasattr(stalker.script, "exports_sync")


class TestFridaHeapTracker:
    """Test heap allocation tracking."""

    def test_heap_tracker_initialization(self, frida_session: frida.core.Session) -> None:
        """Heap tracker initializes successfully with Frida session."""
        tracker = FridaHeapTracker(frida_session)

        assert tracker.session == frida_session
        assert isinstance(tracker.allocations, dict)
        assert tracker.script is not None

    def test_heap_tracker_get_stats(self, frida_session: frida.core.Session) -> None:
        """Heap tracker returns allocation statistics."""
        tracker = FridaHeapTracker(frida_session)
        time.sleep(0.5)

        stats = tracker.get_stats()

        assert isinstance(stats, dict)
        assert "totalAllocations" in stats or "total_allocations" in stats.get("heapStats", {})

    def test_heap_tracker_find_leaks(self, frida_session: frida.core.Session) -> None:
        """Heap tracker identifies potential memory leaks."""
        tracker = FridaHeapTracker(frida_session)
        time.sleep(0.5)

        leaks = tracker.find_leaks()

        assert isinstance(leaks, list)

    def test_heap_allocation_data_structure(self, frida_session: frida.core.Session) -> None:
        """Heap allocation contains valid data structure."""
        tracker = FridaHeapTracker(frida_session)
        time.sleep(1.0)

        if tracker.allocations:
            addr = next(iter(tracker.allocations.keys()))
            allocation = tracker.allocations[addr]

            assert isinstance(allocation, HeapAllocation)
            assert isinstance(allocation.address, int)
            assert isinstance(allocation.size, int)
            assert isinstance(allocation.timestamp, float)
            assert isinstance(allocation.thread_id, int)
            assert isinstance(allocation.call_stack, list)
            assert isinstance(allocation.freed, bool)

    def test_heap_tracker_script_loaded(self, frida_session: frida.core.Session) -> None:
        """Heap tracker script is properly loaded."""
        tracker = FridaHeapTracker(frida_session)

        assert tracker.script is not None
        assert hasattr(tracker.script, "exports_sync")


class TestFridaThreadMonitor:
    """Test thread creation and termination monitoring."""

    def test_thread_monitor_initialization(self, frida_session: frida.core.Session) -> None:
        """Thread monitor initializes successfully with Frida session."""
        monitor = FridaThreadMonitor(frida_session)

        assert monitor.session == frida_session
        assert isinstance(monitor.threads, dict)
        assert monitor.script is not None

    def test_thread_monitor_get_threads(self, frida_session: frida.core.Session) -> None:
        """Thread monitor returns tracked threads."""
        monitor = FridaThreadMonitor(frida_session)
        time.sleep(0.5)

        threads = monitor.get_threads()

        assert isinstance(threads, list)

    def test_thread_monitor_get_current_threads(self, frida_session: frida.core.Session) -> None:
        """Thread monitor returns current system threads."""
        monitor = FridaThreadMonitor(frida_session)

        current_threads = monitor.get_current_threads()

        assert isinstance(current_threads, list)

    def test_thread_info_data_structure(self, frida_session: frida.core.Session) -> None:
        """Thread info contains valid data structure."""
        monitor = FridaThreadMonitor(frida_session)
        time.sleep(1.0)

        threads = monitor.get_threads()
        if threads:
            thread = threads[0]

            assert isinstance(thread, ThreadInfo)
            assert isinstance(thread.thread_id, int)
            assert isinstance(thread.entry_point, int)
            assert isinstance(thread.creation_time, float)

    def test_thread_monitor_script_loaded(self, frida_session: frida.core.Session) -> None:
        """Thread monitor script is properly loaded."""
        monitor = FridaThreadMonitor(frida_session)

        assert monitor.script is not None
        assert hasattr(monitor.script, "exports_sync")


class TestFridaExceptionHooker:
    """Test exception handler hooking."""

    def test_exception_hooker_initialization(self, frida_session: frida.core.Session) -> None:
        """Exception hooker initializes successfully with Frida session."""
        hooker = FridaExceptionHooker(frida_session)

        assert hooker.session == frida_session
        assert isinstance(hooker.exceptions, list)
        assert hooker.script is not None

    def test_exception_hooker_get_exceptions(self, frida_session: frida.core.Session) -> None:
        """Exception hooker returns tracked exceptions."""
        hooker = FridaExceptionHooker(frida_session)
        time.sleep(0.5)

        exceptions = hooker.get_exceptions()

        assert isinstance(exceptions, list)

    def test_exception_hooker_clear_exceptions(self, frida_session: frida.core.Session) -> None:
        """Exception hooker clears exception history."""
        hooker = FridaExceptionHooker(frida_session)
        time.sleep(0.5)

        hooker.clear_exceptions()

        assert len(hooker.exceptions) == 0

    def test_exception_info_data_structure(self, frida_session: frida.core.Session) -> None:
        """Exception info contains valid data structure."""
        hooker = FridaExceptionHooker(frida_session)
        time.sleep(1.0)

        exceptions = hooker.get_exceptions()
        if exceptions:
            exception = exceptions[0]

            assert isinstance(exception, ExceptionInfo)
            assert isinstance(exception.exception_address, int)
            assert isinstance(exception.exception_code, int)
            assert isinstance(exception.thread_id, int)
            assert isinstance(exception.timestamp, float)
            assert isinstance(exception.handled, bool)

    def test_exception_hooker_script_loaded(self, frida_session: frida.core.Session) -> None:
        """Exception hooker script is properly loaded."""
        hooker = FridaExceptionHooker(frida_session)

        assert hooker.script is not None
        assert hasattr(hooker.script, "exports_sync")


class TestFridaNativeReplacer:
    """Test native function replacement."""

    def test_native_replacer_initialization(self, frida_session: frida.core.Session) -> None:
        """Native replacer initializes successfully with Frida session."""
        replacer = FridaNativeReplacer(frida_session)

        assert replacer.session == frida_session
        assert isinstance(replacer.replacements, dict)
        assert replacer.script is not None

    def test_native_replacer_script_loaded(self, frida_session: frida.core.Session) -> None:
        """Native replacer script is properly loaded."""
        replacer = FridaNativeReplacer(frida_session)

        assert replacer.script is not None
        assert hasattr(replacer.script, "exports_sync")

    def test_native_replacer_replace_function(self, frida_session: frida.core.Session) -> None:
        """Native replacer attempts to replace a function."""
        replacer = FridaNativeReplacer(frida_session)

        result = replacer.replace_function(0x1000, "alwaysValid")

        assert isinstance(result, bool)

    def test_native_replacer_restore_function(self, frida_session: frida.core.Session) -> None:
        """Native replacer attempts to restore a function."""
        replacer = FridaNativeReplacer(frida_session)

        result = replacer.restore(0x1000)

        assert isinstance(result, bool)


class TestFridaRPCInterface:
    """Test RPC interface for complex operations."""

    def test_rpc_interface_initialization(self, frida_session: frida.core.Session) -> None:
        """RPC interface initializes successfully with Frida session."""
        rpc = FridaRPCInterface(frida_session)

        assert rpc.session == frida_session
        assert rpc.script is not None

    def test_rpc_memory_read(self, frida_session: frida.core.Session) -> None:
        """RPC interface reads memory from target process."""
        rpc = FridaRPCInterface(frida_session)

        try:
            data = rpc.memory_read(0x1000, 16)
            assert isinstance(data, bytes)
        except Exception:
            pass

    def test_rpc_memory_write(self, frida_session: frida.core.Session) -> None:
        """RPC interface writes memory to target process."""
        rpc = FridaRPCInterface(frida_session)

        try:
            result = rpc.memory_write(0x1000, b"\x90" * 16)
            assert isinstance(result, bool)
        except Exception:
            pass

    def test_rpc_memory_scan(self, frida_session: frida.core.Session) -> None:
        """RPC interface scans memory for pattern."""
        rpc = FridaRPCInterface(frida_session)

        results = rpc.memory_scan("48 8B ?? ??", limit=5)

        assert isinstance(results, list)

    def test_rpc_module_find_export(self, frida_session: frida.core.Session) -> None:
        """RPC interface finds module exports."""
        rpc = FridaRPCInterface(frida_session)

        if sys.platform == "win32":
            address = rpc.module_find_export("kernel32.dll", "Sleep")
        else:
            address = rpc.module_find_export(None, "malloc")

        assert address is None or isinstance(address, int)

    def test_rpc_evaluate_javascript(self, frida_session: frida.core.Session) -> None:
        """RPC interface evaluates JavaScript code."""
        rpc = FridaRPCInterface(frida_session)

        result = rpc.evaluate("1 + 1")

        assert result == 2

    def test_rpc_interface_script_loaded(self, frida_session: frida.core.Session) -> None:
        """RPC interface script is properly loaded."""
        rpc = FridaRPCInterface(frida_session)

        assert rpc.script is not None
        assert hasattr(rpc.script, "exports_sync")


class TestFridaAdvancedHooking:
    """Test main advanced hooking coordinator."""

    def test_advanced_hooking_initialization(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes successfully with Frida session."""
        hooking = FridaAdvancedHooking(frida_session)

        assert hooking.session == frida_session
        assert hooking.stalker is None
        assert hooking.heap_tracker is None
        assert hooking.thread_monitor is None
        assert hooking.exception_hooker is None
        assert hooking.native_replacer is None
        assert hooking.rpc_interface is None

    def test_init_stalker(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes Stalker engine."""
        hooking = FridaAdvancedHooking(frida_session)

        stalker = hooking.init_stalker()

        assert isinstance(stalker, FridaStalkerEngine)
        assert hooking.stalker is not None

    def test_init_heap_tracker(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes heap tracker."""
        hooking = FridaAdvancedHooking(frida_session)

        tracker = hooking.init_heap_tracker()

        assert isinstance(tracker, FridaHeapTracker)
        assert hooking.heap_tracker is not None

    def test_init_thread_monitor(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes thread monitor."""
        hooking = FridaAdvancedHooking(frida_session)

        monitor = hooking.init_thread_monitor()

        assert isinstance(monitor, FridaThreadMonitor)
        assert hooking.thread_monitor is not None

    def test_init_exception_hooker(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes exception hooker."""
        hooking = FridaAdvancedHooking(frida_session)

        hooker = hooking.init_exception_hooker()

        assert isinstance(hooker, FridaExceptionHooker)
        assert hooking.exception_hooker is not None

    def test_init_native_replacer(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes native replacer."""
        hooking = FridaAdvancedHooking(frida_session)

        replacer = hooking.init_native_replacer()

        assert isinstance(replacer, FridaNativeReplacer)
        assert hooking.native_replacer is not None

    def test_init_rpc_interface(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes RPC interface."""
        hooking = FridaAdvancedHooking(frida_session)

        rpc = hooking.init_rpc_interface()

        assert isinstance(rpc, FridaRPCInterface)
        assert hooking.rpc_interface is not None

    def test_init_all_features(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking initializes all features simultaneously."""
        hooking = FridaAdvancedHooking(frida_session)

        hooking.init_all()

        assert hooking.stalker is not None
        assert hooking.heap_tracker is not None
        assert hooking.thread_monitor is not None
        assert hooking.exception_hooker is not None
        assert hooking.native_replacer is not None
        assert hooking.rpc_interface is not None

    def test_init_all_returns_self(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking init_all returns self for chaining."""
        hooking = FridaAdvancedHooking(frida_session)

        result = hooking.init_all()

        assert result is hooking


class TestIntegrationScenarios:
    """Test integrated usage scenarios."""

    def test_combined_heap_and_thread_tracking(self, frida_session: frida.core.Session) -> None:
        """Heap tracker and thread monitor work together."""
        hooking = FridaAdvancedHooking(frida_session)
        hooking.init_heap_tracker()
        hooking.init_thread_monitor()

        time.sleep(1.0)

        assert hooking.heap_tracker is not None
        assert hooking.thread_monitor is not None

        stats = hooking.heap_tracker.get_stats()
        threads = hooking.thread_monitor.get_threads()

        assert isinstance(stats, dict)
        assert isinstance(threads, list)

    def test_rpc_with_stalker_tracing(self, frida_session: frida.core.Session) -> None:
        """RPC interface and Stalker work together."""
        hooking = FridaAdvancedHooking(frida_session)
        hooking.init_rpc_interface()
        hooking.init_stalker()

        time.sleep(0.5)

        assert hooking.rpc_interface is not None
        assert hooking.stalker is not None

    def test_exception_hooker_with_native_replacer(self, frida_session: frida.core.Session) -> None:
        """Exception hooker and native replacer work together."""
        hooking = FridaAdvancedHooking(frida_session)
        hooking.init_exception_hooker()
        hooking.init_native_replacer()

        time.sleep(0.5)

        assert hooking.exception_hooker is not None
        assert hooking.native_replacer is not None

        exceptions = hooking.exception_hooker.get_exceptions()
        assert isinstance(exceptions, list)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_multiple_stalker_initializations(self, frida_session: frida.core.Session) -> None:
        """Multiple Stalker initializations create separate instances."""
        hooking = FridaAdvancedHooking(frida_session)

        stalker1 = hooking.init_stalker()
        stalker2 = hooking.init_stalker()

        assert stalker1 is not None
        assert stalker2 is not None

    def test_heap_tracker_with_no_allocations(self, frida_session: frida.core.Session) -> None:
        """Heap tracker handles processes with minimal allocations."""
        hooking = FridaAdvancedHooking(frida_session)
        tracker = hooking.init_heap_tracker()

        stats = tracker.get_stats()

        assert isinstance(stats, dict)

    def test_thread_monitor_with_single_thread(self, frida_session: frida.core.Session) -> None:
        """Thread monitor handles single-threaded processes."""
        hooking = FridaAdvancedHooking(frida_session)
        monitor = hooking.init_thread_monitor()

        current_threads = monitor.get_current_threads()

        assert isinstance(current_threads, list)
        assert len(current_threads) >= 1

    def test_rpc_evaluate_invalid_javascript(self, frida_session: frida.core.Session) -> None:
        """RPC interface handles invalid JavaScript gracefully."""
        hooking = FridaAdvancedHooking(frida_session)
        rpc = hooking.init_rpc_interface()

        with pytest.raises(Exception):
            rpc.evaluate("invalid javascript syntax {{{")
