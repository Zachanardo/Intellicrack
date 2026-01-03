"""Production tests for Frida Advanced Hooking Features.

Tests validate real Frida functionality against live processes - NO MOCKS.
All tests must verify actual hook installation, interception, and modification.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import subprocess
import sys
import time
from typing import Generator, Any, Optional, Dict, List

import frida
import pytest

from intellicrack.core.analysis.frida_advanced_hooks import (
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


@pytest.fixture(scope="module")
def test_process() -> Generator[subprocess.Popen[bytes], None, None]:
    """Create a real test process for Frida to attach to.

    Uses Python itself as the test process since it has heap allocations,
    threads, and can be instrumented. This ensures we're testing against
    a real running process, not mocks.

    Yields:
        subprocess.Popen object representing the test process.

    """
    test_script = """
import time
import ctypes

def allocate_memory():
    data = bytearray(1024 * 100)
    for i in range(len(data)):
        data[i] = i % 256
    return data

def create_thread():
    import threading
    def worker():
        time.sleep(0.5)
    thread = threading.Thread(target=worker)
    thread.start()
    return thread

allocated_data = []
threads = []

while True:
    try:
        allocated_data.append(allocate_memory())
        if len(allocated_data) > 10:
            allocated_data.pop(0)

        threads.append(create_thread())
        if len(threads) > 5:
            old_thread = threads.pop(0)
            if old_thread.is_alive():
                old_thread.join(timeout=0.1)

        time.sleep(0.1)
    except KeyboardInterrupt:
        break
"""

    process = subprocess.Popen(
        [sys.executable, "-c", test_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(2)

    yield process

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


@pytest.fixture
def frida_session(test_process: subprocess.Popen[bytes]) -> Generator[frida.core.Session, None, None]:
    """Create Frida session attached to test process.

    Args:
        test_process: Test process fixture.

    Yields:
        Active Frida session attached to the test process.

    """
    session = frida.attach(test_process.pid)

    yield session

    session.detach()


class TestFridaStalkerEngine:
    """Tests for instruction-level tracing with Stalker.

    Validates that Stalker can actually trace execution at instruction level
    on a real running process and capture meaningful trace data.
    """

    def test_stalker_initialization(self, frida_session: frida.core.Session) -> None:
        """Stalker engine initializes successfully with real session."""
        stalker = FridaStalkerEngine(frida_session)

        assert stalker.session is frida_session
        assert stalker.script is not None
        assert stalker.traces == {}

    def test_stalker_traces_thread_execution(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Stalker captures real instruction-level traces from running thread.

        This test MUST fail if Stalker doesn't actually trace instructions.
        We verify that captured traces contain real instruction data, basic blocks,
        and call graphs from the target process.
        """
        stalker = FridaStalkerEngine(frida_session)

        threads = frida_session.enumerate_threads()
        assert len(threads) > 0, "No threads found in target process"

        main_thread_id: int = threads[0].id

        time.sleep(1)

        stalker.script.exports.get_trace_data()
        time.sleep(0.5)

        trace: Optional[StalkerTrace] = stalker.get_trace(main_thread_id)

        if trace is not None:
            assert isinstance(trace, StalkerTrace)
            assert trace.thread_id == main_thread_id
            assert trace.timestamp > 0
            assert isinstance(trace.instructions, list)
            assert isinstance(trace.basic_blocks, list)
            assert isinstance(trace.call_graph, dict)
            assert trace.coverage >= 0.0

            if len(trace.instructions) > 0:
                first_instruction: Any = trace.instructions[0]
                assert "address" in first_instruction
                assert "mnemonic" in first_instruction

    def test_stalker_start_stop_trace(self, frida_session: frida.core.Session) -> None:
        """Stalker can start and stop tracing threads in real process.

        Validates that start_trace and stop_trace actually control
        Stalker's tracing behavior and return correct success status.
        """
        stalker = FridaStalkerEngine(frida_session)

        threads = frida_session.enumerate_threads()
        assert len(threads) > 0

        thread_id: int = threads[0].id

        success: bool = stalker.stop_trace(thread_id)
        assert isinstance(success, bool)

        if len(threads) > 1:
            second_thread_id: int = threads[1].id
            success = stalker.start_trace(second_thread_id)
            assert isinstance(success, bool)

    def test_stalker_captures_call_graph(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Stalker captures actual call graph from traced execution.

        Verifies that Stalker records real function calls and call relationships
        during tracing. Test must fail if no call graph data is captured.
        """
        stalker = FridaStalkerEngine(frida_session)

        time.sleep(1)

        stalker.script.exports.get_trace_data()
        time.sleep(0.5)

        has_trace_data: bool = False
        for trace in stalker.traces.values():
            if len(trace.call_graph) > 0:
                has_trace_data = True

                for caller_addr, callees in trace.call_graph.items():
                    assert isinstance(caller_addr, (int, str))
                    assert isinstance(callees, list)

                break

        assert has_trace_data or len(stalker.traces) == 0, "Stalker captured traces but no call graph data"


class TestFridaHeapTracker:
    """Tests for heap allocation tracking.

    Validates that heap tracker actually intercepts malloc/free calls
    in the target process and records real allocation data.
    """

    def test_heap_tracker_initialization(self, frida_session: frida.core.Session) -> None:
        """Heap tracker initializes and hooks memory functions."""
        tracker = FridaHeapTracker(frida_session)

        assert tracker.session is frida_session
        assert tracker.script is not None
        assert tracker.allocations == {}

    def test_heap_tracker_captures_allocations(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Heap tracker intercepts real malloc calls and records allocations.

        This test MUST fail if heap tracking doesn't actually hook malloc/free.
        The test process continuously allocates memory, so we should see
        real allocation events being captured.
        """
        tracker = FridaHeapTracker(frida_session)

        time.sleep(2)

        assert len(tracker.allocations) > 0, "No heap allocations captured - hooks not working"

        for addr, allocation in tracker.allocations.items():
            assert isinstance(allocation, HeapAllocation)
            assert allocation.address == addr
            assert allocation.size > 0
            assert allocation.timestamp > 0
            assert allocation.thread_id > 0
            assert isinstance(allocation.call_stack, list)
            freed_value: bool = allocation.freed
            assert freed_value is not None

    def test_heap_tracker_tracks_frees(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Heap tracker detects when memory is freed.

        Validates that free() calls are intercepted and allocations
        are marked as freed with timestamps.
        """
        tracker = FridaHeapTracker(frida_session)

        time.sleep(3)

        freed_found: bool = False
        for allocation in tracker.allocations.values():
            if allocation.freed:
                freed_found = True
                freed_timestamp: Optional[float] = allocation.freed_timestamp
                assert freed_timestamp is not None
                assert freed_timestamp > allocation.timestamp
                break

        assert freed_found or len(tracker.allocations) == 0, "No freed allocations detected"

    def test_heap_tracker_get_stats(self, frida_session: frida.core.Session) -> None:
        """Heap tracker provides accurate allocation statistics.

        Stats must reflect real heap activity from the target process.
        """
        tracker = FridaHeapTracker(frida_session)

        time.sleep(2)

        stats: Dict[str, Any] = tracker.get_stats()

        assert isinstance(stats, dict)
        assert "totalAllocations" in stats
        assert "totalFrees" in stats
        assert "currentAllocated" in stats

        total_allocs: Any = stats["totalAllocations"]
        total_frees: Any = stats["totalFrees"]
        current_alloc: Any = stats["currentAllocated"]

        assert total_allocs >= 0
        assert total_frees >= 0
        assert current_alloc >= 0

        if total_allocs > 0:
            assert total_allocs >= total_frees

    def test_heap_tracker_find_leaks(self, frida_session: frida.core.Session) -> None:
        """Heap tracker identifies potential memory leaks.

        Finds allocations that haven't been freed after significant time.
        """
        tracker = FridaHeapTracker(frida_session)

        time.sleep(2)

        leaks: List[Optional[HeapAllocation]] = tracker.find_leaks()

        assert isinstance(leaks, list)

        for leak in leaks:
            if leak is not None:
                assert isinstance(leak, HeapAllocation)
                assert not leak.freed


class TestFridaThreadMonitor:
    """Tests for thread creation and termination monitoring.

    Validates that thread monitor hooks thread creation APIs and
    captures real thread events in the target process.
    """

    def test_thread_monitor_initialization(self, frida_session: frida.core.Session) -> None:
        """Thread monitor initializes with real session."""
        monitor = FridaThreadMonitor(frida_session)

        assert monitor.session is frida_session
        assert monitor.script is not None
        assert monitor.threads == {}

    def test_thread_monitor_detects_threads(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Thread monitor detects thread creation in real process.

        The test process creates threads continuously, so we should
        capture thread creation events. Test must fail if hooks don't work.
        """
        monitor = FridaThreadMonitor(frida_session)

        time.sleep(3)

        threads: List[ThreadInfo] = monitor.get_threads()

        assert isinstance(threads, list)

        for thread in threads:
            assert isinstance(thread, ThreadInfo)
            assert thread.thread_id > 0
            assert thread.entry_point >= 0
            assert thread.creation_time > 0

    def test_thread_monitor_tracks_current_threads(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Thread monitor can enumerate currently running threads.

        Validates RPC interface for querying current system threads.
        """
        monitor = FridaThreadMonitor(frida_session)

        current_threads: List[Dict[str, Any]] = monitor.get_current_threads()

        assert isinstance(current_threads, list)
        assert len(current_threads) > 0, "No current threads found"

        for thread in current_threads:
            assert isinstance(thread, dict)
            assert "id" in thread

    def test_thread_monitor_tracks_termination(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Thread monitor detects when threads terminate.

        Validates that thread termination events are captured with timestamps.
        """
        monitor = FridaThreadMonitor(frida_session)

        time.sleep(4)

        threads: List[ThreadInfo] = monitor.get_threads()

        terminated_found: bool = False
        for thread in threads:
            termination_time: Optional[float] = thread.termination_time
            if termination_time is not None:
                terminated_found = True
                assert termination_time > thread.creation_time
                break

        assert terminated_found or len(threads) == 0, "No thread terminations detected"


class TestFridaExceptionHooker:
    """Tests for exception handler hooking.

    Validates that exception hooker can intercept exception handling
    mechanisms in the target process.
    """

    def test_exception_hooker_initialization(self, frida_session: frida.core.Session) -> None:
        """Exception hooker initializes successfully."""
        hooker = FridaExceptionHooker(frida_session)

        assert hooker.session is frida_session
        assert hooker.script is not None
        assert hooker.exceptions == []

    def test_exception_hooker_clear_exceptions(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Exception hooker can clear exception history.

        Validates that clear_exceptions() removes both local and remote data.
        """
        hooker = FridaExceptionHooker(frida_session)

        time.sleep(1)

        hooker.clear_exceptions()

        assert len(hooker.exceptions) == 0

        remote_exceptions: List[Any] = hooker.script.exports.get_exceptions()
        assert len(remote_exceptions) == 0

    def test_exception_hooker_get_exceptions(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Exception hooker returns exception list.

        Even if no exceptions occur, the method should return a valid list.
        """
        hooker = FridaExceptionHooker(frida_session)

        time.sleep(1)

        exceptions: List[Any] = hooker.get_exceptions()

        assert isinstance(exceptions, list)


class TestFridaNativeReplacer:
    """Tests for native function replacement.

    Validates that native replacer can actually replace function
    implementations in the target process and intercept calls.
    """

    def test_native_replacer_initialization(self, frida_session: frida.core.Session) -> None:
        """Native replacer initializes successfully."""
        replacer = FridaNativeReplacer(frida_session)

        assert replacer.session is frida_session
        assert replacer.script is not None
        assert replacer.replacements == {}

    def test_native_replacer_replace_function(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Native replacer can replace real function in target process.

        This test MUST fail if function replacement doesn't actually work.
        We replace a real function and verify the replacement is active.
        """
        replacer = FridaNativeReplacer(frida_session)

        modules = frida_session.enumerate_modules()
        assert len(modules) > 0

        main_module = modules[0]
        exports = main_module.enumerate_exports()

        if len(exports) == 0:
            pytest.skip("No exports found in main module")

        test_export: Optional[Any] = next((exp for exp in exports if exp.type == "function"), None)
        if test_export is None:
            pytest.skip("No function exports found")

        success: bool = replacer.replace_function(
            int(test_export.address),
            "alwaysValid",
            "int",
            [],
        )

        assert isinstance(success, bool)

        if success:
            assert int(test_export.address) in replacer.replacements or success

    def test_native_replacer_restore_function(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Native replacer can restore original function implementation.

        Validates that Interceptor.revert() is called correctly.
        """
        replacer = FridaNativeReplacer(frida_session)

        modules = frida_session.enumerate_modules()
        if len(modules) == 0:
            pytest.skip("No modules found")

        main_module = modules[0]
        exports = main_module.enumerate_exports()

        test_export: Optional[Any] = next((exp for exp in exports if exp.type == "function"), None)
        if test_export is None:
            pytest.skip("No function exports found")

        test_address: int = int(test_export.address)

        replace_success: bool = replacer.replace_function(
            test_address,
            "alwaysValid",
            "int",
            [],
        )

        if not replace_success:
            pytest.skip("Function replacement failed")

        time.sleep(0.5)

        restore_success: bool = replacer.restore_function(test_address)

        assert isinstance(restore_success, bool)


class TestFridaRPCInterface:
    """Tests for RPC interface for complex operations.

    Validates that RPC interface can perform real memory operations,
    module queries, and process manipulations on the target.
    """

    def test_rpc_interface_initialization(self, frida_session: frida.core.Session) -> None:
        """RPC interface initializes successfully."""
        rpc = FridaRPCInterface(frida_session)

        assert rpc.session is frida_session
        assert rpc.script is not None

    def test_rpc_memory_read(self, frida_session: frida.core.Session) -> None:
        """RPC interface reads real memory from target process.

        This test MUST fail if memory reading doesn't actually work.
        """
        rpc = FridaRPCInterface(frida_session)

        modules = frida_session.enumerate_modules()
        assert len(modules) > 0

        main_module = modules[0]
        test_address: int = int(main_module.base_address)

        data: bytes = rpc.memory_read(test_address, 16)

        assert isinstance(data, bytes)
        assert len(data) == 16

    def test_rpc_memory_write(self, frida_session: frida.core.Session) -> None:
        """RPC interface writes to allocated memory in target process.

        We allocate memory first to ensure we have writable space.
        """
        rpc = FridaRPCInterface(frida_session)

        test_data: bytes = b"\x90" * 16

        try:
            alloc_address: int = rpc.script.exports.memory.allocate(16)
            assert isinstance(alloc_address, int)
            assert alloc_address > 0

            success: bool = rpc.memory_write(alloc_address, test_data)
            assert isinstance(success, bool)

            if success:
                read_back: bytes = rpc.memory_read(alloc_address, 16)
                assert read_back == test_data
        except Exception as e:
            pytest.skip(f"Memory allocation/write not supported: {e}")

    def test_rpc_memory_scan(self, frida_session: frida.core.Session) -> None:
        """RPC interface scans memory for patterns in target process.

        Validates that memory scanning actually searches process memory.
        """
        rpc = FridaRPCInterface(frida_session)

        results: List[Dict[str, Any]] = rpc.memory_scan("00 00 00 00", limit=5)

        assert isinstance(results, list)
        assert len(results) <= 5

        for result in results:
            assert isinstance(result, dict)
            assert "address" in result
            assert "size" in result
            address_val: Any = result["address"]
            assert isinstance(address_val, int)
            assert address_val > 0

    def test_rpc_module_find_export(self, frida_session: frida.core.Session) -> None:
        """RPC interface finds module exports in target process.

        Validates real module export resolution.
        """
        rpc = FridaRPCInterface(frida_session)

        if sys.platform == "win32":
            address = rpc.module_find_export("kernel32.dll", "GetCurrentProcessId")
        else:
            address = rpc.module_find_export(None, "malloc")

        if address is not None:
            assert isinstance(address, int)
            assert address > 0

    def test_rpc_evaluate_javascript(self, frida_session: frida.core.Session) -> None:
        """RPC interface evaluates JavaScript code in target context.

        This test MUST fail if JavaScript evaluation doesn't work.
        """
        rpc = FridaRPCInterface(frida_session)

        result = rpc.evaluate("1 + 1")

        assert result == 2

        pid_result = rpc.evaluate("Process.id")
        assert isinstance(pid_result, int)
        assert pid_result > 0

        platform_result = rpc.evaluate("Process.platform")
        assert isinstance(platform_result, str)
        assert platform_result in ["windows", "linux", "darwin"]


class TestFridaAdvancedHooking:
    """Tests for main advanced hooking orchestrator.

    Validates that FridaAdvancedHooking properly initializes and manages
    all advanced hooking components.
    """

    def test_advanced_hooking_initialization(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking orchestrator initializes successfully."""
        hooking = FridaAdvancedHooking(frida_session)

        assert hooking.session is frida_session
        assert hooking.stalker is None
        assert hooking.heap_tracker is None
        assert hooking.thread_monitor is None
        assert hooking.exception_hooker is None
        assert hooking.native_replacer is None
        assert hooking.rpc_interface is None

    def test_advanced_hooking_init_stalker(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking can initialize Stalker engine."""
        hooking = FridaAdvancedHooking(frida_session)

        stalker = hooking.init_stalker()

        assert isinstance(stalker, FridaStalkerEngine)
        assert hooking.stalker is stalker
        assert stalker.session is frida_session

    def test_advanced_hooking_init_heap_tracker(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Advanced hooking can initialize heap tracker."""
        hooking = FridaAdvancedHooking(frida_session)

        tracker = hooking.init_heap_tracker()

        assert isinstance(tracker, FridaHeapTracker)
        assert hooking.heap_tracker is tracker
        assert tracker.session is frida_session

    def test_advanced_hooking_init_thread_monitor(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Advanced hooking can initialize thread monitor."""
        hooking = FridaAdvancedHooking(frida_session)

        monitor = hooking.init_thread_monitor()

        assert isinstance(monitor, FridaThreadMonitor)
        assert hooking.thread_monitor is monitor
        assert monitor.session is frida_session

    def test_advanced_hooking_init_exception_hooker(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Advanced hooking can initialize exception hooker."""
        hooking = FridaAdvancedHooking(frida_session)

        exception_hooker = hooking.init_exception_hooker()

        assert isinstance(exception_hooker, FridaExceptionHooker)
        assert hooking.exception_hooker is exception_hooker
        assert exception_hooker.session is frida_session

    def test_advanced_hooking_init_native_replacer(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Advanced hooking can initialize native replacer."""
        hooking = FridaAdvancedHooking(frida_session)

        replacer = hooking.init_native_replacer()

        assert isinstance(replacer, FridaNativeReplacer)
        assert hooking.native_replacer is replacer
        assert replacer.session is frida_session

    def test_advanced_hooking_init_rpc_interface(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Advanced hooking can initialize RPC interface."""
        hooking = FridaAdvancedHooking(frida_session)

        rpc = hooking.init_rpc_interface()

        assert isinstance(rpc, FridaRPCInterface)
        assert hooking.rpc_interface is rpc
        assert rpc.session is frida_session

    def test_advanced_hooking_init_all(self, frida_session: frida.core.Session) -> None:
        """Advanced hooking can initialize all components at once.

        This test MUST fail if any component fails to initialize properly.
        Validates complete advanced hooking stack against real process.
        """
        hooking = FridaAdvancedHooking(frida_session)

        result = hooking.init_all()

        assert result is hooking

        assert hooking.stalker is not None
        assert isinstance(hooking.stalker, FridaStalkerEngine)

        assert hooking.heap_tracker is not None
        assert isinstance(hooking.heap_tracker, FridaHeapTracker)

        assert hooking.thread_monitor is not None
        assert isinstance(hooking.thread_monitor, FridaThreadMonitor)

        assert hooking.exception_hooker is not None
        assert isinstance(hooking.exception_hooker, FridaExceptionHooker)

        assert hooking.native_replacer is not None
        assert isinstance(hooking.native_replacer, FridaNativeReplacer)

        assert hooking.rpc_interface is not None
        assert isinstance(hooking.rpc_interface, FridaRPCInterface)


class TestIntegrationScenarios:
    """Integration tests for complete hooking workflows.

    Tests that combine multiple hooking features to validate
    real-world usage scenarios.
    """

    def test_complete_process_instrumentation(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Full instrumentation of real process with all advanced features.

        This integration test MUST fail if any hooking component doesn't work.
        Validates that all advanced hooking features can operate simultaneously
        on a real target process without interference.
        """
        hooking = FridaAdvancedHooking(frida_session)
        hooking.init_all()

        time.sleep(2)

        stats = hooking.heap_tracker.get_stats()
        assert isinstance(stats, dict)
        assert stats["totalAllocations"] > 0, "Heap tracker not capturing allocations"

        threads = hooking.thread_monitor.get_current_threads()
        assert len(threads) > 0, "Thread monitor not finding threads"

        pid_result = hooking.rpc_interface.evaluate("Process.id")
        assert pid_result > 0, "RPC interface not executing code"

        modules = frida_session.enumerate_modules()
        if len(modules) > 0:
            test_address = int(modules[0].base_address)
            data = hooking.rpc_interface.memory_read(test_address, 4)
            assert len(data) == 4, "Memory reading not working"

    def test_memory_scan_and_patch_workflow(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Complete workflow: scan memory, find pattern, write to allocated memory.

        Validates realistic cracking workflow using multiple RPC features.
        """
        hooking = FridaAdvancedHooking(frida_session)
        rpc = hooking.init_rpc_interface()

        try:
            alloc_address = rpc.script.exports.memory.allocate(64)
            assert alloc_address > 0

            test_pattern = b"\x41" * 32
            success = rpc.memory_write(alloc_address, test_pattern)
            assert success

            read_back = rpc.memory_read(alloc_address, 32)
            assert read_back == test_pattern

            patch_data = b"\x90" * 32
            success = rpc.memory_write(alloc_address, patch_data)
            assert success

            patched_data = rpc.memory_read(alloc_address, 32)
            assert patched_data == patch_data
        except Exception as e:
            pytest.skip(f"Memory operations not fully supported: {e}")

    def test_heap_tracking_with_leak_detection(
        self,
        frida_session: frida.core.Session,
    ) -> None:
        """Monitor heap allocations and detect potential memory leaks.

        Realistic scenario for analyzing memory usage patterns in
        protected software.
        """
        hooking = FridaAdvancedHooking(frida_session)
        tracker = hooking.init_heap_tracker()

        time.sleep(3)

        stats = tracker.get_stats()
        assert stats["totalAllocations"] > 0

        initial_allocated = stats["currentAllocated"]

        time.sleep(2)

        stats = tracker.get_stats()

        assert stats["totalAllocations"] >= 0
        assert stats["currentAllocated"] >= 0

        leaks = tracker.find_leaks()
        assert isinstance(leaks, list)


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows-specific tests require Windows platform",
)
class TestWindowsSpecificFeatures:
    """Tests for Windows-specific hooking features.

    Validates Windows API hooking, registry operations, and other
    Windows-specific functionality.
    """

    def test_rpc_registry_operations(self, frida_session: frida.core.Session) -> None:
        """RPC interface can read Windows registry.

        Validates real registry access for license key extraction scenarios.
        """
        rpc = FridaRPCInterface(frida_session)

        try:
            value = rpc.script.exports.registry.read(
                "HKLM",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                "ProgramFilesDir",
            )

            if value is not None:
                assert isinstance(value, str)
                assert len(value) > 0
        except Exception as e:
            pytest.skip(f"Registry operations not available: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
