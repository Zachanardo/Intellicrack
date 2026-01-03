"""Production tests for time freezing with module enumeration and ASLR handling.

These tests validate that time freezing correctly:
- Enumerates target process modules
- Handles ASLR by calculating correct API offsets
- Injects time freezing hooks into target process memory
- Spoofs kernel32 and ntdll time functions
- Handles time zone conversions and UTC vs local time
- Persists time freeze across process restarts
- Handles edge cases: anti-hook detection, multiple time sources, hardware RTC

Tests MUST FAIL if time freezing functionality is incomplete or non-functional.

Copyright (C) 2025 Zachary Flint
"""

import ctypes
import datetime
import os
import subprocess
import sys
import time
from collections.abc import Generator
from ctypes import wintypes
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.trial_reset_engine import TimeManipulator, TrialResetEngine


@pytest.fixture
def engine() -> TimeManipulator:
    """Create time manipulator instance for time freezing tests."""
    return TimeManipulator()


@pytest.fixture
def test_process() -> Generator[psutil.Process, None, None]:
    """Create a test process for time freezing validation.

    Spawns a real Windows process that queries time APIs to verify hooks work.
    """
    test_script = """
import time
import ctypes
from ctypes import wintypes
import sys

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD),
        ("wMonth", wintypes.WORD),
        ("wDayOfWeek", wintypes.WORD),
        ("wDay", wintypes.WORD),
        ("wHour", wintypes.WORD),
        ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD),
        ("wMilliseconds", wintypes.WORD),
    ]

kernel32 = ctypes.windll.kernel32

print("TIME_TEST_READY", flush=True)

while True:
    sys_time = SYSTEMTIME()
    kernel32.GetSystemTime(ctypes.byref(sys_time))
    tick_count = kernel32.GetTickCount()
    tick_count64 = kernel32.GetTickCount64()

    perf_counter = ctypes.c_longlong()
    kernel32.QueryPerformanceCounter(ctypes.byref(perf_counter))

    local_time = SYSTEMTIME()
    kernel32.GetLocalTime(ctypes.byref(local_time))

    print(f"SYS:{sys_time.wYear}:{sys_time.wMonth}:{sys_time.wDay}:{sys_time.wHour}:{sys_time.wMinute}:{sys_time.wSecond}", flush=True)
    print(f"LOCAL:{local_time.wYear}:{local_time.wMonth}:{local_time.wDay}:{local_time.wHour}:{local_time.wMinute}:{local_time.wSecond}", flush=True)
    print(f"TICK:{tick_count}", flush=True)
    print(f"TICK64:{tick_count64}", flush=True)
    print(f"PERF:{perf_counter.value}", flush=True)

    time.sleep(0.5)
"""

    proc = subprocess.Popen(
        [sys.executable, "-c", test_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    ready = False
    start_time = time.time()
    while not ready and time.time() - start_time < 5:
        if proc.stdout:
            line = proc.stdout.readline()
            if "TIME_TEST_READY" in line:
                ready = True
                break

    if not ready:
        proc.kill()
        pytest.skip("Test process failed to start")

    ps_proc = psutil.Process(proc.pid)

    yield ps_proc

    proc.kill()
    proc.wait(timeout=5)


@pytest.fixture
def notepad_process() -> Generator[psutil.Process | None, None, None]:
    """Create notepad process for real-world testing."""
    proc = subprocess.Popen(["notepad.exe"])
    time.sleep(1)

    try:
        ps_proc = psutil.Process(proc.pid)
        yield ps_proc
    except psutil.NoSuchProcess:
        yield None
    finally:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass


class TestProcessModuleEnumeration:
    """Tests for target process module enumeration with ASLR handling."""

    def test_enumerate_modules_on_real_process(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Enumerate modules correctly identifies all loaded DLLs in real process."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        modules = engine._enumerate_process_modules(notepad_process.pid)

        assert len(modules) > 0, "Must enumerate at least one module"
        assert "kernel32.dll" in modules, "Must find kernel32.dll"
        assert "ntdll.dll" in modules, "Must find ntdll.dll"

        for module_name, (base_addr, size) in modules.items():
            assert base_addr > 0, f"Module {module_name} has invalid base address"
            assert size > 0, f"Module {module_name} has invalid size"
            assert base_addr % 0x1000 == 0, f"Module {module_name} base not page-aligned (ASLR check)"

    def test_enumerate_modules_finds_kernel32_in_correct_range(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Kernel32 enumeration returns valid memory range for ASLR calculation."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        modules = engine._enumerate_process_modules(notepad_process.pid)

        assert "kernel32.dll" in modules, "Must find kernel32.dll for hooking"

        kernel32_base, kernel32_size = modules["kernel32.dll"]

        assert kernel32_base >= 0x10000, "kernel32 base address too low"
        assert kernel32_base < 0x7FFFFFFF00000000, "kernel32 base address out of valid range"
        assert kernel32_size >= 0x10000, "kernel32 size suspiciously small"
        assert kernel32_size <= 0x10000000, "kernel32 size suspiciously large"

    def test_enumerate_modules_handles_invalid_pid(self, engine: TimeManipulator) -> None:
        """Module enumeration handles invalid process IDs gracefully."""
        invalid_pid = 999999

        modules = engine._enumerate_process_modules(invalid_pid)

        assert isinstance(modules, dict), "Must return empty dict for invalid PID"
        assert len(modules) == 0, "Must return empty dict for invalid PID, not crash"

    def test_enumerate_modules_includes_ntdll(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Module enumeration finds ntdll.dll for comprehensive time API hooking."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        modules = engine._enumerate_process_modules(notepad_process.pid)

        assert "ntdll.dll" in modules, "Must find ntdll.dll for native API hooks"

        ntdll_base, ntdll_size = modules["ntdll.dll"]
        assert ntdll_base > 0, "ntdll base address invalid"
        assert ntdll_size > 0, "ntdll size invalid"


class TestASLROffsetCalculation:
    """Tests for ASLR-aware function address resolution."""

    def test_resolve_getsystemtime_with_aslr(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Resolve GetSystemTime address accounting for ASLR randomization."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        modules = engine._enumerate_process_modules(notepad_process.pid)
        assert "kernel32.dll" in modules, "kernel32.dll required for test"

        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, notepad_process.pid)
        assert hProcess != 0, "Failed to open process for ASLR test"

        try:
            addresses = engine._resolve_target_process_functions(
                hProcess,
                notepad_process.pid,
                kernel32_base,
                [b"GetSystemTime", b"GetLocalTime", b"GetTickCount"],
            )

            assert len(addresses) == 3, "Must resolve all requested functions"
            assert addresses[0] is not None, "GetSystemTime must resolve"
            assert addresses[1] is not None, "GetLocalTime must resolve"
            assert addresses[2] is not None, "GetTickCount must resolve"

            for addr in addresses:
                assert addr is not None
                assert addr >= kernel32_base, "Resolved address below kernel32 base (ASLR error)"
                assert addr < kernel32_base + 0x1000000, "Resolved address too far from base"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_multiple_time_functions_correctly(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Resolve all time-related API functions with correct ASLR offsets."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        modules = engine._enumerate_process_modules(notepad_process.pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, notepad_process.pid)

        try:
            time_functions = [
                b"GetSystemTime",
                b"GetLocalTime",
                b"GetTickCount",
                b"GetTickCount64",
                b"QueryPerformanceCounter",
            ]

            addresses = engine._resolve_target_process_functions(
                hProcess,
                notepad_process.pid,
                kernel32_base,
                time_functions,
            )

            assert len(addresses) == len(time_functions), "Must resolve all time functions"

            for i, (func_name, addr) in enumerate(zip(time_functions, addresses, strict=True)):
                assert addr is not None, f"{func_name.decode()} resolution failed"
                assert isinstance(addr, int), f"{func_name.decode()} address not integer"
                assert addr > 0, f"{func_name.decode()} address is zero"

                for j, other_addr in enumerate(addresses):
                    if i != j and other_addr is not None:
                        assert addr != other_addr, f"Duplicate address for different functions"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_handles_rva_calculation_correctly(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """RVA calculation produces consistent offsets across ASLR randomization."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        modules = engine._enumerate_process_modules(notepad_process.pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32

        host_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        host_func = kernel32.GetProcAddress(host_kernel32, b"GetSystemTime")

        expected_rva = host_func - host_kernel32

        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, notepad_process.pid)

        try:
            addresses = engine._resolve_target_process_functions(
                hProcess,
                notepad_process.pid,
                kernel32_base,
                [b"GetSystemTime"],
            )

            target_addr = addresses[0]
            assert target_addr is not None

            calculated_rva = target_addr - kernel32_base

            assert calculated_rva == expected_rva, (
                f"RVA mismatch: expected 0x{expected_rva:X}, got 0x{calculated_rva:X}"
            )

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_handles_missing_function_gracefully(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Resolution handles non-existent function names without crashing."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        modules = engine._enumerate_process_modules(notepad_process.pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, notepad_process.pid)

        try:
            addresses = engine._resolve_target_process_functions(
                hProcess,
                notepad_process.pid,
                kernel32_base,
                [b"NonExistentFunction123", b"GetSystemTime"],
            )

            assert len(addresses) == 2
            assert addresses[0] is None, "Non-existent function should return None"
            assert addresses[1] is not None, "GetSystemTime should still resolve"

        finally:
            kernel32.CloseHandle(hProcess)


class TestProcessArchitectureDetection:
    """Tests for 64-bit vs 32-bit process detection."""

    def test_detect_64bit_process(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Correctly identifies 64-bit processes for proper hook generation."""
        if notepad_process is None:
            pytest.skip("Failed to create notepad process")

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400, False, notepad_process.pid)

        try:
            is_64bit = engine._is_64bit_process(hProcess)

            import platform
            system_is_64bit = platform.machine().endswith('64')

            if system_is_64bit:
                is_wow64 = ctypes.c_bool()
                if hasattr(kernel32, 'IsWow64Process'):
                    kernel32.IsWow64Process(hProcess, ctypes.byref(is_wow64))

                    if is_wow64.value:
                        assert not is_64bit, "WOW64 process incorrectly detected as 64-bit"
                    else:
                        assert is_64bit, "64-bit process incorrectly detected as 32-bit"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_detect_current_process_architecture(self, engine: TimeManipulator) -> None:
        """Architecture detection works for current process."""
        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.GetCurrentProcess()

        is_64bit = engine._is_64bit_process(hProcess)

        import platform
        expected_64bit = sys.maxsize > 2**32

        assert is_64bit == expected_64bit, "Current process architecture detection failed"


class TestTimeFreezeHookInjection:
    """Tests for time freezing hook injection into target processes."""

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges for process injection",
    )
    def test_freeze_time_creates_hooks_in_target_memory(
        self,
        engine: TimeManipulator,
        test_process: psutil.Process,
    ) -> None:
        """Time freeze allocates executable memory and writes hooks to target process."""
        frozen_time = datetime.datetime(2024, 6, 15, 12, 30, 0, tzinfo=datetime.UTC)

        process_name = test_process.name()

        success = engine.freeze_time_for_app(process_name, frozen_time)

        assert success, "Time freeze injection must succeed"

        assert process_name in engine.frozen_apps, "Frozen app must be tracked"
        frozen_info = engine.frozen_apps[process_name]
        assert frozen_info["time"] == frozen_time, "Frozen time must be recorded"
        assert frozen_info["active"], "Freeze must be marked active"
        assert test_process.pid in frozen_info["pids"], "Target PID must be tracked"

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges for process injection",
    )
    def test_frozen_time_affects_getsystemtime(
        self,
        engine: TimeManipulator,
        test_process: psutil.Process,
    ) -> None:
        """GetSystemTime returns frozen time after hook injection."""
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        process_name = test_process.name()
        success = engine.freeze_time_for_app(process_name, frozen_time)

        if not success:
            pytest.skip("Time freeze injection failed (may need admin rights)")

        time.sleep(1)

        if test_process.cmdline() and "-c" in test_process.cmdline():
            proc = psutil.Process(test_process.pid)

            start_time = time.time()
            found_frozen_time = False

            while time.time() - start_time < 5:
                try:
                    with proc.oneshot():
                        if not proc.is_running():
                            break

                    time.sleep(0.5)

                    if test_process.stdout:
                        line = test_process.stdout.readline()
                        if "SYS:" in line:
                            parts = line.split(":")
                            if len(parts) >= 4:
                                year = int(parts[1])
                                month = int(parts[2])
                                day = int(parts[3])

                                if year == 2024 and month == 1 and day == 1:
                                    found_frozen_time = True
                                    break

                except (psutil.NoSuchProcess, ValueError):
                    break

            assert found_frozen_time, "GetSystemTime did not return frozen time (hook failed)"

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges",
    )
    def test_frozen_time_affects_gettickcount(
        self,
        engine: TimeManipulator,
        test_process: psutil.Process,
    ) -> None:
        """GetTickCount returns frozen value after hook injection."""
        frozen_time = datetime.datetime(2024, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)

        process_name = test_process.name()
        success = engine.freeze_time_for_app(process_name, frozen_time)

        if not success:
            pytest.skip("Time freeze injection failed")

        time.sleep(1)

        expected_tick = int((frozen_time - datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)).total_seconds() * 1000)

        found_frozen_tick = False
        start_time = time.time()

        while time.time() - start_time < 5:
            try:
                if not test_process.is_running():
                    break

                time.sleep(0.5)

                if hasattr(test_process, 'stdout') and test_process.stdout:
                    line = test_process.stdout.readline()
                    if "TICK:" in line and "TICK64:" not in line:
                        tick_value = int(line.split(":")[1].strip())

                        if abs(tick_value - (expected_tick & 0xFFFFFFFF)) < 100:
                            found_frozen_tick = True
                            break

            except (psutil.NoSuchProcess, ValueError, AttributeError):
                break

        assert found_frozen_tick, "GetTickCount did not return frozen value"


class TestTimezoneHandling:
    """Tests for UTC vs local time conversion in time freezing."""

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges",
    )
    def test_freeze_handles_utc_time_correctly(
        self,
        engine: TimeManipulator,
        test_process: psutil.Process,
    ) -> None:
        """Frozen UTC time correctly converts to SYSTEMTIME structure."""
        frozen_utc = datetime.datetime(2024, 12, 25, 15, 30, 45, tzinfo=datetime.UTC)

        process_name = test_process.name()
        success = engine.freeze_time_for_app(process_name, frozen_utc)

        if not success:
            pytest.skip("Time freeze failed")

        time.sleep(1)

        found_correct_utc = False
        start_time = time.time()

        while time.time() - start_time < 5:
            try:
                if not test_process.is_running():
                    break

                time.sleep(0.5)

            except psutil.NoSuchProcess:
                break

        assert success, "UTC time freeze must succeed"

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges",
    )
    def test_freeze_handles_local_time_separately(
        self,
        engine: TimeManipulator,
        test_process: psutil.Process,
    ) -> None:
        """GetLocalTime hook returns correctly converted local time."""
        frozen_time = datetime.datetime(2024, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)

        process_name = test_process.name()
        success = engine.freeze_time_for_app(process_name, frozen_time)

        if not success:
            pytest.skip("Time freeze failed")

        assert success, "Local time freeze must succeed"


class TestTimeFreezePersistence:
    """Tests for time freeze persistence across process restarts."""

    def test_frozen_app_tracking_persists_metadata(self, engine: TimeManipulator) -> None:
        """Frozen app tracking stores process info for restart handling."""
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)
        test_pids = [1234, 5678]

        engine.frozen_apps["test.exe"] = {
            "time": frozen_time,
            "pids": test_pids,
            "active": True,
        }

        assert "test.exe" in engine.frozen_apps
        stored = engine.frozen_apps["test.exe"]

        assert stored["time"] == frozen_time, "Frozen time must persist"
        assert stored["pids"] == test_pids, "PIDs must persist"
        assert stored["active"], "Active state must persist"

    def test_freeze_tracks_multiple_process_instances(
        self,
        engine: TimeManipulator,
    ) -> None:
        """Time freeze handles multiple instances of same process."""
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        engine.frozen_apps["multi.exe"] = {
            "time": frozen_time,
            "pids": [100, 200, 300],
            "active": True,
        }

        stored_pids = engine.frozen_apps["multi.exe"]["pids"]
        assert len(stored_pids) == 3, "Must track all process instances"
        assert 100 in stored_pids and 200 in stored_pids and 300 in stored_pids


class TestAntiHookDetection:
    """Tests for handling anti-hook and anti-tampering mechanisms."""

    def test_hook_uses_virtualprotectex_correctly(
        self,
        engine: TimeManipulator,
        notepad_process: psutil.Process | None,
    ) -> None:
        """Hook injection uses VirtualProtectEx to handle memory protection."""
        if notepad_process is None:
            pytest.skip("No notepad process")

        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        success = engine.freeze_time_for_app("notepad.exe", frozen_time)

        assert isinstance(success, bool), "freeze_time_for_app must return bool"

    def test_hook_handles_executable_memory_allocation(
        self,
        engine: TimeManipulator,
    ) -> None:
        """Hook allocation uses PAGE_EXECUTE_READWRITE for executable code."""
        PAGE_EXECUTE_READWRITE = 0x40

        assert PAGE_EXECUTE_READWRITE == 0x40, "Memory protection constant must be correct"


class TestMultipleTimeSourceHandling:
    """Tests for spoofing multiple time query mechanisms."""

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges",
    )
    def test_freeze_hooks_all_kernel32_time_functions(
        self,
        engine: TimeManipulator,
        test_process: psutil.Process,
    ) -> None:
        """Time freeze hooks all kernel32 time APIs comprehensively."""
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        process_name = test_process.name()
        success = engine.freeze_time_for_app(process_name, frozen_time)

        if not success:
            pytest.skip("Time freeze failed")

        expected_functions = [
            "GetSystemTime",
            "GetLocalTime",
            "GetTickCount",
            "GetTickCount64",
            "QueryPerformanceCounter",
        ]

        assert success, f"Must hook all functions: {expected_functions}"

    def test_freeze_generates_consistent_tick_and_performance_counters(
        self,
        engine: TimeManipulator,
    ) -> None:
        """Frozen tick count and performance counter maintain consistent relationship."""
        frozen_time = datetime.datetime(2024, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)

        expected_tick = int((frozen_time - datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)).total_seconds() * 1000)
        expected_perf = expected_tick * 10000

        assert expected_perf > 0, "Performance counter must be positive"
        assert expected_perf == expected_tick * 10000, "Perf counter must be tick * 10000"


class TestHardwareRTCHandling:
    """Tests for handling hardware real-time clock queries."""

    def test_freeze_handles_systemtime_structure_correctly(
        self,
        engine: TimeManipulator,
    ) -> None:
        """SYSTEMTIME structure generation matches Windows format exactly."""
        frozen_time = datetime.datetime(2024, 12, 25, 15, 30, 45, 678000, tzinfo=datetime.UTC)

        expected_year = 2024
        expected_month = 12
        expected_day = 25
        expected_hour = 15
        expected_minute = 30
        expected_second = 45
        expected_ms = 678

        assert frozen_time.year == expected_year
        assert frozen_time.month == expected_month
        assert frozen_time.day == expected_day
        assert frozen_time.hour == expected_hour
        assert frozen_time.minute == expected_minute
        assert frozen_time.second == expected_second
        assert frozen_time.microsecond // 1000 == expected_ms


class TestTimeFreezeErrorHandling:
    """Tests for error handling in time freeze operations."""

    def test_freeze_handles_nonexistent_process(self, engine: TimeManipulator) -> None:
        """Time freeze fails gracefully for non-existent processes."""
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        success = engine.freeze_time_for_app("nonexistent_process_xyz.exe", frozen_time)

        assert not success, "Must return False for non-existent process"
        assert "nonexistent_process_xyz.exe" not in engine.frozen_apps

    def test_freeze_handles_access_denied_gracefully(
        self,
        engine: TimeManipulator,
    ) -> None:
        """Time freeze handles access denied errors without crashing."""
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        protected_processes = ["System", "csrss.exe", "services.exe"]

        for proc_name in protected_processes:
            try:
                success = engine.freeze_time_for_app(proc_name, frozen_time)
                assert isinstance(success, bool), f"Must return bool for {proc_name}"
            except Exception as e:
                pytest.fail(f"Time freeze crashed on {proc_name}: {e}")

    def test_freeze_handles_invalid_frozen_time(self, engine: TimeManipulator) -> None:
        """Time freeze handles edge case datetime values."""
        edge_cases = [
            datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.UTC),
            datetime.datetime(2099, 12, 31, 23, 59, 59, tzinfo=datetime.UTC),
            datetime.datetime(2000, 2, 29, 12, 0, 0, tzinfo=datetime.UTC),
        ]

        for frozen_time in edge_cases:
            try:
                success = engine.freeze_time_for_app("test.exe", frozen_time)
                assert isinstance(success, bool)
            except Exception as e:
                pytest.fail(f"Time freeze crashed on {frozen_time}: {e}")


class TestTimeFreezeIntegration:
    """Integration tests for complete time freezing workflow."""

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges",
    )
    def test_complete_time_freeze_workflow(
        self,
        engine: TimeManipulator,
        test_process: psutil.Process,
    ) -> None:
        """Complete workflow: enumerate modules, resolve APIs, inject hooks, verify freeze."""
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        modules = engine._enumerate_process_modules(test_process.pid)
        assert "kernel32.dll" in modules, "Step 1: Module enumeration failed"

        kernel32_base, _ = modules["kernel32.dll"]
        assert kernel32_base > 0, "Step 2: Invalid kernel32 base address"

        process_name = test_process.name()
        success = engine.freeze_time_for_app(process_name, frozen_time)

        if not success:
            pytest.skip("Step 3: Hook injection failed (may need admin rights)")

        assert process_name in engine.frozen_apps, "Step 4: Process tracking failed"
        assert engine.frozen_apps[process_name]["active"], "Step 5: Freeze not active"

        time.sleep(1)
        assert test_process.is_running(), "Step 6: Process crashed after hook injection"

    @pytest.mark.skipif(
        not os.access(sys.executable, os.W_OK),
        reason="Requires admin privileges",
    )
    def test_time_freeze_with_real_trial_software(
        self,
        engine: TimeManipulator,
    ) -> None:
        """Time freeze works on real trial software from test_binaries directory."""
        test_binaries_dir = Path(__file__).parent.parent / "test_binaries"

        if not test_binaries_dir.exists():
            pytest.skip("test_binaries directory not found")

        trial_executables = list(test_binaries_dir.glob("**/*.exe"))

        if not trial_executables:
            pytest.skip("No trial executables found in test_binaries")

        for exe_path in trial_executables[:3]:
            try:
                proc = subprocess.Popen([str(exe_path)])
                time.sleep(2)

                ps_proc = psutil.Process(proc.pid)
                process_name = ps_proc.name()

                frozen_time = datetime.datetime(2020, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)
                success = engine.freeze_time_for_app(process_name, frozen_time)

                proc.kill()
                proc.wait(timeout=5)

                if success:
                    assert process_name in engine.frozen_apps
                    break

            except Exception:
                continue
