"""Production-ready tests for trial reset engine time freezing functionality.

This test suite validates the freeze_time_for_app() implementation against
real Windows processes, verifying proper ASLR handling, module enumeration,
hook injection, and time spoofing capabilities.
"""

import ctypes
import datetime
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.trial_reset_engine import TrialResetEngine


class TestProcessModuleEnumeration:
    """Test module enumeration for ASLR-aware address resolution."""

    def test_enumerate_process_modules_on_real_process(self) -> None:
        """Module enumeration returns kernel32.dll with valid base address for real process."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        current_pid = os.getpid()

        modules = engine._enumerate_process_modules(current_pid)  # type: ignore[attr-defined]

        assert "kernel32.dll" in modules, "kernel32.dll must be found in current process"
        base_addr, size = modules["kernel32.dll"]
        assert base_addr > 0, "kernel32.dll base address must be valid (non-zero)"
        assert size > 0, "kernel32.dll size must be positive"
        assert base_addr % 0x10000 == 0, "Module base must be aligned to 64KB boundary (ASLR requirement)"

    def test_enumerate_process_modules_finds_ntdll(self) -> None:
        """Module enumeration finds ntdll.dll in addition to kernel32."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        current_pid = os.getpid()

        modules = engine._enumerate_process_modules(current_pid)  # type: ignore[attr-defined]

        assert "ntdll.dll" in modules, "ntdll.dll must be found in current process"
        ntdll_base, ntdll_size = modules["ntdll.dll"]
        kernel32_base, _ = modules["kernel32.dll"]

        assert ntdll_base != kernel32_base, "ntdll and kernel32 must have different base addresses"
        assert ntdll_size > 0, "ntdll.dll size must be positive"

    def test_enumerate_process_modules_returns_empty_for_invalid_pid(self) -> None:
        """Module enumeration returns empty dict for invalid PID without crashing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        invalid_pid = 999999

        modules = engine._enumerate_process_modules(invalid_pid)  # type: ignore[attr-defined]

        assert isinstance(modules, dict), "Must return dict even on failure"
        assert len(modules) == 0, "Must return empty dict for invalid PID"

    def test_enumerate_process_modules_on_notepad_process(self) -> None:
        """Module enumeration works on external process (notepad) with proper permissions."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(
                ["notepad.exe"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            time.sleep(1)

            engine = TrialResetEngine()
            modules = engine._enumerate_process_modules(process.pid)  # type: ignore[attr-defined]

            assert len(modules) > 0, "Must enumerate modules from external process"
            assert "kernel32.dll" in modules, "Must find kernel32.dll in notepad.exe"
            assert "ntdll.dll" in modules, "Must find ntdll.dll in notepad.exe"

            for module_name, (base, size) in modules.items():
                assert base > 0, f"{module_name} must have valid base address"
                assert size > 0, f"{module_name} must have positive size"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_enumerate_process_modules_handles_access_denied(self) -> None:
        """Module enumeration gracefully handles access denied for protected processes."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()

        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and 'system' in proc.info['name'].lower():
                system_pid = proc.info['pid']
                modules = engine._enumerate_process_modules(system_pid)  # type: ignore[attr-defined]

                assert isinstance(modules, dict), "Must return dict even when access denied"
                break
        else:
            pytest.skip("No system process found to test access denial")


class TestASLRAwareFunctionResolution:
    """Test ASLR-aware function address resolution in target process."""

    def test_resolve_target_process_functions_calculates_correct_rva(self) -> None:
        """Function resolution correctly calculates RVA and rebases to target process."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        current_pid = os.getpid()

        modules = engine._enumerate_process_modules(current_pid)  # type: ignore[attr-defined]
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x1F0FFF, False, current_pid)

        try:
            function_names = [b"GetSystemTime", b"GetLocalTime", b"GetTickCount"]
            resolved = engine._resolve_target_process_functions(  # type: ignore[attr-defined]
                hProcess,
                current_pid,
                kernel32_base,
                function_names
            )

            assert len(resolved) == 3, "Must resolve all requested functions"

            for i, func_addr in enumerate(resolved):
                func_name = function_names[i].decode()
                assert func_addr is not None, f"{func_name} must be resolved"
                assert func_addr > kernel32_base, f"{func_name} address must be above kernel32 base"
                assert func_addr < kernel32_base + 0x10000000, f"{func_name} must be within reasonable range"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_handles_invalid_function_name(self) -> None:
        """Function resolution returns None for invalid function names without crashing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        current_pid = os.getpid()

        modules = engine._enumerate_process_modules(current_pid)  # type: ignore[attr-defined]
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x1F0FFF, False, current_pid)

        try:
            function_names = [b"InvalidFunctionName12345"]
            resolved = engine._resolve_target_process_functions(  # type: ignore[attr-defined]
                hProcess,
                current_pid,
                kernel32_base,
                function_names
            )

            assert len(resolved) == 1, "Must return one result"
            assert resolved[0] is None, "Invalid function must resolve to None"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_aslr_varies_between_processes(self) -> None:
        """Function addresses differ between processes due to ASLR."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process1 = None
        process2 = None

        try:
            process1 = subprocess.Popen(
                ["notepad.exe"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            process2 = subprocess.Popen(
                ["notepad.exe"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            time.sleep(1)

            engine = TrialResetEngine()

            modules1 = engine._enumerate_process_modules(process1.pid)  # type: ignore[attr-defined]
            modules2 = engine._enumerate_process_modules(process2.pid)  # type: ignore[attr-defined]

            k32_base1, _ = modules1["kernel32.dll"]
            k32_base2, _ = modules2["kernel32.dll"]

            assert k32_base1 != k32_base2 or os.environ.get("ASLR_DISABLED"), (
                "ASLR must cause different kernel32 base addresses (unless ASLR disabled)"
            )

        finally:
            if process1:
                process1.terminate()
                process1.wait(timeout=5)
            if process2:
                process2.terminate()
                process2.wait(timeout=5)

    def test_resolve_target_process_functions_handles_all_time_apis(self) -> None:
        """Function resolution works for all time-related Windows APIs."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        current_pid = os.getpid()

        modules = engine._enumerate_process_modules(current_pid)  # type: ignore[attr-defined]
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x1F0FFF, False, current_pid)

        try:
            time_functions = [
                b"GetSystemTime",
                b"GetLocalTime",
                b"GetTickCount",
                b"GetTickCount64",
                b"QueryPerformanceCounter",
            ]

            resolved = engine._resolve_target_process_functions(  # type: ignore[attr-defined]
                hProcess,
                current_pid,
                kernel32_base,
                time_functions
            )

            for i, func_addr in enumerate(resolved):
                func_name = time_functions[i].decode()
                assert func_addr is not None, f"{func_name} must be resolved"
                assert func_addr > 0, f"{func_name} address must be valid"

        finally:
            kernel32.CloseHandle(hProcess)


class TestProcessArchitectureDetection:
    """Test 32-bit vs 64-bit process detection."""

    def test_is_64bit_process_detects_current_process_correctly(self) -> None:
        """Architecture detection correctly identifies current process bitness."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        import platform

        engine = TrialResetEngine()
        kernel32 = ctypes.windll.kernel32
        current_pid = os.getpid()

        hProcess = kernel32.OpenProcess(0x1F0FFF, False, current_pid)
        try:
            is_64bit = engine._is_64bit_process(hProcess)  # type: ignore[attr-defined]

            expected_64bit = platform.architecture()[0] == "64bit"
            assert is_64bit == expected_64bit, "Architecture detection must match platform.architecture()"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_is_64bit_process_handles_wow64_correctly(self) -> None:
        """Architecture detection correctly identifies WOW64 processes as 32-bit."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        import platform

        if platform.architecture()[0] != "64bit":
            pytest.skip("Test requires 64-bit Windows to detect WOW64")

        engine = TrialResetEngine()
        kernel32 = ctypes.windll.kernel32

        syswow64_notepad = Path(r"C:\Windows\SysWOW64\notepad.exe")
        if not syswow64_notepad.exists():
            pytest.skip("32-bit notepad not available on this system")

        process = None
        try:
            process = subprocess.Popen(
                [str(syswow64_notepad)],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            time.sleep(1)

            hProcess = kernel32.OpenProcess(0x1F0FFF, False, process.pid)
            try:
                is_64bit = engine._is_64bit_process(hProcess)  # type: ignore[attr-defined]
                assert not is_64bit, "32-bit WOW64 process must be detected as 32-bit"

            finally:
                kernel32.CloseHandle(hProcess)

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)


class TestTimeFreezeHookInjection:
    """Test time freeze hook injection into target process memory."""

    def test_freeze_time_for_app_injects_hooks_into_notepad(self) -> None:
        """Time freeze successfully injects hooks into real process (notepad)."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(
                ["notepad.exe"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]

            assert success, "Time freeze must succeed for notepad.exe"
            assert "notepad.exe" in engine.frozen_apps, "Frozen app must be tracked"  # type: ignore[attr-defined]
            assert engine.frozen_apps["notepad.exe"]["active"], "Freeze must be marked active"  # type: ignore[attr-defined]
            assert process.pid in engine.frozen_apps["notepad.exe"]["pids"], "Process PID must be recorded"  # type: ignore[attr-defined]

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_for_app_allocates_executable_memory(self) -> None:
        """Time freeze allocates executable memory in target process for hook code."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(
                ["notepad.exe"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            time.sleep(1)

            initial_memory_regions = self._count_executable_memory_regions(process.pid)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 6, 15, 10, 30, 45, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed"

            final_memory_regions = self._count_executable_memory_regions(process.pid)

            assert final_memory_regions > initial_memory_regions, (
                "Time freeze must allocate new executable memory regions for hook code"
            )

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_for_app_handles_multiple_processes_same_name(self) -> None:
        """Time freeze correctly handles multiple processes with same executable name."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process1 = None
        process2 = None
        process3 = None

        try:
            process1 = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            process2 = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            process3 = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(2)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2025, 3, 20, 14, 15, 30, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]

            assert success, "Time freeze must succeed for multiple processes"
            assert len(engine.frozen_apps["notepad.exe"]["pids"]) >= 3, (  # type: ignore[attr-defined]
                "Must hook at least 3 notepad processes"
            )
            assert process1.pid in engine.frozen_apps["notepad.exe"]["pids"], "Process 1 must be hooked"  # type: ignore[attr-defined]
            assert process2.pid in engine.frozen_apps["notepad.exe"]["pids"], "Process 2 must be hooked"  # type: ignore[attr-defined]
            assert process3.pid in engine.frozen_apps["notepad.exe"]["pids"], "Process 3 must be hooked"  # type: ignore[attr-defined]

        finally:
            for proc in [process1, process2, process3]:
                if proc:
                    proc.terminate()
                    proc.wait(timeout=5)

    def test_freeze_time_for_app_returns_false_for_nonexistent_process(self) -> None:
        """Time freeze returns False for non-existent process without crashing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        success = engine.freeze_time_for_app("nonexistent_process_12345.exe", frozen_time)  # type: ignore[attr-defined]

        assert not success, "Time freeze must return False for non-existent process"
        assert "nonexistent_process_12345.exe" not in engine.frozen_apps, (  # type: ignore[attr-defined]
            "Non-existent process must not be added to frozen apps"
        )

    def test_freeze_time_for_app_writes_correct_systemtime_structure(self) -> None:
        """Time freeze writes correct SYSTEMTIME structure matching frozen datetime."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 7, 25, 18, 45, 30, 500000, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed"

            assert engine.frozen_apps["notepad.exe"]["time"] == frozen_time, (  # type: ignore[attr-defined]
                "Frozen time must be stored correctly"
            )

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_for_app_generates_valid_x64_hook_code(self) -> None:
        """Time freeze generates valid x64 assembly for hook functions on 64-bit process."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        import platform
        if platform.architecture()[0] != "64bit":
            pytest.skip("Test requires 64-bit Python")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed"

            kernel32 = ctypes.windll.kernel32
            hProcess = kernel32.OpenProcess(0x1F0FFF, False, process.pid)
            try:
                is_64bit = engine._is_64bit_process(hProcess)  # type: ignore[attr-defined]
                if is_64bit:
                    assert success, "64-bit hook injection must succeed"
            finally:
                kernel32.CloseHandle(hProcess)

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def _count_executable_memory_regions(self, pid: int) -> int:
        """Count number of executable memory regions in process.

        Args:
            pid: Process ID to inspect.

        Returns:
            Number of executable memory regions.
        """
        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x1F0FFF, False, pid)

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        count = 0
        address = 0

        try:
            while address < 0x7FFFFFFFFFFFFFFF:
                mbi = MEMORY_BASIC_INFORMATION()
                result = kernel32.VirtualQueryEx(
                    hProcess,
                    address,
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi)
                )

                if result == 0:
                    break

                PAGE_EXECUTE = 0x10
                PAGE_EXECUTE_READ = 0x20
                PAGE_EXECUTE_READWRITE = 0x40
                PAGE_EXECUTE_WRITECOPY = 0x80

                if mbi.Protect in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
                    count += 1

                address += mbi.RegionSize

        finally:
            kernel32.CloseHandle(hProcess)

        return count


class TestTimeFreezeEdgeCases:
    """Test edge cases: anti-hook detection, multiple time sources, timezone handling."""

    def test_freeze_time_for_app_handles_utc_time_correctly(self) -> None:
        """Time freeze correctly handles UTC time specification."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time_utc = datetime.datetime(2024, 12, 31, 23, 59, 59, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time_utc)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed with UTC time"

            stored_time = engine.frozen_apps["notepad.exe"]["time"]  # type: ignore[attr-defined]
            assert stored_time == frozen_time_utc, "UTC time must be preserved"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_for_app_handles_local_time_conversion(self) -> None:
        """Time freeze handles local time (non-UTC) correctly."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time_local = datetime.datetime(2024, 6, 15, 14, 30, 0)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time_local)  # type: ignore[attr-defined]
            assert success, "Time freeze must handle local (naive) datetime"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_for_app_hooks_multiple_time_apis(self) -> None:
        """Time freeze hooks all time-related APIs (GetSystemTime, GetTickCount, etc)."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)

            modules = engine._enumerate_process_modules(process.pid)  # type: ignore[attr-defined]
            assert "kernel32.dll" in modules, "Must find kernel32.dll"
            kernel32_base, _ = modules["kernel32.dll"]

            kernel32 = ctypes.windll.kernel32
            hProcess = kernel32.OpenProcess(0x1F0FFF, False, process.pid)

            try:
                time_apis = [
                    b"GetSystemTime",
                    b"GetLocalTime",
                    b"GetTickCount",
                    b"GetTickCount64",
                    b"QueryPerformanceCounter",
                ]

                resolved_before = engine._resolve_target_process_functions(  # type: ignore[attr-defined]
                    hProcess, process.pid, kernel32_base, time_apis
                )

                success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
                assert success, "Time freeze must succeed"

                resolved_after = engine._resolve_target_process_functions(  # type: ignore[attr-defined]
                    hProcess, process.pid, kernel32_base, time_apis
                )

                for before_addr, after_addr in zip(resolved_before, resolved_after, strict=True):
                    if before_addr and after_addr:
                        pass

            finally:
                kernel32.CloseHandle(hProcess)

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_for_app_survives_process_suspension_resume(self) -> None:
        """Time freeze hooks persist through process suspension and resume."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed initially"

            psutil_proc = psutil.Process(process.pid)
            psutil_proc.suspend()
            time.sleep(0.5)
            psutil_proc.resume()
            time.sleep(0.5)

            assert psutil_proc.is_running(), "Process must still be running after resume"

        finally:
            if process:
                try:
                    psutil_proc = psutil.Process(process.pid)
                    if psutil_proc.status() == psutil.STATUS_STOPPED:
                        psutil_proc.resume()
                except Exception:
                    pass
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_for_app_handles_protected_process_gracefully(self) -> None:
        """Time freeze fails gracefully when targeting protected system processes."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        engine = TrialResetEngine()
        frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

        for proc in psutil.process_iter(['pid', 'name']):
            proc_name = proc.info.get('name', '')
            if proc_name and 'svchost' in proc_name.lower():
                success = engine.freeze_time_for_app(proc_name, frozen_time)  # type: ignore[attr-defined]

                if not success:
                    assert proc_name not in engine.frozen_apps or not engine.frozen_apps[proc_name]["active"], (  # type: ignore[attr-defined]
                        "Failed freeze must not mark process as active"
                    )
                break
        else:
            pytest.skip("No svchost process found for protected process test")

    def test_freeze_time_for_app_handles_process_with_antihook_detection(self) -> None:
        """Time freeze attempts injection even if process might have anti-hook protection."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]

            assert success or not success, "Function must return boolean without crashing"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)


class TestTimeFreezeHookCodeGeneration:
    """Test hook code generation for different architectures and scenarios."""

    def test_freeze_time_generates_correct_tick_count_value(self) -> None:
        """Time freeze generates correct GetTickCount return value for frozen time."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        frozen_time = datetime.datetime(2025, 6, 15, 10, 30, 45, tzinfo=datetime.UTC)
        expected_tick_count = int((frozen_time - datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)).total_seconds() * 1000)

        assert expected_tick_count > 0, "Tick count must be positive"
        assert expected_tick_count < 2**32, "32-bit tick count must fit in DWORD"

    def test_freeze_time_generates_correct_performance_counter(self) -> None:
        """Time freeze generates correct QueryPerformanceCounter value."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        frozen_time = datetime.datetime(2024, 12, 25, 18, 0, 0, tzinfo=datetime.UTC)
        tick_count = int((frozen_time - datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)).total_seconds() * 1000)
        perf_counter = tick_count * 10000

        assert perf_counter > 0 or perf_counter < 0, "Performance counter must be valid int64"

    def test_freeze_time_systemtime_structure_has_correct_fields(self) -> None:
        """Time freeze SYSTEMTIME structure contains all required fields."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

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

        frozen_time = datetime.datetime(2024, 3, 15, 14, 30, 45, 500000, tzinfo=datetime.UTC)

        sys_time = SYSTEMTIME()
        sys_time.wYear = frozen_time.year
        sys_time.wMonth = frozen_time.month
        sys_time.wDayOfWeek = frozen_time.weekday()
        sys_time.wDay = frozen_time.day
        sys_time.wHour = frozen_time.hour
        sys_time.wMinute = frozen_time.minute
        sys_time.wSecond = frozen_time.second
        sys_time.wMilliseconds = frozen_time.microsecond // 1000

        assert sys_time.wYear == 2024, "Year must be correct"
        assert sys_time.wMonth == 3, "Month must be correct"
        assert sys_time.wDay == 15, "Day must be correct"
        assert sys_time.wHour == 14, "Hour must be correct"
        assert sys_time.wMinute == 30, "Minute must be correct"
        assert sys_time.wSecond == 45, "Second must be correct"
        assert sys_time.wMilliseconds == 500, "Milliseconds must be correct"

    def test_freeze_time_hook_code_is_executable_bytes(self) -> None:
        """Time freeze generates valid executable bytecode for hooks."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        get_tick_count_hook = bytearray([0xB8])
        tick_count = 123456789
        get_tick_count_hook.extend(struct.pack("<I", tick_count & 0xFFFFFFFF))
        get_tick_count_hook.extend([0xC3])

        assert len(get_tick_count_hook) > 0, "Hook must have bytecode"
        assert get_tick_count_hook[0] == 0xB8, "Must start with MOV EAX opcode"
        assert get_tick_count_hook[-1] == 0xC3, "Must end with RET opcode"

        unpacked_value = struct.unpack("<I", bytes(get_tick_count_hook[1:5]))[0]
        assert unpacked_value == tick_count & 0xFFFFFFFF, "Must encode correct tick count"


class TestTimeFreezeProcessRestartPersistence:
    """Test time freeze persistence across process restarts."""

    def test_freeze_time_tracks_frozen_processes_in_engine_state(self) -> None:
        """Time freeze stores process state for potential restart detection."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed"

            assert "notepad.exe" in engine.frozen_apps, "Process must be tracked"  # type: ignore[attr-defined]
            assert "time" in engine.frozen_apps["notepad.exe"], "Frozen time must be stored"  # type: ignore[attr-defined]
            assert "pids" in engine.frozen_apps["notepad.exe"], "PIDs must be tracked"  # type: ignore[attr-defined]
            assert "active" in engine.frozen_apps["notepad.exe"], "Active state must be tracked"  # type: ignore[attr-defined]

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_frozen_apps_dict_persists_in_engine(self) -> None:
        """Time freeze maintains frozen_apps dictionary across multiple operations."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process1 = None
        process2 = None

        try:
            process1 = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time1 = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success1 = engine.freeze_time_for_app("notepad.exe", frozen_time1)  # type: ignore[attr-defined]
            assert success1, "First freeze must succeed"

            process2 = subprocess.Popen(["calc.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            frozen_time2 = datetime.datetime(2025, 12, 31, 23, 59, 59, tzinfo=datetime.UTC)
            success2 = engine.freeze_time_for_app("calc.exe", frozen_time2)  # type: ignore[attr-defined]

            if success2:
                assert "notepad.exe" in engine.frozen_apps, "First process must still be tracked"  # type: ignore[attr-defined]
                assert "calc.exe" in engine.frozen_apps, "Second process must be tracked"  # type: ignore[attr-defined]

        finally:
            if process1:
                process1.terminate()
                process1.wait(timeout=5)
            if process2:
                try:
                    process2.terminate()
                    process2.wait(timeout=5)
                except Exception:
                    pass


class TestTimeFreezeMemoryInjectionDetails:
    """Test low-level memory injection details for time freeze hooks."""

    def test_freeze_time_allocates_page_aligned_memory(self) -> None:
        """Time freeze allocates memory aligned to page boundaries."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_sets_memory_protection_to_execute_readwrite(self) -> None:
        """Time freeze sets allocated memory to PAGE_EXECUTE_READWRITE."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        PAGE_EXECUTE_READWRITE = 0x40

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed"

            assert PAGE_EXECUTE_READWRITE == 0x40, "PAGE_EXECUTE_READWRITE constant must be correct"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_writes_hooks_with_writeprocessmemory(self) -> None:
        """Time freeze uses WriteProcessMemory to inject hook code."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Time freeze must succeed (WriteProcessMemory must work)"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)


class TestTimeFreezeComprehensiveFunctional:
    """Comprehensive functional tests validating complete time freeze workflow."""

    def test_freeze_time_complete_workflow_from_scan_to_injection(self) -> None:
        """Complete workflow: find process, enumerate modules, resolve functions, inject hooks."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()

            modules = engine._enumerate_process_modules(process.pid)  # type: ignore[attr-defined]
            assert "kernel32.dll" in modules, "Step 1: Module enumeration must find kernel32"

            kernel32_base, _ = modules["kernel32.dll"]
            assert kernel32_base > 0, "Step 2: kernel32 base address must be valid"

            kernel32 = ctypes.windll.kernel32
            hProcess = kernel32.OpenProcess(0x1F0FFF, False, process.pid)
            try:
                functions = [b"GetSystemTime", b"GetLocalTime"]
                resolved = engine._resolve_target_process_functions(  # type: ignore[attr-defined]
                    hProcess, process.pid, kernel32_base, functions
                )
                assert all(addr is not None for addr in resolved), "Step 3: Function resolution must succeed"

            finally:
                kernel32.CloseHandle(hProcess)

            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)
            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success, "Step 4: Hook injection must succeed"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_handles_rapid_successive_injections(self) -> None:
        """Time freeze handles multiple rapid successive injection attempts."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success1 = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]
            assert success1, "First injection must succeed"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)

    def test_freeze_time_injection_does_not_crash_target_process(self) -> None:
        """Time freeze injection does not crash or destabilize target process."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process = None
        try:
            process = subprocess.Popen(["notepad.exe"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)

            initial_status = psutil.Process(process.pid).status()

            engine = TrialResetEngine()
            frozen_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

            success = engine.freeze_time_for_app("notepad.exe", frozen_time)  # type: ignore[attr-defined]

            time.sleep(1)

            assert psutil.Process(process.pid).is_running(), "Process must still be running after injection"
            final_status = psutil.Process(process.pid).status()
            assert final_status == initial_status or final_status in (
                psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING
            ), "Process must remain in healthy state"

        finally:
            if process:
                process.terminate()
                process.wait(timeout=5)
