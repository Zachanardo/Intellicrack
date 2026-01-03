"""Regression tests for trial reset time freezing module enumeration and ASLR handling.

These tests validate that previously implemented time freezing functionality continues
to work correctly. Tests verify module enumeration and ASLR-aware function resolution
work on real Windows processes.

Tests MUST FAIL if:
- Module enumeration fails to find loaded DLLs
- ASLR handling incorrectly calculates target addresses
- Function resolution produces invalid addresses
- Process architecture detection is broken

Copyright (C) 2025 Zachary Flint
"""

import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.trial_reset_engine import TimeManipulator, TrialResetEngine


class RegressionTestTimeFreezingModuleEnumeration:
    """Regression tests for time freezing module enumeration and ASLR handling."""

    @pytest.fixture
    def engine(self) -> TrialResetEngine:
        """Create trial reset engine instance."""
        return TrialResetEngine()

    @pytest.fixture
    def time_manipulator(self) -> TimeManipulator:
        """Create time manipulator instance."""
        return TimeManipulator()

    @pytest.fixture
    def test_process(self) -> Any:
        """Create test process for module enumeration testing.

        Starts notepad.exe as a real Windows process for testing module
        enumeration and ASLR handling functionality.
        """
        process = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(1)

        yield process

        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    @pytest.fixture
    def current_process_pid(self) -> int:
        """Return current process PID for self-enumeration testing."""
        return os.getpid()

    def test_enumerate_process_modules_finds_kernel32(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration finds kernel32.dll in target process.

        REGRESSION: Verify module enumeration still works correctly and finds
        essential system DLLs in target processes.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        assert isinstance(modules, dict), "Must return dictionary of modules"
        assert len(modules) > 0, "Must find at least one module in target process"
        assert "kernel32.dll" in modules, "Must find kernel32.dll in every Windows process"

        kernel32_base, kernel32_size = modules["kernel32.dll"]
        assert kernel32_base > 0, "kernel32.dll base address must be valid"
        assert kernel32_size > 0, "kernel32.dll size must be greater than zero"
        assert kernel32_base % 0x10000 == 0, "Base address must be aligned to 64KB boundary"

    def test_enumerate_process_modules_finds_ntdll(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration finds ntdll.dll in target process.

        REGRESSION: Verify enumeration finds ntdll which is critical for time hooks.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        assert "ntdll.dll" in modules, "Must find ntdll.dll in every Windows process"

        ntdll_base, ntdll_size = modules["ntdll.dll"]
        assert ntdll_base > 0, "ntdll.dll base address must be valid"
        assert ntdll_size > 0, "ntdll.dll size must be greater than zero"
        assert ntdll_base % 0x10000 == 0, "Base address must be aligned to 64KB boundary"

    def test_enumerate_process_modules_handles_multiple_modules(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration correctly handles processes with multiple loaded modules.

        REGRESSION: Verify enumeration works on real processes with multiple DLLs.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        assert len(modules) >= 3, "Notepad must have at least kernel32, ntdll, and executable"

        module_names = list(modules.keys())
        assert "notepad.exe" in module_names, "Must find main executable module"

        for module_name, (base_addr, size) in modules.items():
            assert isinstance(module_name, str), f"Module name must be string: {module_name}"
            assert module_name.lower() == module_name, "Module names must be lowercase"
            assert base_addr > 0, f"{module_name} base address must be valid"
            assert size > 0, f"{module_name} size must be greater than zero"

    def test_enumerate_process_modules_returns_unique_addresses(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration returns unique base addresses for each module.

        REGRESSION: Verify ASLR causes different base addresses for modules.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        base_addresses = [base_addr for base_addr, _ in modules.values()]
        unique_addresses = set(base_addresses)

        assert len(unique_addresses) == len(base_addresses), (
            "All modules must have unique base addresses (ASLR)"
        )

    def test_enumerate_process_modules_handles_invalid_pid(
        self,
        time_manipulator: TimeManipulator,
    ) -> None:
        """Module enumeration handles invalid PID gracefully.

        REGRESSION: Verify error handling for non-existent processes.
        """
        invalid_pid = 999999

        modules = time_manipulator._enumerate_process_modules(invalid_pid)

        assert isinstance(modules, dict), "Must return empty dict for invalid PID"
        assert len(modules) == 0, "Must return empty dict when process cannot be opened"

    def test_enumerate_process_modules_self_enumeration(
        self,
        time_manipulator: TimeManipulator,
        current_process_pid: int,
    ) -> None:
        """Module enumeration works on current process (self-enumeration).

        REGRESSION: Verify enumeration can introspect the current process.
        """
        modules = time_manipulator._enumerate_process_modules(current_process_pid)

        assert len(modules) > 0, "Must find modules in current process"
        assert "kernel32.dll" in modules, "Must find kernel32.dll in current process"
        assert "ntdll.dll" in modules, "Must find ntdll.dll in current process"

        python_exe = Path(sys.executable).name.lower()
        assert python_exe in modules, f"Must find Python executable '{python_exe}' in current process"

    def test_resolve_target_process_functions_getsystemtime(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution correctly resolves GetSystemTime accounting for ASLR.

        REGRESSION: Verify ASLR-aware function resolution still works for time functions.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        assert "kernel32.dll" in modules, "Must find kernel32.dll for function resolution"

        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            function_names = [b"GetSystemTime"]
            addresses = time_manipulator._resolve_target_process_functions(
                hProcess,
                pid,
                kernel32_base,
                function_names,
            )

            assert len(addresses) == 1, "Must resolve exactly one function"
            assert addresses[0] is not None, "GetSystemTime must resolve successfully"
            assert addresses[0] > kernel32_base, "Function address must be within kernel32"
            assert addresses[0] < kernel32_base + 0x1000000, "Function address must be reasonable offset"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_multiple_time_apis(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution resolves multiple time APIs with correct ASLR offsets.

        REGRESSION: Verify batch function resolution with ASLR handling.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            function_names = [
                b"GetSystemTime",
                b"GetLocalTime",
                b"GetTickCount",
                b"GetTickCount64",
            ]

            addresses = time_manipulator._resolve_target_process_functions(
                hProcess,
                pid,
                kernel32_base,
                function_names,
            )

            assert len(addresses) == len(function_names), "Must resolve all requested functions"

            for idx, (func_name, address) in enumerate(zip(function_names, addresses)):
                assert address is not None, f"{func_name.decode()} must resolve successfully"
                assert address > kernel32_base, f"{func_name.decode()} must be within kernel32 range"
                assert address < kernel32_base + 0x1000000, (
                    f"{func_name.decode()} address must be reasonable"
                )

            unique_addresses = set(addr for addr in addresses if addr is not None)
            assert len(unique_addresses) == len(addresses), "All functions must have unique addresses"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_handles_aslr_correctly(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution calculates correct RVA and rebases for ASLR.

        REGRESSION: Verify ASLR calculation produces valid addresses in target process.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32

        host_kernel32_handle = kernel32.GetModuleHandleW("kernel32.dll")
        assert host_kernel32_handle != 0, "Must get kernel32 handle in host process"

        host_getsystemtime = kernel32.GetProcAddress(host_kernel32_handle, b"GetSystemTime")
        assert host_getsystemtime != 0, "Must get GetSystemTime address in host"

        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            addresses = time_manipulator._resolve_target_process_functions(
                hProcess,
                pid,
                kernel32_base,
                [b"GetSystemTime"],
            )

            target_getsystemtime = addresses[0]
            assert target_getsystemtime is not None, "Must resolve GetSystemTime in target"

            host_kernel32_base_addr = host_kernel32_handle
            expected_rva = host_getsystemtime - host_kernel32_base_addr
            expected_target_addr = kernel32_base + expected_rva

            tolerance = 0x1000
            assert abs(target_getsystemtime - expected_target_addr) < tolerance, (
                f"ASLR calculation must produce correct address. "
                f"Expected: 0x{expected_target_addr:X}, Got: 0x{target_getsystemtime:X}"
            )

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_handles_missing_function(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution handles non-existent function names gracefully.

        REGRESSION: Verify error handling for invalid function names.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            addresses = time_manipulator._resolve_target_process_functions(
                hProcess,
                pid,
                kernel32_base,
                [b"NonExistentFunction12345"],
            )

            assert len(addresses) == 1, "Must return one result for one query"
            assert addresses[0] is None, "Non-existent function must return None"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_mixed_valid_invalid(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution handles mix of valid and invalid function names.

        REGRESSION: Verify partial success with some invalid functions.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            function_names = [
                b"GetSystemTime",
                b"InvalidFunc1",
                b"GetTickCount",
                b"InvalidFunc2",
            ]

            addresses = time_manipulator._resolve_target_process_functions(
                hProcess,
                pid,
                kernel32_base,
                function_names,
            )

            assert len(addresses) == len(function_names), "Must return result for each function"

            assert addresses[0] is not None, "GetSystemTime must resolve"
            assert addresses[1] is None, "InvalidFunc1 must return None"
            assert addresses[2] is not None, "GetTickCount must resolve"
            assert addresses[3] is None, "InvalidFunc2 must return None"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_is_64bit_process_correctly_identifies_notepad(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Process architecture detection correctly identifies 64-bit processes.

        REGRESSION: Verify architecture detection for different process types.
        """
        pid = test_process.pid

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            is_64bit = time_manipulator._is_64bit_process(hProcess)

            import platform
            system_arch = platform.machine()

            if "64" in system_arch:
                notepad_path = Path(r"C:\Windows\System32\notepad.exe")
                if notepad_path.exists():
                    assert is_64bit is True, "System32 notepad must be 64-bit on 64-bit Windows"
            else:
                assert is_64bit is False, "Notepad must be 32-bit on 32-bit Windows"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_is_64bit_process_current_process(
        self,
        time_manipulator: TimeManipulator,
        current_process_pid: int,
    ) -> None:
        """Process architecture detection works on current process.

        REGRESSION: Verify self-architecture detection matches Python interpreter.
        """
        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.GetCurrentProcess()

        is_64bit = time_manipulator._is_64bit_process(hProcess)

        expected_64bit = sys.maxsize > 2**32

        assert is_64bit == expected_64bit, (
            f"Architecture detection must match Python architecture. "
            f"Python is {'64-bit' if expected_64bit else '32-bit'}"
        )

    def test_aslr_produces_different_addresses_across_processes(
        self,
        time_manipulator: TimeManipulator,
    ) -> None:
        """ASLR causes kernel32.dll to load at different addresses in different processes.

        REGRESSION: Verify ASLR is working and produces randomized base addresses.
        """
        process1 = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)

        process2 = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)

        try:
            modules1 = time_manipulator._enumerate_process_modules(process1.pid)
            modules2 = time_manipulator._enumerate_process_modules(process2.pid)

            assert "kernel32.dll" in modules1, "Must find kernel32 in first process"
            assert "kernel32.dll" in modules2, "Must find kernel32 in second process"

            base1, _ = modules1["kernel32.dll"]
            base2, _ = modules2["kernel32.dll"]

            assert base1 != base2, (
                "ASLR must cause different base addresses in different processes. "
                f"Process 1: 0x{base1:X}, Process 2: 0x{base2:X}"
            )

        finally:
            try:
                process1.terminate()
                process1.wait(timeout=5)
            except Exception:
                try:
                    process1.kill()
                except Exception:
                    pass

            try:
                process2.terminate()
                process2.wait(timeout=5)
            except Exception:
                try:
                    process2.kill()
                except Exception:
                    pass

    def test_module_enumeration_performance_acceptable(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration completes within acceptable time frame.

        REGRESSION: Verify enumeration performance hasn't degraded.
        """
        import time as time_module

        pid = test_process.pid

        start_time = time_module.perf_counter()
        modules = time_manipulator._enumerate_process_modules(pid)
        elapsed = time_module.perf_counter() - start_time

        assert elapsed < 1.0, f"Module enumeration must complete within 1 second (took {elapsed:.3f}s)"
        assert len(modules) > 0, "Must successfully enumerate modules"

    def test_function_resolution_performance_acceptable(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution completes within acceptable time frame.

        REGRESSION: Verify resolution performance for multiple functions.
        """
        import time as time_module

        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            function_names = [
                b"GetSystemTime",
                b"GetLocalTime",
                b"GetTickCount",
                b"GetTickCount64",
                b"QueryPerformanceCounter",
            ]

            start_time = time_module.perf_counter()
            addresses = time_manipulator._resolve_target_process_functions(
                hProcess,
                pid,
                kernel32_base,
                function_names,
            )
            elapsed = time_module.perf_counter() - start_time

            assert elapsed < 0.5, f"Function resolution must complete within 500ms (took {elapsed:.3f}s)"
            assert all(addr is not None for addr in addresses), "All functions must resolve"

        finally:
            kernel32.CloseHandle(hProcess)
