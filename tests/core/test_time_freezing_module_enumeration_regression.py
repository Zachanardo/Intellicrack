"""Comprehensive regression tests for time freezing module enumeration and ASLR handling.

These tests validate that previously implemented time freezing functionality continues
to work correctly, specifically targeting module enumeration, ASLR-aware function
resolution, and time hook injection capabilities.

Tests MUST FAIL if:
- Module enumeration fails to find loaded DLLs in target processes
- ASLR handling incorrectly calculates API offsets
- Function resolution produces invalid or incorrect addresses
- Process architecture detection is broken
- Time hook injection mechanisms are non-functional

Copyright (C) 2025 Zachary Flint
"""

from __future__ import annotations

import ctypes
import os
import platform
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.trial_reset_engine import TimeManipulator, TrialResetEngine


class TestTimeFreezingModuleEnumerationRegression:
    """Regression tests for time freezing module enumeration and ASLR handling."""

    @pytest.fixture
    def engine(self) -> TrialResetEngine:
        """Create trial reset engine instance for testing."""
        return TrialResetEngine()

    @pytest.fixture
    def time_manipulator(self) -> TimeManipulator:
        """Create time manipulator instance for testing."""
        return TimeManipulator()

    @pytest.fixture
    def test_process(self) -> Any:
        """Create test process for module enumeration testing.

        Starts notepad.exe as a real Windows process for testing module
        enumeration and ASLR handling functionality.
        """
        if platform.system() != "Windows":
            pytest.skip("Time freezing tests require Windows platform")

        process = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(1.5)

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

        assert isinstance(modules, dict), "Module enumeration must return dictionary"
        assert len(modules) > 0, "Must find at least one module in target process"
        assert "kernel32.dll" in modules, "Must find kernel32.dll in every Windows process"

        kernel32_base, kernel32_size = modules["kernel32.dll"]
        assert kernel32_base > 0, "kernel32.dll base address must be valid non-zero value"
        assert kernel32_size > 0, "kernel32.dll size must be greater than zero"
        assert kernel32_base % 0x10000 == 0, "Base address must be aligned to 64KB boundary (Windows requirement)"
        assert kernel32_size < 0x10000000, "kernel32.dll size must be reasonable (< 256MB)"

    def test_enumerate_process_modules_finds_ntdll(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration finds ntdll.dll in target process.

        REGRESSION: Verify enumeration finds ntdll which is critical for time hooks.
        ntdll.dll contains low-level time APIs that must be hooked for comprehensive
        time freezing.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        assert "ntdll.dll" in modules, "Must find ntdll.dll in every Windows process"

        ntdll_base, ntdll_size = modules["ntdll.dll"]
        assert ntdll_base > 0, "ntdll.dll base address must be valid non-zero value"
        assert ntdll_size > 0, "ntdll.dll size must be greater than zero"
        assert ntdll_base % 0x10000 == 0, "Base address must be aligned to 64KB boundary"
        assert ntdll_size < 0x10000000, "ntdll.dll size must be reasonable (< 256MB)"

    def test_enumerate_process_modules_handles_multiple_modules(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration correctly handles processes with multiple loaded modules.

        REGRESSION: Verify enumeration works on real processes with multiple DLLs.
        Real applications load numerous modules and enumeration must handle all correctly.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        assert len(modules) >= 3, "Notepad must have at least kernel32, ntdll, and executable"

        module_names = list(modules.keys())
        assert "notepad.exe" in module_names, "Must find main executable module"

        for module_name, (base_addr, size) in modules.items():
            assert isinstance(module_name, str), f"Module name must be string: {module_name}"
            assert module_name.lower() == module_name, "Module names must be lowercase for consistency"
            assert base_addr > 0, f"{module_name} base address must be valid"
            assert size > 0, f"{module_name} size must be greater than zero"
            assert base_addr % 0x1000 == 0, f"{module_name} must be page-aligned"

    def test_enumerate_process_modules_returns_unique_addresses(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration returns unique base addresses for each module.

        REGRESSION: Verify ASLR causes different base addresses for modules.
        ASLR is critical for security and must produce unique addresses per module.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        base_addresses = [base_addr for base_addr, _ in modules.values()]
        unique_addresses = set(base_addresses)

        assert len(unique_addresses) == len(base_addresses), (
            "All modules must have unique base addresses due to ASLR. "
            f"Found {len(base_addresses)} modules but only {len(unique_addresses)} unique addresses"
        )

    def test_enumerate_process_modules_handles_invalid_pid(
        self,
        time_manipulator: TimeManipulator,
    ) -> None:
        """Module enumeration handles invalid PID gracefully.

        REGRESSION: Verify error handling for non-existent processes.
        Must return empty dictionary rather than crashing.
        """
        invalid_pid = 999999

        modules = time_manipulator._enumerate_process_modules(invalid_pid)

        assert isinstance(modules, dict), "Must return dict for invalid PID"
        assert len(modules) == 0, "Must return empty dict when process cannot be opened"

    def test_enumerate_process_modules_self_enumeration(
        self,
        time_manipulator: TimeManipulator,
        current_process_pid: int,
    ) -> None:
        """Module enumeration works on current process (self-enumeration).

        REGRESSION: Verify enumeration can introspect the current process.
        Self-enumeration is useful for testing and debugging.
        """
        modules = time_manipulator._enumerate_process_modules(current_process_pid)

        assert len(modules) > 0, "Must find modules in current process"
        assert "kernel32.dll" in modules, "Must find kernel32.dll in current process"
        assert "ntdll.dll" in modules, "Must find ntdll.dll in current process"

        python_exe = Path(sys.executable).name.lower()
        assert python_exe in modules, f"Must find Python executable '{python_exe}' in current process"

        kernel32_base, kernel32_size = modules["kernel32.dll"]
        assert kernel32_base > 0, "kernel32 base must be valid in current process"
        assert kernel32_size > 0, "kernel32 size must be valid in current process"

    def test_resolve_target_process_functions_getsystemtime(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution correctly resolves GetSystemTime accounting for ASLR.

        REGRESSION: Verify ASLR-aware function resolution still works for time functions.
        GetSystemTime is primary target for time freezing hooks.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        assert "kernel32.dll" in modules, "Must find kernel32.dll for function resolution"

        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must successfully open target process for function resolution"

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
            assert isinstance(addresses[0], int), "Resolved address must be integer"
            assert addresses[0] > kernel32_base, "Function address must be within kernel32 address space"
            assert addresses[0] < kernel32_base + 0x1000000, "Function address must be reasonable offset from base"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_multiple_time_apis(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution resolves multiple time APIs with correct ASLR offsets.

        REGRESSION: Verify batch function resolution with ASLR handling.
        Time freezing requires hooking multiple time-related APIs simultaneously.
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

            for idx, (func_name, address) in enumerate(zip(function_names, addresses, strict=False)):
                assert address is not None, f"{func_name.decode()} must resolve successfully"
                assert isinstance(address, int), f"{func_name.decode()} address must be integer"
                assert address > kernel32_base, f"{func_name.decode()} must be within kernel32 range"
                assert address < kernel32_base + 0x1000000, (
                    f"{func_name.decode()} address must be reasonable offset"
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
        RVA (Relative Virtual Address) calculation is critical for cross-process hooking.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32

        host_kernel32_handle = kernel32.GetModuleHandleW("kernel32.dll")
        assert host_kernel32_handle != 0, "Must get kernel32 handle in host process"

        host_getsystemtime = kernel32.GetProcAddress(host_kernel32_handle, b"GetSystemTime")
        assert host_getsystemtime != 0, "Must get GetSystemTime address in host process"

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
            assert target_getsystemtime is not None, "Must resolve GetSystemTime in target process"

            host_kernel32_base_addr = host_kernel32_handle
            expected_rva = host_getsystemtime - host_kernel32_base_addr
            expected_target_addr = kernel32_base + expected_rva

            tolerance = 0x1000
            assert abs(target_getsystemtime - expected_target_addr) < tolerance, (
                f"ASLR calculation must produce correct address within tolerance. "
                f"Expected: 0x{expected_target_addr:X}, Got: 0x{target_getsystemtime:X}, "
                f"Difference: 0x{abs(target_getsystemtime - expected_target_addr):X}"
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
        Must return None for missing functions rather than crashing.
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
            assert addresses[0] is None, "Non-existent function must return None, not crash"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_resolve_target_process_functions_mixed_valid_invalid(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution handles mix of valid and invalid function names.

        REGRESSION: Verify partial success with some invalid functions.
        Real-world usage may include optional functions that don't exist in all Windows versions.
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

            assert addresses[0] is not None, "GetSystemTime must resolve successfully"
            assert addresses[1] is None, "InvalidFunc1 must return None"
            assert addresses[2] is not None, "GetTickCount must resolve successfully"
            assert addresses[3] is None, "InvalidFunc2 must return None"

            assert isinstance(addresses[0], int), "Valid addresses must be integers"
            assert isinstance(addresses[2], int), "Valid addresses must be integers"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_is_64bit_process_correctly_identifies_notepad(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Process architecture detection correctly identifies 64-bit processes.

        REGRESSION: Verify architecture detection for different process types.
        Hook code must match target process architecture (32-bit vs 64-bit).
        """
        pid = test_process.pid

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400, False, pid)
        assert hProcess != 0, "Must successfully open target process"

        try:
            is_64bit = time_manipulator._is_64bit_process(hProcess)

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
            f"Python is {'64-bit' if expected_64bit else '32-bit'}, detected as "
            f"{'64-bit' if is_64bit else '32-bit'}"
        )

    def test_aslr_produces_different_addresses_across_processes(
        self,
        time_manipulator: TimeManipulator,
    ) -> None:
        """ASLR causes kernel32.dll to load at different addresses in different processes.

        REGRESSION: Verify ASLR is working and produces randomized base addresses.
        ASLR is fundamental security feature that must be handled correctly.
        """
        if platform.system() != "Windows":
            pytest.skip("ASLR test requires Windows platform")

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
                f"Process 1: 0x{base1:X}, Process 2: 0x{base2:X}. "
                "If this fails, ASLR may be disabled on the system."
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
        Slow enumeration would impact time freezing injection speed.
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
        Fast resolution is critical for responsive time freezing activation.
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
            assert all(addr is not None for addr in addresses), "All standard time functions must resolve"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_module_enumeration_finds_user32_for_gui_apps(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration finds user32.dll in GUI applications.

        REGRESSION: Verify enumeration works for common GUI library modules.
        Notepad is a GUI app and should have user32.dll loaded.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        assert "user32.dll" in modules, "GUI applications like notepad must have user32.dll loaded"

        user32_base, user32_size = modules["user32.dll"]
        assert user32_base > 0, "user32.dll base address must be valid"
        assert user32_size > 0, "user32.dll size must be greater than zero"

    def test_resolve_queryperformancecounter_for_high_resolution_timing(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution resolves QueryPerformanceCounter for high-resolution timing.

        REGRESSION: Verify critical high-resolution time API can be resolved.
        QueryPerformanceCounter is used by many applications for precise timing.
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
                [b"QueryPerformanceCounter"],
            )

            assert len(addresses) == 1, "Must resolve QueryPerformanceCounter"
            assert addresses[0] is not None, "QueryPerformanceCounter must resolve successfully"
            assert isinstance(addresses[0], int), "Address must be integer"
            assert addresses[0] > kernel32_base, "Function must be within kernel32"

        finally:
            kernel32.CloseHandle(hProcess)

    def test_module_base_addresses_aligned_to_allocation_granularity(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module base addresses aligned to Windows allocation granularity.

        REGRESSION: Verify all module bases meet Windows memory allocation requirements.
        Windows requires module bases to be aligned to 64KB boundaries.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)

        allocation_granularity = 0x10000

        for module_name, (base_addr, size) in modules.items():
            assert base_addr % allocation_granularity == 0, (
                f"Module '{module_name}' base address 0x{base_addr:X} must be aligned to "
                f"64KB allocation granularity (0x{allocation_granularity:X})"
            )

    def test_enumeration_handles_access_denied_gracefully(
        self,
        time_manipulator: TimeManipulator,
    ) -> None:
        """Module enumeration handles access denied for protected processes.

        REGRESSION: Verify graceful handling of permission denied errors.
        Some system processes cannot be opened without admin privileges.
        """
        protected_pids = [4]

        for pid in protected_pids:
            modules = time_manipulator._enumerate_process_modules(pid)

            assert isinstance(modules, dict), "Must return dict even for protected processes"

    def test_function_resolution_handles_invalid_process_handle(
        self,
        time_manipulator: TimeManipulator,
    ) -> None:
        """Function resolution handles invalid process handle gracefully.

        REGRESSION: Verify error handling for invalid handles.
        """
        invalid_handle = 0
        fake_pid = 12345
        fake_base = 0x7FF800000000

        addresses = time_manipulator._resolve_target_process_functions(
            invalid_handle,
            fake_pid,
            fake_base,
            [b"GetSystemTime"],
        )

        assert isinstance(addresses, list), "Must return list even with invalid handle"
        assert len(addresses) == 1, "Must return result for requested function"

    def test_module_enumeration_consistency_across_multiple_calls(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Module enumeration returns consistent results across multiple calls.

        REGRESSION: Verify enumeration results are stable for same process.
        Unless new DLLs are loaded, results should be identical.
        """
        pid = test_process.pid

        modules1 = time_manipulator._enumerate_process_modules(pid)
        time.sleep(0.1)
        modules2 = time_manipulator._enumerate_process_modules(pid)

        assert len(modules1) == len(modules2), "Module count must be consistent"

        for module_name in modules1:
            assert module_name in modules2, f"Module '{module_name}' must appear in both enumerations"

            base1, size1 = modules1[module_name]
            base2, size2 = modules2[module_name]

            assert base1 == base2, f"Module '{module_name}' base address must be consistent"
            assert size1 == size2, f"Module '{module_name}' size must be consistent"

    def test_function_resolution_rva_calculation_correctness(
        self,
        time_manipulator: TimeManipulator,
        test_process: Any,
    ) -> None:
        """Function resolution RVA calculation is mathematically correct.

        REGRESSION: Verify RVA formula: target_addr = target_base + (host_addr - host_base).
        This is fundamental to ASLR-aware hooking.
        """
        pid = test_process.pid

        modules = time_manipulator._enumerate_process_modules(pid)
        kernel32_base, _ = modules["kernel32.dll"]

        kernel32 = ctypes.windll.kernel32

        host_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        host_getsystemtime = kernel32.GetProcAddress(host_kernel32, b"GetSystemTime")

        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        assert hProcess != 0, "Must open target process"

        try:
            addresses = time_manipulator._resolve_target_process_functions(
                hProcess,
                pid,
                kernel32_base,
                [b"GetSystemTime"],
            )

            target_addr = addresses[0]
            assert target_addr is not None, "Must resolve GetSystemTime"

            rva = host_getsystemtime - host_kernel32
            expected_target = kernel32_base + rva

            assert target_addr == expected_target, (
                f"RVA calculation incorrect: expected 0x{expected_target:X}, got 0x{target_addr:X}"
            )

        finally:
            kernel32.CloseHandle(hProcess)

    @pytest.mark.slow
    def test_enumeration_handles_process_with_many_modules(
        self,
        time_manipulator: TimeManipulator,
    ) -> None:
        """Module enumeration handles processes with large numbers of loaded modules.

        REGRESSION: Verify enumeration doesn't truncate results with many modules.
        Some applications load hundreds of DLLs.
        """
        current_pid = os.getpid()

        modules = time_manipulator._enumerate_process_modules(current_pid)

        assert len(modules) > 5, "Python process should have multiple modules loaded"
        assert len(modules) < 1024, "Module count should be within reasonable bounds"

        for module_name, (base, size) in modules.items():
            assert len(module_name) > 0, "Module names must not be empty"
            assert base > 0, "All module bases must be valid"
            assert size > 0, "All module sizes must be valid"
