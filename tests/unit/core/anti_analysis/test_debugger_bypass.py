"""Tests for anti-anti-debug bypass functionality.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

import ctypes
import os
import platform
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest

try:
    from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass, install_anti_antidebug
    MODULE_AVAILABLE = True
except ImportError:
    DebuggerBypass = None
    install_anti_antidebug = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestDebuggerBypass(unittest.TestCase):
    """Test anti-anti-debug bypass functionality."""

    def setUp(self):
        """Set up test environment."""
        self.bypass = DebuggerBypass()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        try:
            if hasattr(self, "bypass"):
                self.bypass.remove_bypasses()
        except Exception:
            pass

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_isdebuggerpresent_windows(self):
        """Test IsDebuggerPresent bypass on Windows."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_isdebuggerpresent()
        assert isinstance(result, bool)

        if ctypes.windll.kernel32.IsDebuggerPresent():
            assert result is True

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_peb_flags_windows(self):
        """Test PEB flags bypass clears BeingDebugged and NtGlobalFlag."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_peb_flags()
        assert isinstance(result, bool)

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
                ("Reserved3", ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        ntdll = ctypes.windll.ntdll
        status = ntdll.NtQueryInformationProcess(current_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)

        if status == 0 and pbi.PebBaseAddress:
            being_debugged_addr = ctypes.c_void_p(pbi.PebBaseAddress.value + 2)
            being_debugged = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()

            kernel32.ReadProcessMemory(
                current_process, being_debugged_addr, ctypes.byref(being_debugged), 1, ctypes.byref(bytes_read)
            )

            if result:
                assert being_debugged.value == 0

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_hardware_breakpoints_windows(self):
        """Test hardware breakpoint bypass clears debug registers."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_hardware_breakpoints()
        assert isinstance(result, bool)

        kernel32 = ctypes.windll.kernel32
        current_thread = kernel32.GetCurrentThread()

        class CONTEXT(ctypes.Structure):
            _fields_ = [
                ("ContextFlags", ctypes.c_uint32),
                ("Dr0", ctypes.c_uint32),
                ("Dr1", ctypes.c_uint32),
                ("Dr2", ctypes.c_uint32),
                ("Dr3", ctypes.c_uint32),
                ("Dr6", ctypes.c_uint32),
                ("Dr7", ctypes.c_uint32),
                ("_reserved", ctypes.c_ubyte * 512),
            ]

        CONTEXT_DEBUG_REGISTERS = 0x00000010
        context = CONTEXT()
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS

        if kernel32.GetThreadContext(current_thread, ctypes.byref(context)) and result:
            assert context.Dr0 == 0
            assert context.Dr1 == 0
            assert context.Dr2 == 0
            assert context.Dr3 == 0
            assert context.Dr6 == 0
            assert context.Dr7 == 0

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_timing_windows(self):
        """Test timing bypass hooks time functions."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_timing_windows()
        assert isinstance(result, bool)

        if result:
            assert self.bypass.timing_base is not None
            assert "QueryPerformanceCounter" in self.bypass.original_functions
            assert "GetTickCount" in self.bypass.original_functions

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_debug_port_windows(self):
        """Test debug port bypass via NtQueryInformationProcess hooking."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_debug_port()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_exception_handling_windows(self):
        """Test exception handling bypass."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_exception_handling()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_window_detection_windows(self):
        """Test debugger window detection bypass."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_window_detection()
        assert isinstance(result, bool)
        assert result is True

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_bypass_process_detection_windows(self):
        """Test debugger process name detection bypass."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_process_detection()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_bypass_ptrace_linux(self):
        """Test ptrace bypass on Linux."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        result = self.bypass._bypass_ptrace_linux()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_bypass_proc_status_linux(self):
        """Test /proc/self/status TracerPid bypass."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        result = self.bypass._bypass_proc_status()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_bypass_ld_preload_linux(self):
        """Test LD_PRELOAD bypass."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        os.environ["LD_PRELOAD"] = "/tmp/test.so"
        os.environ["LD_LIBRARY_PATH"] = "/usr/lib:/usr/local/lib:/tmp/debug"

        result = self.bypass._bypass_ld_preload()
        assert isinstance(result, bool)

        if result:
            assert "LD_PRELOAD" not in os.environ
            assert "debug" not in os.environ.get("LD_LIBRARY_PATH", "")

    def test_install_bypasses_all(self):
        """Test installing all bypass methods."""
        results = self.bypass.install_bypasses()

        assert isinstance(results, dict)
        assert len(results) > 0

        for method, success in results.items():
            assert isinstance(success, bool)

    def test_install_bypasses_selective(self):
        """Test installing specific bypass methods."""
        if platform.system() == "Windows":
            methods = ["isdebuggerpresent", "peb_flags", "timing_checks"]
        else:
            methods = ["ptrace", "timing_checks"]

        results = self.bypass.install_bypasses(methods)

        assert isinstance(results, dict)
        assert len(results) == len(methods)

        for method in methods:
            assert method in results

    def test_install_bypasses_invalid_method(self):
        """Test installing invalid bypass method."""
        methods = ["invalid_method"]

        results = self.bypass.install_bypasses(methods)

        assert isinstance(results, dict)
        assert "invalid_method" in results
        assert results["invalid_method"] is False

    def test_remove_bypasses(self):
        """Test removing all installed bypasses."""
        self.bypass.install_bypasses()

        result = self.bypass.remove_bypasses()

        assert result is True
        assert self.bypass.hooks_installed is False
        assert len(self.bypass.original_functions) == 0

    def test_get_bypass_status_initial(self):
        """Test getting bypass status before installation."""
        status = self.bypass.get_bypass_status()

        assert isinstance(status, dict)
        assert "hooks_installed" in status
        assert "active_hooks" in status
        assert "hypervisor_enabled" in status
        assert "platform" in status
        assert "hooked_functions" in status

        assert status["hooks_installed"] is False
        assert status["active_hooks"] == 0
        assert status["hypervisor_enabled"] is False
        assert status["platform"] == platform.system()

    def test_get_bypass_status_after_install(self):
        """Test getting bypass status after installation."""
        self.bypass.install_bypasses()

        status = self.bypass.get_bypass_status()

        assert isinstance(status, dict)
        assert status["hooks_installed"] is True or status["active_hooks"] == 0

    def test_hypervisor_support_check(self):
        """Test hypervisor support detection."""
        result = self.bypass._check_hypervisor_support()

        assert isinstance(result, bool)

    def test_enable_hypervisor_debugging(self):
        """Test enabling hypervisor-based debugging."""
        result = self.bypass.enable_hypervisor_debugging()

        assert isinstance(result, bool)

        if result:
            assert self.bypass.hypervisor_enabled is True

    def test_ntquery_hook_generation(self):
        """Test NtQueryInformationProcess hook code generation."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        self.bypass.original_functions["NtQueryInformationProcess"] = 0x12345678

        hook_code = self.bypass._generate_ntquery_hook()

        assert isinstance(hook_code, bytes)
        assert len(hook_code) > 0

    def test_convenience_function_install(self):
        """Test convenience function for installing bypasses."""
        results = install_anti_antidebug()

        assert isinstance(results, dict)
        assert len(results) > 0

    def test_convenience_function_selective(self):
        """Test convenience function with selective methods."""
        if platform.system() == "Windows":
            methods = ["isdebuggerpresent", "peb_flags"]
        else:
            methods = ["ptrace"]

        results = install_anti_antidebug(methods)

        assert isinstance(results, dict)
        assert len(results) == len(methods)

    def test_bypass_initialization_windows(self):
        """Test Windows-specific initialization."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        bypass = DebuggerBypass()

        assert hasattr(bypass, "kernel32")
        assert hasattr(bypass, "ntdll")
        assert hasattr(bypass, "user32")
        assert len(bypass.bypass_methods) > 0

    def test_bypass_initialization_linux(self):
        """Test Linux-specific initialization."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        bypass = DebuggerBypass()

        assert len(bypass.bypass_methods) > 0
        assert "ptrace" in bypass.bypass_methods
        assert "proc_status" in bypass.bypass_methods

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_checkremotedebuggerpresent_bypass(self):
        """Test CheckRemoteDebuggerPresent bypass."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_checkremotedebuggerpresent()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_ntglobalflag_bypass(self):
        """Test NtGlobalFlag bypass."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = self.bypass._bypass_ntglobalflag()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_hardware_breakpoints_linux(self):
        """Test hardware breakpoint bypass on Linux."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        result = self.bypass._bypass_hardware_breakpoints_linux()
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_timing_bypass_linux(self):
        """Test timing bypass on Linux."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        result = self.bypass._bypass_timing_linux()
        assert isinstance(result, bool)

        if result:
            assert self.bypass.timing_base is not None

    def test_integrated_bypass_workflow(self):
        """Test complete bypass workflow: install, verify, remove."""
        initial_status = self.bypass.get_bypass_status()
        assert initial_status["hooks_installed"] is False

        install_results = self.bypass.install_bypasses()
        assert isinstance(install_results, dict)

        active_status = self.bypass.get_bypass_status()
        assert active_status["hooks_installed"] is True or active_status["active_hooks"] == 0

        remove_result = self.bypass.remove_bypasses()
        assert remove_result is True

        final_status = self.bypass.get_bypass_status()
        assert final_status["hooks_installed"] is False


class TestAntiAntiDebugIntegration(unittest.TestCase):
    """Integration tests for anti-anti-debug bypass."""

    def setUp(self):
        """Set up integration test environment."""
        self.bypass = DebuggerBypass()

    def tearDown(self):
        """Clean up integration test environment."""
        try:
            self.bypass.remove_bypasses()
        except Exception:
            pass

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_scyllahide_resistant_checks_bypass(self):
        """Test bypassing ScyllaHide-resistant anti-debug checks."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        methods = [
            "isdebuggerpresent",
            "peb_flags",
            "debug_port",
            "hardware_breakpoints",
            "timing_checks",
        ]

        results = self.bypass.install_bypasses(methods)

        successful_bypasses = sum(bool(success)
                              for success in results.values())
        assert successful_bypasses > 0

    def test_combined_bypass_effectiveness(self):
        """Test effectiveness of combined bypass methods."""
        initial_status = self.bypass.get_bypass_status()
        assert initial_status["hooks_installed"] is False

        all_results = self.bypass.install_bypasses()
        assert len(all_results) > 0

        active_status = self.bypass.get_bypass_status()
        assert active_status["platform"] == platform.system()

    def test_bypass_persistence(self):
        """Test that bypasses persist across multiple checks."""
        self.bypass.install_bypasses()

        status1 = self.bypass.get_bypass_status()
        status2 = self.bypass.get_bypass_status()

        assert status1["hooks_installed"] == status2["hooks_installed"]
        assert status1["active_hooks"] == status2["active_hooks"]

    def test_error_recovery(self):
        """Test bypass system error recovery."""
        try:
            invalid_methods = ["nonexistent_method"]
            results = self.bypass.install_bypasses(invalid_methods)

            assert "nonexistent_method" in results
            assert results["nonexistent_method"] is False

            status = self.bypass.get_bypass_status()
            assert isinstance(status, dict)

        except Exception as e:
            pytest.fail(f"Error recovery failed: {e}")


if __name__ == "__main__":
    unittest.main()
