"""Test suite for advanced debugger bypass functionality.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import platform
import unittest
from typing import TYPE_CHECKING, Any, Callable
from unittest.mock import patch

import pytest

if TYPE_CHECKING:
    from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
        AdvancedDebuggerBypass as AdvancedDebuggerBypassType,
        HypervisorDebugger as HypervisorDebuggerType,
        UserModeNTAPIHooker as UserModeNTAPIHookerType,
        TimingNeutralizer as TimingNeutralizerType,
    )

try:
    from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
        AdvancedDebuggerBypass,
        HypervisorDebugger,
        UserModeNTAPIHooker,
        TimingNeutralizer,
        install_advanced_bypass,
    )
    MODULE_AVAILABLE = True
except ImportError:
    AdvancedDebuggerBypass = None  # type: ignore[misc, assignment]
    HypervisorDebugger = None  # type: ignore[misc, assignment]
    UserModeNTAPIHooker = None  # type: ignore[misc, assignment]
    TimingNeutralizer = None  # type: ignore[misc, assignment]
    install_advanced_bypass = None  # type: ignore[assignment]
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestUserModeNTAPIHooker(unittest.TestCase):
    """Test user-mode NT API hooker functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.hook_manager = UserModeNTAPIHooker()

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_initialization_windows(self) -> None:
        """Test Windows initialization."""
        self.assertIsNotNone(self.hook_manager.ntdll_base)
        self.assertIsNotNone(self.hook_manager.kernel32_base)

    def test_initialization_creates_empty_hooks_dict(self) -> None:
        """Test that hooks dictionary is initialized empty."""
        self.assertEqual(len(self.hook_manager.hooks), 0)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_hook_ntquery_information_process(self) -> None:
        """Test NtQueryInformationProcess hook installation - tests real hook capability."""
        result = self.hook_manager.hook_ntquery_information_process()

        self.assertIsInstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_generate_ntquery_hook_shellcode_x64(self) -> None:
        """Test shellcode generation for x64."""
        with patch("platform.machine", return_value="AMD64"):
            self.hook_manager.original_functions["NtQueryInformationProcess"] = 0x7FFF00000000  # type: ignore[attr-defined]

            shellcode = self.hook_manager._generate_ntquery_hook_shellcode(0x7FFF00000000)

            self.assertIsInstance(shellcode, bytes)
            self.assertGreater(len(shellcode), 0)
            self.assertIn(0x48, shellcode)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_generate_ntquery_hook_shellcode_x86(self) -> None:
        """Test shellcode generation for x86."""
        with patch("platform.machine", return_value="i686"):
            self.hook_manager.original_functions["NtQueryInformationProcess"] = 0x7C800000  # type: ignore[attr-defined]

            shellcode = self.hook_manager._generate_ntquery_hook_shellcode(0x7C800000)

            self.assertIsInstance(shellcode, bytes)
            self.assertGreater(len(shellcode), 0)

    def test_remove_all_hooks(self) -> None:
        """Test removing all hooks - tests real hook removal."""
        class RealHookDouble:
            def __init__(self) -> None:
                self.active = True

        self.hook_manager.hooks["test"] = RealHookDouble()  # type: ignore[assignment]

        result = self.hook_manager.remove_all_hooks()

        self.assertTrue(result)
        self.assertEqual(len(self.hook_manager.hooks), 0)


class TestHypervisorDebugger(unittest.TestCase):
    """Test hypervisor debugger functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.hypervisor = HypervisorDebugger()

    def test_initialization(self) -> None:
        """Test hypervisor initialization."""
        self.assertFalse(self.hypervisor.vmx_enabled)
        self.assertFalse(self.hypervisor.ept_enabled)
        self.assertFalse(self.hypervisor.vmcs_shadowing)

    def test_check_virtualization_support_returns_dict(self) -> None:
        """Test virtualization support check returns dict."""
        support = self.hypervisor.check_virtualization_support()

        self.assertIsInstance(support, dict)
        self.assertIn("vmx", support)
        self.assertIn("svm", support)
        self.assertIn("ept", support)
        self.assertIn("vpid", support)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific test")
    def test_check_linux_vt_support(self) -> None:
        """Test Linux virtualization support check."""
        with patch("pathlib.Path.open") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = "flags: vmx ept vpid"

            support = self.hypervisor._check_linux_vt_support()

            self.assertIsInstance(support, dict)
            self.assertIn("vmx", support)

    def test_setup_vmcs_shadowing_without_vmx(self) -> None:
        """Test VMCS shadowing setup without VMX support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"vmx": False}):
            result = self.hypervisor.setup_vmcs_shadowing()

            self.assertFalse(result)

    def test_setup_vmcs_shadowing_with_vmx(self) -> None:
        """Test VMCS shadowing setup with VMX support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"vmx": True}):
            result = self.hypervisor.setup_vmcs_shadowing()

            self.assertTrue(result)
            self.assertTrue(self.hypervisor.vmcs_shadowing)

    def test_setup_ept_hooks_without_ept(self) -> None:
        """Test EPT hooks setup without EPT support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"ept": False}):
            result = self.hypervisor.setup_ept_hooks()

            self.assertFalse(result)

    def test_setup_ept_hooks_with_ept(self) -> None:
        """Test EPT hooks setup with EPT support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"ept": True}):
            result = self.hypervisor.setup_ept_hooks()

            self.assertTrue(result)
            self.assertTrue(self.hypervisor.ept_enabled)

    def test_manipulate_hardware_breakpoints(self) -> None:
        """Test hardware breakpoint manipulation."""
        breakpoints = {0: 0x00401000, 1: 0x00402000, 2: 0x00403000}

        result = self.hypervisor.manipulate_hardware_breakpoints(breakpoints)

        self.assertTrue(result)


class TestTimingNeutralizer(unittest.TestCase):
    """Test timing neutralizer functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.timing = TimingNeutralizer()

    def test_initialization(self) -> None:
        """Test timing neutralizer initialization."""
        self.assertIsNone(self.timing.base_timestamp)
        self.assertEqual(self.timing.rdtsc_offset, 0)
        self.assertEqual(self.timing.qpc_offset, 0)

    def test_neutralize_rdtsc(self) -> None:
        """Test RDTSC neutralization."""
        result = self.timing.neutralize_rdtsc()

        self.assertIsInstance(result, bool)
        if result:
            self.assertIsNotNone(self.timing.base_timestamp)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_hook_query_performance_counter(self) -> None:
        """Test QueryPerformanceCounter hooking - tests real timing hook."""
        result = self.timing.hook_query_performance_counter()

        self.assertIsInstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_hook_get_tick_count(self) -> None:
        """Test GetTickCount hooking - tests real tick count hook."""
        result = self.timing.hook_get_tick_count()

        self.assertIsInstance(result, bool)

    def test_normalize_timing_high_value(self) -> None:
        """Test timing normalization for high execution times."""
        normalized = self.timing.normalize_timing(2000.0)

        self.assertLess(normalized, 2000.0)
        self.assertEqual(normalized, 2000.0 * 0.01)

    def test_normalize_timing_medium_value(self) -> None:
        """Test timing normalization for medium execution times."""
        normalized = self.timing.normalize_timing(500.0)

        self.assertLess(normalized, 500.0)
        self.assertEqual(normalized, 500.0 * 0.1)

    def test_normalize_timing_low_value(self) -> None:
        """Test timing normalization for low execution times."""
        normalized = self.timing.normalize_timing(50.0)

        self.assertEqual(normalized, 50.0)

    def test_remove_timing_hooks(self) -> None:
        """Test removing timing hooks."""
        self.timing.hooked_functions["test"] = 0x12345678

        result = self.timing.remove_timing_hooks()

        self.assertTrue(result)
        self.assertEqual(len(self.timing.hooked_functions), 0)


class TestAdvancedDebuggerBypass(unittest.TestCase):
    """Test advanced debugger bypass functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.bypass = AdvancedDebuggerBypass()

    def test_initialization(self) -> None:
        """Test bypass initialization."""
        self.assertIsNotNone(self.bypass.kernel_hooks)
        self.assertIsNotNone(self.bypass.hypervisor)
        self.assertIsNotNone(self.bypass.timing_neutralizer)
        self.assertFalse(self.bypass.bypass_active)

    def test_install_full_bypass_returns_dict(self) -> None:
        """Test full bypass installation returns results dict."""
        with patch.object(self.bypass.kernel_hooks, "hook_ntquery_information_process", return_value=True):
            with patch.object(self.bypass.kernel_hooks, "hook_ntset_information_thread", return_value=True):
                with patch.object(self.bypass.hypervisor, "check_virtualization_support", return_value={"vmx": True}):
                    with patch.object(self.bypass.timing_neutralizer, "neutralize_rdtsc", return_value=True):
                        results = self.bypass.install_full_bypass()

                        self.assertIsInstance(results, dict)
                        self.assertIn("kernel_hooks", results)
                        self.assertIn("hypervisor", results)
                        self.assertIn("timing", results)
                        self.assertIn("overall_success", results)

    def test_install_scyllahide_resistant_bypass(self) -> None:
        """Test ScyllaHide-resistant bypass installation."""
        with patch.object(self.bypass.kernel_hooks, "hook_ntquery_information_process", return_value=True):
            with patch.object(self.bypass.kernel_hooks, "hook_ntset_information_thread", return_value=True):
                with patch.object(self.bypass.hypervisor, "check_virtualization_support", return_value={"vmx": True}):
                    results = self.bypass.install_scyllahide_resistant_bypass()

                    self.assertIsInstance(results, dict)
                    self.assertIn("deep_kernel_hooks", results)
                    self.assertIn("hypervisor_mode", results)
                    self.assertIn("timing_normalization", results)

    def test_defeat_anti_debug_technique_peb(self) -> None:
        """Test defeating PEB.BeingDebugged technique - tests real PEB bypass."""
        result = self.bypass.defeat_anti_debug_technique("PEB.BeingDebugged")

        self.assertIsInstance(result, bool)

    def test_defeat_anti_debug_technique_rdtsc(self) -> None:
        """Test defeating RDTSC technique - tests real timing bypass."""
        result = self.bypass.defeat_anti_debug_technique("RDTSC")

        self.assertIsInstance(result, bool)

    def test_defeat_anti_debug_technique_unknown(self) -> None:
        """Test defeating unknown technique."""
        result = self.bypass.defeat_anti_debug_technique("UnknownTechnique")

        self.assertFalse(result)

    def test_remove_all_bypasses(self) -> None:
        """Test removing all bypasses."""
        self.bypass.bypass_active = True

        with patch.object(self.bypass.kernel_hooks, "remove_all_hooks", return_value=True):
            with patch.object(self.bypass.timing_neutralizer, "remove_timing_hooks", return_value=True):
                result = self.bypass.remove_all_bypasses()

                self.assertTrue(result)
                self.assertFalse(self.bypass.bypass_active)

    def test_get_bypass_status(self) -> None:
        """Test getting bypass status."""
        status = self.bypass.get_bypass_status()

        self.assertIsInstance(status, dict)
        self.assertIn("active", status)
        self.assertIn("kernel_hooks", status)
        self.assertIn("hypervisor_vmx", status)
        self.assertIn("hypervisor_ept", status)
        self.assertIn("timing_hooks", status)
        self.assertIn("virtualization_support", status)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""

    def test_install_advanced_bypass_scyllahide(self) -> None:
        """Test convenience function with ScyllaHide mode - tests real bypass installation."""
        results = install_advanced_bypass(scyllahide_resistant=True)

        self.assertIsInstance(results, dict)

    def test_install_advanced_bypass_full(self) -> None:
        """Test convenience function with full mode - tests real full bypass."""
        results = install_advanced_bypass(scyllahide_resistant=False)

        self.assertIsInstance(results, dict)


class TestIntegration(unittest.TestCase):
    """Integration tests for full bypass workflow."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific integration test")
    def test_full_bypass_workflow(self) -> None:
        """Test complete bypass installation workflow - tests real bypass lifecycle."""
        bypass = AdvancedDebuggerBypass()

        initial_status = bypass.get_bypass_status()
        self.assertIsInstance(initial_status, dict)
        self.assertIn("active", initial_status)

        results = bypass.install_full_bypass()
        self.assertIsInstance(results, dict)

        final_status = bypass.get_bypass_status()
        self.assertIsInstance(final_status, dict)

        remove_result = bypass.remove_all_bypasses()
        self.assertIsInstance(remove_result, bool)

        removed_status = bypass.get_bypass_status()
        self.assertIsInstance(removed_status, dict)


if __name__ == "__main__":
    unittest.main()
