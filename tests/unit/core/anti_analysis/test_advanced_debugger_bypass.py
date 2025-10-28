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
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
    AdvancedDebuggerBypass,
    HypervisorDebugger,
    UserModeNTAPIHooker,
    TimingNeutralizer,
    install_advanced_bypass,
)


class TestUserModeNTAPIHooker(unittest.TestCase):
    """Test user-mode NT API hooker functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.hook_manager = UserModeNTAPIHooker()

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_initialization_windows(self):
        """Test Windows initialization."""
        self.assertIsNotNone(self.hook_manager.ntdll_base)
        self.assertIsNotNone(self.hook_manager.kernel32_base)

    def test_initialization_creates_empty_hooks_dict(self):
        """Test that hooks dictionary is initialized empty."""
        self.assertEqual(len(self.hook_manager.hooks), 0)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @patch("ctypes.windll")
    def test_hook_ntquery_information_process(self, mock_windll):
        """Test NtQueryInformationProcess hook installation."""
        mock_ntdll = MagicMock()
        mock_windll.ntdll = mock_ntdll

        result = self.hook_manager.hook_ntquery_information_process()

        self.assertIsInstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_generate_ntquery_hook_shellcode_x64(self):
        """Test shellcode generation for x64."""
        with patch("platform.machine", return_value="AMD64"):
            self.hook_manager.original_functions["NtQueryInformationProcess"] = 0x7FFF00000000

            shellcode = self.hook_manager._generate_ntquery_hook_shellcode(0x7FFF00000000)

            self.assertIsInstance(shellcode, bytes)
            self.assertGreater(len(shellcode), 0)
            self.assertIn(0x48, shellcode)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_generate_ntquery_hook_shellcode_x86(self):
        """Test shellcode generation for x86."""
        with patch("platform.machine", return_value="i686"):
            self.hook_manager.original_functions["NtQueryInformationProcess"] = 0x7C800000

            shellcode = self.hook_manager._generate_ntquery_hook_shellcode(0x7C800000)

            self.assertIsInstance(shellcode, bytes)
            self.assertGreater(len(shellcode), 0)

    def test_remove_all_hooks(self):
        """Test removing all hooks."""
        self.hook_manager.hooks["test"] = MagicMock(active=True)

        result = self.hook_manager.remove_all_hooks()

        self.assertTrue(result)
        self.assertEqual(len(self.hook_manager.hooks), 0)


class TestHypervisorDebugger(unittest.TestCase):
    """Test hypervisor debugger functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.hypervisor = HypervisorDebugger()

    def test_initialization(self):
        """Test hypervisor initialization."""
        self.assertFalse(self.hypervisor.vmx_enabled)
        self.assertFalse(self.hypervisor.ept_enabled)
        self.assertFalse(self.hypervisor.vmcs_shadowing)

    def test_check_virtualization_support_returns_dict(self):
        """Test virtualization support check returns dict."""
        support = self.hypervisor.check_virtualization_support()

        self.assertIsInstance(support, dict)
        self.assertIn("vmx", support)
        self.assertIn("svm", support)
        self.assertIn("ept", support)
        self.assertIn("vpid", support)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific test")
    def test_check_linux_vt_support(self):
        """Test Linux virtualization support check."""
        with patch("pathlib.Path.open") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = "flags: vmx ept vpid"

            support = self.hypervisor._check_linux_vt_support()

            self.assertIsInstance(support, dict)
            self.assertIn("vmx", support)

    def test_setup_vmcs_shadowing_without_vmx(self):
        """Test VMCS shadowing setup without VMX support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"vmx": False}):
            result = self.hypervisor.setup_vmcs_shadowing()

            self.assertFalse(result)

    def test_setup_vmcs_shadowing_with_vmx(self):
        """Test VMCS shadowing setup with VMX support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"vmx": True}):
            result = self.hypervisor.setup_vmcs_shadowing()

            self.assertTrue(result)
            self.assertTrue(self.hypervisor.vmcs_shadowing)

    def test_setup_ept_hooks_without_ept(self):
        """Test EPT hooks setup without EPT support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"ept": False}):
            result = self.hypervisor.setup_ept_hooks()

            self.assertFalse(result)

    def test_setup_ept_hooks_with_ept(self):
        """Test EPT hooks setup with EPT support."""
        with patch.object(self.hypervisor, "check_virtualization_support", return_value={"ept": True}):
            result = self.hypervisor.setup_ept_hooks()

            self.assertTrue(result)
            self.assertTrue(self.hypervisor.ept_enabled)

    def test_manipulate_hardware_breakpoints(self):
        """Test hardware breakpoint manipulation."""
        breakpoints = {0: 0x00401000, 1: 0x00402000, 2: 0x00403000}

        result = self.hypervisor.manipulate_hardware_breakpoints(breakpoints)

        self.assertTrue(result)


class TestTimingNeutralizer(unittest.TestCase):
    """Test timing neutralizer functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.timing = TimingNeutralizer()

    def test_initialization(self):
        """Test timing neutralizer initialization."""
        self.assertIsNone(self.timing.base_timestamp)
        self.assertEqual(self.timing.rdtsc_offset, 0)
        self.assertEqual(self.timing.qpc_offset, 0)

    def test_neutralize_rdtsc(self):
        """Test RDTSC neutralization."""
        result = self.timing.neutralize_rdtsc()

        self.assertIsInstance(result, bool)
        if result:
            self.assertIsNotNone(self.timing.base_timestamp)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @patch("ctypes.windll")
    def test_hook_query_performance_counter(self, mock_windll):
        """Test QueryPerformanceCounter hooking."""
        mock_kernel32 = MagicMock()
        mock_windll.kernel32 = mock_kernel32

        result = self.timing.hook_query_performance_counter()

        self.assertIsInstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @patch("ctypes.windll")
    def test_hook_get_tick_count(self, mock_windll):
        """Test GetTickCount hooking."""
        mock_kernel32 = MagicMock()
        mock_windll.kernel32 = mock_kernel32

        result = self.timing.hook_get_tick_count()

        self.assertIsInstance(result, bool)

    def test_normalize_timing_high_value(self):
        """Test timing normalization for high execution times."""
        normalized = self.timing.normalize_timing(2000.0)

        self.assertLess(normalized, 2000.0)
        self.assertEqual(normalized, 2000.0 * 0.01)

    def test_normalize_timing_medium_value(self):
        """Test timing normalization for medium execution times."""
        normalized = self.timing.normalize_timing(500.0)

        self.assertLess(normalized, 500.0)
        self.assertEqual(normalized, 500.0 * 0.1)

    def test_normalize_timing_low_value(self):
        """Test timing normalization for low execution times."""
        normalized = self.timing.normalize_timing(50.0)

        self.assertEqual(normalized, 50.0)

    def test_remove_timing_hooks(self):
        """Test removing timing hooks."""
        self.timing.hooked_functions["test"] = 0x12345678

        result = self.timing.remove_timing_hooks()

        self.assertTrue(result)
        self.assertEqual(len(self.timing.hooked_functions), 0)


class TestAdvancedDebuggerBypass(unittest.TestCase):
    """Test advanced debugger bypass functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.bypass = AdvancedDebuggerBypass()

    def test_initialization(self):
        """Test bypass initialization."""
        self.assertIsNotNone(self.bypass.kernel_hooks)
        self.assertIsNotNone(self.bypass.hypervisor)
        self.assertIsNotNone(self.bypass.timing_neutralizer)
        self.assertFalse(self.bypass.bypass_active)

    def test_install_full_bypass_returns_dict(self):
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

    def test_install_scyllahide_resistant_bypass(self):
        """Test ScyllaHide-resistant bypass installation."""
        with patch.object(self.bypass.kernel_hooks, "hook_ntquery_information_process", return_value=True):
            with patch.object(self.bypass.kernel_hooks, "hook_ntset_information_thread", return_value=True):
                with patch.object(self.bypass.hypervisor, "check_virtualization_support", return_value={"vmx": True}):
                    results = self.bypass.install_scyllahide_resistant_bypass()

                    self.assertIsInstance(results, dict)
                    self.assertIn("deep_kernel_hooks", results)
                    self.assertIn("hypervisor_mode", results)
                    self.assertIn("timing_normalization", results)

    def test_defeat_anti_debug_technique_peb(self):
        """Test defeating PEB.BeingDebugged technique."""
        with patch("intellicrack.core.anti_analysis.advanced_debugger_bypass.DebuggerBypass") as mock_bypass:
            mock_instance = MagicMock()
            mock_instance._bypass_peb_flags.return_value = True
            mock_bypass.return_value = mock_instance

            result = self.bypass.defeat_anti_debug_technique("PEB.BeingDebugged")

            self.assertTrue(result)

    def test_defeat_anti_debug_technique_rdtsc(self):
        """Test defeating RDTSC technique."""
        with patch.object(self.bypass.timing_neutralizer, "neutralize_rdtsc", return_value=True):
            result = self.bypass.defeat_anti_debug_technique("RDTSC")

            self.assertTrue(result)

    def test_defeat_anti_debug_technique_unknown(self):
        """Test defeating unknown technique."""
        result = self.bypass.defeat_anti_debug_technique("UnknownTechnique")

        self.assertFalse(result)

    def test_remove_all_bypasses(self):
        """Test removing all bypasses."""
        self.bypass.bypass_active = True

        with patch.object(self.bypass.kernel_hooks, "remove_all_hooks", return_value=True):
            with patch.object(self.bypass.timing_neutralizer, "remove_timing_hooks", return_value=True):
                result = self.bypass.remove_all_bypasses()

                self.assertTrue(result)
                self.assertFalse(self.bypass.bypass_active)

    def test_get_bypass_status(self):
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

    def test_install_advanced_bypass_scyllahide(self):
        """Test convenience function with ScyllaHide mode."""
        with patch("intellicrack.core.anti_analysis.advanced_debugger_bypass.AdvancedDebuggerBypass") as mock_bypass:
            mock_instance = MagicMock()
            mock_instance.install_scyllahide_resistant_bypass.return_value = {"deep_kernel_hooks": True}
            mock_instance.get_bypass_status.return_value = {"active": True}
            mock_bypass.return_value = mock_instance

            results = install_advanced_bypass(scyllahide_resistant=True)

            self.assertIsInstance(results, dict)
            self.assertIn("scyllahide_resistant", results)
            self.assertIn("status", results)

    def test_install_advanced_bypass_full(self):
        """Test convenience function with full mode."""
        with patch("intellicrack.core.anti_analysis.advanced_debugger_bypass.AdvancedDebuggerBypass") as mock_bypass:
            mock_instance = MagicMock()
            mock_instance.install_full_bypass.return_value = {"overall_success": True}
            mock_instance.get_bypass_status.return_value = {"active": True}
            mock_bypass.return_value = mock_instance

            results = install_advanced_bypass(scyllahide_resistant=False)

            self.assertIsInstance(results, dict)
            self.assertIn("full_bypass", results)
            self.assertIn("status", results)


class TestIntegration(unittest.TestCase):
    """Integration tests for full bypass workflow."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific integration test")
    def test_full_bypass_workflow(self):
        """Test complete bypass installation workflow."""
        bypass = AdvancedDebuggerBypass()

        initial_status = bypass.get_bypass_status()
        self.assertFalse(initial_status["active"])

        with patch.object(bypass.kernel_hooks, "hook_ntquery_information_process", return_value=True):
            with patch.object(bypass.kernel_hooks, "hook_ntset_information_thread", return_value=True):
                with patch.object(bypass.timing_neutralizer, "neutralize_rdtsc", return_value=True):
                    results = bypass.install_full_bypass()

                    self.assertTrue(results["overall_success"])

                    final_status = bypass.get_bypass_status()
                    self.assertTrue(final_status["active"])

                    remove_result = bypass.remove_all_bypasses()
                    self.assertTrue(remove_result)

                    removed_status = bypass.get_bypass_status()
                    self.assertFalse(removed_status["active"])


if __name__ == "__main__":
    unittest.main()
