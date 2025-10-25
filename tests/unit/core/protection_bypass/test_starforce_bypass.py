"""
Unit tests for StarForce bypass module.

Tests StarForce protection bypass including driver removal, anti-debug bypass,
disc check bypass, license validation bypass, and hardware ID spoofing.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path

from intellicrack.core.protection_bypass.starforce_bypass import (
    StarForceBypass,
    BypassResult,
    StarForceRemovalResult
)


class TestStarForceBypass(unittest.TestCase):
    """Test cases for StarForceBypass."""

    def setUp(self):
        """Set up test fixtures."""
        self.bypass = StarForceBypass()

    def test_bypass_initialization(self):
        """Test bypass system initializes correctly."""
        self.assertIsNotNone(self.bypass)
        self.assertTrue(hasattr(self.bypass, 'DRIVER_PATHS'))
        self.assertTrue(hasattr(self.bypass, 'SERVICE_NAMES'))
        self.assertTrue(hasattr(self.bypass, 'REGISTRY_KEYS_TO_DELETE'))

    def test_driver_paths_defined(self):
        """Test driver paths are properly defined."""
        self.assertGreater(len(self.bypass.DRIVER_PATHS), 0)
        self.assertTrue(any('sfdrv01.sys' in path for path in self.bypass.DRIVER_PATHS))
        self.assertTrue(any('sfvfs02.sys' in path for path in self.bypass.DRIVER_PATHS))

    def test_service_names_defined(self):
        """Test service names are properly defined."""
        self.assertGreater(len(self.bypass.SERVICE_NAMES), 0)
        self.assertIn('StarForce', self.bypass.SERVICE_NAMES)
        self.assertIn('sfdrv01', self.bypass.SERVICE_NAMES)

    def test_registry_keys_defined(self):
        """Test registry keys to delete are defined."""
        self.assertGreater(len(self.bypass.REGISTRY_KEYS_TO_DELETE), 0)
        for root_key, subkey_path in self.bypass.REGISTRY_KEYS_TO_DELETE:
            self.assertIsInstance(root_key, int)
            self.assertIsInstance(subkey_path, str)

    def test_bypass_result_structure(self):
        """Test BypassResult data structure."""
        result = BypassResult(
            success=True,
            technique='Test Bypass',
            details='Successfully bypassed',
            errors=[]
        )

        self.assertTrue(result.success)
        self.assertEqual(result.technique, 'Test Bypass')
        self.assertIsInstance(result.details, str)
        self.assertIsInstance(result.errors, list)

    def test_removal_result_structure(self):
        """Test StarForceRemovalResult data structure."""
        result = StarForceRemovalResult(
            drivers_removed=['sfdrv01.sys'],
            services_stopped=['StarForce'],
            registry_cleaned=['test_key'],
            files_deleted=['test_file'],
            success=True,
            errors=[]
        )

        self.assertTrue(result.success)
        self.assertEqual(len(result.drivers_removed), 1)
        self.assertEqual(len(result.services_stopped), 1)
        self.assertEqual(len(result.registry_cleaned), 1)
        self.assertEqual(len(result.files_deleted), 1)

    def test_stop_all_services_without_winapi(self):
        """Test service stopping without WinAPI."""
        bypass = StarForceBypass()
        bypass._advapi32 = None

        stopped = bypass._stop_all_services()

        self.assertEqual(len(stopped), 0)

    def test_delete_all_services_without_winapi(self):
        """Test service deletion without WinAPI."""
        bypass = StarForceBypass()
        bypass._advapi32 = None

        deleted = bypass._delete_all_services()

        self.assertEqual(len(deleted), 0)

    @patch('winreg.OpenKey')
    @patch('winreg.CloseKey')
    @patch('winreg.DeleteKey')
    @patch('winreg.EnumKey')
    def test_clean_registry_success(self, mock_enum, mock_del, mock_close, mock_open):
        """Test registry cleaning succeeds."""
        mock_key = Mock()
        mock_open.return_value = mock_key
        mock_enum.side_effect = WindowsError("No more items")

        cleaned = self.bypass._clean_registry()

        self.assertIsInstance(cleaned, list)

    @patch('winreg.OpenKey')
    def test_clean_registry_handles_errors(self, mock_open):
        """Test registry cleaning handles errors gracefully."""
        mock_open.side_effect = WindowsError("Access denied")

        cleaned = self.bypass._clean_registry()

        self.assertEqual(len(cleaned), 0)

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.unlink')
    def test_remove_driver_files_success(self, mock_unlink, mock_exists):
        """Test driver file removal succeeds."""
        mock_exists.return_value = True

        removed = self.bypass._remove_driver_files()

        self.assertIsInstance(removed, list)

    @patch('pathlib.Path.exists')
    def test_remove_driver_files_no_drivers(self, mock_exists):
        """Test driver file removal when no drivers exist."""
        mock_exists.return_value = False

        removed = self.bypass._remove_driver_files()

        self.assertEqual(len(removed), 0)

    @patch('pathlib.Path.exists')
    def test_remove_application_files_no_dirs(self, mock_exists):
        """Test application file removal when directories don't exist."""
        mock_exists.return_value = False

        deleted = self.bypass._remove_application_files()

        self.assertEqual(len(deleted), 0)

    @patch('pathlib.Path.exists')
    @patch('winreg.OpenKey')
    @patch('winreg.DeleteKey')
    @patch('pathlib.Path.unlink')
    def test_remove_starforce_complete_workflow(self, mock_unlink, mock_del_key, mock_open, mock_exists):
        """Test complete StarForce removal workflow."""
        mock_exists.return_value = False
        mock_open.side_effect = WindowsError("Not found")

        result = self.bypass.remove_starforce()

        self.assertIsInstance(result, StarForceRemovalResult)
        self.assertIsInstance(result.drivers_removed, list)
        self.assertIsInstance(result.services_stopped, list)
        self.assertIsInstance(result.registry_cleaned, list)
        self.assertIsInstance(result.files_deleted, list)
        self.assertIsInstance(result.success, bool)
        self.assertIsInstance(result.errors, list)

    def test_bypass_anti_debug_without_winapi(self):
        """Test anti-debug bypass without WinAPI."""
        bypass = StarForceBypass()
        bypass._kernel32 = None

        result = bypass.bypass_anti_debug()

        self.assertIsInstance(result, BypassResult)
        self.assertEqual(result.technique, 'Anti-Debug Bypass')
        self.assertIsInstance(result.errors, list)

    def test_patch_peb_being_debugged_without_winapi(self):
        """Test PEB patching without WinAPI."""
        bypass = StarForceBypass()
        bypass._kernel32 = None

        result = bypass._patch_peb_being_debugged(1234)

        self.assertFalse(result)

    def test_clear_debug_registers_without_winapi(self):
        """Test debug register clearing without WinAPI."""
        bypass = StarForceBypass()
        bypass._kernel32 = None

        result = bypass._clear_debug_registers(1234)

        self.assertFalse(result)

    def test_hook_timing_functions(self):
        """Test timing function hooking."""
        result = self.bypass._hook_timing_functions()

        self.assertTrue(result)

    @patch('pathlib.Path.exists')
    def test_bypass_disc_check_nonexistent_file(self, mock_exists):
        """Test disc check bypass on nonexistent file."""
        mock_exists.return_value = False
        target_exe = Path('D:/nonexistent.exe')

        result = self.bypass.bypass_disc_check(target_exe)

        self.assertIsInstance(result, BypassResult)
        self.assertFalse(result.success)
        self.assertEqual(result.technique, 'Disc Check Bypass')

    def test_emulate_virtual_drive(self):
        """Test virtual drive emulation."""
        target_exe = Path('D:/test.exe')

        result = self.bypass._emulate_virtual_drive(target_exe)

        self.assertTrue(result)

    @patch('pathlib.Path.exists')
    def test_bypass_license_validation_nonexistent_file(self, mock_exists):
        """Test license validation bypass on nonexistent file."""
        mock_exists.return_value = False
        target_exe = Path('D:/nonexistent.exe')

        result = self.bypass.bypass_license_validation(target_exe)

        self.assertIsInstance(result, BypassResult)
        self.assertFalse(result.success)
        self.assertEqual(result.technique, 'License Validation Bypass')

    @patch('winreg.CreateKey')
    @patch('winreg.SetValueEx')
    @patch('winreg.CloseKey')
    def test_create_registry_license_success(self, mock_close, mock_set, mock_create):
        """Test registry license creation succeeds."""
        mock_key = Mock()
        mock_create.return_value = mock_key

        result = self.bypass._create_registry_license()

        self.assertTrue(result)

    @patch('winreg.CreateKey')
    def test_create_registry_license_handles_errors(self, mock_create):
        """Test registry license creation handles errors."""
        mock_create.side_effect = WindowsError("Access denied")

        result = self.bypass._create_registry_license()

        self.assertFalse(result)

    @patch('winreg.CreateKey')
    @patch('winreg.SetValueEx')
    @patch('winreg.CloseKey')
    def test_spoof_hardware_id_success(self, mock_close, mock_set, mock_create):
        """Test hardware ID spoofing."""
        mock_key = Mock()
        mock_create.return_value = mock_key

        result = self.bypass.spoof_hardware_id()

        self.assertIsInstance(result, BypassResult)
        self.assertEqual(result.technique, 'Hardware ID Spoofing')

    @patch('winreg.CreateKey')
    @patch('winreg.SetValueEx')
    @patch('winreg.CloseKey')
    def test_spoof_disk_serial_success(self, mock_close, mock_set, mock_create):
        """Test disk serial spoofing succeeds."""
        mock_key = Mock()
        mock_create.return_value = mock_key

        result = self.bypass._spoof_disk_serial()

        self.assertTrue(result)

    @patch('winreg.CreateKey')
    def test_spoof_disk_serial_handles_errors(self, mock_create):
        """Test disk serial spoofing handles errors."""
        mock_create.side_effect = WindowsError("Access denied")

        result = self.bypass._spoof_disk_serial()

        self.assertFalse(result)

    @patch('winreg.OpenKey')
    @patch('winreg.EnumKey')
    @patch('winreg.SetValueEx')
    @patch('winreg.CloseKey')
    def test_spoof_mac_address_success(self, mock_close, mock_set, mock_enum, mock_open):
        """Test MAC address spoofing succeeds."""
        mock_key = Mock()
        mock_open.return_value = mock_key
        mock_enum.side_effect = ['0000', WindowsError("No more items")]

        result = self.bypass._spoof_mac_address()

        self.assertTrue(result)

    @patch('winreg.OpenKey')
    def test_spoof_mac_address_handles_errors(self, mock_open):
        """Test MAC address spoofing handles errors."""
        mock_open.side_effect = WindowsError("Access denied")

        result = self.bypass._spoof_mac_address()

        self.assertFalse(result)

    @patch('winreg.CreateKey')
    @patch('winreg.SetValueEx')
    @patch('winreg.CloseKey')
    def test_spoof_cpu_id_success(self, mock_close, mock_set, mock_create):
        """Test CPU ID spoofing succeeds."""
        mock_key = Mock()
        mock_create.return_value = mock_key

        result = self.bypass._spoof_cpu_id()

        self.assertTrue(result)

    @patch('winreg.CreateKey')
    def test_spoof_cpu_id_handles_errors(self, mock_create):
        """Test CPU ID spoofing handles errors."""
        mock_create.side_effect = WindowsError("Access denied")

        result = self.bypass._spoof_cpu_id()

        self.assertFalse(result)


class TestStarForceBypassIntegration(unittest.TestCase):
    """Integration tests for StarForce bypass."""

    def setUp(self):
        """Set up test fixtures."""
        self.bypass = StarForceBypass()

    def test_winapi_setup_does_not_crash(self):
        """Test WinAPI setup completes without crashing."""
        bypass = StarForceBypass()

        self.assertIsNotNone(bypass)

    @patch('pathlib.Path.exists')
    @patch('winreg.OpenKey')
    def test_full_removal_workflow(self, mock_reg_open, mock_path_exists):
        """Test complete removal workflow."""
        mock_path_exists.return_value = False
        mock_reg_open.side_effect = WindowsError("Not found")

        result = self.bypass.remove_starforce()

        self.assertIsInstance(result, StarForceRemovalResult)
        self.assertIsInstance(result.success, bool)

    def test_anti_debug_bypass_workflow(self):
        """Test anti-debug bypass workflow."""
        result = self.bypass.bypass_anti_debug()

        self.assertIsInstance(result, BypassResult)
        self.assertIsInstance(result.success, bool)
        self.assertIsInstance(result.details, str)

    @patch('pathlib.Path.exists')
    def test_disc_check_bypass_workflow(self, mock_exists):
        """Test disc check bypass workflow."""
        mock_exists.return_value = False
        target_exe = Path('D:/test.exe')

        result = self.bypass.bypass_disc_check(target_exe)

        self.assertIsInstance(result, BypassResult)
        self.assertEqual(result.technique, 'Disc Check Bypass')

    @patch('pathlib.Path.exists')
    def test_license_validation_bypass_workflow(self, mock_exists):
        """Test license validation bypass workflow."""
        mock_exists.return_value = False
        target_exe = Path('D:/test.exe')

        result = self.bypass.bypass_license_validation(target_exe)

        self.assertIsInstance(result, BypassResult)
        self.assertEqual(result.technique, 'License Validation Bypass')

    def test_hardware_id_spoofing_workflow(self):
        """Test hardware ID spoofing workflow."""
        result = self.bypass.spoof_hardware_id()

        self.assertIsInstance(result, BypassResult)
        self.assertEqual(result.technique, 'Hardware ID Spoofing')


if __name__ == '__main__':
    unittest.main()
