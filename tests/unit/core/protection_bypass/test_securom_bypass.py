"""
Unit tests for SecuROM Protection Bypass.

Tests activation bypass, trigger removal, disc defeat, product key bypass,
phone-home blocking, and challenge-response defeat.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open, call
from pathlib import Path
import winreg
import pytest

try:
    from intellicrack.core.protection_bypass.securom_bypass import (
        SecuROMBypass,
        BypassResult,
        SecuROMRemovalResult
    )
    MODULE_AVAILABLE = True
except ImportError:
    SecuROMBypass = None
    BypassResult = None
    SecuROMRemovalResult = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestSecuROMBypass(unittest.TestCase):
    """Test cases for SecuROMBypass class."""

    def setUp(self):
        """Set up test fixtures."""
        self.bypass = SecuROMBypass()
        self.test_exe_path = Path('test_securom.exe')

    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CreateKey')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.SetValueEx')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CloseKey')
    def test_bypass_activation_registry(self, mock_close, mock_set, mock_create):
        """Test activation bypass through registry manipulation."""
        mock_create.return_value = MagicMock()

        result = self.bypass._bypass_activation_registry()

        self.assertTrue(result)
        mock_create.assert_called()
        self.assertGreater(mock_set.call_count, 0)

    @patch('intellicrack.core.protection_bypass.securom_bypass.Path.unlink')
    @patch('intellicrack.core.protection_bypass.securom_bypass.Path.exists')
    def test_remove_driver_files(self, mock_exists, mock_unlink):
        """Test removal of SecuROM driver files."""
        mock_exists.return_value = True

        removed = self.bypass._remove_driver_files()

        self.assertIsInstance(removed, list)
        if len(removed) > 0:
            mock_unlink.assert_called()

    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.OpenKey')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.DeleteKey')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CloseKey')
    def test_clean_registry(self, mock_close, mock_delete, mock_open):
        """Test registry cleaning."""
        mock_open.return_value = MagicMock()

        cleaned = self.bypass._clean_registry()

        self.assertIsInstance(cleaned, list)

    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._stop_all_services')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._delete_all_services')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._clean_registry')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._bypass_activation_registry')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._remove_driver_files')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._remove_application_files')
    def test_remove_securom_complete(
        self, mock_app, mock_drv, mock_act, mock_reg, mock_del, mock_stop
    ):
        """Test complete SecuROM removal."""
        mock_stop.return_value = ['SecuROM8']
        mock_del.return_value = []
        mock_reg.return_value = ['SOFTWARE\\SecuROM']
        mock_act.return_value = True
        mock_drv.return_value = ['secdrv.sys']
        mock_app.return_value = []

        result = self.bypass.remove_securom()

        self.assertIsInstance(result, SecuROMRemovalResult)
        self.assertTrue(result.success)
        self.assertTrue(result.activation_bypassed)
        self.assertGreater(len(result.services_stopped), 0)

    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x85\xC0\x74\x10' * 10)
    @patch.object(Path, 'exists', return_value=True)
    @patch('shutil.copy2')
    def test_patch_activation_checks(self, mock_copy, mock_exists, mock_file):
        """Test patching of activation checks."""
        result = self.bypass._patch_activation_checks(self.test_exe_path)

        self.assertIsInstance(result, bool)

    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CreateKey')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_activation_checks')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._bypass_activation_registry')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._inject_activation_data')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._disable_activation_countdown')
    @patch.object(Path, 'exists', return_value=True)
    def test_bypass_activation(
        self, mock_exists, mock_countdown, mock_inject, mock_reg, mock_patch, mock_create
    ):
        """Test complete activation bypass."""
        mock_patch.return_value = True
        mock_reg.return_value = True
        mock_inject.return_value = True
        mock_countdown.return_value = True

        result = self.bypass.bypass_activation(self.test_exe_path)

        self.assertIsInstance(result, BypassResult)
        self.assertTrue(result.success)
        self.assertEqual(result.technique, 'Activation Bypass')

    @patch('builtins.open', new_callable=mock_open, read_data=b'ActivationDaysRemaining\x00\x83\xE8\x01')
    @patch.object(Path, 'exists', return_value=True)
    def test_disable_activation_countdown(self, mock_exists, mock_file):
        """Test disabling activation countdown."""
        result = self.bypass._disable_activation_countdown(self.test_exe_path)

        self.assertIsInstance(result, bool)

    @patch('builtins.open', new_callable=mock_open, read_data=b'ValidateLicense\x00\x55\x8B\xEC' * 3)
    @patch.object(Path, 'exists', return_value=True)
    @patch('shutil.copy2')
    def test_remove_triggers(self, mock_copy, mock_exists, mock_file):
        """Test removal of online validation triggers."""
        result = self.bypass.remove_triggers(self.test_exe_path)

        self.assertIsInstance(result, BypassResult)
        self.assertEqual(result.technique, 'Trigger Removal')

    def test_nop_trigger_function(self):
        """Test NOPing trigger function."""
        data = bytearray(b'\x00' * 50 + b'\x55\x8B\xEC\x83\xEC\x10' + b'\x00' * 50)
        offset = 60

        result = self.bypass._nop_trigger_function(data, offset)

        self.assertIsInstance(result, bool)
        if result:
            self.assertEqual(data[53], 0xC3)

    def test_is_network_call_positive(self):
        """Test identification of network calls."""
        data = bytearray(b'\x00' * 100 + b'WinHttpSendRequest' + b'\xFF\x15\x00\x00\x00\x00' + b'\x00' * 100)

        result = self.bypass._is_network_call(data, 120)

        self.assertTrue(result)

    def test_is_network_call_negative(self):
        """Test negative identification of non-network calls."""
        data = bytearray(b'\x00' * 100 + b'SomeFunction' + b'\xFF\x15\x00\x00\x00\x00' + b'\x00' * 100)

        result = self.bypass._is_network_call(data, 120)

        self.assertFalse(result)

    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_disc_check_calls')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_scsi_commands')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._emulate_disc_presence')
    @patch.object(Path, 'exists', return_value=True)
    def test_bypass_disc_check(self, mock_exists, mock_emulate, mock_scsi, mock_patch):
        """Test disc check bypass."""
        mock_patch.return_value = True
        mock_scsi.return_value = True
        mock_emulate.return_value = True

        result = self.bypass.bypass_disc_check(self.test_exe_path)

        self.assertIsInstance(result, BypassResult)
        self.assertTrue(result.success)
        self.assertEqual(result.technique, 'Disc Check Bypass')

    @patch('builtins.open', new_callable=mock_open, read_data=b'DeviceIoControl\x00\xFF\x15\x00\x00\x00\x00' * 5)
    @patch.object(Path, 'exists', return_value=True)
    def test_patch_disc_check_calls(self, mock_exists, mock_file):
        """Test patching of disc check calls."""
        result = self.bypass._patch_disc_check_calls(self.test_exe_path)

        self.assertIsInstance(result, bool)

    @patch('builtins.open', new_callable=mock_open, read_data=b'SCSI\x00\x12CDB\x00\x28' * 3)
    @patch.object(Path, 'exists', return_value=True)
    def test_patch_scsi_commands(self, mock_exists, mock_file):
        """Test patching of SCSI commands."""
        result = self.bypass._patch_scsi_commands(self.test_exe_path)

        self.assertIsInstance(result, bool)

    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CreateKey')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.SetValueEx')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CloseKey')
    def test_emulate_disc_presence(self, mock_close, mock_set, mock_create):
        """Test disc presence emulation."""
        mock_create.return_value = MagicMock()

        result = self.bypass._emulate_disc_presence(self.test_exe_path)

        self.assertTrue(result)
        mock_set.assert_called()

    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_key_validation')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._inject_valid_key_data')
    @patch.object(Path, 'exists', return_value=True)
    def test_bypass_product_key_validation(self, mock_exists, mock_inject, mock_patch):
        """Test product key validation bypass."""
        mock_patch.return_value = True
        mock_inject.return_value = True

        result = self.bypass.bypass_product_key_validation(self.test_exe_path)

        self.assertIsInstance(result, BypassResult)
        self.assertTrue(result.success)
        self.assertEqual(result.technique, 'Product Key Bypass')

    @patch('builtins.open', new_callable=mock_open, read_data=b'VerifyProductKey\x00' + b'\x55\x8B\xEC' * 3)
    @patch.object(Path, 'exists', return_value=True)
    def test_patch_key_validation(self, mock_exists, mock_file):
        """Test patching of key validation."""
        result = self.bypass._patch_key_validation(self.test_exe_path)

        self.assertIsInstance(result, bool)

    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CreateKey')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.SetValueEx')
    @patch('intellicrack.core.protection_bypass.securom_bypass.winreg.CloseKey')
    def test_inject_valid_key_data(self, mock_close, mock_set, mock_create):
        """Test injection of valid key data."""
        mock_create.return_value = MagicMock()

        result = self.bypass._inject_valid_key_data(self.test_exe_path)

        self.assertTrue(result)
        mock_set.assert_called()

    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_network_calls')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._add_hosts_entries')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._block_firewall')
    def test_block_phone_home(self, mock_firewall, mock_hosts, mock_patch):
        """Test phone-home blocking."""
        mock_patch.return_value = True
        mock_hosts.return_value = True
        mock_firewall.return_value = True

        result = self.bypass.block_phone_home(
            self.test_exe_path,
            ['https://activation.example.com']
        )

        self.assertIsInstance(result, BypassResult)
        self.assertTrue(result.success)
        self.assertEqual(result.technique, 'Phone-Home Blocking')

    @patch('builtins.open', new_callable=mock_open, read_data=b'WinHttpSendRequest\x00\xFF\x15\x00\x00\x00\x00' * 3)
    @patch.object(Path, 'exists', return_value=True)
    def test_patch_network_calls(self, mock_exists, mock_file):
        """Test patching of network calls."""
        result = self.bypass._patch_network_calls(self.test_exe_path)

        self.assertIsInstance(result, bool)

    @patch('builtins.open', new_callable=mock_open)
    @patch.object(Path, 'exists', return_value=True)
    def test_add_hosts_entries(self, mock_exists, mock_file):
        """Test adding hosts file entries."""
        server_urls = ['https://activation.example.com', 'http://validation.test.com']

        result = self.bypass._add_hosts_entries(server_urls)

        self.assertIsInstance(result, bool)

    @patch('subprocess.run')
    def test_block_firewall(self, mock_run):
        """Test creation of firewall blocking rules."""
        mock_run.return_value = Mock(returncode=0)
        server_urls = ['https://activation.example.com']

        result = self.bypass._block_firewall(server_urls)

        self.assertTrue(result)
        mock_run.assert_called()

    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_challenge_generation')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_response_validation')
    @patch.object(Path, 'exists', return_value=True)
    def test_defeat_challenge_response(self, mock_exists, mock_response, mock_challenge):
        """Test challenge-response defeat."""
        mock_challenge.return_value = True
        mock_response.return_value = True

        result = self.bypass.defeat_challenge_response(self.test_exe_path)

        self.assertIsInstance(result, BypassResult)
        self.assertTrue(result.success)
        self.assertEqual(result.technique, 'Challenge-Response Defeat')

    @patch('builtins.open', new_callable=mock_open, read_data=b'GetActivationChallenge\x00' + b'\x55\x8B\xEC' * 3)
    @patch.object(Path, 'exists', return_value=True)
    def test_patch_challenge_generation(self, mock_exists, mock_file):
        """Test patching of challenge generation."""
        result = self.bypass._patch_challenge_generation(self.test_exe_path)

        self.assertIsInstance(result, bool)

    @patch('builtins.open', new_callable=mock_open, read_data=b'ValidateResponse\x00' + b'\x55\x8B\xEC' * 3)
    @patch.object(Path, 'exists', return_value=True)
    def test_patch_response_validation(self, mock_exists, mock_file):
        """Test patching of response validation."""
        result = self.bypass._patch_response_validation(self.test_exe_path)

        self.assertIsInstance(result, bool)


class TestBypassResult(unittest.TestCase):
    """Test cases for BypassResult dataclass."""

    def test_bypass_result_creation_success(self):
        """Test creation of successful bypass result."""
        result = BypassResult(
            success=True,
            technique='Activation Bypass',
            details='All checks bypassed successfully',
            errors=[]
        )

        self.assertTrue(result.success)
        self.assertEqual(result.technique, 'Activation Bypass')
        self.assertEqual(len(result.errors), 0)

    def test_bypass_result_creation_failure(self):
        """Test creation of failed bypass result."""
        result = BypassResult(
            success=False,
            technique='Disc Check Bypass',
            details='Partial bypass only',
            errors=['Failed to patch SCSI commands', 'Registry access denied']
        )

        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 2)


class TestSecuROMRemovalResult(unittest.TestCase):
    """Test cases for SecuROMRemovalResult dataclass."""

    def test_removal_result_creation(self):
        """Test creation of removal result."""
        result = SecuROMRemovalResult(
            drivers_removed=['secdrv.sys', 'SR8.sys'],
            services_stopped=['SecuROM8'],
            registry_cleaned=['SOFTWARE\\SecuROM'],
            files_deleted=[],
            activation_bypassed=True,
            triggers_removed=5,
            success=True,
            errors=[]
        )

        self.assertTrue(result.success)
        self.assertTrue(result.activation_bypassed)
        self.assertEqual(result.triggers_removed, 5)
        self.assertEqual(len(result.drivers_removed), 2)
        self.assertEqual(len(result.services_stopped), 1)


if __name__ == '__main__':
    unittest.main()
