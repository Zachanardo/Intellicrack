"""
Integration tests for complete SecuROM workflow.

Tests end-to-end workflow from detection through analysis to bypass.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import winreg

from intellicrack.core.protection_detection.securom_detector import (
    SecuROMDetector,
    SecuROMDetection,
    SecuROMVersion,
    SecuROMActivation
)
from intellicrack.core.analysis.securom_analyzer import (
    SecuROMAnalyzer,
    SecuROMAnalysis
)
from intellicrack.core.protection_bypass.securom_bypass import (
    SecuROMBypass,
    BypassResult,
    SecuROMRemovalResult
)


class TestSecuROMCompleteWorkflow(unittest.TestCase):
    """Integration tests for complete SecuROM cracking workflow."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_exe_path = Path('test_securom_protected.exe')
        self.detector = SecuROMDetector()
        self.analyzer = SecuROMAnalyzer()
        self.bypass = SecuROMBypass()

    @patch.object(Path, 'exists', return_value=True)
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_drivers')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_services')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_registry_keys')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_activation_state')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_protected_sections')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_version')
    def test_detection_to_analysis_workflow(
        self, mock_version, mock_sections, mock_activation,
        mock_registry, mock_services, mock_drivers, mock_exists
    ):
        """Test workflow from detection to analysis."""
        mock_drivers.return_value = ['secdrv.sys', 'SR8.sys']
        mock_services.return_value = ['SecuROM8', 'UserAccess8']
        mock_registry.return_value = ['SOFTWARE\\SecuROM', 'SOFTWARE\\SecuROM\\Activation']
        mock_activation.return_value = SecuROMActivation(
            is_activated=False,
            activation_date=None,
            product_key=None,
            machine_id=None,
            activation_count=0,
            remaining_activations=5
        )
        mock_sections.return_value = ['.securom', '.sdata']
        mock_version.return_value = SecuROMVersion(8, 0, 0, 'PA')

        detection_result = self.detector.detect(self.test_exe_path)

        self.assertIsInstance(detection_result, SecuROMDetection)
        self.assertTrue(detection_result.detected)
        self.assertEqual(detection_result.version.major, 8)
        self.assertFalse(detection_result.activation_state.is_activated)

        with patch('builtins.open', mock_open(read_data=b'UserAccess8 OnlineActivation ProductKey')):
            with patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_imports'):
                with patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_exports'):
                    analysis_result = self.analyzer.analyze(self.test_exe_path)

        self.assertIsInstance(analysis_result, SecuROMAnalysis)
        self.assertEqual(analysis_result.version, '8.x')

    @patch.object(Path, 'exists', return_value=True)
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_drivers')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_services')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_registry_keys')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_activation_state')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._stop_all_services')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._delete_all_services')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._clean_registry')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._bypass_activation_registry')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._remove_driver_files')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._remove_application_files')
    def test_detection_to_bypass_workflow(
        self, mock_app_files, mock_drv_files, mock_bypass_act, mock_clean_reg,
        mock_del_svc, mock_stop_svc, mock_activation, mock_registry,
        mock_services, mock_drivers, mock_exists
    ):
        """Test workflow from detection to bypass."""
        mock_drivers.return_value = ['secdrv.sys', 'SR8.sys']
        mock_services.return_value = ['SecuROM8']
        mock_registry.return_value = ['SOFTWARE\\SecuROM']
        mock_activation.return_value = SecuROMActivation(
            is_activated=False,
            activation_date=None,
            product_key=None,
            machine_id=None,
            activation_count=0,
            remaining_activations=5
        )

        detection_result = self.detector.detect(self.test_exe_path)

        self.assertTrue(detection_result.detected)
        self.assertFalse(detection_result.activation_state.is_activated)

        mock_stop_svc.return_value = ['SecuROM8']
        mock_del_svc.return_value = ['SecuROM8']
        mock_clean_reg.return_value = ['SOFTWARE\\SecuROM']
        mock_bypass_act.return_value = True
        mock_drv_files.return_value = ['secdrv.sys']
        mock_app_files.return_value = []

        bypass_result = self.bypass.remove_securom()

        self.assertIsInstance(bypass_result, SecuROMRemovalResult)
        self.assertTrue(bypass_result.success)
        self.assertTrue(bypass_result.activation_bypassed)

    @patch.object(Path, 'exists', return_value=True)
    @patch('builtins.open', mock_open(read_data=b'ValidateLicense OnlineActivation ProductActivation'))
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_imports')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_exports')
    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_activation_checks')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._bypass_activation_registry')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._inject_activation_data')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._disable_activation_countdown')
    @patch('shutil.copy2')
    def test_analysis_to_bypass_workflow(
        self, mock_copy, mock_countdown, mock_inject, mock_reg, mock_patch,
        mock_exports, mock_imports, mock_exists
    ):
        """Test workflow from analysis to bypass."""
        mock_imports.return_value = ['kernel32.dll!CreateFileW']
        mock_exports.return_value = []

        analysis_result = self.analyzer.analyze(self.test_exe_path)

        self.assertIsInstance(analysis_result, SecuROMAnalysis)
        self.assertGreater(len(analysis_result.trigger_points), 0)

        mock_patch.return_value = True
        mock_reg.return_value = True
        mock_inject.return_value = True
        mock_countdown.return_value = True

        bypass_result = self.bypass.bypass_activation(self.test_exe_path)

        self.assertIsInstance(bypass_result, BypassResult)
        self.assertTrue(bypass_result.success)

    @patch.object(Path, 'exists', return_value=True)
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_drivers')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_services')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_registry_keys')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_activation_state')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_protected_sections')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_version')
    @patch('builtins.open', mock_open(read_data=b'UserAccess8 ValidateLicense DiscSignature'))
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_imports')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_exports')
    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_activation_checks')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._bypass_activation_registry')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._inject_activation_data')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._disable_activation_countdown')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_disc_check_calls')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_scsi_commands')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._emulate_disc_presence')
    @patch('shutil.copy2')
    def test_complete_end_to_end_workflow(
        self, mock_copy, mock_emulate, mock_scsi, mock_disc,
        mock_countdown, mock_inject, mock_reg, mock_patch,
        mock_exports, mock_imports, mock_version, mock_sections,
        mock_activation, mock_registry, mock_services, mock_drivers, mock_exists
    ):
        """Test complete end-to-end workflow: detect, analyze, bypass."""
        mock_drivers.return_value = ['secdrv.sys', 'SR8.sys']
        mock_services.return_value = ['SecuROM8']
        mock_registry.return_value = ['SOFTWARE\\SecuROM']
        mock_activation.return_value = SecuROMActivation(
            is_activated=False,
            activation_date=None,
            product_key=None,
            machine_id=None,
            activation_count=0,
            remaining_activations=5
        )
        mock_sections.return_value = ['.securom']
        mock_version.return_value = SecuROMVersion(8, 0, 0, 'PA')

        detection_result = self.detector.detect(self.test_exe_path)

        self.assertTrue(detection_result.detected)
        self.assertEqual(detection_result.version.major, 8)

        mock_imports.return_value = ['kernel32.dll!CreateFileW', 'advapi32.dll!RegOpenKeyExW']
        mock_exports.return_value = []

        analysis_result = self.analyzer.analyze(self.test_exe_path)

        self.assertIsInstance(analysis_result, SecuROMAnalysis)
        self.assertEqual(analysis_result.version, '8.x')

        mock_patch.return_value = True
        mock_reg.return_value = True
        mock_inject.return_value = True
        mock_countdown.return_value = True

        activation_bypass = self.bypass.bypass_activation(self.test_exe_path)

        self.assertTrue(activation_bypass.success)

        mock_disc.return_value = True
        mock_scsi.return_value = True
        mock_emulate.return_value = True

        disc_bypass = self.bypass.bypass_disc_check(self.test_exe_path)

        self.assertTrue(disc_bypass.success)

    @patch.object(Path, 'exists', return_value=True)
    @patch('builtins.open', mock_open(read_data=b'ValidateLicense CheckActivationStatus PhoneHome'))
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_imports')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_exports')
    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('shutil.copy2')
    def test_trigger_identification_and_removal(
        self, mock_copy, mock_exports, mock_imports, mock_exists
    ):
        """Test identification and removal of validation triggers."""
        mock_imports.return_value = []
        mock_exports.return_value = []

        analysis_result = self.analyzer.analyze(self.test_exe_path)

        triggers = analysis_result.trigger_points
        self.assertIsInstance(triggers, list)

        with patch('builtins.open', mock_open(read_data=b'ValidateLicense\x00\x55\x8B\xEC' * 3)):
            bypass_result = self.bypass.remove_triggers(self.test_exe_path)

        self.assertIsInstance(bypass_result, BypassResult)
        self.assertEqual(bypass_result.technique, 'Trigger Removal')

    @patch.object(Path, 'exists', return_value=True)
    @patch('builtins.open', mock_open(read_data=b'ProductKey Challenge Response RSA'))
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_imports')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_exports')
    @patch('intellicrack.core.protection_bypass.securom_bypass.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_key_validation')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._inject_valid_key_data')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_challenge_generation')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_response_validation')
    def test_product_key_and_challenge_response_bypass(
        self, mock_resp, mock_chal, mock_inject, mock_patch,
        mock_exports, mock_imports, mock_exists
    ):
        """Test product key and challenge-response bypass."""
        mock_imports.return_value = []
        mock_exports.return_value = []

        analysis_result = self.analyzer.analyze(self.test_exe_path)

        product_keys = analysis_result.product_keys
        challenge_flows = analysis_result.challenge_response_flows

        self.assertIsInstance(product_keys, list)
        self.assertIsInstance(challenge_flows, list)

        mock_patch.return_value = True
        mock_inject.return_value = True

        key_bypass = self.bypass.bypass_product_key_validation(self.test_exe_path)

        self.assertTrue(key_bypass.success)

        mock_chal.return_value = True
        mock_resp.return_value = True

        challenge_bypass = self.bypass.defeat_challenge_response(self.test_exe_path)

        self.assertTrue(challenge_bypass.success)

    @patch.object(Path, 'exists', return_value=True)
    @patch('builtins.open', mock_open(read_data=b'WinHttpSendRequest https://activation.server.com'))
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_imports')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._get_exports')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._patch_network_calls')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._add_hosts_entries')
    @patch('intellicrack.core.protection_bypass.securom_bypass.SecuROMBypass._block_firewall')
    def test_phone_home_detection_and_blocking(
        self, mock_firewall, mock_hosts, mock_patch,
        mock_exports, mock_imports, mock_exists
    ):
        """Test phone-home detection and blocking."""
        mock_imports.return_value = []
        mock_exports.return_value = []

        analysis_result = self.analyzer.analyze(self.test_exe_path)

        phone_home = analysis_result.phone_home_mechanisms
        self.assertIsInstance(phone_home, list)

        server_urls = []
        for mechanism in phone_home:
            server_urls.extend(mechanism.server_urls)

        mock_patch.return_value = True
        mock_hosts.return_value = True
        mock_firewall.return_value = True

        bypass_result = self.bypass.block_phone_home(self.test_exe_path, server_urls)

        self.assertTrue(bypass_result.success)


class TestSecuROMVersionSpecificWorkflows(unittest.TestCase):
    """Test version-specific workflows for SecuROM v7 and v8."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = SecuROMDetector()
        self.analyzer = SecuROMAnalyzer()
        self.test_exe_v7 = Path('test_securom_v7.exe')
        self.test_exe_v8 = Path('test_securom_v8.exe')

    @patch.object(Path, 'exists', return_value=True)
    @patch('builtins.open', mock_open(read_data=b'UserAccess7 SR7 Sony DADC'))
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_drivers')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_services')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_registry_keys')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_activation_state')
    def test_securom_v7_detection(
        self, mock_activation, mock_registry, mock_services, mock_drivers, mock_exists
    ):
        """Test detection of SecuROM v7.x."""
        mock_drivers.return_value = ['SR7.sys']
        mock_services.return_value = ['UserAccess7']
        mock_registry.return_value = ['SOFTWARE\\SecuROM']
        mock_activation.return_value = None

        result = self.detector.detect(self.test_exe_v7)

        self.assertTrue(result.detected)
        self.assertEqual(result.version.major, 7)

    @patch.object(Path, 'exists', return_value=True)
    @patch('builtins.open', mock_open(read_data=b'UserAccess8 SR8 ProductActivation OnlineActivation'))
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_drivers')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_services')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_registry_keys')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_activation_state')
    def test_securom_v8_pa_detection(
        self, mock_activation, mock_registry, mock_services, mock_drivers, mock_exists
    ):
        """Test detection of SecuROM v8.x with Product Activation."""
        mock_drivers.return_value = ['SR8.sys']
        mock_services.return_value = ['UserAccess8', 'SecuROM8']
        mock_registry.return_value = ['SOFTWARE\\SecuROM', 'SOFTWARE\\SecuROM\\Activation']
        mock_activation.return_value = SecuROMActivation(
            is_activated=True,
            activation_date='2024-01-01',
            product_key='TEST-KEY',
            machine_id='MACHINE-ID',
            activation_count=1,
            remaining_activations=4
        )

        result = self.detector.detect(self.test_exe_v8)

        self.assertTrue(result.detected)
        self.assertEqual(result.version.major, 8)
        self.assertEqual(result.version.variant, 'PA (Product Activation)')
        self.assertTrue(result.activation_state.is_activated)


if __name__ == '__main__':
    unittest.main()
