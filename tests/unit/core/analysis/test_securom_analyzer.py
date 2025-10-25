"""
Unit tests for SecuROM Protection Analyzer.

Tests activation extraction, trigger identification, product key analysis,
disc authentication analysis, and challenge-response flow mapping.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import struct

from intellicrack.core.analysis.securom_analyzer import (
    SecuROMAnalyzer,
    SecuROMAnalysis,
    ActivationMechanism,
    TriggerPoint,
    ProductActivationKey,
    DiscAuthRoutine,
    PhoneHomeMechanism,
    ChallengeResponseFlow,
    LicenseValidationFunction
)


class TestSecuROMAnalyzer(unittest.TestCase):
    """Test cases for SecuROMAnalyzer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = SecuROMAnalyzer()
        self.test_exe_path = Path('test_securom.exe')

    @patch('builtins.open', mock_open(read_data=b'UserAccess8 SR8 SecuROM'))
    @patch.object(Path, 'exists', return_value=True)
    def test_detect_version_v8(self, mock_exists):
        """Test detection of SecuROM v8.x."""
        version = self.analyzer._detect_version(self.test_exe_path)

        self.assertEqual(version, '8.x')

    @patch('builtins.open', mock_open(read_data=b'UserAccess7 SR7 SecuROM'))
    @patch.object(Path, 'exists', return_value=True)
    def test_detect_version_v7(self, mock_exists):
        """Test detection of SecuROM v7.x."""
        version = self.analyzer._detect_version(self.test_exe_path)

        self.assertEqual(version, '7.x')

    @patch('builtins.open', mock_open(read_data=b'OnlineActivation Challenge Response MachineID HardwareID'))
    @patch.object(Path, 'exists', return_value=True)
    def test_analyze_activation_mechanisms(self, mock_exists):
        """Test analysis of activation mechanisms."""
        mechanisms = self.analyzer._analyze_activation_mechanisms(self.test_exe_path)

        self.assertIsInstance(mechanisms, list)
        self.assertGreater(len(mechanisms), 0)
        self.assertIsInstance(mechanisms[0], ActivationMechanism)
        self.assertTrue(mechanisms[0].online_validation)
        self.assertTrue(mechanisms[0].challenge_response)

    @patch('builtins.open', mock_open(read_data=b'ValidateLicense CheckActivationStatus VerifyProductKey'))
    @patch.object(Path, 'exists', return_value=True)
    def test_identify_trigger_points(self, mock_exists):
        """Test identification of validation trigger points."""
        triggers = self.analyzer._identify_trigger_points(self.test_exe_path)

        self.assertIsInstance(triggers, list)
        self.assertGreater(len(triggers), 0)
        self.assertIsInstance(triggers[0], TriggerPoint)

    def test_classify_trigger_type_validation(self):
        """Test classification of validation triggers."""
        trigger_type = self.analyzer._classify_trigger_type(b'ValidateLicense')

        self.assertEqual(trigger_type, 'Validation')

    def test_classify_trigger_type_check(self):
        """Test classification of check triggers."""
        trigger_type = self.analyzer._classify_trigger_type(b'CheckActivationStatus')

        self.assertEqual(trigger_type, 'Status Check')

    def test_classify_trigger_type_network(self):
        """Test classification of network triggers."""
        trigger_type = self.analyzer._classify_trigger_type(b'ContactActivationServer')

        self.assertEqual(trigger_type, 'Network Communication')

    def test_get_trigger_description(self):
        """Test getting trigger descriptions."""
        description = self.analyzer._get_trigger_description(b'ValidateLicense')

        self.assertIn('license', description.lower())

    @patch('builtins.open', mock_open(read_data=b'CreateWaitableTimer ValidateLicense'))
    def test_estimate_trigger_frequency_periodic(self):
        """Test estimation of periodic trigger frequency."""
        data = b'CreateWaitableTimer ValidateLicense'

        frequency = self.analyzer._estimate_trigger_frequency(data, data.find(b'ValidateLicense'))

        self.assertEqual(frequency, 'Periodic')

    @patch('builtins.open', mock_open(read_data=b'ProductKey SerialNumber ActivationKey'))
    @patch.object(Path, 'exists', return_value=True)
    def test_extract_product_key_info(self, mock_exists):
        """Test extraction of product key information."""
        keys = self.analyzer._extract_product_key_info(self.test_exe_path)

        self.assertIsInstance(keys, list)
        if len(keys) > 0:
            self.assertIsInstance(keys[0], ProductActivationKey)

    def test_detect_key_validation_algorithm_rsa(self):
        """Test detection of RSA key validation."""
        data = b'ProductKey' + b'\x00\x01\xFF\xFF\xFF\xFF' + b'data'

        algorithm = self.analyzer._detect_key_validation_algorithm(data, b'ProductKey')

        self.assertIn('RSA', algorithm)

    def test_detect_checksum_type_crc32(self):
        """Test detection of CRC32 checksum."""
        data = b'ProductKey' + b'CRC32' + b'data'

        checksum_type = self.analyzer._detect_checksum_type(data, b'ProductKey')

        self.assertEqual(checksum_type, 'CRC32')

    @patch('builtins.open', mock_open(read_data=b'DiscSignature SCSI CdRom DeviceIoControl'))
    @patch.object(Path, 'exists', return_value=True)
    def test_analyze_disc_authentication(self, mock_exists):
        """Test analysis of disc authentication routines."""
        routines = self.analyzer._analyze_disc_authentication(self.test_exe_path)

        self.assertIsInstance(routines, list)
        if len(routines) > 0:
            self.assertIsInstance(routines[0], DiscAuthRoutine)

    def test_extract_scsi_commands(self):
        """Test extraction of SCSI commands."""
        data = struct.pack('B', 0x12) + struct.pack('B', 0x28) + struct.pack('B', 0x43)

        commands = self.analyzer._extract_scsi_commands(data, 0)

        self.assertIsInstance(commands, list)
        self.assertIn('INQUIRY', commands)
        self.assertIn('READ_10', commands)

    def test_identify_signature_checks(self):
        """Test identification of disc signature checks."""
        data = b'DiscSignature TOC Subchannel PhysicalFormat'

        checks = self.analyzer._identify_signature_checks(data, 0)

        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)

    def test_determine_fingerprint_method_subchannel(self):
        """Test determination of subchannel fingerprinting."""
        data = b'DiscSignature Subchannel data'

        method = self.analyzer._determine_fingerprint_method(data, 0)

        self.assertIn('Subchannel', method)

    def test_assess_bypass_difficulty_low(self):
        """Test assessment of low bypass difficulty."""
        scsi_commands = ['INQUIRY']
        signature_checks = ['TOC']

        difficulty = self.analyzer._assess_bypass_difficulty(scsi_commands, signature_checks)

        self.assertEqual(difficulty, 'Low')

    def test_assess_bypass_difficulty_high(self):
        """Test assessment of high bypass difficulty."""
        scsi_commands = ['INQUIRY', 'READ_10', 'READ_TOC']
        signature_checks = ['TOC', 'Subchannel', 'PhysicalFormat']

        difficulty = self.analyzer._assess_bypass_difficulty(scsi_commands, signature_checks)

        self.assertEqual(difficulty, 'High')

    @patch('builtins.open', mock_open(read_data=b'WinHttpSendRequest https://activation.example.com MachineID'))
    @patch.object(Path, 'exists', return_value=True)
    def test_detect_phone_home(self, mock_exists):
        """Test detection of phone-home mechanisms."""
        mechanisms = self.analyzer._detect_phone_home(self.test_exe_path)

        self.assertIsInstance(mechanisms, list)
        if len(mechanisms) > 0:
            self.assertIsInstance(mechanisms[0], PhoneHomeMechanism)

    def test_extract_urls_near_offset(self):
        """Test extraction of URLs near offset."""
        data = b'some data https://activation.example.com\x00 more data http://test.com\x00 end'

        urls = self.analyzer._extract_urls_near_offset(data, 10)

        self.assertIsInstance(urls, list)
        self.assertGreater(len(urls), 0)
        self.assertTrue(any('https://' in url for url in urls))

    def test_identify_transmitted_data(self):
        """Test identification of transmitted data."""
        data = b'WinHttpSendRequest MachineID ProductKey ActivationStatus'

        transmitted = self.analyzer._identify_transmitted_data(data, data.find(b'WinHttpSendRequest'))

        self.assertIsInstance(transmitted, list)
        self.assertIn('Machine ID', transmitted)
        self.assertIn('Product Key', transmitted)

    def test_detect_protocol_http(self):
        """Test detection of HTTP protocol."""
        protocol = self.analyzer._detect_protocol(b'WinHttpSendRequest')

        self.assertEqual(protocol, 'HTTP/HTTPS')

    def test_detect_protocol_socket(self):
        """Test detection of socket protocol."""
        protocol = self.analyzer._detect_protocol(b'WSASend')

        self.assertEqual(protocol, 'TCP/IP')

    @patch('builtins.open', mock_open(read_data=b'Challenge Response RSA PBKDF2'))
    @patch.object(Path, 'exists', return_value=True)
    def test_analyze_challenge_response(self, mock_exists):
        """Test analysis of challenge-response flows."""
        flows = self.analyzer._analyze_challenge_response(self.test_exe_path)

        self.assertIsInstance(flows, list)
        if len(flows) > 0:
            self.assertIsInstance(flows[0], ChallengeResponseFlow)

    @patch('builtins.open', mock_open(read_data=b'ValidateLicense CheckActivation VerifyProductKey'))
    @patch.object(Path, 'exists', return_value=True)
    def test_map_license_validation(self, mock_exists):
        """Test mapping of license validation functions."""
        functions = self.analyzer._map_license_validation(self.test_exe_path)

        self.assertIsInstance(functions, list)
        if len(functions) > 0:
            self.assertIsInstance(functions[0], LicenseValidationFunction)

    def test_identify_validation_checks(self):
        """Test identification of validation checks."""
        data = b'ValidateLicense Registry Network Hardware Signature'

        checks = self.analyzer._identify_validation_checks(data, data.find(b'ValidateLicense'))

        self.assertIsInstance(checks, list)
        self.assertIn('Registry Check', checks)
        self.assertIn('Network Validation', checks)

    def test_extract_return_values(self):
        """Test extraction of return values."""
        data = b'ValidateLicense'

        return_values = self.analyzer._extract_return_values(data, 0)

        self.assertIsInstance(return_values, dict)
        self.assertIn('0', return_values)
        self.assertEqual(return_values['0'], 'Validation Success')

    @patch('builtins.open', mock_open(read_data=b'RSA AES SHA256 MD5'))
    @patch.object(Path, 'exists', return_value=True)
    def test_identify_encryption(self, mock_exists):
        """Test identification of encryption techniques."""
        techniques = self.analyzer._identify_encryption(self.test_exe_path)

        self.assertIsInstance(techniques, list)

    @patch('intellicrack.core.analysis.securom_analyzer.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.analysis.securom_analyzer.pefile.PE')
    def test_detect_obfuscation_virtual_section(self, mock_pe):
        """Test detection of virtual section obfuscation."""
        mock_section = Mock()
        mock_section.SizeOfRawData = 0
        mock_section.Misc_VirtualSize = 0x1000

        mock_pe_instance = Mock()
        mock_pe_instance.sections = [mock_section]
        mock_pe_instance.close = Mock()
        mock_pe.return_value = mock_pe_instance

        methods = self.analyzer._detect_obfuscation(self.test_exe_path)

        self.assertIsInstance(methods, list)
        self.assertIn('Virtual Section Obfuscation', methods)

    @patch('intellicrack.core.analysis.securom_analyzer.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.analysis.securom_analyzer.pefile.PE')
    def test_get_imports(self, mock_pe):
        """Test getting imported functions."""
        mock_import = Mock()
        mock_import.name = b'CreateFileW'

        mock_entry = Mock()
        mock_entry.dll = b'kernel32.dll'
        mock_entry.imports = [mock_import]

        mock_pe_instance = Mock()
        mock_pe_instance.DIRECTORY_ENTRY_IMPORT = [mock_entry]
        mock_pe_instance.close = Mock()
        mock_pe.return_value = mock_pe_instance

        imports = self.analyzer._get_imports(self.test_exe_path)

        self.assertIsInstance(imports, list)
        self.assertTrue(any('kernel32.dll!CreateFileW' in imp for imp in imports))

    @patch('intellicrack.core.analysis.securom_analyzer.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.analysis.securom_analyzer.pefile.PE')
    def test_get_exports(self, mock_pe):
        """Test getting exported functions."""
        mock_export = Mock()
        mock_export.name = b'ActivationFunction'

        mock_pe_instance = Mock()
        mock_pe_instance.DIRECTORY_ENTRY_EXPORT = Mock()
        mock_pe_instance.DIRECTORY_ENTRY_EXPORT.symbols = [mock_export]
        mock_pe_instance.close = Mock()
        mock_pe.return_value = mock_pe_instance

        exports = self.analyzer._get_exports(self.test_exe_path)

        self.assertIsInstance(exports, list)
        self.assertIn('ActivationFunction', exports)

    @patch('builtins.open', mock_open(read_data=b'ProductActivation ValidateLicense OnlineActivation'))
    @patch.object(Path, 'exists', return_value=True)
    def test_extract_relevant_strings(self, mock_exists):
        """Test extraction of relevant strings."""
        strings = self.analyzer._extract_relevant_strings(self.test_exe_path)

        self.assertIsInstance(strings, list)
        self.assertLessEqual(len(strings), 50)

    @patch('builtins.open', mock_open(read_data=b'https://activation.server.com\x00http://backup.server.com\x00'))
    @patch.object(Path, 'exists', return_value=True)
    def test_extract_network_endpoints(self, mock_exists):
        """Test extraction of network endpoints."""
        endpoints = self.analyzer._extract_network_endpoints(self.test_exe_path)

        self.assertIsInstance(endpoints, list)
        self.assertTrue(any('https://' in ep for ep in endpoints))

    @patch('builtins.open', mock_open(read_data=b'SOFTWARE\\SecuROM SOFTWARE\\Sony DADC'))
    @patch.object(Path, 'exists', return_value=True)
    def test_identify_registry_access(self, mock_exists):
        """Test identification of registry access."""
        registry_keys = self.analyzer._identify_registry_access(self.test_exe_path)

        self.assertIsInstance(registry_keys, list)
        self.assertTrue(any('SecuROM' in key for key in registry_keys))

    @patch.object(Path, 'exists', return_value=True)
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._detect_version')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._analyze_activation_mechanisms')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._identify_trigger_points')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._extract_product_key_info')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._analyze_disc_authentication')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._detect_phone_home')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._analyze_challenge_response')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._map_license_validation')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._identify_encryption')
    @patch('intellicrack.core.analysis.securom_analyzer.SecuROMAnalyzer._detect_obfuscation')
    def test_full_analysis(
        self, mock_obf, mock_enc, mock_lic, mock_chal, mock_phone,
        mock_disc, mock_keys, mock_trig, mock_act, mock_ver
    ):
        """Test complete analysis workflow."""
        mock_ver.return_value = '8.x'
        mock_act.return_value = [ActivationMechanism(
            activation_type='Online',
            online_validation=True,
            challenge_response=True,
            activation_server_url='https://test.com',
            max_activations=5,
            hardware_binding=['Machine ID'],
            encryption_algorithm='RSA'
        )]
        mock_trig.return_value = []
        mock_keys.return_value = []
        mock_disc.return_value = []
        mock_phone.return_value = []
        mock_chal.return_value = []
        mock_lic.return_value = []
        mock_enc.return_value = ['RSA', 'AES']
        mock_obf.return_value = ['Virtual Section Obfuscation']

        result = self.analyzer.analyze(self.test_exe_path)

        self.assertIsInstance(result, SecuROMAnalysis)
        self.assertEqual(result.version, '8.x')
        self.assertIsInstance(result.activation_mechanisms, list)
        self.assertIsInstance(result.encryption_techniques, list)
        self.assertIsInstance(result.obfuscation_methods, list)


class TestActivationMechanism(unittest.TestCase):
    """Test cases for ActivationMechanism dataclass."""

    def test_activation_mechanism_creation(self):
        """Test creation of activation mechanism."""
        mechanism = ActivationMechanism(
            activation_type='Online with Challenge-Response',
            online_validation=True,
            challenge_response=True,
            activation_server_url='https://activation.example.com',
            max_activations=5,
            hardware_binding=['Machine ID', 'Hardware ID'],
            encryption_algorithm='RSA'
        )

        self.assertEqual(mechanism.activation_type, 'Online with Challenge-Response')
        self.assertTrue(mechanism.online_validation)
        self.assertTrue(mechanism.challenge_response)
        self.assertEqual(mechanism.max_activations, 5)
        self.assertEqual(len(mechanism.hardware_binding), 2)


class TestTriggerPoint(unittest.TestCase):
    """Test cases for TriggerPoint dataclass."""

    def test_trigger_point_creation(self):
        """Test creation of trigger point."""
        trigger = TriggerPoint(
            address=0x1000,
            trigger_type='Validation',
            description='Validates license with server',
            function_name='ValidateLicense',
            frequency='Periodic'
        )

        self.assertEqual(trigger.address, 0x1000)
        self.assertEqual(trigger.trigger_type, 'Validation')
        self.assertEqual(trigger.frequency, 'Periodic')


class TestProductActivationKey(unittest.TestCase):
    """Test cases for ProductActivationKey dataclass."""

    def test_product_key_creation(self):
        """Test creation of product key structure."""
        key = ProductActivationKey(
            key_format='Dashed Format',
            key_length=29,
            validation_algorithm='RSA Signature Verification',
            example_pattern=r'[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}',
            checksum_type='CRC32'
        )

        self.assertEqual(key.key_format, 'Dashed Format')
        self.assertEqual(key.key_length, 29)
        self.assertEqual(key.validation_algorithm, 'RSA Signature Verification')
        self.assertEqual(key.checksum_type, 'CRC32')


if __name__ == '__main__':
    unittest.main()
