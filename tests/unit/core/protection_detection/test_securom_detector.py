"""Unit tests for SecuROM Protection Detector.

Tests signature detection, registry analysis, confidence scoring,
version detection, and activation state detection.
"""

import unittest
import winreg
from pathlib import Path
from unittest.mock import MagicMock, Mock, mock_open, patch

from intellicrack.core.protection_detection.securom_detector import SecuROMActivation, SecuROMDetection, SecuROMDetector, SecuROMVersion


class TestSecuROMDetector(unittest.TestCase):
    """Test cases for SecuROMDetector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = SecuROMDetector()
        self.test_exe_path = Path('test_securom.exe')

    @patch('intellicrack.core.protection_detection.securom_detector.Path.exists')
    def test_driver_detection(self, mock_exists):
        """Test detection of SecuROM kernel drivers."""
        mock_exists.return_value = True

        with patch('builtins.open', mock_open(read_data=b'Sony DADC SecuROM UserAccess8')):
            drivers = self.detector._detect_drivers()

        self.assertIsInstance(drivers, list)

    @patch('intellicrack.core.protection_detection.securom_detector.winreg.OpenKey')
    @patch('intellicrack.core.protection_detection.securom_detector.winreg.CloseKey')
    def test_registry_key_detection(self, mock_closekey, mock_openkey):
        """Test detection of SecuROM registry keys."""
        mock_openkey.return_value = MagicMock()

        registry_keys = self.detector._detect_registry_keys()

        self.assertIsInstance(registry_keys, list)
        self.assertGreater(len(registry_keys), 0)

    @patch('intellicrack.core.protection_detection.securom_detector.winreg.OpenKey')
    @patch('intellicrack.core.protection_detection.securom_detector.winreg.QueryValueEx')
    @patch('intellicrack.core.protection_detection.securom_detector.winreg.CloseKey')
    def test_activation_state_detection_activated(self, mock_close, mock_query, mock_open):
        """Test detection of activated SecuROM."""
        mock_open.return_value = MagicMock()

        def query_side_effect(key, value_name):
            values = {
                'Activated': (1, winreg.REG_DWORD),
                'ActivationDate': ('2024-01-01', winreg.REG_SZ),
                'ProductKey': ('TEST-KEY-12345', winreg.REG_SZ),
                'MachineID': ('MACHINE-ID-TEST', winreg.REG_SZ),
                'ActivationCount': (1, winreg.REG_DWORD),
                'MaxActivations': (5, winreg.REG_DWORD)
            }
            return values.get(value_name, (None, None))

        mock_query.side_effect = query_side_effect

        activation_state = self.detector._detect_activation_state()

        self.assertIsNotNone(activation_state)
        self.assertIsInstance(activation_state, SecuROMActivation)
        self.assertTrue(activation_state.is_activated)
        self.assertEqual(activation_state.activation_date, '2024-01-01')
        self.assertEqual(activation_state.product_key, 'TEST-KEY-12345')
        self.assertEqual(activation_state.activation_count, 1)
        self.assertEqual(activation_state.remaining_activations, 4)

    @patch('intellicrack.core.protection_detection.securom_detector.winreg.OpenKey')
    def test_activation_state_detection_not_activated(self, mock_open):
        """Test detection when SecuROM is not activated."""
        mock_open.side_effect = WindowsError()

        activation_state = self.detector._detect_activation_state()

        self.assertIsNone(activation_state)

    @patch('intellicrack.core.protection_detection.securom_detector.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_detection.securom_detector.pefile.PE')
    def test_protected_section_detection(self, mock_pe):
        """Test detection of protected PE sections."""
        mock_section1 = Mock()
        mock_section1.Name = b'.securom\x00\x00'
        mock_section1.SizeOfRawData = 0
        mock_section1.Misc_VirtualSize = 0x1000
        mock_section1.Characteristics = 0x20000000
        mock_section1.get_data.return_value = b'\x00' * 100

        mock_section2 = Mock()
        mock_section2.Name = b'.text\x00\x00\x00'
        mock_section2.SizeOfRawData = 0x1000
        mock_section2.Misc_VirtualSize = 0x1000
        mock_section2.Characteristics = 0x60000020
        mock_section2.get_data.return_value = bytes(range(256)) * 4

        mock_pe_instance = Mock()
        mock_pe_instance.sections = [mock_section1, mock_section2]
        mock_pe.return_value = mock_pe_instance

        sections = self.detector._detect_protected_sections(self.test_exe_path)

        self.assertIsInstance(sections, list)
        self.assertTrue(any('.securom' in s for s in sections))

    def test_entropy_calculation(self):
        """Test Shannon entropy calculation for sections."""
        low_entropy_data = b'\x00' * 1000
        low_entropy = self.detector._calculate_section_entropy(low_entropy_data)
        self.assertLess(low_entropy, 1.0)

        high_entropy_data = bytes(range(256)) * 4
        high_entropy = self.detector._calculate_section_entropy(high_entropy_data)
        self.assertGreater(high_entropy, 5.0)

    @patch('intellicrack.core.protection_detection.securom_detector.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_detection.securom_detector.pefile.PE')
    def test_version_detection_v7(self, mock_pe):
        """Test detection of SecuROM v7.x."""
        mock_pe_instance = Mock()
        mock_pe_instance.get_memory_mapped_image.return_value = b'UserAccess7 SR7 Sony DADC'
        mock_pe_instance.close = Mock()
        mock_pe_instance.FileInfo = []
        mock_pe.return_value = mock_pe_instance

        version = self.detector._detect_version(self.test_exe_path)

        self.assertIsNotNone(version)
        self.assertIsInstance(version, SecuROMVersion)
        self.assertEqual(version.major, 7)

    @patch('intellicrack.core.protection_detection.securom_detector.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_detection.securom_detector.pefile.PE')
    def test_version_detection_v8(self, mock_pe):
        """Test detection of SecuROM v8.x with PA."""
        mock_pe_instance = Mock()
        mock_pe_instance.get_memory_mapped_image.return_value = b'UserAccess8 SR8 ProductActivation'
        mock_pe_instance.close = Mock()
        mock_pe_instance.FileInfo = []
        mock_pe.return_value = mock_pe_instance

        version = self.detector._detect_version(self.test_exe_path)

        self.assertIsNotNone(version)
        self.assertIsInstance(version, SecuROMVersion)
        self.assertEqual(version.major, 8)
        self.assertEqual(version.variant, 'PA (Product Activation)')

    def test_parse_version_string(self):
        """Test version string parsing."""
        version_str = 'SecuROM 8.1.2 PA'
        version = self.detector._parse_version_string(version_str)

        self.assertIsNotNone(version)
        self.assertEqual(version.major, 8)
        self.assertEqual(version.minor, 1)
        self.assertEqual(version.build, 2)
        self.assertEqual(version.variant, 'PA')

    @patch('intellicrack.core.protection_detection.securom_detector.YARA_AVAILABLE', True)
    def test_yara_rule_compilation(self):
        """Test YARA rule compilation."""
        with patch('intellicrack.core.protection_detection.securom_detector.yara.compile') as mock_compile:
            mock_compile.return_value = Mock()
            detector = SecuROMDetector()

            self.assertIsNotNone(detector._yara_rules)
            mock_compile.assert_called_once()

    @patch('intellicrack.core.protection_detection.securom_detector.YARA_AVAILABLE', True)
    @patch('intellicrack.core.protection_detection.securom_detector.yara.compile')
    def test_yara_scan_matches(self, mock_compile):
        """Test YARA scanning for SecuROM signatures."""
        mock_match = Mock()
        mock_match.rule = 'SecuROM_v8'
        mock_match.meta = {'version': '8.x', 'description': 'SecuROM v8.x protection'}

        mock_rules = Mock()
        mock_rules.match.return_value = [mock_match]
        mock_compile.return_value = mock_rules

        detector = SecuROMDetector()

        with patch.object(Path, 'exists', return_value=True):
            matches = detector._yara_scan(self.test_exe_path)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['rule'], 'SecuROM_v8')
        self.assertEqual(matches[0]['version'], '8.x')

    def test_confidence_calculation_high(self):
        """Test confidence calculation with strong indicators."""
        drivers = ['secdrv.sys', 'SR8.sys']
        services = ['SecuROM8', 'UserAccess8']
        registry_keys = ['SOFTWARE\\SecuROM', 'SOFTWARE\\SecuROM\\Activation']
        sections = ['.securom', '.sdata']
        yara_matches = [{'rule': 'SecuROM_v8'}]
        activation_state = SecuROMActivation(
            is_activated=True,
            activation_date='2024-01-01',
            product_key='TEST',
            machine_id='TEST',
            activation_count=1,
            remaining_activations=4
        )

        confidence = self.detector._calculate_confidence(
            drivers, services, registry_keys, sections, yara_matches, activation_state
        )

        self.assertGreater(confidence, 0.8)
        self.assertLessEqual(confidence, 1.0)

    def test_confidence_calculation_low(self):
        """Test confidence calculation with weak indicators."""
        drivers = []
        services = []
        registry_keys = []
        sections = []
        yara_matches = []
        activation_state = None

        confidence = self.detector._calculate_confidence(
            drivers, services, registry_keys, sections, yara_matches, activation_state
        )

        self.assertEqual(confidence, 0.0)

    def test_confidence_calculation_medium(self):
        """Test confidence calculation with moderate indicators."""
        drivers = ['secdrv.sys']
        services = []
        registry_keys = ['SOFTWARE\\SecuROM']
        sections = ['.securom']
        yara_matches = []
        activation_state = None

        confidence = self.detector._calculate_confidence(
            drivers, services, registry_keys, sections, yara_matches, activation_state
        )

        self.assertGreater(confidence, 0.3)
        self.assertLess(confidence, 0.7)

    def test_is_securom_driver_positive(self):
        """Test positive identification of SecuROM driver."""
        test_path = Path('test_driver.sys')

        with patch('builtins.open', mock_open(read_data=b'Sony DADC SecuROM')):
            result = self.detector._is_securom_driver(test_path)

        self.assertTrue(result)

    def test_is_securom_driver_negative(self):
        """Test negative identification of non-SecuROM driver."""
        test_path = Path('test_driver.sys')

        with patch('builtins.open', mock_open(read_data=b'Generic Driver Data')):
            result = self.detector._is_securom_driver(test_path)

        self.assertFalse(result)

    @patch('builtins.open', mock_open(read_data=b'DiscSignature DiscFingerprint DeviceIoControl'))
    @patch.object(Path, 'exists', return_value=True)
    def test_detect_disc_authentication(self, mock_exists):
        """Test detection of disc authentication mechanisms."""
        result = self.detector._detect_disc_authentication(self.test_exe_path)

        self.assertTrue(result)

    @patch('builtins.open', mock_open(read_data=b'ProductActivation https://activation.server.com WinHttpSendRequest'))
    @patch.object(Path, 'exists', return_value=True)
    def test_detect_online_activation(self, mock_exists):
        """Test detection of online activation mechanisms."""
        result = self.detector._detect_online_activation(self.test_exe_path)

        self.assertTrue(result)

    @patch('intellicrack.core.protection_detection.securom_detector.PEFILE_AVAILABLE', True)
    @patch('intellicrack.core.protection_detection.securom_detector.pefile.PE')
    def test_detect_encryption(self, mock_pe):
        """Test detection of SecuROM encryption."""
        mock_section = Mock()
        mock_section.get_data.return_value = bytes(range(256)) * 10

        mock_pe_instance = Mock()
        mock_pe_instance.sections = [mock_section]
        mock_pe_instance.close = Mock()
        mock_pe.return_value = mock_pe_instance

        result = self.detector._detect_encryption(self.test_exe_path)

        self.assertTrue(result)

    @patch.object(Path, 'exists', return_value=True)
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_drivers')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_services')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_registry_keys')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_activation_state')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_protected_sections')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_version')
    def test_full_detection_positive(
        self, mock_version, mock_sections, mock_activation,
        mock_registry, mock_services, mock_drivers, mock_path_exists
    ):
        """Test complete detection with positive result."""
        mock_drivers.return_value = ['secdrv.sys', 'SR8.sys']
        mock_services.return_value = ['SecuROM8']
        mock_registry.return_value = ['SOFTWARE\\SecuROM']
        mock_activation.return_value = SecuROMActivation(
            is_activated=True,
            activation_date='2024-01-01',
            product_key='TEST',
            machine_id='TEST',
            activation_count=1,
            remaining_activations=4
        )
        mock_sections.return_value = ['.securom']
        mock_version.return_value = SecuROMVersion(8, 0, 0, 'PA')

        result = self.detector.detect(self.test_exe_path)

        self.assertIsInstance(result, SecuROMDetection)
        self.assertTrue(result.detected)
        self.assertGreater(result.confidence, 0.5)
        self.assertEqual(result.version.major, 8)

    @patch.object(Path, 'exists', return_value=True)
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_drivers')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_services')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_registry_keys')
    @patch('intellicrack.core.protection_detection.securom_detector.SecuROMDetector._detect_activation_state')
    def test_full_detection_negative(
        self, mock_activation, mock_registry, mock_services, mock_drivers, mock_path_exists
    ):
        """Test complete detection with negative result."""
        mock_drivers.return_value = []
        mock_services.return_value = []
        mock_registry.return_value = []
        mock_activation.return_value = None

        result = self.detector.detect(self.test_exe_path)

        self.assertIsInstance(result, SecuROMDetection)
        self.assertFalse(result.detected)
        self.assertLessEqual(result.confidence, 0.5)


class TestSecuROMVersion(unittest.TestCase):
    """Test cases for SecuROMVersion dataclass."""

    def test_version_string_representation(self):
        """Test string representation of version."""
        version = SecuROMVersion(8, 1, 2, 'PA')
        version_str = str(version)

        self.assertEqual(version_str, 'SecuROM 8.1.2 PA')

    def test_version_creation(self):
        """Test creation of version object."""
        version = SecuROMVersion(
            major=7,
            minor=5,
            build=10,
            variant='Standard'
        )

        self.assertEqual(version.major, 7)
        self.assertEqual(version.minor, 5)
        self.assertEqual(version.build, 10)
        self.assertEqual(version.variant, 'Standard')


class TestSecuROMActivation(unittest.TestCase):
    """Test cases for SecuROMActivation dataclass."""

    def test_activation_creation_activated(self):
        """Test creation of activated state."""
        activation = SecuROMActivation(
            is_activated=True,
            activation_date='2024-01-01',
            product_key='TEST-KEY',
            machine_id='MACHINE-ID',
            activation_count=2,
            remaining_activations=3
        )

        self.assertTrue(activation.is_activated)
        self.assertEqual(activation.activation_date, '2024-01-01')
        self.assertEqual(activation.activation_count, 2)
        self.assertEqual(activation.remaining_activations, 3)

    def test_activation_creation_not_activated(self):
        """Test creation of non-activated state."""
        activation = SecuROMActivation(
            is_activated=False,
            activation_date=None,
            product_key=None,
            machine_id=None,
            activation_count=0,
            remaining_activations=5
        )

        self.assertFalse(activation.is_activated)
        self.assertIsNone(activation.activation_date)
        self.assertIsNone(activation.product_key)
        self.assertEqual(activation.remaining_activations, 5)


if __name__ == '__main__':
    unittest.main()
