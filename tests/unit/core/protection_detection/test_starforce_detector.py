"""
Unit tests for StarForce detector module.

Tests StarForce protection detection including driver detection,
service enumeration, registry key analysis, and executable signature detection.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import struct

from intellicrack.core.protection_detection.starforce_detector import (
    StarForceDetector,
    StarForceDetection,
    StarForceVersion
)


class TestStarForceDetector(unittest.TestCase):
    """Test cases for StarForceDetector."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = StarForceDetector()

    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        self.assertIsNotNone(self.detector)
        self.assertTrue(hasattr(self.detector, 'DRIVER_NAMES'))
        self.assertTrue(hasattr(self.detector, 'SERVICE_NAMES'))
        self.assertTrue(hasattr(self.detector, 'REGISTRY_KEYS'))

    def test_driver_names_defined(self):
        """Test driver names are properly defined."""
        self.assertGreater(len(self.detector.DRIVER_NAMES), 0)
        self.assertIn('sfdrv01.sys', self.detector.DRIVER_NAMES)
        self.assertIn('sfvfs02.sys', self.detector.DRIVER_NAMES)
        self.assertIn('StarForce.sys', self.detector.DRIVER_NAMES)

    def test_service_names_defined(self):
        """Test service names are properly defined."""
        self.assertGreater(len(self.detector.SERVICE_NAMES), 0)
        self.assertIn('StarForce', self.detector.SERVICE_NAMES)
        self.assertIn('SFVFS', self.detector.SERVICE_NAMES)

    def test_registry_keys_defined(self):
        """Test registry keys are properly defined."""
        self.assertGreater(len(self.detector.REGISTRY_KEYS), 0)
        self.assertTrue(any('sfdrv01' in key for key in self.detector.REGISTRY_KEYS))
        self.assertTrue(any('StarForce' in key for key in self.detector.REGISTRY_KEYS))

    @patch('pathlib.Path.exists')
    def test_detect_drivers_no_drivers_found(self, mock_exists):
        """Test driver detection when no drivers present."""
        mock_exists.return_value = False

        drivers = self.detector._detect_drivers()

        self.assertEqual(len(drivers), 0)

    @patch('pathlib.Path.exists', return_value=True)
    def test_detect_drivers_finds_drivers(self, mock_exists):
        """Test driver detection finds installed drivers."""
        drivers = self.detector._detect_drivers()

        self.assertIsInstance(drivers, list)

    def test_detect_services_without_winapi(self):
        """Test service detection gracefully handles missing WinAPI."""
        detector = StarForceDetector()
        detector._advapi32 = None

        services = detector._detect_services()

        self.assertEqual(len(services), 0)

    @patch('winreg.OpenKey')
    @patch('winreg.CloseKey')
    def test_detect_registry_keys_finds_keys(self, mock_close, mock_open):
        """Test registry key detection finds StarForce keys."""
        mock_key = Mock()
        mock_open.return_value = mock_key

        keys = self.detector._detect_registry_keys()

        self.assertGreater(len(keys), 0)
        self.assertTrue(all(isinstance(k, str) for k in keys))

    @patch('winreg.OpenKey')
    def test_detect_registry_keys_handles_missing_keys(self, mock_open):
        """Test registry key detection handles missing keys."""
        mock_open.side_effect = WindowsError("Key not found")

        keys = self.detector._detect_registry_keys()

        self.assertEqual(len(keys), 0)

    def test_protected_sections_defined(self):
        """Test protected section names are defined."""
        self.assertGreater(len(self.detector.SECTION_NAMES), 0)
        self.assertIn('.sforce', self.detector.SECTION_NAMES)
        self.assertIn('.sf', self.detector.SECTION_NAMES)

    def test_calculate_confidence_no_indicators(self):
        """Test confidence calculation with no indicators."""
        confidence = self.detector._calculate_confidence([], [], [], [], [])

        self.assertEqual(confidence, 0.0)

    def test_calculate_confidence_all_indicators(self):
        """Test confidence calculation with all indicators present."""
        drivers = ['sfdrv01.sys', 'sfvfs02.sys', 'StarForce.sys']
        services = ['StarForce', 'sfdrv01']
        registry_keys = ['key1', 'key2', 'key3']
        sections = ['.sforce', '.sfdata']
        yara_matches = [{'rule': 'StarForce_v3'}]

        confidence = self.detector._calculate_confidence(
            drivers, services, registry_keys, sections, yara_matches
        )

        self.assertGreater(confidence, 0.6)
        self.assertLessEqual(confidence, 1.0)

    def test_calculate_confidence_some_indicators(self):
        """Test confidence calculation with partial indicators."""
        drivers = ['sfdrv01.sys']
        services = []
        registry_keys = ['key1']
        sections = []
        yara_matches = []

        confidence = self.detector._calculate_confidence(
            drivers, services, registry_keys, sections, yara_matches
        )

        self.assertGreater(confidence, 0.0)
        self.assertLess(confidence, 0.6)

    def test_parse_version_string_valid(self):
        """Test version string parsing with valid input."""
        version_str = "StarForce 3.5.1234 Pro"

        version = self.detector._parse_version_string(version_str)

        self.assertIsNotNone(version)
        self.assertEqual(version.major, 3)
        self.assertEqual(version.minor, 5)
        self.assertEqual(version.build, 1234)
        self.assertEqual(version.variant, 'Pro')

    def test_parse_version_string_standard(self):
        """Test version string parsing for standard variant."""
        version_str = "StarForce 4.0 Standard"

        version = self.detector._parse_version_string(version_str)

        self.assertIsNotNone(version)
        self.assertEqual(version.major, 4)
        self.assertEqual(version.minor, 0)
        self.assertEqual(version.variant, 'Standard')

    def test_parse_version_string_no_build(self):
        """Test version string parsing without build number."""
        version_str = "StarForce 5.2"

        version = self.detector._parse_version_string(version_str)

        self.assertIsNotNone(version)
        self.assertEqual(version.major, 5)
        self.assertEqual(version.minor, 2)
        self.assertEqual(version.build, 0)

    def test_parse_version_string_invalid(self):
        """Test version string parsing with invalid input."""
        version_str = "Not a StarForce version"

        version = self.detector._parse_version_string(version_str)

        self.assertIsNone(version)

    def test_starforce_version_str_representation(self):
        """Test StarForceVersion string representation."""
        version = StarForceVersion(3, 5, 1234, 'Pro')

        version_str = str(version)

        self.assertEqual(version_str, "StarForce 3.5.1234 Pro")

    @patch('pathlib.Path.exists')
    def test_detect_nonexistent_file(self, mock_exists):
        """Test detection on nonexistent file."""
        mock_exists.return_value = False
        target_path = Path('D:/nonexistent.exe')

        result = self.detector.detect(target_path)

        self.assertIsInstance(result, StarForceDetection)
        self.assertIsInstance(result.detected, bool)
        self.assertIsInstance(result.drivers, list)
        self.assertIsInstance(result.services, list)
        self.assertIsInstance(result.registry_keys, list)
        self.assertIsInstance(result.protected_sections, list)
        self.assertIsInstance(result.confidence, float)
        self.assertIsInstance(result.details, dict)

    def test_get_driver_paths_with_existing_drivers(self):
        """Test getting full paths for detected drivers."""
        drivers = ['sfdrv01.sys', 'sfvfs02.sys']

        with patch.object(Path, 'exists', return_value=True):
            paths = self.detector._get_driver_paths(drivers)

            self.assertIsInstance(paths, dict)
            for driver in drivers:
                if driver in paths:
                    self.assertIn('drivers', paths[driver])

    def test_get_driver_paths_with_missing_drivers(self):
        """Test getting paths when drivers don't exist."""
        drivers = ['nonexistent.sys']

        with patch.object(Path, 'exists', return_value=False):
            paths = self.detector._get_driver_paths(drivers)

            self.assertIsInstance(paths, dict)
            self.assertEqual(len(paths), 0)

    def test_get_service_status_without_winapi(self):
        """Test service status query without WinAPI."""
        detector = StarForceDetector()
        detector._advapi32 = None

        status_info = detector._get_service_status(['StarForce'])

        self.assertEqual(len(status_info), 0)

    @patch('winreg.OpenKey')
    @patch('winreg.CloseKey')
    @patch('winreg.EnumKey')
    def test_detect_scsi_miniport_found(self, mock_enum, mock_close, mock_open):
        """Test SCSI miniport detection when StarForce present."""
        mock_key = Mock()
        mock_open.return_value = mock_key
        mock_enum.side_effect = ['Adapter0', WindowsError()]

        with patch('winreg.QueryValueEx', return_value=('StarForce Driver', None)):
            result = self.detector._detect_scsi_miniport()

            self.assertTrue(result)

    @patch('winreg.OpenKey')
    def test_detect_scsi_miniport_not_found(self, mock_open):
        """Test SCSI miniport detection when not present."""
        mock_open.side_effect = WindowsError("Key not found")

        result = self.detector._detect_scsi_miniport()

        self.assertFalse(result)

    def test_detection_result_structure(self):
        """Test StarForceDetection result structure."""
        result = StarForceDetection(
            detected=True,
            version=StarForceVersion(3, 0, 0, 'Standard'),
            drivers=['sfdrv01.sys'],
            services=['StarForce'],
            registry_keys=['test_key'],
            protected_sections=['.sforce'],
            confidence=0.85,
            details={'test': 'data'}
        )

        self.assertTrue(result.detected)
        self.assertIsInstance(result.version, StarForceVersion)
        self.assertEqual(len(result.drivers), 1)
        self.assertEqual(len(result.services), 1)
        self.assertEqual(len(result.registry_keys), 1)
        self.assertEqual(len(result.protected_sections), 1)
        self.assertEqual(result.confidence, 0.85)
        self.assertIn('test', result.details)


class TestStarForceDetectorIntegration(unittest.TestCase):
    """Integration tests for StarForce detector."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = StarForceDetector()

    @patch('pathlib.Path.exists')
    @patch('winreg.OpenKey')
    def test_full_detection_workflow(self, mock_reg_open, mock_path_exists):
        """Test complete detection workflow."""
        mock_path_exists.return_value = False
        mock_reg_open.side_effect = WindowsError("Not found")

        target_path = Path('D:/test.exe')
        result = self.detector.detect(target_path)

        self.assertIsInstance(result, StarForceDetection)
        self.assertIsInstance(result.detected, bool)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

    def test_winapi_setup_does_not_crash(self):
        """Test WinAPI setup completes without crashing."""
        detector = StarForceDetector()

        self.assertIsNotNone(detector)


if __name__ == '__main__':
    unittest.main()
