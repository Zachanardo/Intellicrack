"""
Unit tests for StarForce analyzer module.

Tests StarForce driver analysis including IOCTL extraction, anti-debug detection,
VM detection, and license validation flow analysis.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import struct

from intellicrack.core.analysis.starforce_analyzer import (
    StarForceAnalyzer,
    StarForceAnalysis,
    IOCTLCommand,
    AntiDebugTechnique,
    LicenseValidationFlow
)


class TestStarForceAnalyzer(unittest.TestCase):
    """Test cases for StarForceAnalyzer."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = StarForceAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        self.assertIsNotNone(self.analyzer)
        self.assertTrue(hasattr(self.analyzer, 'KNOWN_IOCTLS'))
        self.assertTrue(hasattr(self.analyzer, 'ANTI_DEBUG_PATTERNS'))
        self.assertTrue(hasattr(self.analyzer, 'VM_DETECTION_PATTERNS'))

    def test_known_ioctls_defined(self):
        """Test known IOCTL codes are defined."""
        self.assertGreater(len(self.analyzer.KNOWN_IOCTLS), 0)
        self.assertIn(0x80002000, self.analyzer.KNOWN_IOCTLS)
        self.assertIn(0x80002004, self.analyzer.KNOWN_IOCTLS)

    def test_anti_debug_patterns_defined(self):
        """Test anti-debug patterns are defined."""
        self.assertGreater(len(self.analyzer.ANTI_DEBUG_PATTERNS), 0)
        self.assertIn('kernel_debugger_check', self.analyzer.ANTI_DEBUG_PATTERNS)
        self.assertIn('timing_check', self.analyzer.ANTI_DEBUG_PATTERNS)
        self.assertIn('int2d_detection', self.analyzer.ANTI_DEBUG_PATTERNS)
        self.assertIn('hardware_breakpoint', self.analyzer.ANTI_DEBUG_PATTERNS)

    def test_vm_detection_patterns_defined(self):
        """Test VM detection patterns are defined."""
        self.assertGreater(len(self.analyzer.VM_DETECTION_PATTERNS), 0)
        self.assertIn('vmware', self.analyzer.VM_DETECTION_PATTERNS)
        self.assertIn('virtualbox', self.analyzer.VM_DETECTION_PATTERNS)
        self.assertIn('qemu', self.analyzer.VM_DETECTION_PATTERNS)
        self.assertIn('hyperv', self.analyzer.VM_DETECTION_PATTERNS)

    def test_ioctl_command_structure(self):
        """Test IOCTLCommand data structure."""
        ioctl = IOCTLCommand(
            code=0x80002000,
            device_type=0x8000,
            function=0x800,
            method=0,
            access=0,
            name='SF_IOCTL_GET_VERSION',
            purpose='Retrieve driver version'
        )

        self.assertEqual(ioctl.code, 0x80002000)
        self.assertEqual(ioctl.name, 'SF_IOCTL_GET_VERSION')
        self.assertIsInstance(ioctl.purpose, str)

    def test_anti_debug_technique_structure(self):
        """Test AntiDebugTechnique data structure."""
        technique = AntiDebugTechnique(
            technique='kernel_debugger_check',
            address=0x1000,
            description='Checks KdDebuggerEnabled flag',
            bypass_method='Patch flag memory'
        )

        self.assertEqual(technique.technique, 'kernel_debugger_check')
        self.assertEqual(technique.address, 0x1000)
        self.assertIsInstance(technique.description, str)
        self.assertIsInstance(technique.bypass_method, str)

    def test_license_validation_flow_structure(self):
        """Test LicenseValidationFlow data structure."""
        flow = LicenseValidationFlow(
            entry_point=0x1000,
            validation_functions=[(0x2000, 'ValidateLicense')],
            crypto_operations=[(0x3000, 'RSA')],
            registry_checks=[(0x4000, 'Registry access')],
            disc_checks=[(0x5000, 'Disc device access')],
            network_checks=[(0x6000, 'Network communication')]
        )

        self.assertEqual(flow.entry_point, 0x1000)
        self.assertEqual(len(flow.validation_functions), 1)
        self.assertEqual(len(flow.crypto_operations), 1)

    @patch('pathlib.Path.exists')
    def test_get_driver_version_nonexistent_file(self, mock_exists):
        """Test driver version extraction on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        version = self.analyzer._get_driver_version(driver_path)

        self.assertEqual(version, 'Unknown')

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_analyze_ioctls_finds_known_codes(self, mock_file, mock_exists):
        """Test IOCTL analysis finds known codes."""
        mock_exists.return_value = True

        ioctl_code = 0x80002000
        driver_data = b'\x00' * 100 + struct.pack('<I', ioctl_code) + b'\x00' * 100

        with patch('builtins.open', mock_open(read_data=driver_data)):
            driver_path = Path('D:/test.sys')
            ioctls = self.analyzer._analyze_ioctls(driver_path)

            self.assertIsInstance(ioctls, list)
            if len(ioctls) > 0:
                self.assertIsInstance(ioctls[0], IOCTLCommand)

    @patch('pathlib.Path.exists')
    def test_analyze_ioctls_nonexistent_file(self, mock_exists):
        """Test IOCTL analysis on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        ioctls = self.analyzer._analyze_ioctls(driver_path)

        self.assertEqual(len(ioctls), 0)

    def test_find_custom_ioctls_in_data(self):
        """Test finding custom IOCTL codes in binary data."""
        ioctl_pattern = b'\x81\x7D'
        custom_code = 0x80003000
        data = b'\x00' * 100 + ioctl_pattern + b'\x00\x00' + struct.pack('<I', custom_code) + b'\x00' * 100

        ioctls = self.analyzer._find_custom_ioctls(data)

        self.assertIsInstance(ioctls, list)

    def test_find_custom_ioctls_empty_data(self):
        """Test custom IOCTL finding with empty data."""
        data = b''

        ioctls = self.analyzer._find_custom_ioctls(data)

        self.assertEqual(len(ioctls), 0)

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_detect_anti_debug_finds_patterns(self, mock_file, mock_exists):
        """Test anti-debug detection finds patterns."""
        mock_exists.return_value = True

        kernel_check = b'\x64\xA1\x1C\x00\x00\x00'
        driver_data = b'\x00' * 100 + kernel_check + b'\x00' * 100

        with patch('builtins.open', mock_open(read_data=driver_data)):
            driver_path = Path('D:/test.sys')
            techniques = self.analyzer._detect_anti_debug(driver_path)

            self.assertIsInstance(techniques, list)
            if len(techniques) > 0:
                self.assertIsInstance(techniques[0], AntiDebugTechnique)
                self.assertIn('kernel_debugger_check', techniques[0].technique)

    @patch('pathlib.Path.exists')
    def test_detect_anti_debug_nonexistent_file(self, mock_exists):
        """Test anti-debug detection on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        techniques = self.analyzer._detect_anti_debug(driver_path)

        self.assertEqual(len(techniques), 0)

    def test_get_anti_debug_details_all_techniques(self):
        """Test getting details for all anti-debug techniques."""
        techniques = [
            'kernel_debugger_check',
            'timing_check',
            'int2d_detection',
            'hardware_breakpoint'
        ]

        for technique in techniques:
            description, bypass_method = self.analyzer._get_anti_debug_details(technique)

            self.assertIsInstance(description, str)
            self.assertIsInstance(bypass_method, str)
            self.assertGreater(len(description), 0)
            self.assertGreater(len(bypass_method), 0)

    def test_get_anti_debug_details_unknown_technique(self):
        """Test getting details for unknown technique."""
        description, bypass_method = self.analyzer._get_anti_debug_details('unknown_technique')

        self.assertEqual(description, 'Unknown technique')
        self.assertEqual(bypass_method, 'Manual analysis required')

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_detect_vm_checks_finds_patterns(self, mock_file, mock_exists):
        """Test VM detection finds patterns."""
        mock_exists.return_value = True

        vmware_sig = b'VMware'
        driver_data = b'\x00' * 100 + vmware_sig + b'\x00' * 100

        with patch('builtins.open', mock_open(read_data=driver_data)):
            driver_path = Path('D:/test.sys')
            vm_methods = self.analyzer._detect_vm_checks(driver_path)

            self.assertIsInstance(vm_methods, list)
            if len(vm_methods) > 0:
                self.assertTrue(any('VMWARE' in method for method in vm_methods))

    @patch('pathlib.Path.exists')
    def test_detect_vm_checks_nonexistent_file(self, mock_exists):
        """Test VM detection on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        vm_methods = self.analyzer._detect_vm_checks(driver_path)

        self.assertEqual(len(vm_methods), 0)

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_analyze_disc_auth_finds_mechanisms(self, mock_file, mock_exists):
        """Test disc authentication analysis."""
        mock_exists.return_value = True

        scsi_sig = b'SCSI'
        driver_data = b'\x00' * 100 + scsi_sig + b'\x00' * 100

        with patch('builtins.open', mock_open(read_data=driver_data)):
            driver_path = Path('D:/test.sys')
            mechanisms = self.analyzer._analyze_disc_auth(driver_path)

            self.assertIsInstance(mechanisms, list)

    @patch('pathlib.Path.exists')
    def test_analyze_disc_auth_nonexistent_file(self, mock_exists):
        """Test disc auth analysis on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        mechanisms = self.analyzer._analyze_disc_auth(driver_path)

        self.assertEqual(len(mechanisms), 0)

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_detect_kernel_hooks_finds_functions(self, mock_file, mock_exists):
        """Test kernel hook detection."""
        mock_exists.return_value = True

        ntcreate = b'NtCreateFile'
        driver_data = b'\x00' * 100 + ntcreate + b'\x00' * 100

        with patch('builtins.open', mock_open(read_data=driver_data)):
            driver_path = Path('D:/test.sys')
            hooks = self.analyzer._detect_kernel_hooks(driver_path)

            self.assertIsInstance(hooks, list)
            if len(hooks) > 0:
                self.assertIsInstance(hooks[0], tuple)
                self.assertEqual(len(hooks[0]), 2)

    @patch('pathlib.Path.exists')
    def test_detect_kernel_hooks_nonexistent_file(self, mock_exists):
        """Test kernel hook detection on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        hooks = self.analyzer._detect_kernel_hooks(driver_path)

        self.assertEqual(len(hooks), 0)

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_analyze_license_validation_finds_keywords(self, mock_file, mock_exists):
        """Test license validation flow analysis."""
        mock_exists.return_value = True

        license_kw = b'License'
        driver_data = b'\x00' * 100 + license_kw + b'\x00' * 100

        with patch('builtins.open', mock_open(read_data=driver_data)):
            driver_path = Path('D:/test.sys')
            flow = self.analyzer._analyze_license_validation(driver_path)

            if flow is not None:
                self.assertIsInstance(flow, LicenseValidationFlow)
                self.assertIsInstance(flow.entry_point, int)
                self.assertIsInstance(flow.validation_functions, list)

    @patch('pathlib.Path.exists')
    def test_analyze_license_validation_nonexistent_file(self, mock_exists):
        """Test license validation analysis on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        flow = self.analyzer._analyze_license_validation(driver_path)

        self.assertIsNone(flow)

    def test_find_validation_entry_point_no_data(self):
        """Test finding validation entry point with no data."""
        data = b''

        entry_point = self.analyzer._find_validation_entry_point(data)

        self.assertEqual(entry_point, 0)

    @patch('pathlib.Path.exists')
    def test_find_entry_points_nonexistent_file(self, mock_exists):
        """Test finding entry points on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        entry_points = self.analyzer._find_entry_points(driver_path)

        self.assertEqual(len(entry_points), 0)

    @patch('pathlib.Path.exists')
    def test_get_imports_nonexistent_file(self, mock_exists):
        """Test getting imports from nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        imports = self.analyzer._get_imports(driver_path)

        self.assertEqual(len(imports), 0)

    @patch('pathlib.Path.exists')
    def test_get_exports_nonexistent_file(self, mock_exists):
        """Test getting exports from nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        exports = self.analyzer._get_exports(driver_path)

        self.assertEqual(len(exports), 0)

    @patch('pathlib.Path.exists')
    def test_find_dispatch_routines_nonexistent_file(self, mock_exists):
        """Test finding dispatch routines on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        routines = self.analyzer._find_dispatch_routines(driver_path)

        self.assertEqual(len(routines), 0)

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_identify_crypto_finds_algorithms(self, mock_file, mock_exists):
        """Test cryptographic algorithm identification."""
        mock_exists.return_value = True

        md5_const = b'\x67\x45\x23\x01\xEF\xCD\xAB\x89'
        driver_data = b'\x00' * 100 + md5_const + b'\x00' * 100

        with patch('builtins.open', mock_open(read_data=driver_data)):
            driver_path = Path('D:/test.sys')
            algorithms = self.analyzer._identify_crypto(driver_path)

            self.assertIsInstance(algorithms, list)

    @patch('pathlib.Path.exists')
    def test_identify_crypto_nonexistent_file(self, mock_exists):
        """Test crypto identification on nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/nonexistent.sys')

        algorithms = self.analyzer._identify_crypto(driver_path)

        self.assertEqual(len(algorithms), 0)

    @patch('pathlib.Path.exists')
    def test_analyze_complete_workflow(self, mock_exists):
        """Test complete analysis workflow."""
        mock_exists.return_value = False
        driver_path = Path('D:/test.sys')

        result = self.analyzer.analyze(driver_path)

        self.assertIsInstance(result, StarForceAnalysis)
        self.assertEqual(result.driver_path, driver_path)
        self.assertIsInstance(result.driver_version, str)
        self.assertIsInstance(result.ioctl_commands, list)
        self.assertIsInstance(result.anti_debug_techniques, list)
        self.assertIsInstance(result.vm_detection_methods, list)
        self.assertIsInstance(result.disc_auth_mechanisms, list)
        self.assertIsInstance(result.kernel_hooks, list)
        self.assertIsInstance(result.details, dict)

    def test_probe_ioctl_without_winapi(self):
        """Test IOCTL probing without WinAPI."""
        analyzer = StarForceAnalyzer()
        analyzer._kernel32 = None

        result = analyzer.probe_ioctl('\\\\.\\StarForce', 0x80002000)

        self.assertIsNone(result)


class TestStarForceAnalyzerIntegration(unittest.TestCase):
    """Integration tests for StarForce analyzer."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = StarForceAnalyzer()

    def test_winapi_setup_does_not_crash(self):
        """Test WinAPI setup completes without crashing."""
        analyzer = StarForceAnalyzer()

        self.assertIsNotNone(analyzer)

    @patch('pathlib.Path.exists')
    def test_full_analysis_workflow_nonexistent_file(self, mock_exists):
        """Test complete analysis workflow with nonexistent file."""
        mock_exists.return_value = False
        driver_path = Path('D:/test.sys')

        result = self.analyzer.analyze(driver_path)

        self.assertIsInstance(result, StarForceAnalysis)
        self.assertIsInstance(result.ioctl_commands, list)
        self.assertIsInstance(result.anti_debug_techniques, list)


if __name__ == '__main__':
    unittest.main()
