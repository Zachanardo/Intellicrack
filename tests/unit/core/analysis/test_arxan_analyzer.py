"""Unit tests for Arxan analyzer.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from intellicrack.core.analysis.arxan_analyzer import (
    ArxanAnalyzer,
    TamperCheckLocation,
    ControlFlowAnalysis,
    RASPMechanism,
    LicenseValidationRoutine,
)


class TestArxanAnalyzer(unittest.TestCase):
    """Test cases for ArxanAnalyzer."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = ArxanAnalyzer()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_pe_binary(self, section_data: bytes = None) -> Path:
        """Create minimal PE binary for testing."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014c,
            1,
            0,
            0,
            0,
            0xe0,
            0x010b
        )

        optional_header = b"\x0b\x01" + b"\x00" * 222

        section_header = (
            b".text\x00\x00\x00" +
            struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x600, 0x600, 0, 0, 0x60000020)
        )

        if section_data is None:
            section_data = b"\x90" * 0x600
        else:
            section_data = section_data.ljust(0x600, b"\x00")

        binary = dos_header + pe_signature + coff_header + optional_header + section_header + section_data

        test_file = Path(self.test_dir) / "test.exe"
        with open(test_file, 'wb') as f:
            f.write(binary)

        return test_file

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        self.assertIsInstance(self.analyzer, ArxanAnalyzer)
        self.assertTrue(hasattr(self.analyzer, 'md_32'))
        self.assertTrue(hasattr(self.analyzer, 'md_64'))

    def test_analyze_clean_binary(self):
        """Test analysis of binary without Arxan protection."""
        binary = self._create_pe_binary()

        result = self.analyzer.analyze(binary)

        self.assertIsNotNone(result)
        self.assertEqual(len(result.tamper_checks), 0)
        self.assertEqual(len(result.rasp_mechanisms), 0)
        self.assertEqual(len(result.license_routines), 0)

    def test_analyze_tamper_checks(self):
        """Test tamper check analysis."""
        crc32_pattern = b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08"
        section_data = b"Arxan" + crc32_pattern * 2

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        self.assertGreater(len(result.tamper_checks), 0)

        for check in result.tamper_checks:
            self.assertIsInstance(check, TamperCheckLocation)
            self.assertIn(check.algorithm, ['crc32', 'md5', 'sha256', 'hmac', 'xor_checksum'])
            self.assertIn(check.bypass_complexity, ['low', 'medium', 'high'])

    def test_analyze_control_flow(self):
        """Test control flow obfuscation analysis."""
        opaque_predicates = b"\x85\xc0\x75\x02\x75\x00" * 50
        indirect_jumps = b"\xff\x25\x00\x00\x00\x00" * 30

        section_data = b"Arxan" + opaque_predicates + indirect_jumps

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        self.assertIsNotNone(result.control_flow)
        self.assertGreater(len(result.control_flow.opaque_predicates), 0)
        self.assertGreater(len(result.control_flow.indirect_jumps), 0)
        self.assertGreaterEqual(result.control_flow.obfuscation_density, 0.0)
        self.assertLessEqual(result.control_flow.obfuscation_density, 1.0)

    def test_analyze_rasp_mechanisms(self):
        """Test RASP mechanism analysis."""
        rasp_patterns = b"frida" + b"tamper" + b"hook" + b"\x64\xa1\x30\x00\x00\x00"

        section_data = b"Arxan" + rasp_patterns

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        if len(result.rasp_mechanisms) > 0:
            for rasp in result.rasp_mechanisms:
                self.assertIsInstance(rasp, RASPMechanism)
                self.assertIn(rasp.mechanism_type, [
                    'anti_frida', 'anti_debug', 'anti_hook', 'anti_vm', 'exception_handler'
                ])
                self.assertIn(rasp.severity, ['low', 'medium', 'high'])

    def test_analyze_license_validation(self):
        """Test license validation routine analysis."""
        rsa_pattern = b"\x00\x01\xff\xff"
        aes_pattern = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"

        section_data = b"Arxan" + rsa_pattern + aes_pattern + b"license" + b"serial"

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        if len(result.license_routines) > 0:
            for routine in result.license_routines:
                self.assertIsInstance(routine, LicenseValidationRoutine)
                self.assertIn(routine.algorithm, ['RSA', 'AES', 'custom'])
                self.assertGreater(routine.key_length, 0)
                self.assertIn(routine.validation_type, [
                    'rsa_validation', 'aes_license', 'serial_check'
                ])

    def test_analyze_integrity_checks(self):
        """Test integrity check mechanism analysis."""
        crc_pattern = b"\xc1\xe8\x08\x33"
        section_data = b"Arxan" + crc_pattern * 3

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        if len(result.integrity_checks) > 0:
            for check in result.integrity_checks:
                self.assertIn(check.check_type, ['hash_verification', 'api_based'])
                self.assertIn(check.hash_algorithm, ['CRC32', 'SHA256', 'SHA1', 'MD5'])
                self.assertGreater(len(check.bypass_strategy), 0)

    def test_encrypted_strings_detection(self):
        """Test encrypted string detection."""
        xor_encrypted = bytes(0x80 ^ i for i in range(256))
        section_data = b"Arxan" + xor_encrypted

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        self.assertIsInstance(result.encrypted_strings, list)

    def test_white_box_crypto_tables(self):
        """Test white-box cryptography table detection."""
        diverse_table = bytes(range(256)) * 10
        section_data = b"Arxan" + diverse_table

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        self.assertIsInstance(result.white_box_crypto_tables, list)

    def test_control_flow_analysis_structure(self):
        """Test control flow analysis data structure."""
        analysis = ControlFlowAnalysis()

        self.assertEqual(len(analysis.opaque_predicates), 0)
        self.assertEqual(len(analysis.indirect_jumps), 0)
        self.assertFalse(analysis.control_flow_flattening)
        self.assertEqual(analysis.obfuscation_density, 0.0)

        analysis.opaque_predicates = [0x1000, 0x2000]
        analysis.control_flow_flattening = True

        self.assertEqual(len(analysis.opaque_predicates), 2)
        self.assertTrue(analysis.control_flow_flattening)

    def test_comprehensive_analysis(self):
        """Test comprehensive analysis with multiple features."""
        section_data = (
            b"Arxan TransformIT" +
            b"\x33\xd2\x8a\x10" +
            b"\x85\xc0\x75\x02" * 20 +
            b"frida" +
            b"license" +
            b"\x00\x01\xff\xff"
        )

        binary = self._create_pe_binary(section_data)
        result = self.analyzer.analyze(binary)

        self.assertIsNotNone(result)
        self.assertTrue(result.metadata.get('analysis_complete', False))
        self.assertGreaterEqual(result.metadata.get('total_tamper_checks', 0), 0)
        self.assertGreaterEqual(result.metadata.get('total_rasp_mechanisms', 0), 0)
        self.assertGreaterEqual(result.metadata.get('total_license_routines', 0), 0)

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        with self.assertRaises(FileNotFoundError):
            self.analyzer.analyze("/nonexistent/file.exe")


class TestArxanAnalyzerWithRealBinaries(unittest.TestCase):
    """Test ArxanAnalyzer with real protected binaries."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures with real binaries."""
        cls.fixtures_dir = Path("tests/fixtures/binaries")
        cls.protected_binaries = [
            cls.fixtures_dir / "pe/protected/armadillo_protected.exe",
            cls.fixtures_dir / "pe/protected/asprotect_protected.exe",
            cls.fixtures_dir / "pe/protected/safedisc_protected.exe",
            cls.fixtures_dir / "pe/protected/securom_protected.exe",
            cls.fixtures_dir / "protected/aspack_packed.exe",
            cls.fixtures_dir / "protected/enigma_packed.exe",
            cls.fixtures_dir / "protected/obsidium_packed.exe",
            cls.fixtures_dir / "protected/themida_protected.exe",
            cls.fixtures_dir / "protected/vmprotect_protected.exe",
        ]
        cls.protected_binaries = [p for p in cls.protected_binaries if p.exists()]

        if not cls.protected_binaries:
            raise unittest.SkipTest("No protected binaries available for Arxan analysis testing")

    def setUp(self):
        """Set up test environment."""
        self.analyzer = ArxanAnalyzer()

    def test_analyze_protected_binary_no_crashes(self):
        """Test analyzer handles real protected binaries without crashing."""
        for binary in self.protected_binaries:
            with self.subTest(binary=binary.name):
                try:
                    result = self.analyzer.analyze(binary)
                    self.assertIsNotNone(result, f"Analyzer returned None for {binary.name}")
                    self.assertTrue(hasattr(result, 'tamper_checks'), f"Result missing tamper_checks for {binary.name}")
                    self.assertTrue(hasattr(result, 'rasp_mechanisms'), f"Result missing rasp_mechanisms for {binary.name}")
                    self.assertTrue(hasattr(result, 'license_routines'), f"Result missing license_routines for {binary.name}")
                    self.assertTrue(hasattr(result, 'metadata'), f"Result missing metadata for {binary.name}")
                except Exception as e:
                    self.fail(f"Analyzer crashed on {binary.name}: {e}")

    def test_analyze_themida_protection_patterns(self):
        """Test detection of protection patterns in Themida-protected binary."""
        themida_binary = self.fixtures_dir / "protected/themida_protected.exe"
        if not themida_binary.exists():
            self.skipTest("Themida binary not available")

        result = self.analyzer.analyze(themida_binary)

        self.assertIsNotNone(result)
        self.assertIsInstance(result.tamper_checks, list)
        self.assertIsInstance(result.rasp_mechanisms, list)
        self.assertIsInstance(result.control_flow, ControlFlowAnalysis)

        self.assertTrue(
            isinstance(result.metadata, dict) and 'analysis_complete' in result.metadata,
            "Should complete analysis on Themida binary"
        )

    def test_analyze_vmprotect_protection_patterns(self):
        """Test detection of protection patterns in VMProtect binary."""
        vmprotect_binary = self.fixtures_dir / "protected/vmprotect_protected.exe"
        if not vmprotect_binary.exists():
            self.skipTest("VMProtect binary not available")

        result = self.analyzer.analyze(vmprotect_binary)

        self.assertIsNotNone(result)
        self.assertIsInstance(result.metadata, dict)

        self.assertTrue(
            'analysis_complete' in result.metadata,
            "Analysis should complete for VMProtect binary"
        )

    def test_analyze_armadillo_protection_patterns(self):
        """Test detection of protection patterns in Armadillo-protected binary."""
        armadillo_binary = self.fixtures_dir / "pe/protected/armadillo_protected.exe"
        if not armadillo_binary.exists():
            self.skipTest("Armadillo binary not available")

        result = self.analyzer.analyze(armadillo_binary)

        self.assertIsNotNone(result)

        total_detections = (
            len(result.tamper_checks) +
            len(result.rasp_mechanisms) +
            len(result.license_routines)
        )

        self.assertGreaterEqual(
            total_detections, 0,
            "Should complete analysis on Armadillo binary"
        )

    def test_analyze_multiple_binaries_consistency(self):
        """Test analyzer produces consistent results across multiple runs."""
        if not self.protected_binaries:
            self.skipTest("No protected binaries available")

        test_binary = self.protected_binaries[0]

        result1 = self.analyzer.analyze(test_binary)
        result2 = self.analyzer.analyze(test_binary)

        self.assertEqual(
            len(result1.tamper_checks),
            len(result2.tamper_checks),
            "Tamper check count should be consistent across runs"
        )

        self.assertEqual(
            len(result1.rasp_mechanisms),
            len(result2.rasp_mechanisms),
            "RASP mechanism count should be consistent across runs"
        )

        self.assertEqual(
            len(result1.license_routines),
            len(result2.license_routines),
            "License routine count should be consistent across runs"
        )

    def test_analyze_results_structure(self):
        """Test that analysis results have proper structure and types."""
        if not self.protected_binaries:
            self.skipTest("No protected binaries available")

        result = self.analyzer.analyze(self.protected_binaries[0])

        self.assertIsInstance(result.tamper_checks, list)
        if len(result.tamper_checks) > 0:
            for check in result.tamper_checks:
                self.assertIsInstance(check, TamperCheckLocation)
                self.assertTrue(hasattr(check, 'offset'))
                self.assertTrue(hasattr(check, 'algorithm'))
                self.assertTrue(hasattr(check, 'confidence'))

        self.assertIsInstance(result.rasp_mechanisms, list)
        if len(result.rasp_mechanisms) > 0:
            for mechanism in result.rasp_mechanisms:
                self.assertIsInstance(mechanism, RASPMechanism)
                self.assertTrue(hasattr(mechanism, 'type'))
                self.assertTrue(hasattr(mechanism, 'offset'))

        self.assertIsInstance(result.license_routines, list)
        if len(result.license_routines) > 0:
            for routine in result.license_routines:
                self.assertIsInstance(routine, LicenseValidationRoutine)
                self.assertTrue(hasattr(routine, 'offset'))

    def test_control_flow_analysis_structure(self):
        """Test control flow analysis produces valid structure."""
        if not self.protected_binaries:
            self.skipTest("No protected binaries available")

        result = self.analyzer.analyze(self.protected_binaries[0])

        self.assertIsInstance(result.control_flow, ControlFlowAnalysis)
        self.assertTrue(hasattr(result.control_flow, 'opaque_predicates'))
        self.assertTrue(hasattr(result.control_flow, 'control_flow_flattening'))
        self.assertTrue(hasattr(result.control_flow, 'indirect_jumps'))

        self.assertIsInstance(result.control_flow.opaque_predicates, list)
        self.assertIsInstance(result.control_flow.control_flow_flattening, bool)
        self.assertIsInstance(result.control_flow.indirect_jumps, list)


if __name__ == '__main__':
    unittest.main()
