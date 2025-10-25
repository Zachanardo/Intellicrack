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
        xor_encrypted = bytes([0x80 ^ i for i in range(256)])
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


if __name__ == '__main__':
    unittest.main()
