"""Unit tests for Arxan bypass.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from intellicrack.core.protection_bypass.arxan_bypass import (
    ArxanBypass,
    BypassPatch,
    ArxanBypassResult,
)


class TestArxanBypass(unittest.TestCase):
    """Test cases for ArxanBypass."""

    def setUp(self):
        """Set up test fixtures."""
        self.bypass = ArxanBypass()
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

    def test_bypass_initialization(self):
        """Test bypass engine initializes correctly."""
        self.assertIsInstance(self.bypass, ArxanBypass)
        self.assertTrue(hasattr(self.bypass, 'detector'))
        self.assertTrue(hasattr(self.bypass, 'analyzer'))
        self.assertTrue(hasattr(self.bypass, 'ks_32'))
        self.assertTrue(hasattr(self.bypass, 'ks_64'))

    def test_bypass_clean_binary(self):
        """Test bypass on binary without Arxan protection."""
        binary = self._create_pe_binary()

        result = self.bypass.bypass(binary)

        self.assertIsNotNone(result)
        self.assertTrue(result.success)
        self.assertEqual(len(result.patches_applied), 0)

    def test_bypass_with_arxan_signatures(self):
        """Test bypass on binary with Arxan signatures."""
        section_data = (
            b"Arxan TransformIT" +
            b"\x33\xd2\x8a\x10\x8b\xc2" +
            b"license" +
            b"frida"
        )

        binary = self._create_pe_binary(section_data)
        result = self.bypass.bypass(binary)

        self.assertIsNotNone(result)
        self.assertTrue(result.success)
        self.assertTrue(Path(result.patched_binary_path).exists())

    def test_bypass_patch_structure(self):
        """Test bypass patch data structure."""
        patch = BypassPatch(
            address=0x1000,
            original_bytes=b"\x85\xc0\x74\x10",
            patched_bytes=b"\x90\x90\x90\x90",
            patch_type="tamper_bypass",
            description="Test patch"
        )

        self.assertEqual(patch.address, 0x1000)
        self.assertEqual(patch.patch_type, "tamper_bypass")
        self.assertEqual(len(patch.patched_bytes), 4)

    def test_bypass_result_structure(self):
        """Test bypass result data structure."""
        result = ArxanBypassResult(success=True)

        self.assertTrue(result.success)
        self.assertEqual(len(result.patches_applied), 0)
        self.assertEqual(result.runtime_hooks_installed, 0)
        self.assertEqual(result.license_checks_bypassed, 0)
        self.assertEqual(result.integrity_checks_neutralized, 0)

        result.patches_applied = [
            BypassPatch(0x1000, b"\x00", b"\x90", "test", "test")
        ]
        result.license_checks_bypassed = 5

        self.assertEqual(len(result.patches_applied), 1)
        self.assertEqual(result.license_checks_bypassed, 5)

    def test_pe_checksum_calculation(self):
        """Test PE checksum calculation."""
        binary_data = b"MZ" + b"\x00" * 1000

        checksum = self.bypass._calculate_pe_checksum(binary_data)

        self.assertIsInstance(checksum, int)
        self.assertGreater(checksum, 0)

    def test_frida_script_generation(self):
        """Test Frida bypass script generation."""
        section_data = (
            b"Arxan" +
            b"\x33\xd2\x8a\x10" +
            b"license" +
            b"frida"
        )

        binary = self._create_pe_binary(section_data)

        from intellicrack.core.analysis.arxan_analyzer import ArxanAnalyzer
        analyzer = ArxanAnalyzer()
        analysis_result = analyzer.analyze(binary)

        script = self.bypass._generate_frida_bypass_script(analysis_result)

        self.assertIsInstance(script, str)
        self.assertGreater(len(script), 100)
        self.assertIn("Arxan", script)
        self.assertIn("Interceptor", script)

    def test_bypass_with_output_path(self):
        """Test bypass with custom output path."""
        binary = self._create_pe_binary()
        output_path = Path(self.test_dir) / "bypassed.exe"

        result = self.bypass.bypass(binary, output_path)

        self.assertTrue(result.success)
        self.assertEqual(result.patched_binary_path, str(output_path))
        self.assertTrue(output_path.exists())

    def test_tamper_check_bypass(self):
        """Test tamper check bypass logic."""
        from intellicrack.core.analysis.arxan_analyzer import TamperCheckLocation

        binary_data = bytearray(b"\x90" * 1000)
        patches = []

        tamper_checks = [
            TamperCheckLocation(
                address=0x100,
                size=10,
                check_type="tamper_detection",
                target_region=(0, 0x200),
                algorithm="crc32",
                bypass_complexity="low"
            )
        ]

        self.bypass._bypass_tamper_checks(binary_data, tamper_checks, patches)

        self.assertGreater(len(patches), 0)
        self.assertEqual(patches[0].patch_type, "tamper_bypass")

    def test_license_validation_bypass(self):
        """Test license validation bypass logic."""
        from intellicrack.core.analysis.arxan_analyzer import LicenseValidationRoutine

        binary_data = bytearray(b"\x90" * 1000)
        patches = []

        license_routines = [
            LicenseValidationRoutine(
                address=0x200,
                function_name="check_license",
                algorithm="RSA",
                key_length=2048,
                validation_type="rsa_validation",
                crypto_operations=["modular_exponentiation"]
            )
        ]

        self.bypass._bypass_license_validation(binary_data, license_routines, patches)

        self.assertGreater(len(patches), 0)
        self.assertEqual(patches[0].patch_type, "license_bypass")

    def test_rasp_neutralization(self):
        """Test RASP mechanism neutralization."""
        from intellicrack.core.analysis.arxan_analyzer import RASPMechanism

        binary_data = bytearray(b"\x90" * 1000)
        patches = []

        rasp_mechanisms = [
            RASPMechanism(
                mechanism_type="anti_debug",
                address=0x300,
                hook_target="runtime",
                detection_method="peb_check",
                severity="high"
            )
        ]

        self.bypass._neutralize_rasp(binary_data, rasp_mechanisms, patches)

        self.assertGreater(len(patches), 0)
        self.assertEqual(patches[0].patch_type, "rasp_bypass")

    def test_string_decryption(self):
        """Test string decryption logic."""
        xor_key = 0x42
        plaintext = b"This is a secret string"
        encrypted = bytes(b ^ xor_key for b in plaintext)

        binary_data = bytearray(b"\x90" * 100 + encrypted + b"\x90" * 100)
        patches = []

        encrypted_regions = [(100, len(encrypted))]

        self.bypass._decrypt_strings(binary_data, encrypted_regions, patches)

        if patches:
            self.assertEqual(patches[0].patch_type, "string_decryption")
            self.assertIn(b"secret", patches[0].patched_bytes)

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        with self.assertRaises(FileNotFoundError):
            self.bypass.bypass("/nonexistent/file.exe")

    def test_comprehensive_bypass(self):
        """Test comprehensive bypass with multiple protection features."""
        section_data = (
            b"Arxan TransformIT" +
            b"\x33\xd2\x8a\x10" +
            b"\x85\xc0\x75\x02" * 10 +
            b"license" + b"serial" +
            b"frida" + b"tamper" +
            b"\x00\x01\xff\xff"
        )

        binary = self._create_pe_binary(section_data)
        result = self.bypass.bypass(binary)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.patched_binary_path)
        self.assertTrue(Path(result.patched_binary_path).exists())

        patched_size = Path(result.patched_binary_path).stat().st_size
        self.assertGreater(patched_size, 0)


if __name__ == '__main__':
    unittest.main()
