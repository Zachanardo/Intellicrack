"""Unit tests for Arxan detector.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import io
import struct
import tempfile
import unittest
from pathlib import Path

from intellicrack.core.protection_detection.arxan_detector import (
    ArxanDetector,
    ArxanVersion,
    ArxanProtectionFeatures,
)


class TestArxanDetector(unittest.TestCase):
    """Test cases for ArxanDetector."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = ArxanDetector()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_test_binary(self, content: bytes, suffix: str = '.exe') -> Path:
        """Create test binary file."""
        test_file = Path(self.test_dir) / f"test{suffix}"
        with open(test_file, 'wb') as f:
            f.write(content)
        return test_file

    def _create_pe_binary(self, arxan_signatures: list[bytes] | None = None) -> Path:
        """Create minimal PE binary with optional Arxan signatures."""
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
            struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0x60000020)
        )

        section_data = b"\x90" * 0x200

        if arxan_signatures:
            for sig in arxan_signatures:
                section_data += sig + b"\x90" * 50

        section_data = section_data[:0x200].ljust(0x200, b"\x00")

        binary = dos_header + pe_signature + coff_header + optional_header + section_header + section_data

        return self._create_test_binary(binary, '.exe')

    def test_detector_initialization(self) -> None:
        """Test detector initializes correctly."""
        self.assertIsInstance(self.detector, ArxanDetector)
        self.assertTrue(len(self.detector.ARXAN_STRING_SIGNATURES) > 0)
        self.assertTrue(len(self.detector.ARXAN_SECTION_NAMES) > 0)

    def test_detect_clean_binary(self) -> None:
        """Test detection on binary without Arxan protection."""
        binary = self._create_pe_binary()

        result = self.detector.detect(binary)

        self.assertIsNotNone(result)
        self.assertFalse(result.is_protected)
        self.assertLess(result.confidence, 0.5)
        self.assertEqual(result.version, ArxanVersion.UNKNOWN)

    def test_detect_arxan_signatures(self) -> None:
        """Test detection with Arxan string signatures."""
        arxan_sigs = [
            b"Arxan Technologies",
            b"TransformIT",
            b"GuardIT",
        ]

        binary = self._create_pe_binary(arxan_sigs)
        result = self.detector.detect(binary)

        self.assertIsNotNone(result)
        self.assertTrue(result.is_protected)
        self.assertGreater(result.confidence, 0.5)
        self.assertGreater(len(result.signatures_found), 0)

    def test_detect_version_5x(self) -> None:
        """Test detection of Arxan 5.x version."""
        version_sig = b"\x40\x72\x78\x61\x6e\x35"
        arxan_sigs = [b"Arxan", version_sig]

        binary = self._create_pe_binary(arxan_sigs)
        result = self.detector.detect(binary)

        self.assertTrue(result.is_protected)
        self.assertIn(result.version, [ArxanVersion.TRANSFORM_5X, ArxanVersion.UNKNOWN])

    def test_detect_version_7x(self) -> None:
        """Test detection of Arxan 7.x version."""
        version_sig = b"\x40\x72\x78\x61\x6e\x37"
        arxan_sigs = [b"Arxan", version_sig]

        binary = self._create_pe_binary(arxan_sigs)
        result = self.detector.detect(binary)

        self.assertTrue(result.is_protected)

    def test_entropy_calculation(self) -> None:
        """Test entropy calculation."""
        low_entropy = b"\x00" * 1000
        entropy_low = self.detector._calculate_entropy(low_entropy)
        self.assertLess(entropy_low, 1.0)

        high_entropy = bytes(range(256)) * 4
        entropy_high = self.detector._calculate_entropy(high_entropy)
        self.assertGreater(entropy_high, 7.0)

    def test_anti_debug_detection(self) -> None:
        """Test anti-debugging pattern detection."""
        anti_debug_pattern = b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02"
        binary_data = b"Arxan" + anti_debug_pattern * 3

        binary = self._create_test_binary(binary_data)
        result = self.detector.detect(binary)

        if result.is_protected:
            self.assertTrue(result.features.anti_debugging)

    def test_string_encryption_detection(self) -> None:
        """Test encrypted string detection."""
        xor_pattern = b"\x80\x30" * 20
        binary_data = b"Arxan" + xor_pattern

        encrypted = self.detector._check_string_encryption(binary_data)
        self.assertTrue(encrypted)

    def test_control_flow_obfuscation_detection(self) -> None:
        """Test control flow obfuscation detection."""
        jmp_heavy_code = b"\xe9\x00\x00\x00\x00" * 150

        obfuscated = self.detector._check_control_flow_obfuscation(jmp_heavy_code)
        self.assertTrue(obfuscated)

    def test_rasp_indicators_detection(self) -> None:
        """Test RASP mechanism detection."""
        rasp_strings = b"frida" + b"tamper" + b"hook" + b"inject"

        has_rasp = self.detector._check_rasp_indicators(rasp_strings)
        self.assertTrue(has_rasp)

    def test_license_validation_detection(self) -> None:
        """Test license validation routine detection."""
        license_strings = b"license" + b"serial" + b"activation" + b"validate"

        has_license = self.detector._check_license_validation(license_strings)
        self.assertTrue(has_license)

    def test_white_box_crypto_detection(self) -> None:
        """Test white-box cryptography detection."""
        diverse_data = bytes(range(256)) * 20

        has_whitebox = self.detector._check_white_box_crypto(diverse_data)
        self.assertTrue(has_whitebox)

    def test_file_not_found(self) -> None:
        """Test handling of non-existent file."""
        with self.assertRaises(FileNotFoundError):
            self.detector.detect("/nonexistent/file.exe")

    def test_protection_features(self) -> None:
        """Test protection features structure."""
        features = ArxanProtectionFeatures()

        self.assertFalse(features.anti_debugging)
        self.assertFalse(features.anti_tampering)
        self.assertFalse(features.rasp_protection)

        features.anti_debugging = True
        features.license_validation = True

        self.assertTrue(features.anti_debugging)
        self.assertTrue(features.license_validation)

    def test_comprehensive_detection(self) -> None:
        """Test comprehensive detection with multiple features."""
        signatures = [
            b"Arxan Technologies",
            b"TransformIT",
            b"\x64\xa1\x30\x00\x00\x00",
            b"license",
            b"frida",
        ]

        binary = self._create_pe_binary(signatures)
        result = self.detector.detect(binary)

        self.assertTrue(result.is_protected)
        self.assertGreater(result.confidence, 0.7)
        self.assertGreater(len(result.signatures_found), 0)

        if result.features.anti_debugging or result.features.rasp_protection:
            self.assertGreater(result.confidence, 0.5)


if __name__ == '__main__':
    unittest.main()
