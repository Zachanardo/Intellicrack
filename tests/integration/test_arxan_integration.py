"""Integration tests for Arxan detection, analysis, and bypass.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from intellicrack.core.protection_detection.arxan_detector import ArxanDetector
from intellicrack.core.analysis.arxan_analyzer import ArxanAnalyzer
from intellicrack.core.protection_bypass.arxan_bypass import ArxanBypass


class TestArxanIntegration(unittest.TestCase):
    """Integration tests for complete Arxan protection workflow."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = ArxanDetector()
        self.analyzer = ArxanAnalyzer()
        self.bypass = ArxanBypass()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_arxan_protected_binary(self) -> Path:
        """Create test binary simulating Arxan protection."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014c,
            2,
            0,
            0,
            0,
            0xe0,
            0x010b
        )

        optional_header = b"\x0b\x01" + b"\x00" * 222

        text_section = (
            b".text\x00\x00\x00" +
            struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x600, 0x600, 0, 0, 0x60000020)
        )

        arxan_section = (
            b".arxan\x00\x00" +
            struct.pack("<IIIIHHI", 0x2000, 0x1600, 0x200, 0xc00, 0, 0, 0x40000040)
        )

        text_data = (
            b"Arxan Technologies Inc." +
            b"TransformIT 7.0" +
            b"GuardIT Protection" +
            b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02" * 3 +
            b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08" * 2 +
            b"\x85\xc0\x75\x02\x75\x00" * 20 +
            b"\xff\x25\x00\x00\x00\x00" * 10 +
            b"license_check" +
            b"validate_serial" +
            b"product_activation" +
            b"\x00\x01\xff\xff" +
            b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5" +
            b"frida-agent" +
            b"hook_detected" +
            b"tamper_check"
        )
        text_data = text_data.ljust(0x600, b"\x90")

        arxan_data = (
            b"ARXAN_RUNTIME_v7" +
            b"\x40\x72\x78\x61\x6e\x37" +
            bytes(range(256)) * 2
        )
        arxan_data = arxan_data.ljust(0x200, b"\x00")

        binary = (
            dos_header +
            pe_signature +
            coff_header +
            optional_header +
            text_section +
            arxan_section +
            text_data +
            arxan_data
        )

        test_file = Path(self.test_dir) / "arxan_protected.exe"
        with open(test_file, 'wb') as f:
            f.write(binary)

        return test_file

    def test_complete_workflow(self):
        """Test complete detection -> analysis -> bypass workflow."""
        binary = self._create_arxan_protected_binary()

        detection_result = self.detector.detect(binary)

        self.assertTrue(detection_result.is_protected)
        self.assertGreater(detection_result.confidence, 0.7)
        self.assertGreater(len(detection_result.signatures_found), 0)

        analysis_result = self.analyzer.analyze(binary)

        self.assertIsNotNone(analysis_result)
        self.assertTrue(analysis_result.metadata.get('analysis_complete', False))

        bypass_result = self.bypass.bypass(binary)

        self.assertTrue(bypass_result.success)
        self.assertIsNotNone(bypass_result.patched_binary_path)
        self.assertTrue(Path(bypass_result.patched_binary_path).exists())

    def test_detection_to_analysis(self):
        """Test detection results flow to analysis."""
        binary = self._create_arxan_protected_binary()

        detection_result = self.detector.detect(binary)

        self.assertTrue(detection_result.is_protected)

        analysis_result = self.analyzer.analyze(binary)

        self.assertEqual(
            analysis_result.metadata.get('arxan_version'),
            detection_result.version.value
        )

    def test_analysis_to_bypass(self):
        """Test analysis results inform bypass strategy."""
        binary = self._create_arxan_protected_binary()

        analysis_result = self.analyzer.analyze(binary)

        total_protections = (
            len(analysis_result.tamper_checks) +
            len(analysis_result.rasp_mechanisms) +
            len(analysis_result.license_routines) +
            len(analysis_result.integrity_checks)
        )

        if total_protections > 0:
            bypass_result = self.bypass.bypass(binary)

            self.assertGreater(len(bypass_result.patches_applied), 0)

    def test_bypass_preserves_binary_structure(self):
        """Test bypass maintains valid binary structure."""
        binary = self._create_arxan_protected_binary()

        original_size = binary.stat().st_size

        bypass_result = self.bypass.bypass(binary)

        patched_binary = Path(bypass_result.patched_binary_path)
        patched_size = patched_binary.stat().st_size

        self.assertEqual(original_size, patched_size)

        with open(patched_binary, 'rb') as f:
            header = f.read(2)
            self.assertEqual(header, b"MZ")

    def test_detection_consistency(self):
        """Test detection is consistent across multiple runs."""
        binary = self._create_arxan_protected_binary()

        result1 = self.detector.detect(binary)
        result2 = self.detector.detect(binary)

        self.assertEqual(result1.is_protected, result2.is_protected)
        self.assertAlmostEqual(result1.confidence, result2.confidence, places=2)
        self.assertEqual(result1.version, result2.version)

    def test_analysis_metadata_completeness(self):
        """Test analysis provides complete metadata."""
        binary = self._create_arxan_protected_binary()

        analysis_result = self.analyzer.analyze(binary)

        required_metadata = [
            'binary_size',
            'arxan_version',
            'protection_features',
            'analysis_complete',
            'total_tamper_checks',
            'total_rasp_mechanisms',
            'total_license_routines'
        ]

        for key in required_metadata:
            self.assertIn(key, analysis_result.metadata)

    def test_bypass_frida_script_validity(self):
        """Test generated Frida script is valid JavaScript."""
        binary = self._create_arxan_protected_binary()

        bypass_result = self.bypass.bypass(binary, runtime_bypass=False)

        analysis_result = self.analyzer.analyze(binary)
        script = self.bypass._generate_frida_bypass_script(analysis_result)

        self.assertGreater(len(script), 100)

        self.assertIn("Interceptor", script)
        self.assertIn("console.log", script)

        self.assertNotIn("undefined", script)

    def test_multiple_protection_features(self):
        """Test handling of binaries with multiple protection features."""
        binary = self._create_arxan_protected_binary()

        detection_result = self.detector.detect(binary)
        features = detection_result.features

        protected_features = [
            features.anti_debugging,
            features.anti_tampering,
            features.control_flow_obfuscation,
            features.rasp_protection,
            features.license_validation
        ]

        self.assertGreater(sum(protected_features), 0)

        bypass_result = self.bypass.bypass(binary)

        self.assertTrue(bypass_result.success)

    def test_error_handling(self):
        """Test error handling across components."""
        nonexistent = Path(self.test_dir) / "nonexistent.exe"

        with self.assertRaises(FileNotFoundError):
            self.detector.detect(nonexistent)

        with self.assertRaises(FileNotFoundError):
            self.analyzer.analyze(nonexistent)

        with self.assertRaises(FileNotFoundError):
            self.bypass.bypass(nonexistent)

    def test_performance_acceptable(self):
        """Test operations complete in reasonable time."""
        import time

        binary = self._create_arxan_protected_binary()

        start = time.time()
        detection_result = self.detector.detect(binary)
        detection_time = time.time() - start
        self.assertLess(detection_time, 5.0)

        start = time.time()
        analysis_result = self.analyzer.analyze(binary)
        analysis_time = time.time() - start
        self.assertLess(analysis_time, 10.0)

        start = time.time()
        bypass_result = self.bypass.bypass(binary)
        bypass_time = time.time() - start
        self.assertLess(bypass_time, 10.0)


if __name__ == '__main__':
    unittest.main()
