"""
REAL SecuROM integration tests against ACTUAL protected binaries.

These tests validate Intellicrack works on genuine SecuROM-protected software.
Tests SKIP if real binaries unavailable. Tests FAIL if detection/analysis/bypass doesn't work.
"""

import unittest
import json
from pathlib import Path
import hashlib

from intellicrack.core.protection_detection.securom_detector import (
    SecuROMDetector,
    SecuROMDetection
)
from intellicrack.core.analysis.securom_analyzer import SecuROMAnalyzer
from intellicrack.core.protection_bypass.securom_bypass import SecuROMBypass


class RealBinaryTestBase(unittest.TestCase):
    """Base class for real binary tests with helper methods."""

    BINARY_ROOT = Path(__file__).parent / 'binaries'
    MANIFEST_ROOT = Path(__file__).parent / 'manifests'

    @classmethod
    def load_manifest(cls, manifest_file):
        """Load test binary manifest."""
        manifest_path = cls.MANIFEST_ROOT / manifest_file
        if not manifest_path.exists():
            return []

        with open(manifest_path) as f:
            return json.load(f)

    @classmethod
    def get_real_binaries(cls, protection_dir):
        """Get list of real binaries in directory."""
        binary_dir = cls.BINARY_ROOT / protection_dir
        if not binary_dir.exists():
            return []

        return [f for f in binary_dir.iterdir() if f.is_file() and f.suffix.lower() in ['.exe', '.dll']]

    def verify_binary_hash(self, binary_path, expected_sha256):
        """Verify binary hasn't been tampered with."""
        if not expected_sha256:
            return True

        sha256 = hashlib.sha256()
        with open(binary_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)

        return sha256.hexdigest() == expected_sha256


class TestSecuROMv7Real(RealBinaryTestBase):
    """Real tests against actual SecuROM v7.x protected binaries."""

    @classmethod
    def setUpClass(cls):
        """Load SecuROM v7 test binaries."""
        cls.v7_manifest = cls.load_manifest('securom_v7_samples.json')
        cls.v7_binaries = cls.get_real_binaries('securom/v7')

        if not cls.v7_binaries and not cls.v7_manifest:
            print("\nWARNING: No SecuROM v7 test binaries found")
            print(f"Place protected executables in: {cls.BINARY_ROOT / 'securom' / 'v7'}")
            print("See tests/integration/real_binary_tests/README.md for sources")

    def setUp(self):
        """Initialize detector for each test."""
        self.detector = SecuROMDetector()
        self.analyzer = SecuROMAnalyzer()
        self.bypass = SecuROMBypass()

    def test_detect_real_securom_v7_from_manifest(self):
        """Test detection on real SecuROM v7 binaries from manifest."""
        if not self.v7_manifest:
            self.skipTest("No SecuROM v7 manifest entries - add binaries and manifests to enable test")

        for entry in self.v7_manifest:
            with self.subTest(binary=entry['name']):
                binary_path = self.BINARY_ROOT / 'securom' / 'v7' / entry['file']

                if not binary_path.exists():
                    self.fail(f"Manifest references missing binary: {binary_path}")

                if entry.get('sha256'):
                    if not self.verify_binary_hash(binary_path, entry['sha256']):
                        self.fail(f"Binary hash mismatch - file may be corrupted: {binary_path}")

                result = self.detector.detect(binary_path)

                self.assertIsInstance(result, SecuROMDetection,
                    f"Detector must return SecuROMDetection for {entry['name']}")

                self.assertTrue(result.detected,
                    f"FAILED: Detector did not detect SecuROM in real binary {entry['name']}")

                if entry.get('version'):
                    expected_version = entry['version']
                    if result.version:
                        actual_version = f"{result.version.major}.{result.version.minor:02d}.{result.version.build:04d}"
                        self.assertEqual(actual_version, expected_version,
                            f"Version mismatch for {entry['name']}: expected {expected_version}, got {actual_version}")

                if entry.get('expected_drivers'):
                    for driver in entry['expected_drivers']:
                        self.assertIn(driver, result.drivers,
                            f"Expected driver {driver} not detected in {entry['name']}")

                if entry.get('expected_sections'):
                    for section in entry['expected_sections']:
                        self.assertIn(section, result.protected_sections,
                            f"Expected section {section} not detected in {entry['name']}")

    def test_detect_real_securom_v7_discovery(self):
        """Test detection on all real v7 binaries found in directory."""
        if not self.v7_binaries:
            self.skipTest("No SecuROM v7 binaries found - place protected .exe files in binaries/securom/v7/")

        for binary_path in self.v7_binaries:
            with self.subTest(binary=binary_path.name):
                result = self.detector.detect(binary_path)

                self.assertIsInstance(result, SecuROMDetection)

                self.assertTrue(result.detected or result.confidence > 0.5,
                    f"FAILED: Detector did not detect SecuROM in {binary_path.name} "
                    f"(detected={result.detected}, confidence={result.confidence})")

                if result.detected and result.version:
                    self.assertEqual(result.version.major, 7,
                        f"Binary in v7 directory detected as version {result.version.major}")

    def test_analyze_real_securom_v7_activation(self):
        """Test activation analysis on real SecuROM v7 binaries."""
        if not self.v7_manifest:
            self.skipTest("No SecuROM v7 manifest entries")

        for entry in self.v7_manifest:
            if not entry.get('has_activation'):
                continue

            with self.subTest(binary=entry['name']):
                binary_path = self.BINARY_ROOT / 'securom' / 'v7' / entry['file']

                if not binary_path.exists():
                    continue

                activation = self.analyzer.analyze_activation(binary_path)

                if entry.get('has_activation'):
                    self.assertIsNotNone(activation,
                        f"FAILED: Analyzer did not extract activation mechanism from {entry['name']}")

                    if entry.get('expected_activation_type'):
                        self.assertEqual(activation.activation_type, entry['expected_activation_type'])

                    if entry.get('expected_max_activations'):
                        self.assertEqual(activation.max_activations, entry['expected_max_activations'])

    def test_bypass_real_securom_v7(self):
        """Test bypass on real SecuROM v7 binaries."""
        if not self.v7_manifest:
            self.skipTest("No SecuROM v7 manifest entries")

        import tempfile

        for entry in self.v7_manifest:
            if not entry.get('allow_bypass_test'):
                continue

            with self.subTest(binary=entry['name']):
                binary_path = self.BINARY_ROOT / 'securom' / 'v7' / entry['file']

                if not binary_path.exists():
                    continue

                with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
                    output_path = Path(tmp.name)

                try:
                    result = self.bypass.bypass_activation(binary_path, output_path)

                    self.assertIsNotNone(result,
                        f"Bypass must return result for {entry['name']}")

                    self.assertTrue(result.success,
                        f"FAILED: Bypass did not succeed on {entry['name']}: {result.errors}")

                    self.assertTrue(output_path.exists(),
                        f"Bypassed binary not created for {entry['name']}")

                    self.assertGreater(output_path.stat().st_size, 0,
                        f"Bypassed binary is empty for {entry['name']}")

                    with open(output_path, 'rb') as f:
                        data = f.read(2)
                        self.assertEqual(data, b'MZ',
                            f"Bypassed binary has invalid DOS header for {entry['name']}")

                finally:
                    if output_path.exists():
                        output_path.unlink()


class TestSecuROMv8Real(RealBinaryTestBase):
    """Real tests against actual SecuROM v8.x protected binaries."""

    @classmethod
    def setUpClass(cls):
        """Load SecuROM v8 test binaries."""
        cls.v8_manifest = cls.load_manifest('securom_v8_samples.json')
        cls.v8_binaries = cls.get_real_binaries('securom/v8')

        if not cls.v8_binaries and not cls.v8_manifest:
            print("\nWARNING: No SecuROM v8 test binaries found")
            print(f"Place protected executables in: {cls.BINARY_ROOT / 'securom' / 'v8'}")

    def setUp(self):
        """Initialize detector for each test."""
        self.detector = SecuROMDetector()
        self.analyzer = SecuROMAnalyzer()

    def test_detect_real_securom_v8_from_manifest(self):
        """Test detection on real SecuROM v8 binaries from manifest."""
        if not self.v8_manifest:
            self.skipTest("No SecuROM v8 manifest entries")

        for entry in self.v8_manifest:
            with self.subTest(binary=entry['name']):
                binary_path = self.BINARY_ROOT / 'securom' / 'v8' / entry['file']

                if not binary_path.exists():
                    self.fail(f"Manifest references missing binary: {binary_path}")

                result = self.detector.detect(binary_path)

                self.assertTrue(result.detected,
                    f"FAILED: Detector did not detect SecuROM v8 in {entry['name']}")

                if result.version:
                    self.assertEqual(result.version.major, 8,
                        f"Binary reported as v{result.version.major} instead of v8")

    def test_detect_real_securom_v8_discovery(self):
        """Test detection on all real v8 binaries found in directory."""
        if not self.v8_binaries:
            self.skipTest("No SecuROM v8 binaries found")

        for binary_path in self.v8_binaries:
            with self.subTest(binary=binary_path.name):
                result = self.detector.detect(binary_path)

                self.assertTrue(result.detected or result.confidence > 0.5,
                    f"FAILED: Detector did not detect SecuROM in {binary_path.name}")


class TestSecuROMDrivers(RealBinaryTestBase):
    """Test detection against real SecuROM driver files."""

    @classmethod
    def setUpClass(cls):
        """Check for real driver files."""
        cls.driver_dir = cls.BINARY_ROOT / 'drivers'
        cls.securom_drivers = []

        if cls.driver_dir.exists():
            for driver_file in ['secdrv.sys', 'SR7.sys', 'SR8.sys', 'SecuROMv7.sys', 'SecuROMv8.sys']:
                driver_path = cls.driver_dir / driver_file
                if driver_path.exists():
                    cls.securom_drivers.append(driver_path)

        system_drivers = Path('C:/Windows/System32/drivers')
        if system_drivers.exists():
            for driver_file in ['secdrv.sys', 'SR7.sys', 'SR8.sys']:
                driver_path = system_drivers / driver_file
                if driver_path.exists():
                    cls.securom_drivers.append(driver_path)

    def setUp(self):
        """Initialize analyzer."""
        self.analyzer = SecuROMAnalyzer()

    def test_analyze_real_securom_drivers(self):
        """Test analysis on real SecuROM driver files."""
        if not self.securom_drivers:
            self.skipTest("No real SecuROM driver files found")

        for driver_path in self.securom_drivers:
            with self.subTest(driver=driver_path.name):
                self.assertTrue(driver_path.exists())

                result = self.analyzer.analyze_driver(driver_path)

                self.assertIsNotNone(result,
                    f"FAILED: Analyzer returned None for real driver {driver_path.name}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
