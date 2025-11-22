"""
REAL StarForce integration tests against ACTUAL protected binaries.

These tests validate Intellicrack works on genuine StarForce-protected software.
Tests SKIP if real binaries unavailable. Tests FAIL if detection/analysis/bypass doesn't work.
"""

import unittest
import json
from pathlib import Path
import hashlib

from intellicrack.core.protection_detection.starforce_detector import (
    StarForceDetector,
    StarForceDetection
)
from intellicrack.core.analysis.starforce_analyzer import StarForceAnalyzer
from intellicrack.core.protection_bypass.starforce_bypass import StarForceBypass


class RealBinaryTestBase(unittest.TestCase):
    """Base class for real binary tests."""

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


class TestStarForceReal(RealBinaryTestBase):
    """Real tests against actual StarForce protected binaries."""

    @classmethod
    def setUpClass(cls):
        """Load StarForce test binaries."""
        cls.manifest = cls.load_manifest('starforce_samples.json')
        cls.v3_binaries = cls.get_real_binaries('starforce/v3')
        cls.v4_binaries = cls.get_real_binaries('starforce/v4')
        cls.v5_binaries = cls.get_real_binaries('starforce/v5')
        cls.all_binaries = cls.v3_binaries + cls.v4_binaries + cls.v5_binaries

        if not cls.all_binaries and not cls.manifest:
            print("\nWARNING: No StarForce test binaries found")
            print(f"Place protected executables in: {cls.BINARY_ROOT / 'starforce'}")
            print("See tests/integration/real_binary_tests/README.md for sources")

    def setUp(self):
        """Initialize components for each test."""
        self.detector = StarForceDetector()
        self.analyzer = StarForceAnalyzer()
        self.bypass = StarForceBypass()

    def test_detect_real_starforce_from_manifest(self):
        """Test detection on real StarForce binaries from manifest."""
        if not self.manifest:
            self.skipTest("No StarForce manifest entries - add binaries and manifests to enable test")

        for entry in self.manifest:
            with self.subTest(binary=entry['name']):
                version_dir = f"v{entry.get('version', '').split('.')[0]}" if entry.get('version') else ''
                binary_path = self.BINARY_ROOT / 'starforce' / version_dir / entry['file']

                if not binary_path.exists():
                    self.fail(f"Manifest references missing binary: {binary_path}")

                result = self.detector.detect(binary_path)

                self.assertIsInstance(result, StarForceDetection,
                    f"Detector must return StarForceDetection for {entry['name']}")

                self.assertTrue(result.detected,
                    f"FAILED: Detector did not detect StarForce in real binary {entry['name']}")

                if entry.get('version') and result.version:
                    expected_major = int(entry['version'].split('.')[0])
                    self.assertEqual(result.version.major, expected_major,
                        f"Version mismatch for {entry['name']}")

                if entry.get('expected_drivers'):
                    for driver in entry['expected_drivers']:
                        self.assertIn(driver, result.drivers,
                            f"Expected driver {driver} not detected in {entry['name']}")

    def test_detect_real_starforce_v3(self):
        """Test detection on all real StarForce v3 binaries."""
        if not self.v3_binaries:
            self.skipTest("No StarForce v3 binaries found - place protected .exe files in binaries/starforce/v3/")

        for binary_path in self.v3_binaries:
            with self.subTest(binary=binary_path.name):
                result = self.detector.detect(binary_path)

                self.assertTrue(result.detected or result.confidence > 0.5,
                    f"FAILED: Detector did not detect StarForce in {binary_path.name}")

                if result.detected and result.version:
                    self.assertEqual(result.version.major, 3,
                        f"Binary in v3 directory detected as version {result.version.major}")

    def test_detect_real_starforce_v4(self):
        """Test detection on all real StarForce v4 binaries."""
        if not self.v4_binaries:
            self.skipTest("No StarForce v4 binaries found")

        for binary_path in self.v4_binaries:
            with self.subTest(binary=binary_path.name):
                result = self.detector.detect(binary_path)

                self.assertTrue(result.detected or result.confidence > 0.5,
                    f"FAILED: Detector did not detect StarForce in {binary_path.name}")

    def test_detect_real_starforce_v5(self):
        """Test detection on all real StarForce v5 binaries."""
        if not self.v5_binaries:
            self.skipTest("No StarForce v5 binaries found")

        for binary_path in self.v5_binaries:
            with self.subTest(binary=binary_path.name):
                result = self.detector.detect(binary_path)

                self.assertTrue(result.detected or result.confidence > 0.5,
                    f"FAILED: Detector did not detect StarForce in {binary_path.name}")

    def test_analyze_real_starforce_drivers(self):
        """Test analysis on real StarForce driver files."""
        driver_dir = self.BINARY_ROOT / 'drivers'
        if not driver_dir.exists():
            self.skipTest("No driver directory")

        starforce_drivers = [f for f in driver_dir.iterdir()
                           if f.name.startswith('sf') and f.suffix == '.sys']

        if not starforce_drivers:
            self.skipTest("No real StarForce driver files found")

        for driver_path in starforce_drivers:
            with self.subTest(driver=driver_path.name):
                result = self.analyzer.analyze_driver(driver_path)

                self.assertIsNotNone(result,
                    f"FAILED: Analyzer returned None for real driver {driver_path.name}")

    def test_bypass_real_starforce(self):
        """Test bypass on real StarForce binaries."""
        if not self.manifest:
            self.skipTest("No StarForce manifest entries")

        import tempfile

        for entry in self.manifest:
            if not entry.get('allow_bypass_test'):
                continue

            with self.subTest(binary=entry['name']):
                version_dir = f"v{entry.get('version', '').split('.')[0]}"
                binary_path = self.BINARY_ROOT / 'starforce' / version_dir / entry['file']

                if not binary_path.exists():
                    continue

                with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
                    output_path = Path(tmp.name)

                try:
                    result = self.bypass.remove_protection(binary_path, output_path)

                    self.assertIsNotNone(result)

                    self.assertTrue(result.success,
                        f"FAILED: Bypass did not succeed on {entry['name']}: {result.errors}")

                    self.assertTrue(output_path.exists())
                    self.assertGreater(output_path.stat().st_size, 0)

                finally:
                    if output_path.exists():
                        output_path.unlink()


if __name__ == '__main__':
    unittest.main(verbosity=2)
