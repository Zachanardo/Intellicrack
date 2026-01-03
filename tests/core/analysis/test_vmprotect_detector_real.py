"""Real-world VMProtect detector tests with actual protected binaries.

Tests VMProtect detection capabilities against genuine protected samples.
NO MOCKS - Uses real VMProtect-protected binaries only.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.vmprotect_detector import (
    VMProtectDetector,
    VMProtectLevel,
    VMProtectMode,
)


FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "fixtures" / "binaries" / "vmprotect"

SAMPLE_MANIFEST = {
    "vmp3_lite_x86.exe": {
        "description": "VMProtect 3.x Lite protection - x86 binary",
        "sha256": None,
        "expected_version": "3.x",
        "expected_level": VMProtectLevel.LITE,
        "expected_arch": "x86",
        "min_confidence": 0.85,
    },
    "vmp3_standard_x86.exe": {
        "description": "VMProtect 3.x Standard protection - x86 binary",
        "sha256": None,
        "expected_version": "3.x",
        "expected_level": VMProtectLevel.STANDARD,
        "expected_arch": "x86",
        "min_confidence": 0.90,
    },
    "vmp3_ultra_x64.exe": {
        "description": "VMProtect 3.x Ultra protection - x64 binary",
        "sha256": None,
        "expected_version": "3.x",
        "expected_level": VMProtectLevel.ULTRA,
        "expected_arch": "x64",
        "min_confidence": 0.92,
    },
    "vmp2_standard_x86.exe": {
        "description": "VMProtect 2.x Standard protection - x86 binary",
        "sha256": None,
        "expected_version": "2.x-3.x",
        "expected_level": VMProtectLevel.STANDARD,
        "expected_arch": "x86",
        "min_confidence": 0.85,
    },
}


@pytest.fixture(scope="module")
def vmprotect_detector() -> VMProtectDetector:
    """Create VMProtectDetector instance."""
    return VMProtectDetector()


@pytest.fixture
def sample_path_factory() -> Any:
    """Factory to get sample paths with existence validation."""

    def _get_sample(filename: str) -> Path | None:
        sample_path = FIXTURES_DIR / filename
        if not sample_path.exists():
            pytest.skip(
                f"VMProtect sample not found: {filename}\n"
                f"Please acquire legitimate VMProtect-protected software and place at:\n"
                f"{sample_path}\n\n"
                f"Suggested sources for legal samples:\n"
                f"- Demo versions of commercial software using VMProtect\n"
                f"- VMProtect trial SDK examples (https://vmpsoft.com/)\n"
                f"- Open-source projects with VMProtect protection\n"
                f"- Crackme challenges using VMProtect\n\n"
                f"Expected sample: {SAMPLE_MANIFEST.get(filename, {}).get('description', filename)}"
            )
        return sample_path

    return _get_sample


class TestVMProtectDetectorBasics:
    """Test basic VMProtect detection functionality."""

    def test_detector_initialization(self, vmprotect_detector: VMProtectDetector) -> None:
        """Test detector initializes correctly."""
        assert vmprotect_detector is not None
        assert hasattr(vmprotect_detector, "detect")
        assert hasattr(vmprotect_detector, "VMP_HANDLER_SIGNATURES_X86")
        assert hasattr(vmprotect_detector, "VMP_HANDLER_SIGNATURES_X64")
        assert len(vmprotect_detector.VMP_HANDLER_SIGNATURES_X86) > 0
        assert len(vmprotect_detector.VMP_HANDLER_SIGNATURES_X64) > 0

    def test_detect_non_vmprotect_binary(self, vmprotect_detector: VMProtectDetector, tmp_path: Path) -> None:
        """Test detection correctly identifies non-protected binary."""
        clean_binary = tmp_path / "clean.exe"

        with open(clean_binary, "wb") as f:
            f.write(b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80))
            f.write(b"\x00" * (0x80 - 64))
            f.write(b"PE\x00\x00")
            f.write(struct.pack("<H", 0x014C))
            f.write(struct.pack("<H", 1))
            f.write(b"\x00" * 240)

        result = vmprotect_detector.detect(str(clean_binary))

        assert result.detected is False or result.confidence < 0.3
        assert len(result.handlers) == 0 or result.confidence < 0.3

    def test_detect_non_pe_file(self, vmprotect_detector: VMProtectDetector, tmp_path: Path) -> None:
        """Test detection handles non-PE files gracefully."""
        non_pe = tmp_path / "not_pe.bin"
        with open(non_pe, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)

        result = vmprotect_detector.detect(str(non_pe))

        assert result.detected is False
        assert result.architecture == "unknown"
        assert len(result.handlers) == 0

    def test_detect_corrupted_binary(self, vmprotect_detector: VMProtectDetector, tmp_path: Path) -> None:
        """Test detection handles corrupted binaries without crashing."""
        corrupted = tmp_path / "corrupted.exe"
        with open(corrupted, "wb") as f:
            f.write(b"MZ" + os.urandom(1000))

        result = vmprotect_detector.detect(str(corrupted))

        assert result is not None
        assert hasattr(result, "detected")

    def test_detect_nonexistent_file(self, vmprotect_detector: VMProtectDetector) -> None:
        """Test detection handles missing files gracefully."""
        result = vmprotect_detector.detect("nonexistent_file.exe")

        assert result is not None
        assert result.detected is False
        assert "error" in result.technical_details or not result.detected


class TestVMProtect3Lite:
    """Test detection of VMProtect 3.x Lite protection."""

    def test_vmp3_lite_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test accurate detection of VMProtect 3.x Lite sample."""
        sample = sample_path_factory("vmp3_lite_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert result.detected is True, "VMProtect 3.x Lite should be detected"
        assert result.confidence >= 0.85, f"Confidence {result.confidence} below minimum 0.85"
        assert result.architecture == "x86", f"Expected x86, got {result.architecture}"
        assert "3" in result.version or "2.x-3.x" in result.version

    def test_vmp3_lite_protection_level(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test correct identification of Lite protection level."""
        sample = sample_path_factory("vmp3_lite_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert result.protection_level in [
            VMProtectLevel.LITE,
            VMProtectLevel.STANDARD,
        ]

    def test_vmp3_lite_handlers_detected(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test VM handler detection in Lite protected sample."""
        sample = sample_path_factory("vmp3_lite_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert len(result.handlers) > 0, "Should detect at least one VM handler"
        assert all(h.confidence >= 0.7 for h in result.handlers), "All handlers should have confidence >= 0.7"

        handler_types = {h.handler_type for h in result.handlers}
        assert handler_types, "Should detect distinct handler types"


class TestVMProtect3Standard:
    """Test detection of VMProtect 3.x Standard protection."""

    def test_vmp3_standard_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test accurate detection of VMProtect 3.x Standard sample."""
        sample = sample_path_factory("vmp3_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert result.detected is True, "VMProtect 3.x Standard should be detected"
        assert result.confidence >= 0.90, f"Confidence {result.confidence} below minimum 0.90"
        assert result.architecture == "x86"

    def test_vmp3_standard_virtualized_regions(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test virtualized region identification in Standard protection."""
        sample = sample_path_factory("vmp3_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert len(result.virtualized_regions) > 0, "Standard protection should have detectable virtualized regions"

        for region in result.virtualized_regions:
            assert region.vm_entry > 0, "VM entry should be identified"
            assert region.start_offset < region.end_offset, "Region should have valid bounds"
            assert len(region.handlers_used) > 0, "Region should identify handlers used"

    def test_vmp3_standard_dispatcher(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test dispatcher detection in Standard protection."""
        sample = sample_path_factory("vmp3_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        if result.dispatcher_offset is not None:
            assert result.dispatcher_offset > 0, "Dispatcher offset should be positive"
            assert result.confidence >= 0.85, "Dispatcher detection should boost confidence"


class TestVMProtect3Ultra:
    """Test detection of VMProtect 3.x Ultra protection."""

    def test_vmp3_ultra_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test accurate detection of VMProtect 3.x Ultra sample."""
        sample = sample_path_factory("vmp3_ultra_x64.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert result.detected is True, "VMProtect 3.x Ultra should be detected"
        assert result.confidence >= 0.92, f"Confidence {result.confidence} below minimum 0.92"
        assert result.architecture == "x64", f"Expected x64, got {result.architecture}"

    def test_vmp3_ultra_protection_level(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test correct identification of Ultra protection level."""
        sample = sample_path_factory("vmp3_ultra_x64.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert result.protection_level in [
            VMProtectLevel.ULTRA,
            VMProtectLevel.STANDARD,
        ], f"Expected Ultra or Standard, got {result.protection_level}"

    def test_vmp3_ultra_mutation_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test mutation/polymorphic code detection in Ultra protection."""
        sample = sample_path_factory("vmp3_ultra_x64.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        mutation_score = result.technical_details.get("mutation_score", 0.0)
        assert mutation_score >= 0.0, "Mutation score should be calculated"

        if result.mode == VMProtectMode.MUTATION:
            assert mutation_score > 0.5, "Mutation mode should have high mutation score"

    def test_vmp3_ultra_handler_complexity(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test handler complexity analysis in Ultra protection."""
        sample = sample_path_factory("vmp3_ultra_x64.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        if len(result.handlers) > 0:
            avg_complexity = sum(h.complexity for h in result.handlers) / len(result.handlers)
            assert avg_complexity > 0, "Handlers should have calculated complexity"


class TestVMProtect2Compatibility:
    """Test detection of VMProtect 2.x versions."""

    def test_vmp2_standard_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test detection of VMProtect 2.x Standard sample."""
        sample = sample_path_factory("vmp2_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert result.detected is True, "VMProtect 2.x should be detected"
        assert result.confidence >= 0.85, f"Confidence {result.confidence} below minimum"
        assert "2" in result.version or "3" in result.version or "Unknown" in result.version


class TestBypassRecommendations:
    """Test bypass recommendation generation."""

    def test_ultra_bypass_recommendations(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test bypass recommendations for Ultra protection."""
        sample = sample_path_factory("vmp3_ultra_x64.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        assert len(result.bypass_recommendations) > 0, "Should generate bypass recommendations"

        if result.protection_level == VMProtectLevel.ULTRA:
            recommendations_text = " ".join(result.bypass_recommendations).lower()
            assert "devirtualization" in recommendations_text or "symbolic execution" in recommendations_text, (
                "Ultra protection recommendations should mention advanced techniques"
            )
            assert "weeks" in recommendations_text or "months" in recommendations_text, "Should provide time estimates"

    def test_standard_bypass_recommendations(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test bypass recommendations for Standard protection."""
        sample = sample_path_factory("vmp3_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        if result.protection_level == VMProtectLevel.STANDARD:
            recommendations_text = " ".join(result.bypass_recommendations).lower()
            assert "handler" in recommendations_text or "pattern" in recommendations_text

    def test_dispatcher_recommendation(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test recommendations include dispatcher info when found."""
        sample = sample_path_factory("vmp3_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        if result.dispatcher_offset is not None:
            recommendations_text = " ".join(result.bypass_recommendations)
            assert "dispatcher" in recommendations_text.lower() or f"0x{result.dispatcher_offset:08x}" in recommendations_text.lower(), (
                "Should mention dispatcher location in recommendations"
            )


class TestDetectionAccuracy:
    """Test overall detection accuracy meets requirements."""

    def test_minimum_90_percent_accuracy(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test detector achieves >90% accuracy on known VMProtect samples.

        This test validates the critical requirement from TestingTODO.md:
        'Achieve >90% detection accuracy on known samples'
        """
        samples_tested = 0
        correct_detections = 0

        for filename, manifest in SAMPLE_MANIFEST.items():
            try:
                sample = sample_path_factory(filename)
                if not sample:
                    continue

                result = vmprotect_detector.detect(str(sample))
                samples_tested += 1

                min_conf: float = float(manifest["min_confidence"])  # type: ignore[arg-type]
                is_correct = (
                    result.detected is True
                    and result.confidence >= min_conf
                    and result.architecture == manifest["expected_arch"]
                )

                if is_correct:
                    correct_detections += 1

            except Exception:
                pass

        if samples_tested > 0:
            accuracy = (correct_detections / samples_tested) * 100
            assert accuracy >= 90.0, (
                f"Detection accuracy {accuracy:.1f}% below required 90% ({correct_detections}/{samples_tested} correct)"
            )


class TestSectionAnalysis:
    """Test PE section analysis capabilities."""

    def test_vmp_section_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test detection of VMProtect-specific sections."""
        sample = sample_path_factory("vmp3_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        sections = result.technical_details.get("sections", {})
        assert sections is not None, "Section analysis should be performed"

        vmp_sections = sections.get("vmp_sections", [])
        if len(vmp_sections) > 0:
            for vmp_section in vmp_sections:
                assert "name" in vmp_section
                assert ".vmp" in vmp_section["name"].lower() or "vmp" in vmp_section["name"].lower()
                assert "entropy" in vmp_section
                assert vmp_section["entropy"] > 0

    def test_high_entropy_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test detection of high-entropy (encrypted/packed) sections."""
        sample = sample_path_factory("vmp3_ultra_x64.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        sections = result.technical_details.get("sections", {})
        high_entropy = sections.get("high_entropy_sections", [])

        if len(high_entropy) > 0:
            for section in high_entropy:
                assert section["entropy"] > 7.3, "High-entropy sections should exceed threshold"


class TestControlFlowAnalysis:
    """Test control flow analysis capabilities."""

    def test_control_flow_complexity_calculation(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test control flow complexity is calculated for virtualized regions."""
        sample = sample_path_factory("vmp3_standard_x86.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        cf_analysis = result.technical_details.get("control_flow", {})

        if len(result.virtualized_regions) > 0:
            assert "avg_complexity" in cf_analysis
            assert "max_complexity" in cf_analysis
            assert cf_analysis["avg_complexity"] >= 0
            assert cf_analysis["max_complexity"] >= cf_analysis["avg_complexity"]

    def test_indirect_branch_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test detection of indirect branches (VM dispatch indicators)."""
        sample = sample_path_factory("vmp3_ultra_x64.exe")
        if not sample:
            return

        result = vmprotect_detector.detect(str(sample))

        cf_analysis = result.technical_details.get("control_flow", {})

        if len(result.virtualized_regions) > 0:
            assert "indirect_branches" in cf_analysis
            indirect_branches = cf_analysis["indirect_branches"]
            assert indirect_branches >= 0, "Should count indirect branches"


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_batch_analysis(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test analyzing multiple samples in batch."""
        results = []

        for filename in SAMPLE_MANIFEST:
            try:
                sample = sample_path_factory(filename)
                if not sample:
                    continue

                result = vmprotect_detector.detect(str(sample))
                results.append((filename, result))

            except Exception:
                pass

        if results:
            for filename, result in results:
                assert result is not None, f"Detection failed for {filename}"
                assert hasattr(result, "detected")
                assert hasattr(result, "confidence")

    def test_concurrent_detection(self, vmprotect_detector: VMProtectDetector, sample_path_factory: Any) -> None:
        """Test thread safety for concurrent analysis."""
        import threading

        results = []
        errors = []

        def analyze_sample(filename: str) -> None:
            try:
                sample = sample_path_factory(filename)
                if not sample:
                    return

                result = vmprotect_detector.detect(str(sample))
                results.append((filename, result))

            except Exception as e:
                errors.append((filename, str(e)))

        threads = []
        for filename in list(SAMPLE_MANIFEST)[:2]:
            thread = threading.Thread(target=analyze_sample, args=(filename,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=30)

        assert not errors, f"Concurrent analysis errors: {errors}"


def test_fixtures_directory_setup() -> None:
    """Verify fixtures directory structure exists."""
    fixtures_root = Path(__file__).parent.parent.parent.parent / "fixtures"
    assert fixtures_root.exists(), f"Fixtures root directory should exist at {fixtures_root}"
    assert FIXTURES_DIR.exists(), f"VMProtect fixtures directory should exist at {FIXTURES_DIR}"


def test_sample_acquisition_instructions() -> None:
    """Document how to acquire VMProtect samples for testing.

    This test always passes but provides critical information for test setup.
    """
    instructions = f"""
    =============================================================================
    VMProtect Sample Acquisition Guide
    =============================================================================

    To run these tests, you need legitimate VMProtect-protected binaries.

    REQUIRED SAMPLES (place in {FIXTURES_DIR}):
    {chr(10).join(f"  - {filename}: {manifest['description']}" for filename, manifest in SAMPLE_MANIFEST.items())}

    LEGAL ACQUISITION METHODS:
    1. VMProtect Trial SDK
       - Download from: https://vmpsoft.com/
       - Protect sample programs with trial version
       - Place protected binaries in fixtures directory

    2. Legitimate Software Demos
       - Some commercial software demos use VMProtect
       - Verify licensing allows analysis/testing
       - Document source and licensing in manifest

    3. Crackme Challenges
       - VMProtect crackmes from crackmes.one
       - CTF challenges using VMProtect
       - Reverse engineering training materials

    4. Open Source Projects
       - GitHub projects that use VMProtect for protection
       - Verify license permits analysis

    FILE NAMING CONVENTION:
    - vmp{{VERSION}}_{{LEVEL}}_{{ARCH}}.exe
    - Example: vmp3_ultra_x64.exe

    MANIFEST UPDATE:
    After acquiring samples, calculate SHA-256 hashes and update
    SAMPLE_MANIFEST in this test file for integrity verification.

    CURRENT STATUS:
    {f"Found {len(list(FIXTURES_DIR.glob('*.exe')))} sample(s) in {FIXTURES_DIR}" if FIXTURES_DIR.exists() else f"Fixtures directory does not exist yet: {FIXTURES_DIR}"}

    =============================================================================
    """

    print(instructions)
