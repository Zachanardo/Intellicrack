"""Regression tests for Denuvo activation triggers and integrity checks detection.

REGRESSION TESTS - Validate previously completed functionality continues to work.

These tests ensure the Denuvo analyzer's capability to detect activation triggers
and integrity checks in protected binaries remains functional across code changes.

Expected Behavior (from testingtodo.md):
- Verify activation triggers detection
- Verify integrity checks analysis

Test Scope:
- Activation trigger point detection in Denuvo-protected binaries
- Integrity check routine identification and classification
- Steam API wrapper detection for Denuvo integration
- Hardware binding mechanism detection
- Timing validation routine detection
- Online activation endpoint analysis

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from pathlib import Path
from typing import Any

import pytest

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from intellicrack.protection.denuvo_ticket_analyzer import (
    DenuvoAnalysisResult,
    DenuvoTicketAnalyzer,
    DenuvoTrigger,
    HardwareBinding,
    IntegrityCheck,
    OnlineActivation,
    SteamAPIWrapper,
    TimingCheck,
)


@pytest.fixture(scope="module")
def test_binaries_dir() -> Path:
    """Directory containing test binaries with Denuvo protection."""
    return Path(__file__).parent.parent / "test_binaries"


@pytest.fixture(scope="module")
def denuvo_binaries(test_binaries_dir: Path) -> list[Path]:
    """Scan for Denuvo-protected binaries in test directory."""
    binaries: list[Path] = []

    if not test_binaries_dir.exists():
        return binaries

    for pattern in ["*.exe", "*.dll", "*.bin"]:
        binaries.extend(test_binaries_dir.rglob(pattern))

    return [b for b in binaries if b.is_file() and b.stat().st_size > 0]


@pytest.fixture
def analyzer() -> DenuvoTicketAnalyzer:
    """Create Denuvo ticket analyzer instance."""
    return DenuvoTicketAnalyzer()


def is_likely_denuvo_protected(binary_path: Path) -> bool:
    """Check if binary likely contains Denuvo protection.

    Args:
        binary_path: Path to binary file

    Returns:
        True if binary appears to have Denuvo protection

    """
    if not LIEF_AVAILABLE:
        return False

    try:
        binary = lief.parse(str(binary_path))
        if not binary:
            return False

        section_names = [s.name.lower() for s in binary.sections]
        denuvo_indicators = [".denuvo", ".text$dn", ".rdata$dn", ".data$dn", "denuvo"]

        return any(indicator in name for name in section_names for indicator in denuvo_indicators)

    except Exception:
        return False


class RegressionActivationTriggerDetection:
    """Regression tests for activation trigger detection."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required for binary analysis")
    def test_regression_detect_activation_triggers(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector finds activation trigger points in Denuvo binaries.

        Validates that activation trigger detection continues to work on real
        Denuvo-protected binaries after code changes.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found in test_binaries directory")

        found_triggers = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)

            if triggers:
                found_triggers = True
                for trigger in triggers:
                    assert isinstance(trigger, DenuvoTrigger)
                    assert trigger.address > 0
                    assert trigger.type in [
                        "steam_init",
                        "origin_init",
                        "epic_init",
                        "uplay_init",
                        "generic_drm_init",
                        "license_check",
                        "activation_request",
                        "ticket_validation",
                    ]
                    assert trigger.confidence >= 0.0
                    assert trigger.confidence <= 1.0
                    assert len(trigger.function_name) > 0
                    assert len(trigger.description) > 0
                    assert isinstance(trigger.opcode_sequence, bytes)
                    assert len(trigger.opcode_sequence) > 0
                    assert isinstance(trigger.referenced_imports, list)
                    assert isinstance(trigger.cross_references, list)

        assert found_triggers, "No activation triggers detected in any Denuvo binaries - regression failure"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_trigger_opcode_sequences(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector extracts valid opcode sequences from triggers.

        Validates that trigger detection includes actual opcode sequences
        from the detection location in the binary.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        found_opcodes = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)

            for trigger in triggers:
                if len(trigger.opcode_sequence) > 0:
                    found_opcodes = True
                    assert isinstance(trigger.opcode_sequence, bytes)
                    assert len(trigger.opcode_sequence) >= 4, "Opcode sequence too short"
                    assert len(trigger.opcode_sequence) <= 64, "Opcode sequence too long"

        if not found_opcodes:
            pytest.skip("No triggers with opcode sequences found")

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_trigger_cross_references(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector provides cross-reference information.

        Validates that detected triggers include valid cross-references
        to other code locations that call the trigger.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        found_xrefs = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)

            for trigger in triggers:
                if len(trigger.cross_references) > 0:
                    found_xrefs = True
                    for xref in trigger.cross_references:
                        assert isinstance(xref, int)
                        assert xref > 0

        if triggers and not found_xrefs:
            pytest.skip("No cross-references found in detected triggers")

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_trigger_referenced_imports(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector identifies imported functions used by triggers.

        Validates that trigger detection includes referenced import functions
        that may be used for activation purposes.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers = analyzer.detect_activation_triggers(binary)

            for trigger in triggers:
                assert isinstance(trigger.referenced_imports, list)
                for import_name in trigger.referenced_imports:
                    assert isinstance(import_name, str)
                    assert len(import_name) > 0


class RegressionIntegrityCheckDetection:
    """Regression tests for integrity check routine detection."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_detect_integrity_checks(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector finds integrity check routines in Denuvo binaries.

        Validates that integrity check detection continues to identify
        hash-based protection mechanisms after code changes.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        found_checks = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)

            if checks:
                found_checks = True
                for check in checks:
                    assert isinstance(check, IntegrityCheck)
                    assert check.address > 0
                    assert check.type in [
                        "crc32",
                        "crc64",
                        "md5",
                        "sha1",
                        "sha256",
                        "custom_hash",
                        "section_hash",
                        "code_hash",
                    ]
                    assert check.algorithm in [
                        "crc32",
                        "crc64",
                        "md5",
                        "sha1",
                        "sha256",
                        "sha512",
                        "custom",
                        "unknown",
                    ]
                    assert check.confidence >= 0.0
                    assert check.confidence <= 1.0
                    assert check.bypass_difficulty in ["low", "medium", "high", "very_high"]
                    assert check.check_size >= 0
                    assert check.frequency in [
                        "startup",
                        "periodic",
                        "on_demand",
                        "continuous",
                        "random",
                        "unknown",
                    ]
                    assert len(check.target) > 0

        assert found_checks, "No integrity checks detected in any Denuvo binaries - regression failure"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_integrity_check_algorithms(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector correctly classifies hash algorithms.

        Validates that integrity checks are classified with accurate
        algorithm identification (CRC32, MD5, SHA256, etc.).
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        found_classified = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)

            for check in checks:
                if check.algorithm != "unknown":
                    found_classified = True
                    assert check.algorithm in ["crc32", "crc64", "md5", "sha1", "sha256", "sha512", "custom"]

        if not found_classified:
            pytest.skip("No integrity checks with classified algorithms found")

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_integrity_check_targets(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector identifies integrity check targets.

        Validates that integrity checks include target information
        (code, data, sections, headers, entire binary).
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)

            for check in checks:
                assert check.target in ["code", "data", "sections", "headers", "entire", "code_section"]

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_integrity_check_frequency_assessment(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector assesses integrity check execution frequency.

        Validates that detected integrity checks include frequency
        assessment (startup, periodic, continuous, etc.).
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)

            for check in checks:
                assert check.frequency in [
                    "startup",
                    "periodic",
                    "on_demand",
                    "continuous",
                    "random",
                    "unknown",
                ]

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_integrity_bypass_difficulty_rating(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector rates bypass difficulty for integrity checks.

        Validates that each detected integrity check includes a bypass
        difficulty assessment to guide cracking efforts.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks = analyzer.detect_integrity_checks(binary)

            for check in checks:
                assert check.bypass_difficulty in ["low", "medium", "high", "very_high"]


class RegressionComprehensiveBinaryAnalysis:
    """Regression tests for complete binary analysis workflow."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_analyze_binary_complete_workflow(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Binary analysis produces complete results structure.

        Validates that analyze_binary() returns a properly structured
        DenuvoAnalysisResult with all required fields populated.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        found_analysis = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                found_analysis = True
                assert isinstance(result, DenuvoAnalysisResult)
                assert len(result.version) > 0
                assert result.version in ["4.x", "5.x", "6.x", "7.x", "unknown"]
                assert isinstance(result.triggers, list)
                assert isinstance(result.integrity_checks, list)
                assert isinstance(result.timing_checks, list)
                assert isinstance(result.hardware_bindings, list)
                assert result.protection_density >= 0.0
                assert result.protection_density <= 1.0
                assert result.obfuscation_level in ["low", "medium", "high", "very_high"]

        assert found_analysis, "No successful binary analysis on Denuvo binaries - regression failure"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_protection_density_calculation(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Analyzer calculates protection density metric.

        Validates that the protection_density field is correctly calculated
        based on the number and distribution of protection mechanisms.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                assert result.protection_density >= 0.0
                assert result.protection_density <= 1.0

                if result.triggers or result.integrity_checks or result.timing_checks:
                    assert result.protection_density > 0.0

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_obfuscation_level_assessment(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Analyzer assesses code obfuscation level.

        Validates that the obfuscation_level field is correctly assessed
        and categorized (low, medium, high, very_high).
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result = analyzer.analyze_binary(binary_path)

            if result:
                assert result.obfuscation_level in ["low", "medium", "high", "very_high"]


class RegressionTimingValidationDetection:
    """Regression tests for timing validation mechanism detection."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_detect_timing_checks(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector finds timing validation mechanisms.

        Validates that timing check detection continues to identify
        anti-debugging timing mechanisms in Denuvo binaries.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        found_timing = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            timing_checks = analyzer.detect_timing_validation(binary)

            if timing_checks:
                found_timing = True
                for check in timing_checks:
                    assert isinstance(check, TimingCheck)
                    assert check.address > 0
                    assert check.method in [
                        "rdtsc",
                        "queryperformancecounter",
                        "gettickcount",
                        "systemtime",
                        "ntp_sync",
                        "custom_timer",
                    ]
                    assert len(check.instruction) > 0
                    assert check.confidence >= 0.0
                    assert check.confidence <= 1.0
                    assert len(check.bypass_method) > 0
                    assert check.threshold_min >= 0
                    assert check.threshold_max >= check.threshold_min

        assert found_timing, "No timing validation detected in any Denuvo binaries - regression failure"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_timing_bypass_recommendations(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector provides bypass recommendations for timing checks.

        Validates that each detected timing check includes a specific
        bypass method recommendation.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            timing_checks = analyzer.detect_timing_validation(binary)

            for check in timing_checks:
                assert len(check.bypass_method) > 0
                assert isinstance(check.bypass_method, str)


class RegressionHardwareFingerprintingDetection:
    """Regression tests for hardware fingerprinting detection."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_detect_hardware_binding(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector finds hardware binding mechanisms.

        Validates that hardware fingerprinting detection continues to
        identify machine ID collection routines in Denuvo binaries.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        found_bindings = False

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            bindings = analyzer.detect_hardware_binding(binary)

            if bindings:
                found_bindings = True
                for binding in bindings:
                    assert isinstance(binding, HardwareBinding)
                    assert binding.binding_type in [
                        "cpu_id",
                        "disk_serial",
                        "mac_address",
                        "gpu_id",
                        "motherboard_id",
                        "bios_info",
                        "composite",
                    ]
                    assert binding.collection_address >= 0
                    assert binding.validation_address >= 0
                    assert binding.hash_algorithm in ["md5", "sha1", "sha256", "custom", "unknown"]
                    assert isinstance(binding.components, list)
                    assert binding.confidence >= 0.0
                    assert binding.confidence <= 1.0

        assert found_bindings, "No hardware binding detected in any Denuvo binaries - regression failure"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF_required")
    def test_regression_hardware_binding_components(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Detector identifies hardware components used in binding.

        Validates that hardware binding detection includes the specific
        hardware components used for fingerprinting.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            bindings = analyzer.detect_hardware_binding(binary)

            for binding in bindings:
                assert isinstance(binding.components, list)
                for component in binding.components:
                    assert isinstance(component, str)
                    assert len(component) > 0


class RegressionOnlineActivationDetection:
    """Regression tests for online activation endpoint detection."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_detect_online_activation(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Analyzer detects online activation endpoints.

        Validates that online activation detection continues to identify
        server communication endpoints in Denuvo binaries.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result = analyzer.analyze_binary(binary_path)

            if result and result.online_activation:
                activation = result.online_activation
                assert isinstance(activation, OnlineActivation)
                assert len(activation.endpoint_url) > 0
                assert activation.protocol in ["https", "http", "tcp", "custom"]
                assert activation.encryption_type in ["tls", "aes", "rsa", "custom", "none"]
                assert activation.validation_address >= 0
                assert len(activation.request_format) > 0
                assert len(activation.response_format) > 0


class RegressionSteamAPIWrapperDetection:
    """Regression tests for Steam API wrapper detection."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_analyze_steam_api_wrapper(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
        test_binaries_dir: Path,
    ) -> None:
        """REGRESSION: Analyzer detects Denuvo-wrapped Steam API DLLs.

        Validates that Steam API wrapper detection continues to identify
        Denuvo protection embedded in Steam API libraries.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        steam_dlls = list(test_binaries_dir.rglob("steam_api*.dll"))

        for dll_path in steam_dlls:
            wrapper = analyzer.analyze_steam_api_wrapper(dll_path)

            if wrapper:
                assert isinstance(wrapper, SteamAPIWrapper)
                assert len(wrapper.dll_path) > 0
                assert isinstance(wrapper.is_wrapper, bool)
                assert isinstance(wrapper.original_exports, list)
                assert isinstance(wrapper.hooked_exports, list)
                assert isinstance(wrapper.denuvo_sections, list)
                assert wrapper.confidence >= 0.0
                assert wrapper.confidence <= 1.0

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_steam_wrapper_export_analysis(
        self,
        analyzer: DenuvoTicketAnalyzer,
        test_binaries_dir: Path,
    ) -> None:
        """REGRESSION: Wrapper analysis identifies hooked exports.

        Validates that Steam API wrapper analysis continues to identify
        which exports have been hooked by Denuvo protection.
        """
        steam_dlls = list(test_binaries_dir.rglob("steam_api*.dll"))

        for dll_path in steam_dlls:
            wrapper = analyzer.analyze_steam_api_wrapper(dll_path)

            if wrapper and wrapper.is_wrapper:
                if len(wrapper.hooked_exports) > 0:
                    for export in wrapper.hooked_exports:
                        assert isinstance(export, str)
                        assert len(export) > 0


class RegressionErrorHandling:
    """Regression tests for error handling and edge cases."""

    def test_regression_analyze_nonexistent_binary(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """REGRESSION: Analyzer handles nonexistent file gracefully.

        Validates that the analyzer properly handles missing files
        without crashing or raising exceptions.
        """
        result = analyzer.analyze_binary("/nonexistent/path/to/binary.exe")

        assert result is None

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_analyze_invalid_binary(self, analyzer: DenuvoTicketAnalyzer, tmp_path: Path) -> None:
        """REGRESSION: Analyzer handles invalid binary format gracefully.

        Validates that the analyzer properly handles malformed or
        non-PE files without crashing.
        """
        invalid_binary = tmp_path / "invalid.exe"
        invalid_binary.write_bytes(b"This is not a valid PE file")

        result = analyzer.analyze_binary(invalid_binary)

        assert result is None

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_analyze_empty_binary(self, analyzer: DenuvoTicketAnalyzer, tmp_path: Path) -> None:
        """REGRESSION: Analyzer handles empty file gracefully.

        Validates that the analyzer properly handles empty files
        without crashing.
        """
        empty_binary = tmp_path / "empty.exe"
        empty_binary.write_bytes(b"")

        result = analyzer.analyze_binary(empty_binary)

        assert result is None


class RegressionPerformance:
    """Regression tests for analysis performance."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    @pytest.mark.benchmark
    def test_regression_analysis_completes_within_timeout(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Analysis completes within acceptable timeframe.

        Validates that binary analysis performance has not regressed
        and completes within expected time limits.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        import time

        for binary_path in denuvo_binaries:
            if binary_path.stat().st_size < 1_000_000:
                continue

            start_time = time.perf_counter()
            result = analyzer.analyze_binary(binary_path)
            elapsed = time.perf_counter() - start_time

            if result:
                assert elapsed < 60.0, f"Analysis took {elapsed:.2f}s, expected < 60s - performance regression"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    @pytest.mark.benchmark
    def test_regression_trigger_detection_performance(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Trigger detection completes within timeout.

        Validates that activation trigger detection performance has not
        regressed and completes within expected time limits.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        import time

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            start_time = time.perf_counter()
            triggers = analyzer.detect_activation_triggers(binary)
            elapsed = time.perf_counter() - start_time

            if triggers:
                assert elapsed < 30.0, f"Trigger detection took {elapsed:.2f}s - performance regression"

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    @pytest.mark.benchmark
    def test_regression_integrity_detection_performance(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Integrity check detection completes within timeout.

        Validates that integrity check detection performance has not
        regressed and completes within expected time limits.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        import time

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            start_time = time.perf_counter()
            checks = analyzer.detect_integrity_checks(binary)
            elapsed = time.perf_counter() - start_time

            if checks:
                assert elapsed < 30.0, f"Integrity detection took {elapsed:.2f}s - performance regression"


class RegressionConsistency:
    """Regression tests for detection consistency."""

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_multiple_analysis_consistent_results(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Multiple analyses produce consistent results.

        Validates that running analysis multiple times on the same
        binary produces consistent detection results.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            result1 = analyzer.analyze_binary(binary_path)
            result2 = analyzer.analyze_binary(binary_path)

            if result1 and result2:
                assert result1.version == result2.version
                assert len(result1.triggers) == len(result2.triggers)
                assert len(result1.integrity_checks) == len(result2.integrity_checks)
                assert len(result1.timing_checks) == len(result2.timing_checks)
                assert result1.protection_density == result2.protection_density
                assert result1.obfuscation_level == result2.obfuscation_level

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_trigger_detection_deterministic(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Trigger detection is deterministic.

        Validates that activation trigger detection produces identical
        results across multiple runs on the same binary.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            triggers1 = analyzer.detect_activation_triggers(binary)
            triggers2 = analyzer.detect_activation_triggers(binary)

            assert len(triggers1) == len(triggers2)

            if triggers1:
                for t1, t2 in zip(triggers1, triggers2):
                    assert t1.address == t2.address
                    assert t1.type == t2.type
                    assert t1.confidence == t2.confidence

    @pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required")
    def test_regression_integrity_detection_deterministic(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_binaries: list[Path],
    ) -> None:
        """REGRESSION: Integrity check detection is deterministic.

        Validates that integrity check detection produces identical
        results across multiple runs on the same binary.
        """
        if not denuvo_binaries:
            pytest.skip("No Denuvo-protected binaries found")

        for binary_path in denuvo_binaries:
            if not is_likely_denuvo_protected(binary_path):
                continue

            binary = lief.parse(str(binary_path))
            if not binary:
                continue

            checks1 = analyzer.detect_integrity_checks(binary)
            checks2 = analyzer.detect_integrity_checks(binary)

            assert len(checks1) == len(checks2)

            if checks1:
                for c1, c2 in zip(checks1, checks2):
                    assert c1.address == c2.address
                    assert c1.type == c2.type
                    assert c1.algorithm == c2.algorithm
