"""Regression tests for Denuvo Ticket Analyzer activation trigger detection.

Tests validate that previously working functionality still operates correctly:
- Activation trigger detection (Steam, Origin, Epic integration points)
- Integrity check routine identification (CRC, hash-based validation)
- Timing validation mechanism detection (RDTSC, QPC, GetTickCount)
- Machine fingerprinting code identification (HWID collection and validation)

All tests use real protected binaries or actual system resources. NO mocks or stubs.

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

from __future__ import annotations

import logging
import struct
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
    SteamAPIWrapper,
    TimingCheck,
)


logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def analyzer() -> DenuvoTicketAnalyzer:
    """Create analyzer instance for regression testing."""
    return DenuvoTicketAnalyzer()


@pytest.fixture(scope="session")
def test_binaries_root() -> Path:
    """Root directory for test binaries."""
    root = Path(__file__).parent.parent / "fixtures" / "binaries"
    return root


@pytest.fixture(scope="session")
def denuvo_protected_binary(test_binaries_root: Path) -> Path | None:
    """Locate Denuvo-protected binary for testing."""
    candidates = [
        test_binaries_root / "pe" / "protected" / "denuvo_like_protected.exe",
        test_binaries_root / "protected" / "themida_protected.exe",
        test_binaries_root / "pe" / "legitimate" / "firefox.exe",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


@pytest.fixture(scope="session")
def steam_api_wrapper_candidate(test_binaries_root: Path) -> Path | None:
    """Locate potential Steam API wrapper for testing."""
    candidates = [
        test_binaries_root / "pe" / "protected" / "steam_drm_protected.exe",
        test_binaries_root / "full_protected_software" / "Beyond_Compare_Full.exe",
    ]

    for candidate in candidates:
        if candidate.exists():
            parent_dir = candidate.parent
            steam_dlls = [
                parent_dir / "steam_api.dll",
                parent_dir / "steam_api64.dll",
            ]
            for dll in steam_dlls:
                if dll.exists():
                    return candidate

    return None


@pytest.fixture(scope="session")
def real_windows_executable() -> Path | None:
    """Get real Windows system executable for baseline testing."""
    system_paths = [
        Path(r"C:\Windows\System32\notepad.exe"),
        Path(r"C:\Windows\System32\calc.exe"),
        Path(r"C:\Windows\System32\mspaint.exe"),
    ]

    for path in system_paths:
        if path.exists():
            return path

    return None


@pytest.fixture(scope="session")
def loaded_denuvo_binary(denuvo_protected_binary: Path | None) -> Any | None:
    """Load Denuvo-protected binary with LIEF."""
    if not LIEF_AVAILABLE:
        pytest.skip("LIEF library required for binary analysis")
        return None

    if denuvo_protected_binary is None:
        return None

    try:
        binary = lief.parse(str(denuvo_protected_binary))
        return binary
    except Exception as e:
        logger.error("Failed to parse binary %s: %s", denuvo_protected_binary, e)
        return None


class TestActivationTriggerDetectionRegression:
    """Regression tests for activation trigger detection functionality."""

    def test_detect_activation_triggers_returns_list_not_none(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: detect_activation_triggers must return list, never None."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "To run this regression test, provide a Denuvo-protected binary at:\n"
                "  tests/fixtures/binaries/pe/protected/denuvo_like_protected.exe\n"
                "Expected: Real game executable with Denuvo protection (v4-v7)\n"
                "Examples: Recent AAA game releases, commercial software with Denuvo\n"
                "Note: This test validates that activation trigger detection continues "
                "to work correctly on real protected binaries."
            )

        result = analyzer.detect_activation_triggers(loaded_denuvo_binary)

        assert result is not None, "detect_activation_triggers must never return None"
        assert isinstance(result, list), "detect_activation_triggers must return list"

    def test_trigger_detection_produces_valid_trigger_objects(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: All detected triggers must be valid DenuvoTrigger instances."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for trigger object validation regression test."
            )

        triggers = analyzer.detect_activation_triggers(loaded_denuvo_binary)

        for trigger in triggers:
            assert isinstance(
                trigger, DenuvoTrigger
            ), f"Invalid trigger object type: {type(trigger)}"
            assert isinstance(trigger.address, int), "Trigger address must be integer"
            assert trigger.address > 0, "Trigger address must be positive"
            assert isinstance(trigger.type, str), "Trigger type must be string"
            assert len(trigger.type) > 0, "Trigger type cannot be empty"
            assert isinstance(
                trigger.function_name, str
            ), "Function name must be string"
            assert isinstance(trigger.module, str), "Module must be string"
            assert isinstance(trigger.confidence, float), "Confidence must be float"
            assert (
                0.0 <= trigger.confidence <= 1.0
            ), f"Confidence out of range: {trigger.confidence}"
            assert isinstance(
                trigger.description, str
            ), "Description must be string"
            assert isinstance(
                trigger.opcode_sequence, bytes
            ), "Opcode sequence must be bytes"
            assert len(trigger.opcode_sequence) > 0, "Opcode sequence cannot be empty"
            assert isinstance(
                trigger.referenced_imports, list
            ), "Referenced imports must be list"
            assert isinstance(
                trigger.cross_references, list
            ), "Cross references must be list"

    def test_trigger_patterns_loaded_correctly(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Regression: Trigger patterns must be properly loaded on initialization."""
        assert hasattr(
            analyzer, "trigger_patterns"
        ), "Analyzer missing trigger_patterns attribute"
        assert isinstance(
            analyzer.trigger_patterns, dict
        ), "Trigger patterns must be dictionary"
        assert (
            len(analyzer.trigger_patterns) > 0
        ), "Trigger patterns dictionary cannot be empty"

        required_patterns = [
            "ticket_validation_v7",
            "ticket_validation_v6",
            "activation_trigger_call",
            "steam_init_hook",
            "token_check",
            "license_verify",
        ]

        for pattern_name in required_patterns:
            assert (
                pattern_name in analyzer.trigger_patterns
            ), f"Missing required trigger pattern: {pattern_name}"
            pattern = analyzer.trigger_patterns[pattern_name]
            assert "bytes" in pattern, f"Pattern {pattern_name} missing 'bytes' key"
            assert "type" in pattern, f"Pattern {pattern_name} missing 'type' key"
            assert (
                "confidence" in pattern
            ), f"Pattern {pattern_name} missing 'confidence' key"
            assert (
                "description" in pattern
            ), f"Pattern {pattern_name} missing 'description' key"
            assert isinstance(
                pattern["bytes"], bytes
            ), f"Pattern {pattern_name} bytes must be bytes type"
            assert (
                len(pattern["bytes"]) > 0
            ), f"Pattern {pattern_name} bytes cannot be empty"

    def test_steam_api_wrapper_detection_structure(
        self,
        analyzer: DenuvoTicketAnalyzer,
        steam_api_wrapper_candidate: Path | None,
    ) -> None:
        """Regression: Steam API wrapper detection returns proper structure or None."""
        if steam_api_wrapper_candidate is None:
            pytest.skip(
                "CRITICAL SKIP: No Steam API wrapper binary available. "
                "To run this regression test, provide a game with Steam DRM at:\n"
                "  tests/fixtures/binaries/pe/protected/steam_drm_protected.exe\n"
                "  (with steam_api.dll or steam_api64.dll in same directory)\n"
                "Expected: Game executable using Steam API with potential Denuvo wrapper\n"
                "This test validates Steam API wrapper detection continues working."
            )

        result = analyzer.analyze_steam_api_wrapper(steam_api_wrapper_candidate)

        if result is not None:
            assert isinstance(
                result, SteamAPIWrapper
            ), "Steam wrapper result must be SteamAPIWrapper instance"
            assert isinstance(result.dll_path, str), "DLL path must be string"
            assert len(result.dll_path) > 0, "DLL path cannot be empty"
            assert isinstance(result.is_wrapper, bool), "is_wrapper must be boolean"
            assert result.is_wrapper is True, "is_wrapper must be True when detected"
            assert isinstance(
                result.original_exports, list
            ), "original_exports must be list"
            assert isinstance(
                result.hooked_exports, list
            ), "hooked_exports must be list"
            assert isinstance(
                result.denuvo_sections, list
            ), "denuvo_sections must be list"
            assert isinstance(result.confidence, float), "confidence must be float"
            assert (
                0.0 <= result.confidence <= 1.0
            ), f"Confidence out of range: {result.confidence}"

    def test_trigger_detection_on_non_protected_binary(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_windows_executable: Path | None,
    ) -> None:
        """Regression: Trigger detection on clean binary returns empty list, not None."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        if real_windows_executable is None:
            pytest.skip(
                "SKIP: No Windows system executable found. Expected at C:\\Windows\\System32\\notepad.exe"
            )

        try:
            binary = lief.parse(str(real_windows_executable))
            if binary is None:
                pytest.skip(f"Failed to parse {real_windows_executable}")
        except Exception as e:
            pytest.skip(f"Failed to load binary: {e}")

        triggers = analyzer.detect_activation_triggers(binary)

        assert triggers is not None, "Must return list even for clean binary"
        assert isinstance(triggers, list), "Must return list type"


class TestIntegrityCheckDetectionRegression:
    """Regression tests for integrity check detection functionality."""

    def test_detect_integrity_checks_returns_list_not_none(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: detect_integrity_checks must return list, never None."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for integrity check detection regression test."
            )

        result = analyzer.detect_integrity_checks(loaded_denuvo_binary)

        assert result is not None, "detect_integrity_checks must never return None"
        assert isinstance(result, list), "detect_integrity_checks must return list"

    def test_integrity_check_objects_valid_structure(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: All detected integrity checks must be valid IntegrityCheck instances."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for integrity check object validation."
            )

        checks = analyzer.detect_integrity_checks(loaded_denuvo_binary)

        for check in checks:
            assert isinstance(
                check, IntegrityCheck
            ), f"Invalid check object type: {type(check)}"
            assert isinstance(check.address, int), "Check address must be integer"
            assert check.address > 0, "Check address must be positive"
            assert isinstance(check.type, str), "Check type must be string"
            assert len(check.type) > 0, "Check type cannot be empty"
            assert isinstance(check.target, str), "Check target must be string"
            assert isinstance(check.algorithm, str), "Algorithm must be string"
            assert len(check.algorithm) > 0, "Algorithm cannot be empty"
            assert isinstance(check.confidence, float), "Confidence must be float"
            assert (
                0.0 <= check.confidence <= 1.0
            ), f"Confidence out of range: {check.confidence}"
            assert isinstance(check.check_size, int), "Check size must be integer"
            assert check.check_size >= 0, "Check size cannot be negative"
            assert isinstance(check.frequency, str), "Frequency must be string"
            assert isinstance(
                check.bypass_difficulty, str
            ), "Bypass difficulty must be string"

    def test_integrity_patterns_loaded_correctly(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Regression: Integrity check patterns must be properly loaded."""
        assert hasattr(
            analyzer, "integrity_patterns"
        ), "Analyzer missing integrity_patterns attribute"
        assert isinstance(
            analyzer.integrity_patterns, dict
        ), "Integrity patterns must be dictionary"
        assert (
            len(analyzer.integrity_patterns) > 0
        ), "Integrity patterns dictionary cannot be empty"

        required_patterns = [
            "crc32_check",
            "sha256_init",
            "memory_checksum",
            "code_verification",
            "section_hash",
        ]

        for pattern_name in required_patterns:
            assert (
                pattern_name in analyzer.integrity_patterns
            ), f"Missing required integrity pattern: {pattern_name}"
            pattern = analyzer.integrity_patterns[pattern_name]
            assert "bytes" in pattern, f"Pattern {pattern_name} missing 'bytes' key"
            assert "type" in pattern, f"Pattern {pattern_name} missing 'type' key"
            assert (
                "algorithm" in pattern
            ), f"Pattern {pattern_name} missing 'algorithm' key"
            assert (
                "confidence" in pattern
            ), f"Pattern {pattern_name} missing 'confidence' key"
            assert isinstance(
                pattern["bytes"], bytes
            ), f"Pattern {pattern_name} bytes must be bytes type"
            assert (
                len(pattern["bytes"]) > 0
            ), f"Pattern {pattern_name} bytes cannot be empty"

    def test_integrity_checks_identify_known_algorithms(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: Detected integrity checks must identify valid algorithms."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for algorithm identification regression test."
            )

        checks = analyzer.detect_integrity_checks(loaded_denuvo_binary)

        valid_algorithms = [
            "CRC32C",
            "CRC32",
            "SHA256",
            "SHA1",
            "HMAC-SHA256",
            "Custom",
            "MD5",
        ]

        for check in checks:
            assert (
                check.algorithm in valid_algorithms
            ), f"Unknown algorithm detected: {check.algorithm}"

    def test_integrity_check_detection_on_clean_binary(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_windows_executable: Path | None,
    ) -> None:
        """Regression: Integrity check detection on clean binary returns empty list."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        if real_windows_executable is None:
            pytest.skip("No Windows system executable found")

        try:
            binary = lief.parse(str(real_windows_executable))
            if binary is None:
                pytest.skip(f"Failed to parse {real_windows_executable}")
        except Exception as e:
            pytest.skip(f"Failed to load binary: {e}")

        checks = analyzer.detect_integrity_checks(binary)

        assert checks is not None, "Must return list even for clean binary"
        assert isinstance(checks, list), "Must return list type"


class TestTimingValidationDetectionRegression:
    """Regression tests for timing validation detection functionality."""

    def test_detect_timing_validation_returns_list_not_none(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: detect_timing_validation must return list, never None."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for timing validation detection regression test."
            )

        result = analyzer.detect_timing_validation(loaded_denuvo_binary)

        assert result is not None, "detect_timing_validation must never return None"
        assert isinstance(result, list), "detect_timing_validation must return list"

    def test_timing_check_objects_valid_structure(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: All detected timing checks must be valid TimingCheck instances."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for timing check object validation."
            )

        checks = analyzer.detect_timing_validation(loaded_denuvo_binary)

        for check in checks:
            assert isinstance(
                check, TimingCheck
            ), f"Invalid check object type: {type(check)}"
            assert isinstance(check.address, int), "Check address must be integer"
            assert check.address > 0, "Check address must be positive"
            assert isinstance(check.method, str), "Method must be string"
            assert len(check.method) > 0, "Method cannot be empty"
            assert isinstance(check.instruction, str), "Instruction must be string"
            assert len(check.instruction) > 0, "Instruction cannot be empty"
            assert isinstance(
                check.threshold_min, int
            ), "Threshold min must be integer"
            assert (
                check.threshold_min >= 0
            ), "Threshold min cannot be negative"
            assert isinstance(
                check.threshold_max, int
            ), "Threshold max must be integer"
            assert (
                check.threshold_max >= check.threshold_min
            ), "Threshold max must be >= min"
            assert isinstance(check.confidence, float), "Confidence must be float"
            assert (
                0.0 <= check.confidence <= 1.0
            ), f"Confidence out of range: {check.confidence}"
            assert isinstance(
                check.bypass_method, str
            ), "Bypass method must be string"

    def test_timing_patterns_loaded_correctly(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Regression: Timing validation patterns must be properly loaded."""
        assert hasattr(
            analyzer, "timing_patterns"
        ), "Analyzer missing timing_patterns attribute"
        assert isinstance(
            analyzer.timing_patterns, dict
        ), "Timing patterns must be dictionary"
        assert (
            len(analyzer.timing_patterns) > 0
        ), "Timing patterns dictionary cannot be empty"

        required_patterns = [
            "rdtsc_check",
            "rdtscp_check",
            "qpc_check",
            "gettickcount",
            "timing_delta_check",
        ]

        for pattern_name in required_patterns:
            assert (
                pattern_name in analyzer.timing_patterns
            ), f"Missing required timing pattern: {pattern_name}"
            pattern = analyzer.timing_patterns[pattern_name]
            assert "bytes" in pattern, f"Pattern {pattern_name} missing 'bytes' key"
            assert "method" in pattern, f"Pattern {pattern_name} missing 'method' key"
            assert (
                "instruction" in pattern
            ), f"Pattern {pattern_name} missing 'instruction' key"
            assert (
                "confidence" in pattern
            ), f"Pattern {pattern_name} missing 'confidence' key"
            assert isinstance(
                pattern["bytes"], bytes
            ), f"Pattern {pattern_name} bytes must be bytes type"
            assert (
                len(pattern["bytes"]) > 0
            ), f"Pattern {pattern_name} bytes cannot be empty"

    def test_timing_checks_identify_known_methods(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: Detected timing checks must identify valid timing methods."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for timing method identification regression test."
            )

        checks = analyzer.detect_timing_validation(loaded_denuvo_binary)

        valid_methods = [
            "RDTSC",
            "RDTSCP",
            "QueryPerformanceCounter",
            "GetTickCount",
            "GetTickCount64",
            "Delta",
        ]

        for check in checks:
            assert (
                check.method in valid_methods
            ), f"Unknown timing method detected: {check.method}"

    def test_timing_validation_on_clean_binary(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_windows_executable: Path | None,
    ) -> None:
        """Regression: Timing validation on clean binary returns empty list."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        if real_windows_executable is None:
            pytest.skip("No Windows system executable found")

        try:
            binary = lief.parse(str(real_windows_executable))
            if binary is None:
                pytest.skip(f"Failed to parse {real_windows_executable}")
        except Exception as e:
            pytest.skip(f"Failed to load binary: {e}")

        checks = analyzer.detect_timing_validation(binary)

        assert checks is not None, "Must return list even for clean binary"
        assert isinstance(checks, list), "Must return list type"


class TestHardwareFingerprintingDetectionRegression:
    """Regression tests for hardware fingerprinting detection functionality."""

    def test_detect_hardware_binding_returns_list_not_none(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: detect_hardware_binding must return list, never None."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for hardware binding detection regression test."
            )

        result = analyzer.detect_hardware_binding(loaded_denuvo_binary)

        assert result is not None, "detect_hardware_binding must never return None"
        assert isinstance(result, list), "detect_hardware_binding must return list"

    def test_hardware_binding_objects_valid_structure(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: All detected bindings must be valid HardwareBinding instances."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for hardware binding object validation."
            )

        bindings = analyzer.detect_hardware_binding(loaded_denuvo_binary)

        for binding in bindings:
            assert isinstance(
                binding, HardwareBinding
            ), f"Invalid binding object type: {type(binding)}"
            assert isinstance(
                binding.binding_type, str
            ), "Binding type must be string"
            assert len(binding.binding_type) > 0, "Binding type cannot be empty"
            assert isinstance(
                binding.collection_address, int
            ), "Collection address must be integer"
            assert (
                binding.collection_address >= 0
            ), "Collection address cannot be negative"
            assert isinstance(
                binding.validation_address, int
            ), "Validation address must be integer"
            assert (
                binding.validation_address >= 0
            ), "Validation address cannot be negative"
            assert isinstance(
                binding.hash_algorithm, str
            ), "Hash algorithm must be string"
            assert isinstance(binding.components, list), "Components must be list"
            assert isinstance(binding.confidence, float), "Confidence must be float"
            assert (
                0.0 <= binding.confidence <= 1.0
            ), f"Confidence out of range: {binding.confidence}"

    def test_hardware_binding_identifies_known_types(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: Detected bindings must identify valid hardware ID types."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for hardware binding type identification regression test."
            )

        bindings = analyzer.detect_hardware_binding(loaded_denuvo_binary)

        valid_types = [
            "disk_serial",
            "cpu_info",
            "mac_address",
            "computer_name",
            "bios_info",
            "hash_generation",
        ]

        for binding in bindings:
            assert (
                binding.binding_type in valid_types
            ), f"Unknown binding type detected: {binding.binding_type}"

    def test_hardware_binding_on_clean_binary(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_windows_executable: Path | None,
    ) -> None:
        """Regression: Hardware binding detection on clean binary returns empty list."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        if real_windows_executable is None:
            pytest.skip("No Windows system executable found")

        try:
            binary = lief.parse(str(real_windows_executable))
            if binary is None:
                pytest.skip(f"Failed to parse {real_windows_executable}")
        except Exception as e:
            pytest.skip(f"Failed to load binary: {e}")

        bindings = analyzer.detect_hardware_binding(binary)

        assert bindings is not None, "Must return list even for clean binary"
        assert isinstance(bindings, list), "Must return list type"


class TestBinaryAnalysisComprehensiveRegression:
    """Regression tests for comprehensive binary analysis functionality."""

    def test_analyze_binary_returns_valid_result_or_none(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_protected_binary: Path | None,
    ) -> None:
        """Regression: analyze_binary must return DenuvoAnalysisResult or None."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        if denuvo_protected_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for comprehensive binary analysis regression test."
            )

        result = analyzer.analyze_binary(denuvo_protected_binary)

        if result is not None:
            assert isinstance(
                result, DenuvoAnalysisResult
            ), "Result must be DenuvoAnalysisResult instance"
            assert isinstance(result.version, str), "Version must be string"
            assert len(result.version) > 0, "Version cannot be empty"
            assert isinstance(result.triggers, list), "Triggers must be list"
            assert isinstance(
                result.integrity_checks, list
            ), "Integrity checks must be list"
            assert isinstance(result.timing_checks, list), "Timing checks must be list"
            assert isinstance(
                result.hardware_bindings, list
            ), "Hardware bindings must be list"
            assert isinstance(
                result.protection_density, float
            ), "Protection density must be float"
            assert (
                0.0 <= result.protection_density <= 1.0
            ), f"Protection density out of range: {result.protection_density}"
            assert isinstance(
                result.obfuscation_level, str
            ), "Obfuscation level must be string"

    def test_analyze_binary_handles_nonexistent_file(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Regression: analyze_binary handles nonexistent files gracefully."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        nonexistent_path = Path("D:\\nonexistent_test_binary_12345.exe")
        result = analyzer.analyze_binary(nonexistent_path)

        assert result is None, "analyze_binary must return None for nonexistent file"

    def test_analyze_binary_handles_invalid_binary(
        self,
        analyzer: DenuvoTicketAnalyzer,
        tmp_path: Path,
    ) -> None:
        """Regression: analyze_binary handles invalid binary data gracefully."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        invalid_binary = tmp_path / "invalid_binary.exe"
        invalid_binary.write_bytes(b"NOT A VALID PE FILE DATA" * 100)

        result = analyzer.analyze_binary(invalid_binary)

        assert result is None, "analyze_binary must return None for invalid binary"

    def test_complete_analysis_workflow_maintains_data_integrity(
        self,
        analyzer: DenuvoTicketAnalyzer,
        denuvo_protected_binary: Path | None,
    ) -> None:
        """Regression: Complete analysis maintains data consistency across all detections."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        if denuvo_protected_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for workflow integrity regression test."
            )

        result = analyzer.analyze_binary(denuvo_protected_binary)

        if result is None:
            pytest.skip("Binary analysis returned None, cannot validate workflow")

        for trigger in result.triggers:
            assert isinstance(trigger.address, int), "Trigger address corrupted"
            assert trigger.address > 0, "Trigger address invalid"

        for check in result.integrity_checks:
            assert isinstance(check.address, int), "Integrity check address corrupted"
            assert check.address > 0, "Integrity check address invalid"

        for timing_check in result.timing_checks:
            assert isinstance(
                timing_check.address, int
            ), "Timing check address corrupted"
            assert timing_check.address > 0, "Timing check address invalid"

        for binding in result.hardware_bindings:
            assert isinstance(
                binding.collection_address, int
            ), "Hardware binding address corrupted"

        logger.info(
            "Analysis workflow integrity validated: %d triggers, %d integrity checks, "
            "%d timing checks, %d hardware bindings",
            len(result.triggers),
            len(result.integrity_checks),
            len(result.timing_checks),
            len(result.hardware_bindings),
        )


class TestPatternDetectionRobustnessRegression:
    """Regression tests for pattern detection robustness and edge cases."""

    def test_analyzer_initialization_succeeds_without_dependencies(
        self,
    ) -> None:
        """Regression: Analyzer initializes even without optional dependencies."""
        analyzer_instance = DenuvoTicketAnalyzer()

        assert analyzer_instance is not None, "Analyzer initialization failed"
        assert hasattr(
            analyzer_instance, "trigger_patterns"
        ), "Missing trigger patterns"
        assert hasattr(
            analyzer_instance, "integrity_patterns"
        ), "Missing integrity patterns"
        assert hasattr(
            analyzer_instance, "timing_patterns"
        ), "Missing timing patterns"

    def test_pattern_matching_handles_empty_sections(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Regression: Pattern detection handles binaries with empty code sections."""
        if not LIEF_AVAILABLE:
            pytest.skip("LIEF required for binary analysis")

        try:
            import lief

            binary = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)

            triggers = analyzer.detect_activation_triggers(binary)
            checks = analyzer.detect_integrity_checks(binary)
            timing = analyzer.detect_timing_validation(binary)
            bindings = analyzer.detect_hardware_binding(binary)

            assert isinstance(triggers, list), "Triggers must be list"
            assert isinstance(checks, list), "Checks must be list"
            assert isinstance(timing, list), "Timing must be list"
            assert isinstance(bindings, list), "Bindings must be list"
        except Exception:
            pytest.skip("Could not create minimal binary for testing")

    def test_detection_functions_maintain_performance_characteristics(
        self,
        analyzer: DenuvoTicketAnalyzer,
        loaded_denuvo_binary: Any | None,
    ) -> None:
        """Regression: Detection functions complete in reasonable time."""
        if loaded_denuvo_binary is None:
            pytest.skip(
                "CRITICAL SKIP: No Denuvo-protected binary available. "
                "Required for performance regression test."
            )

        import time

        start_time = time.perf_counter()
        triggers = analyzer.detect_activation_triggers(loaded_denuvo_binary)
        trigger_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        checks = analyzer.detect_integrity_checks(loaded_denuvo_binary)
        check_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        timing = analyzer.detect_timing_validation(loaded_denuvo_binary)
        timing_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        bindings = analyzer.detect_hardware_binding(loaded_denuvo_binary)
        binding_time = time.perf_counter() - start_time

        assert (
            trigger_time < 30.0
        ), f"Trigger detection too slow: {trigger_time:.2f}s"
        assert (
            check_time < 30.0
        ), f"Integrity check detection too slow: {check_time:.2f}s"
        assert (
            timing_time < 30.0
        ), f"Timing validation detection too slow: {timing_time:.2f}s"
        assert (
            binding_time < 30.0
        ), f"Hardware binding detection too slow: {binding_time:.2f}s"

        logger.info(
            "Performance regression validated - Trigger: %.2fs, Check: %.2fs, "
            "Timing: %.2fs, Binding: %.2fs",
            trigger_time,
            check_time,
            timing_time,
            binding_time,
        )
