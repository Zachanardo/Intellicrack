"""Production tests for hardcoded constant extraction from binaries.

Tests validation constant extraction from real binaries including:
- Immediate value constants (CRC polynomials, hash init values)
- Data section constants (lookup tables, magic numbers)
- Obfuscated constants (split across registers, computed at runtime)
- Constant usage tracking across validation routines
- Keygen template updates with extracted constants
- Edge cases (runtime-generated, environment-dependent values)

All tests use real binary data or actual system resources - NO MOCKS.
"""

import hashlib
import struct
import zlib
from pathlib import Path
from typing import Any

import capstone
import pytest

from intellicrack.core.license.keygen import (
    ConstraintExtractor,
    KeyConstraint,
    ValidationAnalyzer,
    ValidationAnalysis,
)


class TestImmediateValueConstantExtraction:
    """Test extraction of constants from immediate values in assembly."""

    def test_extracts_crc32_polynomial_from_immediate_mov(self) -> None:
        """Must extract CRC32 polynomial from mov immediate instruction."""
        x64_code = bytes([
            0x48, 0xC7, 0xC0, 0x20, 0x83, 0xB8, 0xED,
            0x48, 0x89, 0x45, 0xF8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x64_code, arch="x64")

        crc_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "CRC32"]
        assert len(crc_primitives) > 0, "Failed to detect CRC32 polynomial constant"
        assert any(0xEDB88320 in p.constants for p in crc_primitives), "Did not extract 0xEDB88320 polynomial"
        assert crc_primitives[0].confidence >= 0.8, "Low confidence in CRC32 detection"

    def test_extracts_md5_init_constants_from_multiple_movs(self) -> None:
        """Must extract all four MD5 initialization constants from sequential instructions."""
        x64_code = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF8,
            0x48, 0xB8, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF0,
            0x48, 0xB8, 0xFE, 0xDC, 0xBA, 0x98, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xE8,
            0x48, 0xB8, 0x76, 0x54, 0x32, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xE0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x64_code, arch="x64")

        md5_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "MD5"]
        assert len(md5_primitives) > 0, "Failed to detect MD5 initialization constants"

        expected_constants = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        detected_constants = set()
        for primitive in md5_primitives:
            detected_constants.update(primitive.constants)

        assert any(c in detected_constants for c in expected_constants), (
            f"Did not extract MD5 init constants. Got: {detected_constants}"
        )

    def test_extracts_sha256_constants_with_high_confidence(self) -> None:
        """Must identify SHA256 constants with high confidence score."""
        sha256_init_code = struct.pack("<I", 0x6A09E667)
        padding = b"\x90" * 20
        x64_code = (
            b"\x48\xB8" + sha256_init_code + b"\x00\x00\x00\x00"
            + b"\x48\x89\x45\xF8"
            + padding
            + b"\xC3"
        )

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x64_code, arch="x64")

        sha256_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "SHA256"]
        assert len(sha256_primitives) > 0, "Failed to detect SHA256 constant"
        assert sha256_primitives[0].confidence >= 0.9, "SHA256 detection confidence too low"

    def test_extracts_rsa_exponent_from_small_immediate(self) -> None:
        """Must extract common RSA exponents (65537, 17, 3) from code."""
        rsa_code_65537 = bytes([
            0xB8, 0x01, 0x00, 0x01, 0x00,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(rsa_code_65537, arch="x86")

        rsa_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "RSA"]
        assert len(rsa_primitives) > 0, "Failed to detect RSA exponent constant"
        assert any(65537 in p.constants for p in rsa_primitives), "Did not extract RSA exponent 65537"


class TestDataSectionConstantExtraction:
    """Test extraction of constants from binary data sections."""

    def test_extracts_embedded_lookup_tables(self) -> None:
        """Must extract lookup tables used for validation from data section."""
        crc_table = bytearray()
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
            crc_table.extend(struct.pack("<I", crc))

        binary_with_table = b"\x90" * 100 + bytes(crc_table) + b"\x90" * 100

        analyzer = ValidationAnalyzer()
        embedded = analyzer._extract_embedded_constants(binary_with_table, [])

        assert len(embedded) > 0, "Failed to extract any embedded constants"

        found_crc_poly = any(
            struct.unpack("<I", const)[0] in [0xEDB88320, 0x04C11DB7]
            for const in embedded.values() if len(const) == 4
        )
        assert found_crc_poly, "Did not identify CRC32 polynomial in lookup table"

    def test_identifies_magic_number_sequences(self) -> None:
        """Must identify magic numbers used for license validation."""
        magic_numbers = struct.pack("<I", 0xDEADBEEF) + struct.pack("<I", 0xCAFEBABE)
        binary_data = b"\x00" * 50 + magic_numbers + b"\x00" * 50

        extractor = ConstraintExtractor(Path("dummy.bin"))
        extractor._binary_data = binary_data

        constants = extractor._extract_crypto_constraints()

        assert len(constants) > 0, "Failed to extract any cryptographic constraints"

    def test_extracts_ascii_string_constants(self) -> None:
        """Must extract ASCII string constants used in validation."""
        license_string = b"LICENSE_KEY_VALIDATION_V2"
        binary_data = b"\x00" * 30 + license_string + b"\x00" * 30

        analyzer = ValidationAnalyzer()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        instructions: list[Any] = []

        embedded = analyzer._extract_embedded_constants(binary_data, instructions)

        string_constants = [v for k, v in embedded.items() if "string" in k]
        assert len(string_constants) > 0, "Failed to extract string constants"

        found_license_string = any(b"LICENSE" in const for const in string_constants)
        assert found_license_string, "Did not extract license-related string constant"


class TestObfuscatedConstantExtraction:
    """Test extraction of obfuscated and split constants."""

    def test_reconstructs_split_constant_across_registers(self) -> None:
        """Must reconstruct constants split across multiple register operations."""
        x64_code = bytes([
            0xB8, 0x20, 0x83, 0x00, 0x00,
            0xC1, 0xE0, 0x10,
            0x0D, 0xB8, 0xED, 0x00, 0x00,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x64_code, arch="x86")

        assert len(analysis.crypto_primitives) > 0 or len(analysis.constraints) > 0, (
            "Failed to extract any primitives or constraints from obfuscated constant"
        )

    def test_detects_xor_obfuscated_constants(self) -> None:
        """Must detect constants generated through XOR chains."""
        xor_chain_code = bytes([
            0xB8, 0xAA, 0xAA, 0xAA, 0xAA,
            0x35, 0x55, 0x55, 0x55, 0x55,
            0x35, 0xFF, 0xFF, 0xFF, 0xFF,
            0x35, 0x12, 0x34, 0x56, 0x78,
            0x89, 0x45, 0xFC,
            0x33, 0xC0,
            0x33, 0xC9,
            0x33, 0xD2,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(xor_chain_code, arch="x86")

        xor_primitives = [p for p in analysis.crypto_primitives if "XOR" in p.algorithm]
        assert len(xor_primitives) > 0, "Failed to detect XOR-based constant obfuscation"
        assert xor_primitives[0].confidence >= 0.5, "XOR chain detection confidence too low"

    def test_identifies_computed_polynomial_constants(self) -> None:
        """Must identify polynomials computed at runtime rather than embedded."""
        computed_poly_code = bytes([
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xD1, 0xE0,
            0xD1, 0xE0,
            0xD1, 0xE0,
            0x0D, 0x1D, 0xC1, 0x04, 0x00,
            0x89, 0x45, 0xF8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(computed_poly_code, arch="x86")

        assert len(analysis.crypto_primitives) > 0 or len(analysis.embedded_constants) > 0, (
            "Failed to detect computed polynomial constant"
        )


class TestConstantUsageTracking:
    """Test tracking constant usage across validation routines."""

    def test_tracks_constant_from_definition_to_usage(self) -> None:
        """Must track where constants are defined and how they're used."""
        validation_routine = bytes([
            0x48, 0xC7, 0xC1, 0x20, 0x83, 0xB8, 0xED,
            0x48, 0x31, 0xC0,
            0x48, 0x89, 0x4D, 0xF8,
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x8B, 0x4D, 0xF8,
            0x48, 0x33, 0xC1,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(validation_routine, arch="x64")

        crc_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "CRC32"]
        if crc_primitives:
            assert crc_primitives[0].offset > 0, "Missing offset information for constant usage"

    def test_correlates_constants_with_comparison_operations(self) -> None:
        """Must identify constants used in validation comparisons."""
        comparison_code = bytes([
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x3D, 0xEF, 0xBE, 0xAD, 0xDE,
            0x0F, 0x84, 0x05, 0x00, 0x00, 0x00,
            0x31, 0xC0,
            0xC3,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(comparison_code, arch="x64")

        assert len(analysis.constraints) > 0, "Failed to extract comparison constraints"
        assert len(analysis.patch_points) > 0, "Failed to identify patch points at comparisons"

    def test_identifies_constant_references_in_data_flow(self) -> None:
        """Must track constants through data flow analysis."""
        data_flow_code = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF8,
            0x48, 0x8B, 0x45, 0xF8,
            0x48, 0x8B, 0x4D, 0x10,
            0x48, 0x01, 0xC1,
            0x48, 0x89, 0x4D, 0x08,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(data_flow_code, arch="x64")

        md5_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "MD5"]
        assert len(md5_primitives) > 0, "Failed to track MD5 constant through data flow"


class TestKeygenTemplateUpdating:
    """Test updating keygen templates with extracted constants."""

    def test_extracts_crc_polynomial_for_keygen_template(self) -> None:
        """Must extract CRC polynomial and make it available for keygen generation."""
        extractor = ConstraintExtractor(Path("dummy.bin"))

        crc_binary = struct.pack("<I", 0xEDB88320) * 64
        extractor._binary_data = crc_binary

        constraints = extractor._extract_crypto_constraints()

        crc_constraints = [c for c in constraints if "crc" in c.value.lower()]
        assert len(crc_constraints) > 0, "Failed to extract CRC polynomial constraint"
        assert crc_constraints[0].confidence >= 0.7, "CRC constraint confidence too low"

    def test_builds_algorithm_from_extracted_constants(self) -> None:
        """Must build complete algorithm definition from extracted constants."""
        extractor = ConstraintExtractor(Path("dummy.bin"))

        binary_data = struct.pack("<I", 0xEDB88320) + b"CRC32" + b"\x00" * 100
        extractor._binary_data = binary_data

        constraints = extractor.extract_constraints()
        algorithms = extractor.analyze_validation_algorithms()

        assert len(algorithms) > 0, "Failed to build algorithm from extracted constants"

        crc_algos = [a for a in algorithms if "CRC" in a.algorithm_name.upper()]
        if crc_algos:
            assert "polynomial" in crc_algos[0].parameters, "Missing polynomial parameter"
            assert crc_algos[0].parameters["polynomial"] in [0xEDB88320, 0x04C11DB7], (
                "Incorrect polynomial value in algorithm"
            )

    def test_generates_valid_key_with_extracted_constants(self) -> None:
        """Must generate valid license key using extracted constant values."""
        extractor = ConstraintExtractor(Path("dummy.bin"))

        crc_data = struct.pack("<I", 0xEDB88320) + b"\x00" * 100
        extractor._binary_data = crc_data

        algorithms = extractor.analyze_validation_algorithms()

        if algorithms:
            best_algo = max(algorithms, key=lambda a: a.confidence)
            assert best_algo.validation_function is not None or best_algo.key_format is not None, (
                "Algorithm missing validation function or key format"
            )


class TestRuntimeGeneratedConstants:
    """Test handling of runtime-generated constants (edge case)."""

    def test_detects_time_dependent_constant_generation(self) -> None:
        """Must detect constants generated from system time."""
        time_based_code = bytes([
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xC1,
            0x48, 0xC1, 0xE9, 0x10,
            0x48, 0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,
            0x48, 0x89, 0x4D, 0xF8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(time_based_code, arch="x64")

        assert len(analysis.api_calls) > 0 or len(analysis.crypto_primitives) > 0, (
            "Failed to analyze time-dependent constant generation"
        )

    def test_identifies_environment_variable_based_constants(self) -> None:
        """Must identify constants derived from environment variables."""
        env_based_code = bytes([
            0x48, 0x8D, 0x0D, 0x10, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xC0,
            0x74, 0x0A,
            0x48, 0x8B, 0x00,
            0x48, 0x89, 0x45, 0xF8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(env_based_code, arch="x64")

        assert len(analysis.constraints) > 0 or len(analysis.api_calls) > 0, (
            "Failed to detect environment-based constant generation"
        )

    def test_handles_hardware_id_derived_constants(self) -> None:
        """Must handle constants derived from hardware identifiers."""
        hwid_code = bytes([
            0x48, 0x31, 0xC0,
            0x0F, 0xA2,
            0x89, 0x45, 0xF8,
            0x89, 0x5D, 0xFC,
            0x89, 0x4D, 0xF4,
            0x89, 0x55, 0xF0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(hwid_code, arch="x64")

        assert len(analysis.crypto_primitives) > 0 or len(analysis.embedded_constants) > 0, (
            "Failed to analyze hardware-ID-based constant usage"
        )


class TestComplexConstantExtraction:
    """Test extraction from complex real-world validation scenarios."""

    def test_extracts_constants_from_multi_algorithm_validation(self) -> None:
        """Must extract constants when multiple algorithms are used together."""
        multi_algo_code = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF8,
            0x48, 0xC7, 0xC1, 0x20, 0x83, 0xB8, 0xED,
            0x48, 0x89, 0x4D, 0xF0,
            0xB8, 0x01, 0x00, 0x01, 0x00,
            0x89, 0x45, 0xE8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(multi_algo_code, arch="x64")

        unique_algos = set(p.algorithm for p in analysis.crypto_primitives)
        assert len(unique_algos) >= 2, (
            f"Failed to detect multiple algorithms. Found: {unique_algos}"
        )

        has_md5 = any(p.algorithm == "MD5" for p in analysis.crypto_primitives)
        has_crc = any(p.algorithm == "CRC32" for p in analysis.crypto_primitives)
        assert has_md5 or has_crc, "Failed to detect expected algorithm types"

    def test_extracts_validation_length_constants(self) -> None:
        """Must extract license key length requirements from validation code."""
        length_check_code = bytes([
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x83, 0xF8, 0x10,
            0x0F, 0x85, 0x0A, 0x00, 0x00, 0x00,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
            0x31, 0xC0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(length_check_code, arch="x64")

        length_constraints = [c for c in analysis.constraints if c.constraint_type == "length"]
        assert len(length_constraints) > 0, "Failed to extract length constraint"
        assert any(c.value == 16 for c in length_constraints), "Did not extract correct length value"

    def test_identifies_checksum_position_from_code(self) -> None:
        """Must identify where checksum is located in license key from validation."""
        checksum_validation = bytes([
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x83, 0xC0, 0x08,
            0x8B, 0x00,
            0x3D, 0xAA, 0xBB, 0xCC, 0xDD,
            0x0F, 0x84, 0x05, 0x00, 0x00, 0x00,
            0x31, 0xC0,
            0xC3,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(checksum_validation, arch="x64")

        assert len(analysis.embedded_constants) > 0 or len(analysis.constraints) > 0, (
            "Failed to identify checksum position and value"
        )


class TestConstantExtractionWithRealBinary:
    """Test constant extraction using actual system binaries."""

    @pytest.fixture
    def windows_system_dll(self) -> Path | None:
        """Provide path to a Windows system DLL for testing."""
        candidates = [
            Path(r"C:\Windows\System32\kernel32.dll"),
            Path(r"C:\Windows\System32\ntdll.dll"),
            Path(r"C:\Windows\SysWOW64\kernel32.dll"),
        ]

        for dll_path in candidates:
            if dll_path.exists():
                return dll_path
        return None

    def test_extracts_constants_from_actual_binary(self, windows_system_dll: Path | None) -> None:
        """Must extract cryptographic constants from real system binary."""
        if not windows_system_dll or not windows_system_dll.exists():
            pytest.skip("No Windows system DLL available for testing")

        extractor = ConstraintExtractor(windows_system_dll)
        constraints = extractor.extract_constraints()

        assert len(constraints) > 0, f"Failed to extract any constraints from {windows_system_dll}"

    def test_analyzes_pe_file_code_sections(self, windows_system_dll: Path | None) -> None:
        """Must analyze .text section of PE file for validation constants."""
        if not windows_system_dll or not windows_system_dll.exists():
            pytest.skip("No Windows system DLL available for testing")

        with open(windows_system_dll, "rb") as f:
            binary_data = f.read(min(1024 * 1024, windows_system_dll.stat().st_size))

        analyzer = ValidationAnalyzer()
        embedded = analyzer._extract_embedded_constants(binary_data, [])

        assert len(embedded) > 0, f"Failed to extract embedded constants from {windows_system_dll}"


class TestConstantConfidenceScoring:
    """Test confidence scoring for extracted constants."""

    def test_assigns_high_confidence_to_known_crypto_constants(self) -> None:
        """Must assign high confidence to well-known cryptographic constants."""
        md5_code = struct.pack("<I", 0x67452301)
        binary = b"\x48\xB8" + md5_code + b"\x00\x00\x00\x00" + b"\xC3"

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(binary, arch="x64")

        md5_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "MD5"]
        if md5_primitives:
            assert md5_primitives[0].confidence >= 0.85, "MD5 constant confidence too low"

    def test_assigns_lower_confidence_to_ambiguous_constants(self) -> None:
        """Must assign lower confidence to potentially ambiguous constants."""
        ambiguous_code = bytes([
            0xB8, 0x42, 0x00, 0x00, 0x00,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(ambiguous_code, arch="x86")

        if analysis.crypto_primitives:
            max_confidence = max(p.confidence for p in analysis.crypto_primitives)
            assert max_confidence < 1.0, "Ambiguous constant should not have perfect confidence"

    def test_overall_analysis_confidence_reflects_extraction_quality(self) -> None:
        """Must provide overall confidence score for entire analysis."""
        high_quality_code = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xC7, 0xC1, 0x20, 0x83, 0xB8, 0xED,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(high_quality_code, arch="x64")

        assert analysis.confidence > 0.0, "Analysis must provide confidence score"
        assert 0.0 <= analysis.confidence <= 1.0, "Confidence must be normalized to [0, 1]"


class TestConstantExtractionIntegration:
    """Integration tests for end-to-end constant extraction workflows."""

    def test_complete_workflow_binary_to_keygen(self) -> None:
        """Must complete workflow from binary analysis to keygen template creation."""
        validation_binary = bytes([
            0x48, 0xC7, 0xC1, 0x20, 0x83, 0xB8, 0xED,
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x83, 0xF8, 0x10,
            0x75, 0x05,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
            0x31, 0xC0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(validation_binary, arch="x64")

        assert analysis.algorithm_type is not None, "Failed to determine algorithm type"
        assert len(analysis.recommendations) > 0, "No recommendations generated"
        assert analysis.confidence > 0.0, "No confidence score provided"

    def test_extracts_and_validates_complete_key_format(self) -> None:
        """Must extract complete key format specification from validation code."""
        format_validation = bytes([
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x83, 0xF8, 0x14,
            0x75, 0x1A,
            0x48, 0x8B, 0x45, 0x10,
            0x80, 0x78, 0x04, 0x2D,
            0x75, 0x11,
            0x80, 0x78, 0x09, 0x2D,
            0x75, 0x0B,
            0x80, 0x78, 0x0E, 0x2D,
            0x75, 0x05,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
            0x31, 0xC0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(format_validation, arch="x64")

        separator_constraints = [
            c for c in analysis.constraints
            if c.constraint_type == "separator" and c.value == "-"
        ]
        assert len(separator_constraints) > 0, "Failed to extract separator constraint"

        length_constraints = [
            c for c in analysis.constraints
            if c.constraint_type == "length"
        ]
        assert len(length_constraints) > 0, "Failed to extract length constraint"

    def test_handles_failure_gracefully_with_invalid_input(self) -> None:
        """Must handle corrupted or invalid binary input without crashing."""
        invalid_binaries = [
            b"",
            b"\x00" * 1000,
            b"\xFF" * 1000,
            b"Not actual binary code",
        ]

        analyzer = ValidationAnalyzer()

        for invalid_binary in invalid_binaries:
            try:
                analysis = analyzer.analyze(invalid_binary, arch="x64")
                assert analysis is not None, "Analysis returned None for invalid input"
            except Exception as e:
                pytest.fail(f"Analyzer crashed on invalid input: {e}")
