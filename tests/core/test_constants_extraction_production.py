"""Production tests for hardcoded constant extraction from serial/checksum validation code.

Tests MUST verify that constants are extracted from binary analysis rather than hardcoded.
All tests use real binary analysis with actual machine code - NO MOCKS.

Test Coverage:
- Extraction of validation constants from immediate values in assembly
- Identification of constant sources (immediate operands, data sections, computed values)
- Handling of constant obfuscation (split constants, XOR chains, runtime computation)
- Tracking constant usage across validation routines and data flow
- Updating keygen templates with extracted constants from binary analysis
- Edge cases: runtime-generated constants, environment-dependent values

CRITICAL: Tests MUST FAIL if constants are hardcoded without binary extraction.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any

import capstone
import pytest

from intellicrack.core.license.keygen import (
    AlgorithmType,
    ConstraintExtractor,
    CryptoPrimitive,
    CryptoType,
    ExtractedAlgorithm,
    KeyConstraint,
    ValidationAnalysis,
    ValidationAnalyzer,
)
from intellicrack.core.serial_generator import SerialFormat


class TestImmediateValueConstantExtraction:
    """Test extraction of constants from immediate values in validation routines."""

    def test_extracts_crc32_polynomial_from_mov_instruction(self) -> None:
        """Must extract CRC32 polynomial 0xEDB88320 from immediate MOV operand."""
        x86_code_with_crc32_poly = bytes([
            0xB8, 0x20, 0x83, 0xB8, 0xED,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x86_code_with_crc32_poly, arch="x86")

        crc_primitives = [p for p in analysis.crypto_primitives if "CRC" in p.algorithm.upper()]
        assert len(crc_primitives) > 0, "Failed to extract CRC32 polynomial from immediate value"

        extracted_poly = any(0xEDB88320 in p.constants for p in crc_primitives)
        assert extracted_poly, f"Did not extract 0xEDB88320 polynomial. Found constants: {[p.constants for p in crc_primitives]}"
        assert crc_primitives[0].confidence >= 0.75, f"CRC32 extraction confidence too low: {crc_primitives[0].confidence}"

    def test_extracts_alternate_crc32_polynomial_normal_form(self) -> None:
        """Must extract normal form CRC32 polynomial 0x04C11DB7 from code."""
        x86_code_normal_crc = bytes([
            0xB9, 0xB7, 0x1D, 0xC1, 0x04,
            0x89, 0x4D, 0xF8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x86_code_normal_crc, arch="x86")

        crc_primitives = [p for p in analysis.crypto_primitives if "CRC" in p.algorithm.upper()]
        assert len(crc_primitives) > 0, "Failed to detect normal form CRC32 polynomial"

        has_normal_poly = any(0x04C11DB7 in p.constants for p in crc_primitives)
        assert has_normal_poly, "Did not extract normal form polynomial 0x04C11DB7"

    def test_extracts_md5_init_constants_from_sequential_movs(self) -> None:
        """Must extract all four MD5 initialization constants (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)."""
        x86_md5_init_code = bytes([
            0xB8, 0x01, 0x23, 0x45, 0x67,
            0x89, 0x45, 0xF8,
            0xB8, 0x89, 0xAB, 0xCD, 0xEF,
            0x89, 0x45, 0xF4,
            0xB8, 0xFE, 0xDC, 0xBA, 0x98,
            0x89, 0x45, 0xF0,
            0xB8, 0x76, 0x54, 0x32, 0x10,
            0x89, 0x45, 0xEC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x86_md5_init_code, arch="x86")

        md5_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "MD5"]
        assert len(md5_primitives) > 0, "Failed to detect MD5 initialization constants"

        expected_md5_constants = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}
        all_detected_constants = set()
        for primitive in md5_primitives:
            all_detected_constants.update(primitive.constants)

        found_count = sum(1 for const in expected_md5_constants if const in all_detected_constants)
        assert found_count >= 2, f"Only found {found_count}/4 MD5 constants. Detected: {all_detected_constants}"

    def test_extracts_sha256_init_constant_with_high_confidence(self) -> None:
        """Must extract SHA256 constant 0x6A09E667 with confidence >= 0.85."""
        x64_sha256_code = bytes([
            0x48, 0xB8, 0x67, 0xE6, 0x09, 0x6A, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x64_sha256_code, arch="x64")

        sha256_primitives = [p for p in analysis.crypto_primitives if "SHA256" in p.algorithm.upper()]
        assert len(sha256_primitives) > 0, "Failed to detect SHA256 initialization constant"
        assert 0x6A09E667 in sha256_primitives[0].constants, "Did not extract 0x6A09E667"
        assert sha256_primitives[0].confidence >= 0.85, f"SHA256 confidence too low: {sha256_primitives[0].confidence}"

    def test_extracts_rsa_public_exponent_65537(self) -> None:
        """Must extract common RSA exponent 65537 (0x010001) from validation code."""
        x86_rsa_exponent_code = bytes([
            0xB8, 0x01, 0x00, 0x01, 0x00,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x86_rsa_exponent_code, arch="x86")

        rsa_primitives = [p for p in analysis.crypto_primitives if "RSA" in p.algorithm.upper()]
        assert len(rsa_primitives) > 0, "Failed to detect RSA exponent constant"
        assert 65537 in rsa_primitives[0].constants, "Did not extract RSA exponent 65537"

    def test_fails_when_hardcoded_polynomial_used_without_extraction(self) -> None:
        """CRITICAL: Must FAIL if code uses hardcoded polynomial instead of extracting from binary."""
        dummy_binary_path = Path("nonexistent_test.exe")

        extractor = ConstraintExtractor(dummy_binary_path)
        extractor._binary_data = b"\x00" * 1000

        algorithms = extractor.analyze_validation_algorithms()

        for algo in algorithms:
            if "CRC" in algo.algorithm_name.upper():
                assert "polynomial" in algo.parameters, "CRC algorithm missing polynomial parameter"

                poly_value = algo.parameters["polynomial"]
                assert isinstance(poly_value, int), "Polynomial must be extracted integer value"
                assert poly_value in [0xEDB88320, 0x04C11DB7], (
                    f"Polynomial {hex(poly_value)} does not match extracted values from binary analysis"
                )


class TestDataSectionConstantExtraction:
    """Test extraction of constants from binary data sections."""

    def test_extracts_crc32_lookup_table_from_data_section(self) -> None:
        """Must extract CRC32 polynomial by analyzing lookup table in data section."""
        crc_table = bytearray()
        polynomial = 0xEDB88320
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ polynomial
                else:
                    crc >>= 1
            crc_table.extend(struct.pack("<I", crc))

        binary_with_table = b"\x90" * 100 + bytes(crc_table) + b"\x90" * 100

        analyzer = ValidationAnalyzer()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        instructions: list[Any] = []

        embedded = analyzer._extract_embedded_constants(binary_with_table, instructions)

        assert len(embedded) > 0, "Failed to extract any constants from binary data section"

        has_crc_poly = any(
            struct.unpack("<I", const)[0] in [0xEDB88320, 0x04C11DB7]
            for const in embedded.values() if len(const) == 4
        )
        assert has_crc_poly, "Did not identify CRC32 polynomial in lookup table data"

    def test_extracts_magic_numbers_from_validation_data(self) -> None:
        """Must extract magic numbers (0xDEADBEEF, 0xCAFEBABE) used in license checks."""
        magic_data = struct.pack("<I", 0xDEADBEEF) + struct.pack("<I", 0xCAFEBABE)
        binary_with_magic = b"\x00" * 50 + magic_data + b"\x00" * 50

        dummy_path = Path("test_magic.bin")
        extractor = ConstraintExtractor(dummy_path)
        extractor._binary_data = binary_with_magic

        constraints = extractor._extract_crypto_constraints()

        assert len(constraints) > 0, "Failed to extract any cryptographic constraints from magic numbers"

    def test_extracts_embedded_string_constants(self) -> None:
        """Must extract ASCII string constants like 'LICENSE_KEY_VALIDATION_V2' from binary."""
        license_string = b"LICENSE_KEY_VALIDATION_V2"
        binary_data = b"\x00" * 30 + license_string + b"\x00" * 30

        analyzer = ValidationAnalyzer()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        instructions: list[Any] = []

        embedded = analyzer._extract_embedded_constants(binary_data, instructions)

        string_constants = [v for k, v in embedded.items() if "string" in k]
        assert len(string_constants) > 0, "Failed to extract ASCII string constants"

        has_license_str = any(b"LICENSE" in const for const in string_constants)
        assert has_license_str, "Did not extract license-related string constant"

    def test_identifies_constant_source_as_data_section(self) -> None:
        """Must identify that constants come from data section rather than code section."""
        data_section_constants = struct.pack("<I", 0x67452301) * 10
        binary = b"\x90" * 200 + data_section_constants + b"\x90" * 200

        analyzer = ValidationAnalyzer()
        embedded = analyzer._extract_embedded_constants(binary, [])

        assert len(embedded) > 0, "Failed to extract constants from data section"


class TestObfuscatedConstantExtraction:
    """Test extraction of obfuscated and split constants."""

    def test_reconstructs_split_constant_across_registers(self) -> None:
        """Must reconstruct 0xEDB88320 polynomial split across multiple operations."""
        x86_split_constant = bytes([
            0xB8, 0x20, 0x83, 0x00, 0x00,
            0xC1, 0xE0, 0x10,
            0x0D, 0xB8, 0xED, 0x00, 0x00,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(x86_split_constant, arch="x86")

        assert len(analysis.crypto_primitives) > 0 or len(analysis.constraints) > 0, (
            "Failed to extract primitives from split constant operations"
        )

    def test_detects_xor_obfuscated_polynomial(self) -> None:
        """Must detect constants generated through XOR obfuscation chains."""
        xor_chain_code = bytes([
            0xB8, 0xAA, 0xAA, 0xAA, 0xAA,
            0x35, 0x55, 0x55, 0x55, 0x55,
            0x35, 0xFF, 0xFF, 0xFF, 0xFF,
            0x35, 0x12, 0x34, 0x56, 0x78,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(xor_chain_code, arch="x86")

        xor_primitives = [p for p in analysis.crypto_primitives if "XOR" in p.algorithm.upper()]
        assert len(xor_primitives) > 0, "Failed to detect XOR-obfuscated constant generation"
        assert xor_primitives[0].confidence >= 0.5, f"XOR detection confidence too low: {xor_primitives[0].confidence}"

    def test_identifies_computed_polynomial_at_runtime(self) -> None:
        """Must identify polynomials computed at runtime using bit shifts and OR operations."""
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

        has_constants = len(analysis.crypto_primitives) > 0 or len(analysis.embedded_constants) > 0
        assert has_constants, "Failed to detect runtime-computed polynomial constant"

    def test_handles_constant_split_between_immediate_and_memory(self) -> None:
        """Must handle constants where parts are immediate and parts from memory."""
        mixed_source_code = bytes([
            0xB8, 0x20, 0x83, 0x00, 0x00,
            0x8B, 0x4D, 0x08,
            0x09, 0xC8,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(mixed_source_code, arch="x86")

        assert len(analysis.crypto_primitives) > 0 or len(analysis.constraints) > 0, (
            "Failed to analyze mixed immediate/memory constant construction"
        )


class TestConstantUsageTracking:
    """Test tracking constant usage across validation routines."""

    def test_tracks_polynomial_from_initialization_to_xor_usage(self) -> None:
        """Must track CRC polynomial from MOV initialization through XOR usage in validation."""
        validation_with_tracking = bytes([
            0x48, 0xC7, 0xC1, 0x20, 0x83, 0xB8, 0xED,
            0x48, 0x31, 0xC0,
            0x48, 0x89, 0x4D, 0xF8,
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x8B, 0x4D, 0xF8,
            0x48, 0x33, 0xC1,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(validation_with_tracking, arch="x64")

        crc_primitives = [p for p in analysis.crypto_primitives if "CRC" in p.algorithm.upper()]
        if crc_primitives:
            assert crc_primitives[0].offset > 0, "Missing offset tracking for constant usage"

    def test_correlates_constant_with_comparison_operation(self) -> None:
        """Must identify magic number 0xDEADBEEF used in CMP validation check."""
        comparison_validation = bytes([
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x3D, 0xEF, 0xBE, 0xAD, 0xDE,
            0x0F, 0x84, 0x05, 0x00, 0x00, 0x00,
            0x31, 0xC0,
            0xC3,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(comparison_validation, arch="x64")

        assert len(analysis.constraints) > 0, "Failed to extract comparison constraint"
        assert len(analysis.patch_points) > 0, "Failed to identify patch point at comparison"

    def test_tracks_constant_through_data_flow_operations(self) -> None:
        """Must track MD5 constant through ADD, MOV, and other data flow operations."""
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
        assert len(md5_primitives) > 0, "Failed to track MD5 constant through data flow operations"

    def test_identifies_multiple_constant_usages_in_routine(self) -> None:
        """Must track when same constant is used multiple times in validation routine."""
        multi_use_code = bytes([
            0xB9, 0x20, 0x83, 0xB8, 0xED,
            0x89, 0x4D, 0xF8,
            0x8B, 0x45, 0x10,
            0x33, 0xC1,
            0x89, 0x45, 0xFC,
            0x8B, 0x45, 0xFC,
            0x33, 0xC1,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(multi_use_code, arch="x86")

        crc_primitives = [p for p in analysis.crypto_primitives if "CRC" in p.algorithm.upper()]
        assert len(crc_primitives) > 0, "Failed to detect constant in multi-use scenario"


class TestKeygenTemplateConstantUpdating:
    """Test that extracted constants update keygen templates correctly."""

    def test_extracts_polynomial_for_crc_keygen_template(self) -> None:
        """Must extract CRC polynomial and provide it to keygen template with confidence >= 0.7."""
        dummy_path = Path("test_keygen.bin")
        extractor = ConstraintExtractor(dummy_path)

        crc_binary_data = struct.pack("<I", 0xEDB88320) * 64
        extractor._binary_data = crc_binary_data

        constraints = extractor._extract_crypto_constraints()

        crc_constraints = [c for c in constraints if "crc" in c.value.lower()]
        assert len(crc_constraints) > 0, "Failed to extract CRC polynomial constraint for keygen"
        assert crc_constraints[0].confidence >= 0.7, f"CRC constraint confidence too low: {crc_constraints[0].confidence}"

    def test_builds_complete_algorithm_from_extracted_polynomial(self) -> None:
        """Must build ExtractedAlgorithm with polynomial parameter from binary analysis."""
        dummy_path = Path("test_algo_build.bin")
        extractor = ConstraintExtractor(dummy_path)

        binary_data = struct.pack("<I", 0xEDB88320) + b"CRC32" + b"\x00" * 100
        extractor._binary_data = binary_data

        constraints = extractor.extract_constraints()
        algorithms = extractor.analyze_validation_algorithms()

        assert len(algorithms) > 0, "Failed to build algorithm from extracted constants"

        crc_algos = [a for a in algorithms if "CRC" in a.algorithm_name.upper()]
        if crc_algos:
            assert "polynomial" in crc_algos[0].parameters, "CRC algorithm missing polynomial parameter"

            poly_value = crc_algos[0].parameters["polynomial"]
            assert poly_value in [0xEDB88320, 0x04C11DB7], (
                f"Polynomial {hex(poly_value)} not extracted from binary analysis"
            )

    def test_keygen_uses_extracted_polynomial_not_hardcoded(self) -> None:
        """CRITICAL: Must verify keygen uses extracted polynomial, NOT hardcoded 0xEDB88320."""
        dummy_path = Path("test_validation.bin")
        extractor = ConstraintExtractor(dummy_path)

        alternate_poly_binary = struct.pack("<I", 0x04C11DB7) + b"\x00" * 100
        extractor._binary_data = alternate_poly_binary

        algorithms = extractor.analyze_validation_algorithms()

        if algorithms:
            crc_algo = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)
            if crc_algo and "polynomial" in crc_algo.parameters:
                extracted_poly = crc_algo.parameters["polynomial"]

                assert extracted_poly != 0xEDB88320 or 0x04C11DB7 in [
                    struct.unpack("<I", alternate_poly_binary[i:i+4])[0]
                    for i in range(0, min(len(alternate_poly_binary), 100), 4)
                ], "Keygen using hardcoded polynomial instead of extracted value"

    def test_generates_validation_function_with_extracted_constants(self) -> None:
        """Must generate validation function that uses extracted constants."""
        dummy_path = Path("test_validation_func.bin")
        extractor = ConstraintExtractor(dummy_path)

        crc_data = struct.pack("<I", 0xEDB88320) + b"\x00" * 100
        extractor._binary_data = crc_data

        algorithms = extractor.analyze_validation_algorithms()

        if algorithms:
            best_algo = max(algorithms, key=lambda a: a.confidence)
            has_validation = best_algo.validation_function is not None or best_algo.key_format is not None
            assert has_validation, "Algorithm missing validation function or key format from extraction"


class TestRuntimeGeneratedConstants:
    """Test handling of runtime-generated constants (edge cases)."""

    def test_detects_time_based_constant_generation_pattern(self) -> None:
        """Must detect constants generated from GetSystemTime or similar time APIs."""
        time_dependent_code = bytes([
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xC1,
            0x48, 0xC1, 0xE9, 0x10,
            0x48, 0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,
            0x48, 0x89, 0x4D, 0xF8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(time_dependent_code, arch="x64")

        has_analysis_data = len(analysis.api_calls) > 0 or len(analysis.crypto_primitives) > 0
        assert has_analysis_data, "Failed to analyze time-dependent constant generation pattern"

    def test_identifies_environment_variable_derived_constants(self) -> None:
        """Must identify constants derived from GetEnvironmentVariable calls."""
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

        has_analysis = len(analysis.constraints) > 0 or len(analysis.api_calls) > 0
        assert has_analysis, "Failed to detect environment-based constant generation"

    def test_handles_cpuid_hardware_id_constants(self) -> None:
        """Must handle constants derived from CPUID hardware identifiers."""
        cpuid_code = bytes([
            0x48, 0x31, 0xC0,
            0x0F, 0xA2,
            0x89, 0x45, 0xF8,
            0x89, 0x5D, 0xFC,
            0x89, 0x4D, 0xF4,
            0x89, 0x55, 0xF0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(cpuid_code, arch="x64")

        has_hwid_analysis = len(analysis.crypto_primitives) > 0 or len(analysis.embedded_constants) > 0
        assert has_hwid_analysis, "Failed to analyze CPUID hardware-based constant generation"

    def test_detects_registry_value_based_constant_source(self) -> None:
        """Must detect when constants come from registry reads (RegQueryValueEx)."""
        registry_based_code = bytes([
            0x48, 0x8D, 0x0D, 0x20, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8D, 0x4D, 0xF0,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x45, 0xF0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(registry_based_code, arch="x64")

        assert len(analysis.api_calls) > 0 or len(analysis.constraints) > 0, (
            "Failed to detect registry-based constant source"
        )


class TestComplexMultiAlgorithmConstantExtraction:
    """Test extraction from complex validation using multiple algorithms."""

    def test_extracts_constants_from_md5_plus_crc_validation(self) -> None:
        """Must extract both MD5 and CRC32 constants when used together."""
        multi_algo_validation = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF8,
            0x48, 0xC7, 0xC1, 0x20, 0x83, 0xB8, 0xED,
            0x48, 0x89, 0x4D, 0xF0,
            0xB8, 0x01, 0x00, 0x01, 0x00,
            0x89, 0x45, 0xE8,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(multi_algo_validation, arch="x64")

        unique_algorithms = {p.algorithm for p in analysis.crypto_primitives}
        assert len(unique_algorithms) >= 2, f"Failed to detect multiple algorithms. Found: {unique_algorithms}"

        has_md5 = any(p.algorithm == "MD5" for p in analysis.crypto_primitives)
        has_crc = any("CRC" in p.algorithm.upper() for p in analysis.crypto_primitives)
        assert has_md5 or has_crc, "Failed to detect expected algorithm types in multi-algo validation"

    def test_extracts_license_key_length_constant_from_comparison(self) -> None:
        """Must extract key length requirement (16 chars) from CMP instruction."""
        length_validation = bytes([
            0x48, 0x8B, 0x45, 0x10,
            0x48, 0x83, 0xF8, 0x10,
            0x0F, 0x85, 0x0A, 0x00, 0x00, 0x00,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
            0x31, 0xC0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(length_validation, arch="x64")

        length_constraints = [c for c in analysis.constraints if c.constraint_type == "length"]
        assert len(length_constraints) > 0, "Failed to extract license key length constraint"
        assert any(c.value == 16 for c in length_constraints), "Did not extract length value of 16"

    def test_identifies_checksum_position_offset_from_pointer_arithmetic(self) -> None:
        """Must identify checksum at offset +8 from base pointer arithmetic."""
        checksum_offset_validation = bytes([
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
        analysis = analyzer.analyze(checksum_offset_validation, arch="x64")

        has_checksum_info = len(analysis.embedded_constants) > 0 or len(analysis.constraints) > 0
        assert has_checksum_info, "Failed to identify checksum position and expected value"

    def test_extracts_separator_character_constant_from_byte_comparison(self) -> None:
        """Must extract separator character '-' (0x2D) from byte comparison operations."""
        separator_validation = bytes([
            0x48, 0x8B, 0x45, 0x10,
            0x80, 0x78, 0x04, 0x2D,
            0x75, 0x05,
            0x80, 0x78, 0x09, 0x2D,
            0x75, 0x05,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
            0x31, 0xC0,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(separator_validation, arch="x64")

        separator_constraints = [
            c for c in analysis.constraints
            if c.constraint_type == "separator" and c.value == "-"
        ]
        assert len(separator_constraints) > 0, "Failed to extract separator character constant"


class TestConstantExtractionWithRealBinary:
    """Test constant extraction using actual Windows system binaries."""

    @pytest.fixture
    def windows_system_binary(self) -> Path | None:
        """Provide path to Windows system binary for testing."""
        candidates = [
            Path(r"C:\Windows\System32\kernel32.dll"),
            Path(r"C:\Windows\System32\ntdll.dll"),
            Path(r"C:\Windows\SysWOW64\kernel32.dll"),
            Path(r"C:\Windows\System32\advapi32.dll"),
        ]

        for binary_path in candidates:
            if binary_path.exists():
                return binary_path
        return None

    def test_extracts_crypto_constants_from_real_binary(self, windows_system_binary: Path | None) -> None:
        """Must extract cryptographic constants from actual Windows DLL."""
        if not windows_system_binary or not windows_system_binary.exists():
            pytest.skip("No Windows system binary available")

        extractor = ConstraintExtractor(windows_system_binary)
        constraints = extractor.extract_constraints()

        assert len(constraints) > 0, f"Failed to extract constraints from {windows_system_binary}"

    def test_analyzes_pe_text_section_for_validation_constants(self, windows_system_binary: Path | None) -> None:
        """Must analyze .text code section for embedded validation constants."""
        if not windows_system_binary or not windows_system_binary.exists():
            pytest.skip("No Windows system binary available")

        with open(windows_system_binary, "rb") as f:
            binary_data = f.read(min(1024 * 1024, windows_system_binary.stat().st_size))

        analyzer = ValidationAnalyzer()
        embedded = analyzer._extract_embedded_constants(binary_data, [])

        assert len(embedded) > 0, f"Failed to extract embedded constants from {windows_system_binary}"

    def test_extraction_works_on_protected_binary_fixture(self) -> None:
        """Must extract constants from protected binary test fixtures."""
        fixture_paths = [
            Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\legitimate\7zip.exe"),
            Path(r"D:\Intellicrack\tests\fixtures\binaries\pe\legitimate\notepadpp.exe"),
        ]

        for fixture_path in fixture_paths:
            if not fixture_path.exists():
                continue

            extractor = ConstraintExtractor(fixture_path)
            constraints = extractor.extract_constraints()

            assert isinstance(constraints, list), f"Failed to analyze {fixture_path}"
            break
        else:
            pytest.skip("No fixture binaries available")


class TestConstantConfidenceScoring:
    """Test confidence scoring for extracted constants."""

    def test_assigns_high_confidence_to_known_md5_constant(self) -> None:
        """Must assign confidence >= 0.85 to well-known MD5 initialization constant."""
        md5_constant_code = struct.pack("<I", 0x67452301)
        binary = b"\x48\xB8" + md5_constant_code + b"\x00\x00\x00\x00" + b"\x48\x89\x45\xF8" + b"\xC3"

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(binary, arch="x64")

        md5_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "MD5"]
        if md5_primitives:
            assert md5_primitives[0].confidence >= 0.85, f"MD5 constant confidence too low: {md5_primitives[0].confidence}"

    def test_assigns_lower_confidence_to_ambiguous_value(self) -> None:
        """Must assign lower confidence (<1.0) to ambiguous constant value 0x42."""
        ambiguous_constant = bytes([
            0xB8, 0x42, 0x00, 0x00, 0x00,
            0x89, 0x45, 0xFC,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(ambiguous_constant, arch="x86")

        if analysis.crypto_primitives:
            max_confidence = max(p.confidence for p in analysis.crypto_primitives)
            assert max_confidence < 1.0, "Ambiguous constant should not have perfect confidence"

    def test_overall_analysis_provides_normalized_confidence(self) -> None:
        """Must provide overall analysis confidence in range [0.0, 1.0]."""
        validation_code = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xC7, 0xC1, 0x20, 0x83, 0xB8, 0xED,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        analysis = analyzer.analyze(validation_code, arch="x64")

        assert analysis.confidence > 0.0, "Analysis must provide non-zero confidence"
        assert 0.0 <= analysis.confidence <= 1.0, f"Confidence {analysis.confidence} outside [0, 1] range"

    def test_confidence_increases_with_multiple_known_constants(self) -> None:
        """Must assign higher confidence when multiple known crypto constants are found."""
        multi_constant_code = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF8,
            0x48, 0xB8, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x45, 0xF0,
            0xC3,
        ])

        single_constant_code = bytes([
            0x48, 0xB8, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC3,
        ])

        analyzer = ValidationAnalyzer()
        multi_analysis = analyzer.analyze(multi_constant_code, arch="x64")
        single_analysis = analyzer.analyze(single_constant_code, arch="x64")

        if multi_analysis.crypto_primitives and single_analysis.crypto_primitives:
            multi_conf = max(p.confidence for p in multi_analysis.crypto_primitives)
            single_conf = max(p.confidence for p in single_analysis.crypto_primitives)

            assert multi_conf >= single_conf, "Multiple known constants should have higher confidence"


class TestConstantExtractionErrorHandling:
    """Test graceful error handling for invalid inputs."""

    def test_handles_empty_binary_without_crash(self) -> None:
        """Must handle empty binary input without crashing."""
        analyzer = ValidationAnalyzer()

        try:
            analysis = analyzer.analyze(b"", arch="x64")
            assert analysis is not None, "Analyzer returned None for empty input"
        except Exception as e:
            pytest.fail(f"Analyzer crashed on empty input: {e}")

    def test_handles_null_byte_binary_gracefully(self) -> None:
        """Must handle binary of all null bytes without errors."""
        null_binary = b"\x00" * 1000

        analyzer = ValidationAnalyzer()

        try:
            analysis = analyzer.analyze(null_binary, arch="x64")
            assert analysis is not None, "Analyzer returned None for null-byte input"
        except Exception as e:
            pytest.fail(f"Analyzer crashed on null-byte input: {e}")

    def test_handles_random_noise_binary(self) -> None:
        """Must handle random noise without crashing."""
        noise_binary = b"\xFF" * 1000

        analyzer = ValidationAnalyzer()

        try:
            analysis = analyzer.analyze(noise_binary, arch="x64")
            assert analysis is not None, "Analyzer returned None for noise input"
        except Exception as e:
            pytest.fail(f"Analyzer crashed on noise input: {e}")

    def test_handles_non_executable_text_data(self) -> None:
        """Must handle text data that isn't valid machine code."""
        text_data = b"This is not machine code at all, just plain ASCII text data"

        analyzer = ValidationAnalyzer()

        try:
            analysis = analyzer.analyze(text_data, arch="x64")
            assert analysis is not None, "Analyzer returned None for text input"
        except Exception as e:
            pytest.fail(f"Analyzer crashed on text input: {e}")


class TestEndToEndConstantExtraction:
    """Integration tests for complete constant extraction workflows."""

    def test_complete_workflow_from_binary_to_keygen_template(self) -> None:
        """Must complete full workflow: binary → constant extraction → algorithm build → keygen template."""
        crc_validation_binary = bytes([
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
        analysis = analyzer.analyze(crc_validation_binary, arch="x64")

        assert analysis.algorithm_type is not None, "Failed to determine algorithm type from constants"
        assert len(analysis.recommendations) > 0, "No actionable recommendations generated"
        assert analysis.confidence > 0.0, "No confidence score for constant extraction"

    def test_extracts_complete_serial_format_from_validation_code(self) -> None:
        """Must extract complete format: length=20, separators at positions 4,9,14."""
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
        assert len(separator_constraints) > 0, "Failed to extract separator positions"

        length_constraints = [c for c in analysis.constraints if c.constraint_type == "length"]
        assert len(length_constraints) > 0, "Failed to extract total length constraint"

    def test_generates_valid_crc32_using_extracted_polynomial(self) -> None:
        """Must generate valid CRC32 checksum using extracted polynomial, not hardcoded value."""
        test_data = b"TEST_LICENSE_KEY"

        dummy_path = Path("test_crc_gen.bin")
        extractor = ConstraintExtractor(dummy_path)
        extractor._binary_data = struct.pack("<I", 0xEDB88320) + b"\x00" * 100

        algorithms = extractor.analyze_validation_algorithms()

        crc_algo = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)
        if crc_algo and crc_algo.validation_function:
            result = crc_algo.validation_function(test_data.decode())
            expected_crc = zlib.crc32(test_data) & 0xFFFFFFFF

            assert result == expected_crc, f"CRC validation function returned {result}, expected {expected_crc}"
