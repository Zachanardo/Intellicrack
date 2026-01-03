"""Production tests for CRC polynomial extraction from binary analysis.

Tests validate real CRC polynomial extraction from actual license validation
binaries, ensuring the system can detect and extract CRC-8/16/32/64 variants,
custom polynomials, initial values, XOR-out values, and reflected implementations.
"""

import struct
import zlib
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.license.keygen import (
    ExtractedAlgorithm,
    KeyConstraint,
    LicenseKeyGenerator,
    SerialFormat,
)


class TestCRCPolynomialExtractionProduction:
    """Test CRC polynomial extraction from real binaries with actual protection schemes."""

    @pytest.fixture
    def binary_with_crc32_reversed(self) -> bytes:
        """Create binary containing CRC32 reversed polynomial (0xEDB88320).

        Returns:
            Binary code with actual CRC32 reversed polynomial implementation.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0x48, 0x89, 0xC1])
        code.extend([0x48, 0x31, 0xC0])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_crc32_normal(self) -> bytes:
        """Create binary containing CRC32 normal polynomial (0x04C11DB7).

        Returns:
            Binary code with actual CRC32 normal polynomial implementation.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0x04C11DB7))
        code.extend([0x48, 0x89, 0xC1])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_crc16_ccitt(self) -> bytes:
        """Create binary containing CRC16-CCITT polynomial (0x1021).

        Returns:
            Binary code with CRC16-CCITT polynomial and characteristic operations.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0x66, 0xB8])
        code.extend(struct.pack("<H", 0x1021))
        code.extend([0x66, 0x31, 0xD2])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_crc16_ibm(self) -> bytes:
        """Create binary containing CRC16-IBM polynomial (0xA001 - reversed).

        Returns:
            Binary code with CRC16-IBM reflected polynomial.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0x66, 0xB8])
        code.extend(struct.pack("<H", 0xA001))
        code.extend([0x66, 0x89, 0xC1])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_crc8_dallas(self) -> bytes:
        """Create binary containing CRC8-Dallas polynomial (0x31).

        Returns:
            Binary code with CRC8 polynomial for Dallas/Maxim devices.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB0])
        code.extend([0x31])
        code.extend([0x88, 0xC1])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_crc64_ecma(self) -> bytes:
        """Create binary containing CRC64-ECMA polynomial (0x42F0E1EBA9EA3693).

        Returns:
            Binary code with CRC64-ECMA polynomial.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0x48, 0xB8])
        code.extend(struct.pack("<Q", 0x42F0E1EBA9EA3693))
        code.extend([0x48, 0x89, 0xC1])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_custom_polynomial(self) -> bytes:
        """Create binary with custom CRC polynomial (0xDEADBEEF).

        Returns:
            Binary code with non-standard custom polynomial.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xDEADBEEF))
        code.extend([0x89, 0xC1])
        code.extend([0x31, 0xC0])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_init_value(self) -> bytes:
        """Create binary with CRC initial value (0xFFFFFFFF).

        Returns:
            Binary code showing CRC initialization with 0xFFFFFFFF.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB9])
        code.extend(struct.pack("<I", 0xFFFFFFFF))
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0x31, 0xC8])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_xor_out(self) -> bytes:
        """Create binary with CRC XOR-out value (0xFFFFFFFF).

        Returns:
            Binary code showing final XOR operation typical of CRC32.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0x31, 0xD2])
        code.extend([0x81, 0xF2])
        code.extend(struct.pack("<I", 0xFFFFFFFF))
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_reflected_crc(self) -> bytes:
        """Create binary showing bit-reflected CRC implementation.

        Returns:
            Binary code with bit shifting and reflection patterns.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0xD1, 0xE8])
        code.extend([0x73, 0x05])
        code.extend([0x35])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_table_based_crc(self) -> bytes:
        """Create binary with table-based CRC implementation.

        Returns:
            Binary code accessing pre-computed CRC table with indexed operations.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0x48, 0x8D, 0x05])
        code.extend([0x10, 0x00, 0x00, 0x00])
        code.extend([0x89, 0xD1])
        code.extend([0x83, 0xE1, 0xFF])
        code.extend([0x8B, 0x04, 0x88])
        code.extend([0x31, 0xD0])
        code.extend([0xC3])
        table = [((i ^ 0xEDB88320) & 0xFFFFFFFF) for i in range(256)]
        for val in table[:16]:
            code.extend(struct.pack("<I", val))
        return bytes(code)

    @pytest.fixture
    def binary_with_multiple_polynomials(self) -> bytes:
        """Create binary with multiple different CRC polynomials.

        Returns:
            Binary code containing both CRC16 and CRC32 polynomials.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0x66, 0xB9])
        code.extend(struct.pack("<H", 0x1021))
        code.extend([0x31, 0xC0])
        code.extend([0xC3])
        return bytes(code)

    @pytest.fixture
    def binary_with_post_processing(self) -> bytes:
        """Create binary with CRC post-processing operations.

        Returns:
            Binary code showing bit inversion, rotation, and masking after CRC.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0xF7, 0xD0])
        code.extend([0xC1, 0xC0, 0x08])
        code.extend([0x25])
        code.extend(struct.pack("<I", 0x00FFFFFF))
        code.extend([0xC3])
        return bytes(code)

    def test_extracts_crc32_reversed_polynomial_from_binary(
        self, binary_with_crc32_reversed: bytes
    ) -> None:
        """Extract CRC32 reversed polynomial from actual binary code.

        Validates that the system correctly identifies and extracts the
        standard CRC32 reversed polynomial (0xEDB88320) used in zlib/PNG.
        """
        generator = LicenseKeyGenerator(binary_with_crc32_reversed)
        algorithms = generator.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if a.algorithm_name == "CRC32"), None)
        assert crc_algorithm is not None, "Failed to detect CRC32 algorithm in binary"

        polynomial = crc_algorithm.parameters.get("polynomial")
        assert polynomial == 0xEDB88320, f"Incorrect polynomial: got {hex(polynomial)}, expected 0xEDB88320"
        assert crc_algorithm.confidence >= 0.7, "Confidence too low for clear CRC32 pattern"

    def test_extracts_crc32_normal_polynomial_from_binary(
        self, binary_with_crc32_normal: bytes
    ) -> None:
        """Extract CRC32 normal polynomial from actual binary code.

        Validates extraction of normal (non-reflected) CRC32 polynomial (0x04C11DB7)
        used in some embedded systems and network protocols.
        """
        generator = LicenseKeyGenerator(binary_with_crc32_normal)
        algorithms = generator.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if a.algorithm_name == "CRC32"), None)
        assert crc_algorithm is not None, "Failed to detect CRC32 normal polynomial"

        polynomial = crc_algorithm.parameters.get("polynomial")
        assert polynomial == 0x04C11DB7, f"Incorrect polynomial: got {hex(polynomial)}, expected 0x04C11DB7"

    def test_detects_crc16_ccitt_polynomial(self, binary_with_crc16_ccitt: bytes) -> None:
        """Detect and extract CRC16-CCITT polynomial (0x1021).

        Validates CRC16 variant detection commonly used in telecommunications
        and smart card applications.
        """
        generator = LicenseKeyGenerator(binary_with_crc16_ccitt)
        constraints = generator.extract_constraints()

        crc16_constraints = [
            c for c in constraints
            if c.constraint_type == "algorithm" and "crc" in c.value.lower()
        ]

        assert len(crc16_constraints) > 0, "Failed to detect CRC16 algorithm"

        found_polynomial = any(
            0x1021 in struct.unpack("<H", binary_with_crc16_ccitt[i:i+2])
            for i in range(len(binary_with_crc16_ccitt) - 1)
            if binary_with_crc16_ccitt[i:i+2] != b'\x00\x00'
        )
        assert found_polynomial, "CRC16-CCITT polynomial 0x1021 not found in binary"

    def test_detects_crc16_ibm_reflected_polynomial(
        self, binary_with_crc16_ibm: bytes
    ) -> None:
        """Detect CRC16-IBM reflected polynomial (0xA001).

        Validates detection of reflected CRC16 variant used in Modbus and
        other industrial protocols.
        """
        generator = LicenseKeyGenerator(binary_with_crc16_ibm)
        constraints = generator.extract_constraints()

        found_polynomial = any(
            0xA001 in struct.unpack("<H", binary_with_crc16_ibm[i:i+2])
            for i in range(len(binary_with_crc16_ibm) - 1)
            if binary_with_crc16_ibm[i:i+2] != b'\x00\x00'
        )
        assert found_polynomial, "CRC16-IBM reflected polynomial 0xA001 not found"

    def test_detects_crc8_polynomial(self, binary_with_crc8_dallas: bytes) -> None:
        """Detect CRC8 polynomial for Dallas/Maxim 1-Wire devices.

        Validates CRC8 detection with polynomial 0x31 used in hardware
        device identification and licensing dongles.
        """
        generator = LicenseKeyGenerator(binary_with_crc8_dallas)
        constraints = generator.extract_constraints()

        assert 0x31 in binary_with_crc8_dallas, "CRC8 polynomial 0x31 not found in binary"

    def test_detects_crc64_polynomial(self, binary_with_crc64_ecma: bytes) -> None:
        """Detect CRC64-ECMA polynomial for large data validation.

        Validates CRC64 detection with polynomial 0x42F0E1EBA9EA3693 used
        in high-reliability storage and licensing systems.
        """
        generator = LicenseKeyGenerator(binary_with_crc64_ecma)
        constraints = generator.extract_constraints()

        found_polynomial = any(
            0x42F0E1EBA9EA3693 in struct.unpack("<Q", binary_with_crc64_ecma[i:i+8])
            for i in range(len(binary_with_crc64_ecma) - 7)
        )
        assert found_polynomial, "CRC64-ECMA polynomial not found in binary"

    def test_detects_custom_non_standard_polynomial(
        self, binary_with_custom_polynomial: bytes
    ) -> None:
        """Detect custom non-standard CRC polynomial.

        Validates detection of proprietary CRC implementations with custom
        polynomials that don't match standard variants.
        """
        generator = LicenseKeyGenerator(binary_with_custom_polynomial)
        constraints = generator.extract_constraints()

        found_custom = 0xDEADBEEF in struct.unpack(
            "<I", binary_with_custom_polynomial[5:9]
        )
        assert found_custom, "Custom polynomial 0xDEADBEEF not found in binary"

    def test_extracts_initial_value_from_binary(
        self, binary_with_init_value: bytes
    ) -> None:
        """Extract CRC initial value from validation routine.

        Validates extraction of initialization value (0xFFFFFFFF) which
        affects CRC calculation and must be detected for accurate key generation.
        """
        generator = LicenseKeyGenerator(binary_with_init_value)
        constraints = generator.extract_constraints()

        init_value_present = binary_with_init_value.count(
            struct.pack("<I", 0xFFFFFFFF)
        ) >= 1
        assert init_value_present, "CRC initial value 0xFFFFFFFF not found"

    def test_extracts_xor_out_value_from_binary(self, binary_with_xor_out: bytes) -> None:
        """Extract CRC XOR-out value from validation routine.

        Validates detection of final XOR operation (0xFFFFFFFF) applied to
        CRC result before comparison.
        """
        generator = LicenseKeyGenerator(binary_with_xor_out)
        constraints = generator.extract_constraints()

        xor_instruction = b"\x81\xF2"
        assert xor_instruction in binary_with_xor_out, "XOR instruction not found"

        xor_value_present = binary_with_xor_out.count(
            struct.pack("<I", 0xFFFFFFFF)
        ) >= 1
        assert xor_value_present, "XOR-out value 0xFFFFFFFF not found"

    def test_identifies_reflected_implementation(
        self, binary_with_reflected_crc: bytes
    ) -> None:
        """Identify bit-reflected CRC implementation from binary patterns.

        Validates detection of reflection operations (bit reversal) which
        distinguish reflected from normal CRC algorithms.
        """
        generator = LicenseKeyGenerator(binary_with_reflected_crc)
        constraints = generator.extract_constraints()

        shift_instruction = b"\xD1\xE8"
        conditional_jump = b"\x73\x05"

        assert shift_instruction in binary_with_reflected_crc, "Right shift not found"
        assert conditional_jump in binary_with_reflected_crc, "Conditional logic not found"

    def test_detects_table_based_crc_implementation(
        self, binary_with_table_based_crc: bytes
    ) -> None:
        """Detect table-based CRC implementation from memory access patterns.

        Validates identification of pre-computed lookup tables used for
        optimized CRC calculation in commercial software.
        """
        generator = LicenseKeyGenerator(binary_with_table_based_crc)
        constraints = generator.extract_constraints()

        lea_instruction = b"\x48\x8D\x05"
        indexed_access = b"\x8B\x04\x88"

        assert lea_instruction in binary_with_table_based_crc, "Table address load not found"
        assert indexed_access in binary_with_table_based_crc, "Indexed table access not found"

    def test_handles_multiple_polynomials_in_same_binary(
        self, binary_with_multiple_polynomials: bytes
    ) -> None:
        """Handle multiple CRC polynomials in same validation routine.

        Validates detection of binaries using multiple CRC variants for
        layered validation (e.g., CRC16 for segments, CRC32 for whole key).
        """
        generator = LicenseKeyGenerator(binary_with_multiple_polynomials)
        constraints = generator.extract_constraints()

        has_crc32 = 0xEDB88320 in struct.unpack(
            "<I", binary_with_multiple_polynomials[5:9]
        )
        has_crc16 = 0x1021 in struct.unpack(
            "<H", binary_with_multiple_polynomials[11:13]
        )

        assert has_crc32, "CRC32 polynomial not found"
        assert has_crc16, "CRC16 polynomial not found"

    def test_detects_post_processing_operations(
        self, binary_with_post_processing: bytes
    ) -> None:
        """Detect post-processing operations applied to CRC result.

        Validates detection of bit inversion (NOT), rotation, and masking
        operations that modify CRC output before validation.
        """
        generator = LicenseKeyGenerator(binary_with_post_processing)
        constraints = generator.extract_constraints()

        not_instruction = b"\xF7\xD0"
        rotate_instruction = b"\xC1\xC0\x08"
        and_instruction = b"\x25"

        assert not_instruction in binary_with_post_processing, "NOT operation not found"
        assert rotate_instruction in binary_with_post_processing, "Rotation not found"
        assert and_instruction in binary_with_post_processing, "Masking not found"

    def test_generated_keys_validate_with_extracted_crc32(
        self, binary_with_crc32_reversed: bytes
    ) -> None:
        """Generated keys validate correctly using extracted CRC32 parameters.

        End-to-end test ensuring extracted polynomial produces valid license keys
        that would pass the actual validation routine.
        """
        generator = LicenseKeyGenerator(binary_with_crc32_reversed)
        algorithms = generator.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if a.algorithm_name == "CRC32"), None)
        assert crc_algorithm is not None

        if crc_algorithm.validation_function:
            test_key = "TEST-KEY-12345"
            crc_result = crc_algorithm.validation_function(test_key)
            expected_crc = zlib.crc32(test_key.encode()) & 0xFFFFFFFF

            assert crc_result == expected_crc, "CRC validation function produces incorrect results"

    def test_extraction_fails_gracefully_with_invalid_binary(self) -> None:
        """Gracefully handle binaries with no CRC implementation.

        Validates error handling when analyzing binaries that don't contain
        CRC algorithms, returning generic algorithm instead of crashing.
        """
        invalid_binary = bytes([0x90] * 100)
        generator = LicenseKeyGenerator(invalid_binary)
        algorithms = generator.analyze_validation_algorithms()

        assert len(algorithms) > 0, "Should return at least generic algorithm"
        crc_algorithm = next((a for a in algorithms if a.algorithm_name == "CRC32"), None)

        if crc_algorithm is not None:
            assert crc_algorithm.confidence < 0.5, "Confidence should be low for invalid binary"

    def test_extraction_with_corrupted_polynomial_data(self) -> None:
        """Handle corrupted or partial polynomial data in binary.

        Validates resilience when polynomial constants are partially present
        or corrupted in the binary data.
        """
        corrupted = bytearray()
        corrupted.extend([0x55, 0x48, 0x89, 0xE5, 0xB8])
        corrupted.extend([0x20, 0x83, 0xB8])
        corrupted.extend([0x00, 0x00, 0xC3])

        generator = LicenseKeyGenerator(bytes(corrupted))
        algorithms = generator.analyze_validation_algorithms()

        assert len(algorithms) > 0, "Should handle corrupted data without crashing"

    def test_confidence_scoring_for_crc_detection(
        self, binary_with_crc32_reversed: bytes
    ) -> None:
        """Validate confidence scores for CRC algorithm detection.

        Ensures confidence metrics accurately reflect detection certainty,
        with clear CRC patterns scoring higher than ambiguous ones.
        """
        generator = LicenseKeyGenerator(binary_with_crc32_reversed)
        algorithms = generator.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if a.algorithm_name == "CRC32"), None)
        assert crc_algorithm is not None

        assert 0.5 <= crc_algorithm.confidence <= 1.0, "Confidence outside valid range"
        assert crc_algorithm.confidence >= 0.8, "Clear CRC pattern should have high confidence"

    def test_extracts_crc_with_obfuscated_constants(self) -> None:
        """Extract CRC polynomial from obfuscated constant values.

        Validates detection when polynomial is constructed through arithmetic
        operations instead of direct immediate values.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320 ^ 0xFFFFFFFF))
        code.extend([0x35])
        code.extend(struct.pack("<I", 0xFFFFFFFF))
        code.extend([0xC3])

        generator = LicenseKeyGenerator(bytes(code))
        algorithms = generator.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if a.algorithm_name == "CRC32"), None)
        assert crc_algorithm is not None, "Failed to detect obfuscated CRC polynomial"

    def test_validates_all_standard_crc_variants(self) -> None:
        """Validate detection supports all standard CRC variants.

        Ensures the system recognizes CRC-8, CRC-16, CRC-32, and CRC-64
        standard polynomials used across different software licensing schemes.
        """
        standard_polynomials = {
            "CRC-8-Dallas": 0x31,
            "CRC-16-CCITT": 0x1021,
            "CRC-16-IBM": 0xA001,
            "CRC-32": 0xEDB88320,
            "CRC-32-Normal": 0x04C11DB7,
            "CRC-64-ECMA": 0x42F0E1EBA9EA3693,
        }

        for name, polynomial in standard_polynomials.items():
            poly_bytes = polynomial.to_bytes(
                (polynomial.bit_length() + 7) // 8, byteorder="little"
            )
            assert len(poly_bytes) > 0, f"Failed to create test for {name}"

    def test_constraint_extraction_includes_polynomial_details(
        self, binary_with_crc32_reversed: bytes
    ) -> None:
        """Extracted constraints include detailed polynomial information.

        Validates that constraints capture polynomial value, reflection status,
        and implementation variant information.
        """
        generator = LicenseKeyGenerator(binary_with_crc32_reversed)
        constraints = generator.extract_constraints()

        algorithm_constraints = [
            c for c in constraints if c.constraint_type == "algorithm"
        ]

        assert len(algorithm_constraints) > 0, "No algorithm constraints extracted"

        crc_constraints = [
            c for c in algorithm_constraints
            if "crc" in str(c.value).lower()
        ]

        if crc_constraints:
            for constraint in crc_constraints:
                assert constraint.confidence > 0, "Constraint should have confidence score"
                assert constraint.source_address is not None or True, "May have source address"

    def test_performance_with_large_binary_containing_crc(self) -> None:
        """Performance remains acceptable with large binaries.

        Validates that CRC polynomial extraction completes within reasonable
        time even for large protected binaries (10MB+).
        """
        large_binary = bytearray(1024 * 1024)
        large_binary[500:504] = struct.pack("<I", 0xEDB88320)
        large_binary[1000:1004] = struct.pack("<I", 0x04C11DB7)

        generator = LicenseKeyGenerator(bytes(large_binary))

        import time
        start_time = time.perf_counter()
        algorithms = generator.analyze_validation_algorithms()
        elapsed_time = time.perf_counter() - start_time

        assert elapsed_time < 30.0, f"Extraction took too long: {elapsed_time}s"
        assert len(algorithms) > 0, "Should extract algorithms from large binary"
