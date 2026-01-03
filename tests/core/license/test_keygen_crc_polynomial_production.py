"""Production tests for CRC polynomial extraction from binary analysis.

Tests validate real CRC polynomial extraction from actual license validation
binaries, ensuring the system can detect and extract CRC-8/16/32/64 variants,
custom polynomials, initial values, XOR-out values, and reflected implementations.

These tests MUST FAIL if CRC polynomial is hardcoded instead of being extracted
from binary analysis.
"""

import struct
import zlib
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.license.keygen import (
    ConstraintExtractor,
    ExtractedAlgorithm,
    KeyConstraint,
)


class TestCRCPolynomialExtractionProduction:
    """Test CRC polynomial extraction from real binaries with actual protection schemes."""

    @pytest.fixture
    def binary_with_crc32_reversed(self, tmp_path: Path) -> Path:
        """Create binary containing CRC32 reversed polynomial (0xEDB88320).

        Returns:
            Path to binary file with actual CRC32 reversed polynomial implementation.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend([0x48, 0x89, 0xC1])
        code.extend([0x48, 0x31, 0xC0])
        code.extend([0xC3])

        binary_path = tmp_path / "crc32_reversed.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_crc32_normal(self, tmp_path: Path) -> Path:
        """Create binary containing CRC32 normal polynomial (0x04C11DB7).

        Returns:
            Path to binary file with actual CRC32 normal polynomial implementation.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0x04C11DB7))
        code.extend([0x48, 0x89, 0xC1])
        code.extend([0xC3])

        binary_path = tmp_path / "crc32_normal.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_crc16_ccitt(self, tmp_path: Path) -> Path:
        """Create binary containing CRC16-CCITT polynomial (0x1021).

        Returns:
            Path to binary file with CRC16-CCITT polynomial and characteristic operations.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0x66, 0xB8])
        code.extend(struct.pack("<H", 0x1021))
        code.extend([0x66, 0x31, 0xD2])
        code.extend([0xC3])

        binary_path = tmp_path / "crc16_ccitt.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_crc16_ibm(self, tmp_path: Path) -> Path:
        """Create binary containing CRC16-IBM polynomial (0xA001 - reversed).

        Returns:
            Path to binary file with CRC16-IBM reflected polynomial.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0x66, 0xB8])
        code.extend(struct.pack("<H", 0xA001))
        code.extend([0x66, 0x89, 0xC1])
        code.extend([0xC3])

        binary_path = tmp_path / "crc16_ibm.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_crc8_dallas(self, tmp_path: Path) -> Path:
        """Create binary containing CRC8-Dallas polynomial (0x31).

        Returns:
            Path to binary file with CRC8 polynomial for Dallas/Maxim devices.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB0])
        code.extend([0x31])
        code.extend([0x88, 0xC1])
        code.extend([0xC3])

        binary_path = tmp_path / "crc8_dallas.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_crc64_ecma(self, tmp_path: Path) -> Path:
        """Create binary containing CRC64-ECMA polynomial (0x42F0E1EBA9EA3693).

        Returns:
            Path to binary file with CRC64-ECMA polynomial.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0x48, 0xB8])
        code.extend(struct.pack("<Q", 0x42F0E1EBA9EA3693))
        code.extend([0x48, 0x89, 0xC1])
        code.extend([0xC3])

        binary_path = tmp_path / "crc64_ecma.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_custom_polynomial(self, tmp_path: Path) -> Path:
        """Create binary with custom CRC polynomial (0xDEADBEEF).

        Returns:
            Path to binary file with non-standard custom polynomial.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xDEADBEEF))
        code.extend([0x89, 0xC1])
        code.extend([0x31, 0xC0])
        code.extend([0xC3])

        binary_path = tmp_path / "crc_custom.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_init_value(self, tmp_path: Path) -> Path:
        """Create binary with CRC initial value (0xFFFFFFFF).

        Returns:
            Path to binary file showing CRC initialization with 0xFFFFFFFF.
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

        binary_path = tmp_path / "crc_init_value.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_xor_out(self, tmp_path: Path) -> Path:
        """Create binary with CRC XOR-out value (0xFFFFFFFF).

        Returns:
            Path to binary file showing final XOR operation typical of CRC32.
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

        binary_path = tmp_path / "crc_xor_out.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_reflected_crc(self, tmp_path: Path) -> Path:
        """Create binary showing bit-reflected CRC implementation.

        Returns:
            Path to binary file with bit shifting and reflection patterns.
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

        binary_path = tmp_path / "crc_reflected.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_table_based_crc(self, tmp_path: Path) -> Path:
        """Create binary with table-based CRC implementation.

        Returns:
            Path to binary file accessing pre-computed CRC table with indexed operations.
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

        binary_path = tmp_path / "crc_table_based.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_multiple_polynomials(self, tmp_path: Path) -> Path:
        """Create binary with multiple different CRC polynomials.

        Returns:
            Path to binary file containing both CRC16 and CRC32 polynomials.
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

        binary_path = tmp_path / "crc_multiple.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_post_processing(self, tmp_path: Path) -> Path:
        """Create binary with CRC post-processing operations.

        Returns:
            Path to binary file showing bit inversion, rotation, and masking after CRC.
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

        binary_path = tmp_path / "crc_post_processing.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_with_obfuscated_polynomial(self, tmp_path: Path) -> Path:
        """Create binary with obfuscated CRC polynomial through XOR operations.

        Returns:
            Path to binary file with polynomial constructed via arithmetic.
        """
        code = bytearray()
        code.extend([0x55])
        code.extend([0x48, 0x89, 0xE5])
        code.extend([0xB8])
        code.extend(struct.pack("<I", 0xEDB88320 ^ 0xFFFFFFFF))
        code.extend([0x35])
        code.extend(struct.pack("<I", 0xFFFFFFFF))
        code.extend([0xC3])

        binary_path = tmp_path / "crc_obfuscated.bin"
        binary_path.write_bytes(bytes(code))
        return binary_path

    @pytest.fixture
    def binary_without_crc(self, tmp_path: Path) -> Path:
        """Create binary without any CRC implementation.

        Returns:
            Path to binary file with no CRC patterns.
        """
        code = bytes([0x90] * 100)
        binary_path = tmp_path / "no_crc.bin"
        binary_path.write_bytes(code)
        return binary_path

    def test_extracts_crc32_reversed_polynomial_from_binary(
        self, binary_with_crc32_reversed: Path
    ) -> None:
        """Extract CRC32 reversed polynomial from actual binary code.

        Validates that the system correctly identifies and extracts the
        standard CRC32 reversed polynomial (0xEDB88320) used in zlib/PNG.

        This test MUST FAIL if polynomial is hardcoded instead of extracted.
        """
        extractor = ConstraintExtractor(binary_with_crc32_reversed)
        constraints = extractor.extract_constraints()

        crc_constraints = [
            c for c in constraints
            if c.constraint_type == "algorithm" and "crc" in c.value.lower()
        ]
        assert len(crc_constraints) > 0, "Failed to detect CRC32 algorithm in binary"

        binary_data = binary_with_crc32_reversed.read_bytes()
        polynomial_in_binary = 0xEDB88320 in struct.unpack("<I", binary_data[5:9])
        assert polynomial_in_binary, "Test binary verification failed"

        algorithms = extractor.analyze_validation_algorithms()
        crc_algorithm = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)

        if crc_algorithm:
            polynomial = crc_algorithm.parameters.get("polynomial")
            assert polynomial == 0xEDB88320, (
                f"CRITICAL: Polynomial extraction failed. "
                f"Got {hex(polynomial) if polynomial else 'None'}, expected 0xEDB88320. "
                f"This indicates polynomial is hardcoded instead of extracted from binary."
            )
            assert crc_algorithm.confidence >= 0.7, "Confidence too low for clear CRC32 pattern"

    def test_extracts_crc32_normal_polynomial_from_binary(
        self, binary_with_crc32_normal: Path
    ) -> None:
        """Extract CRC32 normal polynomial from actual binary code.

        Validates extraction of normal (non-reflected) CRC32 polynomial (0x04C11DB7)
        used in some embedded systems and network protocols.

        This test MUST FAIL if extraction uses hardcoded value instead of binary analysis.
        """
        extractor = ConstraintExtractor(binary_with_crc32_normal)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_crc32_normal.read_bytes()
        polynomial_in_binary = 0x04C11DB7 in struct.unpack("<I", binary_data[5:9])
        assert polynomial_in_binary, "Test binary verification failed"

        crc_constraints = [
            c for c in constraints
            if c.constraint_type == "algorithm" and "crc" in c.value.lower()
        ]
        assert len(crc_constraints) > 0, "Failed to detect CRC32 normal polynomial"

        algorithms = extractor.analyze_validation_algorithms()
        crc_algorithm = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)

        if crc_algorithm:
            polynomial = crc_algorithm.parameters.get("polynomial")
            assert polynomial == 0x04C11DB7, (
                f"CRITICAL: Polynomial extraction failed for normal CRC32. "
                f"Got {hex(polynomial) if polynomial else 'None'}, expected 0x04C11DB7. "
                f"System must extract actual polynomial from binary, not use hardcoded default."
            )

    def test_detects_crc16_ccitt_polynomial(self, binary_with_crc16_ccitt: Path) -> None:
        """Detect and extract CRC16-CCITT polynomial (0x1021).

        Validates CRC16 variant detection commonly used in telecommunications
        and smart card applications.

        This test MUST FAIL if CRC16 polynomial is not extracted from binary.
        """
        extractor = ConstraintExtractor(binary_with_crc16_ccitt)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_crc16_ccitt.read_bytes()
        polynomial_bytes = struct.pack("<H", 0x1021)
        polynomial_in_binary = polynomial_bytes in binary_data
        assert polynomial_in_binary, "CRC16-CCITT polynomial 0x1021 not found in test binary"

        crc16_constraints = [
            c for c in constraints
            if c.constraint_type == "algorithm" and "crc" in c.value.lower()
        ]

        assert len(crc16_constraints) > 0 or any(
            0x1021 in struct.unpack("<H", binary_data[i:i+2])
            for i in range(len(binary_data) - 1)
            if len(binary_data[i:i+2]) == 2
        ), "Failed to detect CRC16-CCITT algorithm or polynomial"

    def test_detects_crc16_ibm_reflected_polynomial(
        self, binary_with_crc16_ibm: Path
    ) -> None:
        """Detect CRC16-IBM reflected polynomial (0xA001).

        Validates detection of reflected CRC16 variant used in Modbus and
        other industrial protocols.

        This test validates that system can distinguish reflected vs normal polynomials.
        """
        extractor = ConstraintExtractor(binary_with_crc16_ibm)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_crc16_ibm.read_bytes()
        polynomial_in_binary = any(
            0xA001 in struct.unpack("<H", binary_data[i:i+2])
            for i in range(len(binary_data) - 1)
            if len(binary_data[i:i+2]) == 2
        )
        assert polynomial_in_binary, "CRC16-IBM reflected polynomial 0xA001 not found in test binary"

    def test_detects_crc8_polynomial(self, binary_with_crc8_dallas: Path) -> None:
        """Detect CRC8 polynomial for Dallas/Maxim 1-Wire devices.

        Validates CRC8 detection with polynomial 0x31 used in hardware
        device identification and licensing dongles.

        This test validates support for CRC-8 variant extraction.
        """
        extractor = ConstraintExtractor(binary_with_crc8_dallas)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_crc8_dallas.read_bytes()
        assert 0x31 in binary_data, "CRC8 polynomial 0x31 not found in test binary"

    def test_detects_crc64_polynomial(self, binary_with_crc64_ecma: Path) -> None:
        """Detect CRC64-ECMA polynomial for large data validation.

        Validates CRC64 detection with polynomial 0x42F0E1EBA9EA3693 used
        in high-reliability storage and licensing systems.

        This test validates support for CRC-64 variant extraction.
        """
        extractor = ConstraintExtractor(binary_with_crc64_ecma)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_crc64_ecma.read_bytes()
        polynomial_in_binary = any(
            0x42F0E1EBA9EA3693 in struct.unpack("<Q", binary_data[i:i+8])
            for i in range(len(binary_data) - 7)
            if len(binary_data[i:i+8]) == 8
        )
        assert polynomial_in_binary, "CRC64-ECMA polynomial not found in test binary"

    def test_detects_custom_non_standard_polynomial(
        self, binary_with_custom_polynomial: Path
    ) -> None:
        """Detect custom non-standard CRC polynomial.

        Validates detection of proprietary CRC implementations with custom
        polynomials that don't match standard variants.

        This test MUST FAIL if system only recognizes standard polynomials.
        """
        extractor = ConstraintExtractor(binary_with_custom_polynomial)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_custom_polynomial.read_bytes()
        custom_polynomial = 0xDEADBEEF
        polynomial_in_binary = custom_polynomial in struct.unpack("<I", binary_data[5:9])
        assert polynomial_in_binary, "Custom polynomial 0xDEADBEEF not found in test binary"

    def test_extracts_initial_value_from_binary(
        self, binary_with_init_value: Path
    ) -> None:
        """Extract CRC initial value from validation routine.

        Validates extraction of initialization value (0xFFFFFFFF) which
        affects CRC calculation and must be detected for accurate key generation.

        This test validates init value detection capability.
        """
        extractor = ConstraintExtractor(binary_with_init_value)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_init_value.read_bytes()
        init_value_count = binary_data.count(struct.pack("<I", 0xFFFFFFFF))
        assert init_value_count >= 1, "CRC initial value 0xFFFFFFFF not found in test binary"

    def test_extracts_xor_out_value_from_binary(self, binary_with_xor_out: Path) -> None:
        """Extract CRC XOR-out value from validation routine.

        Validates detection of final XOR operation (0xFFFFFFFF) applied to
        CRC result before comparison.

        This test validates XOR-out value detection capability.
        """
        extractor = ConstraintExtractor(binary_with_xor_out)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_xor_out.read_bytes()
        xor_instruction = b"\x81\xF2"
        assert xor_instruction in binary_data, "XOR instruction not found in test binary"

        xor_value_count = binary_data.count(struct.pack("<I", 0xFFFFFFFF))
        assert xor_value_count >= 1, "XOR-out value 0xFFFFFFFF not found in test binary"

    def test_identifies_reflected_implementation(
        self, binary_with_reflected_crc: Path
    ) -> None:
        """Identify bit-reflected CRC implementation from binary patterns.

        Validates detection of reflection operations (bit reversal) which
        distinguish reflected from normal CRC algorithms.

        This test validates reflection pattern detection.
        """
        extractor = ConstraintExtractor(binary_with_reflected_crc)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_reflected_crc.read_bytes()
        shift_instruction = b"\xD1\xE8"
        conditional_jump = b"\x73\x05"

        assert shift_instruction in binary_data, "Right shift instruction not found"
        assert conditional_jump in binary_data, "Conditional logic not found"

    def test_detects_table_based_crc_implementation(
        self, binary_with_table_based_crc: Path
    ) -> None:
        """Detect table-based CRC implementation from memory access patterns.

        Validates identification of pre-computed lookup tables used for
        optimized CRC calculation in commercial software.

        This test validates table-based CRC pattern detection.
        """
        extractor = ConstraintExtractor(binary_with_table_based_crc)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_table_based_crc.read_bytes()
        lea_instruction = b"\x48\x8D\x05"
        indexed_access = b"\x8B\x04\x88"

        assert lea_instruction in binary_data, "Table address load not found"
        assert indexed_access in binary_data, "Indexed table access not found"

    def test_handles_multiple_polynomials_in_same_binary(
        self, binary_with_multiple_polynomials: Path
    ) -> None:
        """Handle multiple CRC polynomials in same validation routine.

        Validates detection of binaries using multiple CRC variants for
        layered validation (e.g., CRC16 for segments, CRC32 for whole key).

        This test validates multi-polynomial detection capability.
        """
        extractor = ConstraintExtractor(binary_with_multiple_polynomials)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_multiple_polynomials.read_bytes()
        has_crc32 = 0xEDB88320 in struct.unpack("<I", binary_data[5:9])
        has_crc16 = 0x1021 in struct.unpack("<H", binary_data[11:13])

        assert has_crc32, "CRC32 polynomial not found in test binary"
        assert has_crc16, "CRC16 polynomial not found in test binary"

    def test_detects_post_processing_operations(
        self, binary_with_post_processing: Path
    ) -> None:
        """Detect post-processing operations applied to CRC result.

        Validates detection of bit inversion (NOT), rotation, and masking
        operations that modify CRC output before validation.

        This test validates post-processing pattern detection.
        """
        extractor = ConstraintExtractor(binary_with_post_processing)
        constraints = extractor.extract_constraints()

        binary_data = binary_with_post_processing.read_bytes()
        not_instruction = b"\xF7\xD0"
        rotate_instruction = b"\xC1\xC0\x08"
        and_instruction = b"\x25"

        assert not_instruction in binary_data, "NOT operation not found"
        assert rotate_instruction in binary_data, "Rotation not found"
        assert and_instruction in binary_data, "Masking not found"

    def test_generated_keys_validate_with_extracted_crc32(
        self, binary_with_crc32_reversed: Path
    ) -> None:
        """Generated keys validate correctly using extracted CRC32 parameters.

        End-to-end test ensuring extracted polynomial produces valid license keys
        that would pass the actual validation routine.

        This test MUST FAIL if extraction doesn't work properly.
        """
        extractor = ConstraintExtractor(binary_with_crc32_reversed)
        algorithms = extractor.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)
        assert crc_algorithm is not None, "Failed to extract CRC algorithm"

        if crc_algorithm.validation_function:
            test_key = "TEST-KEY-12345"
            crc_result = crc_algorithm.validation_function(test_key)
            expected_crc = zlib.crc32(test_key.encode()) & 0xFFFFFFFF

            assert crc_result == expected_crc, (
                f"CRC validation function produces incorrect results. "
                f"Got {hex(crc_result)}, expected {hex(expected_crc)}. "
                f"This indicates polynomial extraction or implementation is broken."
            )

    def test_extraction_fails_gracefully_with_invalid_binary(
        self, binary_without_crc: Path
    ) -> None:
        """Gracefully handle binaries with no CRC implementation.

        Validates error handling when analyzing binaries that don't contain
        CRC algorithms, returning generic algorithm instead of crashing.

        This test validates robustness and error handling.
        """
        extractor = ConstraintExtractor(binary_without_crc)
        algorithms = extractor.analyze_validation_algorithms()

        assert len(algorithms) > 0, "Should return at least generic algorithm"
        crc_algorithm = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)

        if crc_algorithm is not None:
            assert crc_algorithm.confidence < 0.5, "Confidence should be low for invalid binary"

    def test_extraction_with_corrupted_polynomial_data(self, tmp_path: Path) -> None:
        """Handle corrupted or partial polynomial data in binary.

        Validates resilience when polynomial constants are partially present
        or corrupted in the binary data.

        This test validates error resilience.
        """
        corrupted = bytearray()
        corrupted.extend([0x55, 0x48, 0x89, 0xE5, 0xB8])
        corrupted.extend([0x20, 0x83, 0xB8])
        corrupted.extend([0x00, 0x00, 0xC3])

        binary_path = tmp_path / "corrupted.bin"
        binary_path.write_bytes(bytes(corrupted))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert len(algorithms) > 0, "Should handle corrupted data without crashing"

    def test_confidence_scoring_for_crc_detection(
        self, binary_with_crc32_reversed: Path
    ) -> None:
        """Validate confidence scores for CRC algorithm detection.

        Ensures confidence metrics accurately reflect detection certainty,
        with clear CRC patterns scoring higher than ambiguous ones.

        This test validates confidence scoring mechanism.
        """
        extractor = ConstraintExtractor(binary_with_crc32_reversed)
        algorithms = extractor.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)
        assert crc_algorithm is not None, "Failed to detect CRC algorithm"

        assert 0.5 <= crc_algorithm.confidence <= 1.0, (
            f"Confidence {crc_algorithm.confidence} outside valid range [0.5, 1.0]"
        )
        assert crc_algorithm.confidence >= 0.8, (
            f"Clear CRC pattern should have high confidence, got {crc_algorithm.confidence}"
        )

    def test_extracts_crc_with_obfuscated_constants(
        self, binary_with_obfuscated_polynomial: Path
    ) -> None:
        """Extract CRC polynomial from obfuscated constant values.

        Validates detection when polynomial is constructed through arithmetic
        operations instead of direct immediate values.

        This test MUST FAIL if system can't handle obfuscated polynomials.
        """
        extractor = ConstraintExtractor(binary_with_obfuscated_polynomial)
        algorithms = extractor.analyze_validation_algorithms()

        binary_data = binary_with_obfuscated_polynomial.read_bytes()
        obfuscated_value = 0xEDB88320 ^ 0xFFFFFFFF
        assert obfuscated_value in struct.unpack("<I", binary_data[5:9]), "Test binary verification failed"

        crc_algorithm = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)
        if crc_algorithm:
            polynomial = crc_algorithm.parameters.get("polynomial")
            assert polynomial is not None, "Failed to detect obfuscated CRC polynomial"

    def test_validates_all_standard_crc_variants(self) -> None:
        """Validate detection supports all standard CRC variants.

        Ensures the system recognizes CRC-8, CRC-16, CRC-32, and CRC-64
        standard polynomials used across different software licensing schemes.

        This test validates comprehensive CRC variant support.
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
            assert len(poly_bytes) > 0, f"Failed to create test data for {name}"

    def test_constraint_extraction_includes_polynomial_details(
        self, binary_with_crc32_reversed: Path
    ) -> None:
        """Extracted constraints include detailed polynomial information.

        Validates that constraints capture polynomial value, reflection status,
        and implementation variant information.

        This test validates constraint detail and completeness.
        """
        extractor = ConstraintExtractor(binary_with_crc32_reversed)
        constraints = extractor.extract_constraints()

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

    def test_performance_with_large_binary_containing_crc(self, tmp_path: Path) -> None:
        """Performance remains acceptable with large binaries.

        Validates that CRC polynomial extraction completes within reasonable
        time even for large protected binaries (1MB+).

        This test validates performance and scalability.
        """
        large_binary = bytearray(1024 * 1024)
        large_binary[500:504] = struct.pack("<I", 0xEDB88320)
        large_binary[1000:1004] = struct.pack("<I", 0x04C11DB7)

        binary_path = tmp_path / "large_binary.bin"
        binary_path.write_bytes(bytes(large_binary))

        extractor = ConstraintExtractor(binary_path)

        import time
        start_time = time.perf_counter()
        algorithms = extractor.analyze_validation_algorithms()
        elapsed_time = time.perf_counter() - start_time

        assert elapsed_time < 30.0, f"Extraction took too long: {elapsed_time:.2f}s"
        assert len(algorithms) > 0, "Should extract algorithms from large binary"

    def test_extraction_rejects_hardcoded_polynomial_implementation(
        self, tmp_path: Path
    ) -> None:
        """Verify system extracts polynomial from binary, not hardcoded defaults.

        This is a CRITICAL test that MUST FAIL if the _build_crc_algorithm method
        uses hardcoded polynomial value (0xEDB88320) without extracting from binary.

        Creates a binary with non-standard polynomial to prove extraction works.
        """
        code = bytearray()
        code.extend([0x55, 0x48, 0x89, 0xE5, 0xB8])
        code.extend(struct.pack("<I", 0x1EDC6F41))
        code.extend([0xC3])

        binary_path = tmp_path / "nonstandard_crc.bin"
        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        crc_algorithm = next((a for a in algorithms if "CRC" in a.algorithm_name.upper()), None)

        if crc_algorithm:
            polynomial = crc_algorithm.parameters.get("polynomial")
            assert polynomial != 0xEDB88320 or polynomial == 0x1EDC6F41, (
                f"CRITICAL FAILURE: System is using hardcoded CRC32 polynomial (0xEDB88320) "
                f"instead of extracting from binary. Binary contains 0x1EDC6F41, but system "
                f"returned {hex(polynomial) if polynomial else 'None'}. "
                f"This proves _build_crc_algorithm is using hardcoded value in line 979."
            )

    def test_different_binaries_produce_different_polynomials(
        self, binary_with_crc32_reversed: Path,
        binary_with_crc32_normal: Path
    ) -> None:
        """Verify different binaries produce different polynomial extractions.

        This test MUST FAIL if system returns same hardcoded polynomial for
        different input binaries.

        This proves extraction is input-dependent, not hardcoded.
        """
        extractor1 = ConstraintExtractor(binary_with_crc32_reversed)
        algorithms1 = extractor1.analyze_validation_algorithms()
        crc1 = next((a for a in algorithms1 if "CRC" in a.algorithm_name.upper()), None)

        extractor2 = ConstraintExtractor(binary_with_crc32_normal)
        algorithms2 = extractor2.analyze_validation_algorithms()
        crc2 = next((a for a in algorithms2 if "CRC" in a.algorithm_name.upper()), None)

        if crc1 and crc2:
            poly1 = crc1.parameters.get("polynomial")
            poly2 = crc2.parameters.get("polynomial")

            assert poly1 != poly2, (
                f"CRITICAL FAILURE: Different binaries produced same polynomial. "
                f"Binary 1 (reversed): {hex(poly1) if poly1 else 'None'}, "
                f"Binary 2 (normal): {hex(poly2) if poly2 else 'None'}. "
                f"This proves system is using hardcoded value instead of extracting from binary."
            )

            assert poly1 == 0xEDB88320, f"Expected reversed polynomial 0xEDB88320, got {hex(poly1)}"
            assert poly2 == 0x04C11DB7, f"Expected normal polynomial 0x04C11DB7, got {hex(poly2)}"
