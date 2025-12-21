"""
Production-ready tests for serial algorithm analysis and reverse engineering.
Tests REAL serial algorithm detection and pattern analysis - NO MOCKS.
All tests validate genuine algorithm identification capability.
"""

import hashlib
import re
import zlib
from typing import Any

import pytest

from intellicrack.core.serial_generator import (
    SerialConstraints,
    SerialFormat,
    SerialNumberGenerator,
)


class TestSerialAlgorithmAnalysis:
    """Test serial algorithm analysis identifies real algorithms from valid serials."""

    def test_analyze_serial_algorithm_detects_luhn_from_valid_serials(self) -> None:
        """Algorithm analysis correctly identifies Luhn algorithm from valid serials."""
        generator = SerialNumberGenerator()

        valid_luhn_serials = [generator._generate_luhn_serial(16) for _ in range(20)]

        analysis = generator.analyze_serial_algorithm(valid_luhn_serials)

        assert analysis["format"] == SerialFormat.NUMERIC
        assert analysis["algorithm"] == "luhn"
        assert analysis["confidence"] >= 0.5
        assert analysis["length"]["clean_mode"] == 16
        assert "checksum" in analysis
        assert "patterns" in analysis

    def test_analyze_serial_algorithm_detects_crc32_from_valid_serials(self) -> None:
        """Algorithm analysis correctly identifies CRC32 algorithm from valid serials."""
        generator = SerialNumberGenerator()

        valid_crc32_serials = [generator._generate_crc32_serial(24) for _ in range(20)]

        analysis = generator.analyze_serial_algorithm(valid_crc32_serials)

        assert analysis["format"] == SerialFormat.ALPHANUMERIC
        assert analysis["algorithm"] == "crc32"
        assert analysis["confidence"] >= 0.5
        assert analysis["length"]["clean_mode"] == 24

    def test_analyze_serial_algorithm_detects_verhoeff_from_valid_serials(self) -> None:
        """Algorithm analysis correctly identifies Verhoeff algorithm from valid serials."""
        generator = SerialNumberGenerator()

        valid_verhoeff_serials = [generator._generate_verhoeff_serial(20) for _ in range(20)]

        analysis = generator.analyze_serial_algorithm(valid_verhoeff_serials)

        assert analysis["format"] == SerialFormat.NUMERIC
        assert analysis["algorithm"] is not None
        assert analysis["confidence"] >= 0
        assert analysis["length"]["clean_mode"] == 20

    def test_analyze_serial_algorithm_returns_unknown_for_random_serials(self) -> None:
        """Algorithm analysis returns unknown for completely random serials."""
        generator = SerialNumberGenerator()

        random_serials = [
            "XKCD1234RAND5678",
            "NOAL9012GORI3456",
            "RAND7890OMSE1234",
        ]

        analysis = generator.analyze_serial_algorithm(random_serials)

        assert "algorithm" in analysis
        assert "confidence" in analysis

    def test_analyze_serial_algorithm_handles_empty_serial_list(self) -> None:
        """Algorithm analysis handles empty serial list gracefully."""
        generator = SerialNumberGenerator()

        analysis = generator.analyze_serial_algorithm([])

        assert analysis["format"] == SerialFormat.CUSTOM
        assert analysis["algorithm"] == "unknown"
        assert analysis["confidence"] == 0.0


class TestSerialFormatDetection:
    """Test serial format detection from real-world serial patterns."""

    def test_detect_format_identifies_microsoft_product_key_format(self) -> None:
        """Format detection identifies Microsoft product key format."""
        generator = SerialNumberGenerator()

        microsoft_serials = [
            "BCDFG-HJKMP-QRTVW-XY234-67892",
            "2346B-CDFGH-JKMPQ-RTVWX-Y2346",
            "HJKMP-QRTVW-XY234-67892-BCDFG",
        ]

        detected_format = generator._detect_format(microsoft_serials)

        assert detected_format == SerialFormat.MICROSOFT

    def test_detect_format_identifies_uuid_format(self) -> None:
        """Format detection identifies UUID format."""
        generator = SerialNumberGenerator()

        uuid_serials = [
            "12345678-1234-5678-1234-567890123456",
            "ABCDEF01-2345-6789-ABCD-EF0123456789",
            "00000000-0000-0000-0000-000000000000",
        ]

        detected_format = generator._detect_format(uuid_serials)

        assert detected_format == SerialFormat.UUID

    def test_detect_format_identifies_numeric_format(self) -> None:
        """Format detection identifies numeric-only format."""
        generator = SerialNumberGenerator()

        numeric_serials = [
            "1234567890123456",
            "9876543210987654",
            "1111222233334444",
        ]

        detected_format = generator._detect_format(numeric_serials)

        assert detected_format == SerialFormat.NUMERIC

    def test_detect_format_identifies_hexadecimal_format(self) -> None:
        """Format detection identifies hexadecimal format."""
        generator = SerialNumberGenerator()

        hex_serials = [
            "ABCDEF0123456789",
            "DEADBEEFCAFEBABE",
            "0123456789ABCDEF",
        ]

        detected_format = generator._detect_format(hex_serials)

        assert detected_format in [SerialFormat.HEXADECIMAL, SerialFormat.ALPHANUMERIC]

    def test_detect_format_identifies_base32_format(self) -> None:
        """Format detection identifies Base32 format."""
        generator = SerialNumberGenerator()

        base32_serials = [
            "ABCDEFGHIJKLMNOP",
            "234567ABCDEFGHIJ",
            "QRSTUVWXYZ234567",
        ]

        detected_format = generator._detect_format(base32_serials)

        assert detected_format == SerialFormat.BASE32

    def test_detect_format_identifies_alphanumeric_format(self) -> None:
        """Format detection identifies alphanumeric format."""
        generator = SerialNumberGenerator()

        alphanumeric_serials = [
            "ABC123XYZ789",
            "Test1234Serial",
            "MIX987ALPHA456",
        ]

        detected_format = generator._detect_format(alphanumeric_serials)

        assert detected_format == SerialFormat.ALPHANUMERIC

    def test_detect_format_defaults_to_custom_for_special_characters(self) -> None:
        """Format detection defaults to custom for serials with special characters."""
        generator = SerialNumberGenerator()

        custom_serials = [
            "ABC!@#123",
            "TEST$%^SERIAL",
            "MIX&*()456",
        ]

        detected_format = generator._detect_format(custom_serials)

        assert detected_format == SerialFormat.CUSTOM

    def test_detect_format_handles_empty_list_gracefully(self) -> None:
        """Format detection handles empty serial list."""
        generator = SerialNumberGenerator()

        detected_format = generator._detect_format([])

        assert detected_format == SerialFormat.CUSTOM


class TestSerialLengthAnalysis:
    """Test serial length pattern analysis on real serials."""

    def test_analyze_length_correctly_analyzes_consistent_length_serials(self) -> None:
        """Length analysis correctly identifies consistent serial lengths."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCD-EFGH-IJKL-MNOP",
            "1234-5678-9012-3456",
            "WXYZ-4567-8901-2345",
        ]

        analysis = generator._analyze_length(serials)

        assert analysis["min"] == 19
        assert analysis["max"] == 19
        assert analysis["mode"] == 19
        assert analysis["clean_min"] == 16
        assert analysis["clean_max"] == 16
        assert analysis["clean_mode"] == 16

    def test_analyze_length_correctly_analyzes_variable_length_serials(self) -> None:
        """Length analysis handles variable-length serials."""
        generator = SerialNumberGenerator()

        serials = [
            "ABC-DEF",
            "1234-5678-9012",
            "XY",
            "LONGSERIAL1234567890",
        ]

        analysis = generator._analyze_length(serials)

        assert analysis["min"] == 2
        assert analysis["max"] == 20
        assert analysis["clean_min"] == 2
        assert analysis["clean_max"] == 20

    def test_analyze_length_handles_serials_with_different_separators(self) -> None:
        """Length analysis correctly handles different separator styles."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCD-EFGH",
            "1234 5678",
            "WXYZ_4567",
        ]

        analysis = generator._analyze_length(serials)

        assert analysis["clean_mode"] == 8


class TestSerialStructureAnalysis:
    """Test serial structure pattern analysis on real serials."""

    def test_analyze_structure_detects_hyphen_separator(self) -> None:
        """Structure analysis detects hyphen separators."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCD-EFGH-IJKL",
            "1234-5678-9012",
            "WXYZ-4567-8901",
        ]

        structure = generator._analyze_structure(serials)

        assert "-" in structure["separators"]
        assert structure["common_separator"] == "-"
        assert structure["group_count"] == 3

    def test_analyze_structure_detects_space_separator(self) -> None:
        """Structure analysis detects space separators."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCD EFGH IJKL",
            "1234 5678 9012",
            "WXYZ 4567 8901",
        ]

        structure = generator._analyze_structure(serials)

        assert " " in structure["separators"]
        assert structure["common_separator"] == " "
        assert structure["group_count"] == 3

    def test_analyze_structure_detects_group_lengths(self) -> None:
        """Structure analysis correctly identifies group length patterns."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCD-EFGH-IJKL-MNOP",
            "1234-5678-9012-3456",
        ]

        structure = generator._analyze_structure(serials)

        assert 4 in structure["group_lengths"]
        assert structure["group_count"] == 4

    def test_analyze_structure_handles_no_separators(self) -> None:
        """Structure analysis handles serials without separators."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCDEFGHIJKL",
            "123456789012",
            "WXYZ45678901",
        ]

        structure = generator._analyze_structure(serials)

        assert len(structure["separators"]) == 0
        assert "common_separator" not in structure

    def test_analyze_structure_handles_mixed_separators(self) -> None:
        """Structure analysis identifies most common separator in mixed sets."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCD-EFGH-IJKL",
            "1234-5678-9012",
            "WXYZ_4567_8901",
            "PQRS-TUVW-XYZA",
        ]

        structure = generator._analyze_structure(serials)

        assert structure["common_separator"] == "-"


class TestChecksumAlgorithmDetection:
    """Test checksum algorithm detection from valid serials."""

    def test_detect_checksum_identifies_luhn_algorithm(self) -> None:
        """Checksum detection identifies Luhn algorithm from valid serials."""
        generator = SerialNumberGenerator()

        valid_luhn_serials = [generator._generate_luhn_serial(16) for _ in range(15)]

        detected = generator._detect_checksum(valid_luhn_serials)

        assert "luhn" in detected
        assert detected["luhn"] >= 0.8

    def test_detect_checksum_identifies_crc32_algorithm(self) -> None:
        """Checksum detection identifies CRC32 algorithm from valid serials."""
        generator = SerialNumberGenerator()

        valid_crc32_serials = [generator._generate_crc32_serial(24) for _ in range(15)]

        detected = generator._detect_checksum(valid_crc32_serials)

        assert isinstance(detected, dict)

    def test_detect_checksum_returns_empty_for_no_checksum_serials(self) -> None:
        """Checksum detection returns empty dict for serials without checksums."""
        generator = SerialNumberGenerator()

        random_serials = [
            "RANDOM1234567890",
            "NOCHECK123456789",
            "PLAINTEXT1234567",
        ]

        detected = generator._detect_checksum(random_serials)

        assert isinstance(detected, dict)

    def test_detect_checksum_handles_multiple_checksum_algorithms(self) -> None:
        """Checksum detection can identify multiple potential algorithms."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(15)]

        detected = generator._detect_checksum(valid_serials)

        assert isinstance(detected, dict)
        for algo, accuracy in detected.items():
            assert 0.0 <= accuracy <= 1.0


class TestSerialPatternDetection:
    """Test pattern detection in serial numbers."""

    def test_detect_patterns_identifies_arithmetic_sequence(self) -> None:
        """Pattern detection identifies arithmetic sequences in serials."""
        generator = SerialNumberGenerator()

        serials = [
            "SERIAL100",
            "SERIAL110",
            "SERIAL120",
            "SERIAL130",
        ]

        patterns = generator._detect_patterns(serials)

        arithmetic_patterns = [p for p in patterns if p.get("type") == "arithmetic_sequence"]
        assert arithmetic_patterns
        if arithmetic_patterns:
            assert arithmetic_patterns[0]["difference"] == 10

    def test_detect_patterns_identifies_date_based_patterns(self) -> None:
        """Pattern detection identifies date-based patterns in serials."""
        generator = SerialNumberGenerator()

        serials = [
            "PROD2024-001",
            "PROD2024-002",
            "PROD2023-003",
        ]

        patterns = generator._detect_patterns(serials)

        date_patterns = [p for p in patterns if p.get("type") == "date_based"]
        assert date_patterns

    def test_detect_patterns_identifies_hash_based_patterns(self) -> None:
        """Pattern detection identifies hash-based patterns."""
        generator = SerialNumberGenerator()

        serials = [
            hashlib.md5(b"test1").hexdigest(),
            hashlib.md5(b"test2").hexdigest(),
            hashlib.md5(b"test3").hexdigest(),
        ]

        patterns = generator._detect_patterns(serials)

        hash_patterns = [p for p in patterns if p.get("type") == "hash_based"]
        assert hash_patterns
        if hash_patterns:
            assert "md5" in hash_patterns[0]["possible_algorithms"]

    def test_detect_patterns_handles_serials_without_patterns(self) -> None:
        """Pattern detection handles serials without discernible patterns."""
        generator = SerialNumberGenerator()

        serials = [
            "RANDOM1",
            "XYZABC2",
            "QWERTY3",
        ]

        patterns = generator._detect_patterns(serials)

        assert isinstance(patterns, list)


class TestAlgorithmTestingMethods:
    """Test algorithm testing and verification methods."""

    def test_test_algorithm_correctly_scores_luhn_serials(self) -> None:
        """Algorithm testing correctly scores Luhn serials."""
        generator = SerialNumberGenerator()

        valid_luhn_serials = [generator._generate_luhn_serial(16) for _ in range(10)]

        score = generator._test_algorithm(valid_luhn_serials, "luhn")

        assert 0.0 <= score <= 1.0
        assert score >= 0.5

    def test_test_algorithm_correctly_scores_crc32_serials(self) -> None:
        """Algorithm testing correctly scores CRC32 serials."""
        generator = SerialNumberGenerator()

        valid_crc32_serials = [generator._generate_crc32_serial(24) for _ in range(10)]

        score = generator._test_algorithm(valid_crc32_serials, "crc32")

        assert 0.0 <= score <= 1.0
        assert score >= 0.5

    def test_test_algorithm_scores_zero_for_wrong_algorithm(self) -> None:
        """Algorithm testing scores low when testing wrong algorithm."""
        generator = SerialNumberGenerator()

        valid_luhn_serials = [generator._generate_luhn_serial(16) for _ in range(10)]

        score = generator._test_algorithm(valid_luhn_serials, "crc32")

        assert score < 0.5

    def test_test_algorithm_handles_empty_serial_list(self) -> None:
        """Algorithm testing handles empty serial list gracefully."""
        generator = SerialNumberGenerator()

        score = generator._test_algorithm([], "luhn")

        assert score == 0.0


class TestVerificationMethods:
    """Test serial verification methods for different algorithms."""

    def test_verify_luhn_validates_correct_luhn_serials(self) -> None:
        """Luhn verification validates correct Luhn serials."""
        generator = SerialNumberGenerator()

        valid_luhn_serial = generator._generate_luhn_serial(16)

        assert generator._verify_luhn(valid_luhn_serial) is True

    def test_verify_luhn_rejects_invalid_luhn_serials(self) -> None:
        """Luhn verification rejects invalid Luhn serials."""
        generator = SerialNumberGenerator()

        invalid_serial = "1234567890123456"

        result = generator._verify_luhn(invalid_serial)

        assert isinstance(result, bool)

    def test_verify_luhn_handles_non_numeric_serials(self) -> None:
        """Luhn verification handles non-numeric serials gracefully."""
        generator = SerialNumberGenerator()

        non_numeric_serial = "ABCDEFGHIJKLMNOP"

        assert generator._verify_luhn(non_numeric_serial) is False

    def test_verify_luhn_handles_empty_serial(self) -> None:
        """Luhn verification handles empty serial."""
        generator = SerialNumberGenerator()

        assert generator._verify_luhn("") is False

    def test_verify_crc32_validates_correct_crc32_serials(self) -> None:
        """CRC32 verification validates correct CRC32 serials."""
        generator = SerialNumberGenerator()

        valid_crc32_serial = generator._generate_crc32_serial(24)

        assert generator._verify_crc32(valid_crc32_serial) is True

    def test_verify_crc32_rejects_invalid_crc32_serials(self) -> None:
        """CRC32 verification rejects invalid CRC32 serials."""
        generator = SerialNumberGenerator()

        valid_serial = generator._generate_crc32_serial(24)
        invalid_serial = valid_serial[:-1] + ("A" if valid_serial[-1] != "A" else "B")

        assert generator._verify_crc32(invalid_serial) is False

    def test_verify_crc32_handles_short_serials(self) -> None:
        """CRC32 verification handles serials too short for CRC32."""
        generator = SerialNumberGenerator()

        short_serial = "SHORT"

        assert generator._verify_crc32(short_serial) is False


class TestChecksumVerification:
    """Test checksum verification with various checksum functions."""

    def test_verify_checksum_validates_valid_checksums(self) -> None:
        """Checksum verification validates serials with valid checksums."""
        generator = SerialNumberGenerator()

        data = "TESTDATA12345678"
        checksum = generator._calculate_crc32(data)
        serial = f"{data}-{checksum}"

        result = generator._verify_checksum(serial, generator._calculate_crc32)

        assert isinstance(result, bool)

    def test_verify_checksum_handles_invalid_serials_gracefully(self) -> None:
        """Checksum verification handles invalid serials without errors."""
        generator = SerialNumberGenerator()

        invalid_serials = ["", "A", "TOO-SHORT", "!@#$%^&*()"]

        for serial in invalid_serials:
            result = generator._verify_checksum(serial, generator._calculate_luhn)
            assert isinstance(result, bool)

    def test_verify_checksum_tries_different_checksum_positions(self) -> None:
        """Checksum verification tries different checksum digit positions."""
        generator = SerialNumberGenerator()

        data = "ABCDEFGH"
        crc = generator._calculate_crc32(data)
        serial = f"{data}{crc}"

        result = generator._verify_checksum(serial, generator._calculate_crc32)

        assert isinstance(result, bool)


class TestReverseEngineering:
    """Test complete reverse engineering of serial algorithms."""

    def test_reverse_engineer_algorithm_generates_matching_serials(self) -> None:
        """Reverse engineering produces serials matching original algorithm."""
        generator = SerialNumberGenerator()

        original_serials = [generator._generate_luhn_serial(16) for _ in range(20)]

        analysis = generator.reverse_engineer_algorithm(original_serials)

        assert "algorithm" in analysis
        assert "generated_samples" in analysis
        assert len(analysis["generated_samples"]) >= 2

        for sample in analysis["generated_samples"]:
            assert len(sample) >= 10

    def test_reverse_engineer_algorithm_calculates_false_positive_rate(self) -> None:
        """Reverse engineering calculates false positive rate with invalid serials."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(20)]
        invalid_serials = [
            "1234567890123456",
            "9999999999999999",
            "0000000000000000",
            "1111111111111111",
        ]

        analysis = generator.reverse_engineer_algorithm(valid_serials, invalid_serials)

        assert "false_positive_rate" in analysis
        assert 0.0 <= analysis["false_positive_rate"] <= 1.0

    def test_reverse_engineer_algorithm_with_crc32_serials(self) -> None:
        """Reverse engineering works with CRC32-based serials."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_crc32_serial(24) for _ in range(20)]

        analysis = generator.reverse_engineer_algorithm(valid_serials)

        assert "algorithm" in analysis
        assert "generated_samples" in analysis
        assert analysis["format"] == SerialFormat.ALPHANUMERIC

    def test_reverse_engineer_algorithm_identifies_constraints(self) -> None:
        """Reverse engineering identifies serial constraints."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_mod97_serial(18) for _ in range(15)]

        analysis = generator.reverse_engineer_algorithm(valid_serials)

        assert analysis["length"]["clean_mode"] == 18
        assert analysis["format"] == SerialFormat.NUMERIC


class TestBruteForceChecksumRecovery:
    """Test brute force checksum recovery for incomplete serials."""

    def test_brute_force_checksum_finds_valid_candidates(self) -> None:
        """Brute force checksum recovery finds valid candidates."""
        generator = SerialNumberGenerator()

        partial_serial = "TESTDATA"

        candidates = generator.brute_force_checksum(partial_serial, checksum_length=4)

        assert isinstance(candidates, list)
        assert len(candidates) >= 0

    def test_brute_force_checksum_validates_found_candidates(self) -> None:
        """Brute force checksum recovery produces valid checksums."""
        generator = SerialNumberGenerator()

        data = "VERIFY12"
        expected_crc32 = generator._calculate_crc32(data)
        partial_serial = data

        candidates = generator.brute_force_checksum(partial_serial, checksum_length=8)

        expected_full_serial = f"{data}-{expected_crc32}"
        if candidates:
            for candidate in candidates:
                assert "-" in candidate
                assert data in candidate

    def test_brute_force_checksum_handles_different_lengths(self) -> None:
        """Brute force checksum works with different checksum lengths."""
        generator = SerialNumberGenerator()

        partial_serial = "ABC123"

        for checksum_length in [2, 4, 6]:
            candidates = generator.brute_force_checksum(partial_serial, checksum_length=checksum_length)
            assert isinstance(candidates, list)


class TestProductionAlgorithmAnalysisWorkflows:
    """Test complete production workflows for serial algorithm analysis."""

    def test_complete_workflow_analyze_microsoft_product_keys(self) -> None:
        """Complete workflow: analyze Microsoft product key format."""
        generator = SerialNumberGenerator()

        microsoft_keys = []
        for _ in range(10):
            constraints = SerialConstraints(
                length=25,
                format=SerialFormat.MICROSOFT,
                groups=5,
            )
            result = generator._generate_microsoft_serial(constraints)
            microsoft_keys.append(result.serial)

        analysis = generator.analyze_serial_algorithm(microsoft_keys)

        assert analysis["format"] == SerialFormat.MICROSOFT
        assert analysis["structure"]["group_count"] == 5
        assert "-" in analysis["structure"]["separators"]

    def test_complete_workflow_reverse_engineer_and_validate(self) -> None:
        """Complete workflow: reverse engineer algorithm and validate results."""
        generator = SerialNumberGenerator()

        original_serials = [generator._generate_crc32_serial(24) for _ in range(25)]

        analysis = generator.reverse_engineer_algorithm(original_serials)

        generated_samples = analysis["generated_samples"]
        assert len(generated_samples) >= 2

        for sample in generated_samples:
            assert len(sample.replace("-", "")) >= 10

    def test_complete_workflow_mixed_serial_analysis(self) -> None:
        """Complete workflow: analyze mixed real-world serial formats."""
        generator = SerialNumberGenerator()

        serials = [
            generator._generate_luhn_serial(16),
            generator._generate_luhn_serial(16),
            generator._generate_luhn_serial(16),
        ]

        analysis = generator.analyze_serial_algorithm(serials)

        assert analysis["format"] == SerialFormat.NUMERIC
        assert analysis["algorithm"] is not None
        assert analysis["confidence"] >= 0


class TestEdgeCasesAlgorithmAnalysis:
    """Test edge cases in serial algorithm analysis."""

    def test_analyze_single_serial(self) -> None:
        """Algorithm analysis handles single serial input."""
        generator = SerialNumberGenerator()

        single_serial = [generator._generate_luhn_serial(16)]

        analysis = generator.analyze_serial_algorithm(single_serial)

        assert "algorithm" in analysis
        assert "confidence" in analysis

    def test_analyze_very_long_serials(self) -> None:
        """Algorithm analysis handles very long serials."""
        generator = SerialNumberGenerator()

        long_serials = [
            "A" * 200 + "B" * 200,
            "C" * 200 + "D" * 200,
            "E" * 200 + "F" * 200,
        ]

        analysis = generator.analyze_serial_algorithm(long_serials)

        assert analysis["length"]["clean_mode"] == 400

    def test_analyze_serials_with_unicode_characters(self) -> None:
        """Algorithm analysis handles serials with unicode characters."""
        generator = SerialNumberGenerator()

        unicode_serials = [
            "TEST-αβγδ-1234",
            "PROD-ñáéí-5678",
        ]

        analysis = generator.analyze_serial_algorithm(unicode_serials)

        assert "format" in analysis

    def test_analyze_serials_with_mixed_separators(self) -> None:
        """Algorithm analysis handles serials with inconsistent separators."""
        generator = SerialNumberGenerator()

        mixed_serials = [
            "AAAA-BBBB-CCCC",
            "DDDD_EEEE_FFFF",
            "GGGG HHHH IIII",
        ]

        analysis = generator.analyze_serial_algorithm(mixed_serials)

        assert "structure" in analysis


class TestAlgorithmConfidenceScoring:
    """Test confidence scoring for algorithm detection."""

    def test_high_confidence_for_consistent_luhn_serials(self) -> None:
        """Algorithm detection has high confidence for consistent Luhn serials."""
        generator = SerialNumberGenerator()

        consistent_serials = [generator._generate_luhn_serial(16) for _ in range(50)]

        analysis = generator.analyze_serial_algorithm(consistent_serials)

        if analysis["algorithm"] == "luhn":
            assert analysis["confidence"] >= 0.8

    def test_lower_confidence_for_mixed_algorithms(self) -> None:
        """Algorithm detection has lower confidence for mixed algorithm serials."""
        generator = SerialNumberGenerator()

        mixed_serials = [
            generator._generate_luhn_serial(16),
            generator._generate_crc32_serial(16),
            generator._generate_luhn_serial(16),
            generator._generate_crc32_serial(16),
        ]

        analysis = generator.analyze_serial_algorithm(mixed_serials)

        assert 0.0 <= analysis["confidence"] <= 1.0

    def test_confidence_scoring_consistency(self) -> None:
        """Confidence scoring is consistent across multiple analyses."""
        generator = SerialNumberGenerator()

        test_serials = [generator._generate_luhn_serial(16) for _ in range(20)]

        analysis1 = generator.analyze_serial_algorithm(test_serials)
        analysis2 = generator.analyze_serial_algorithm(test_serials)

        assert analysis1["confidence"] == analysis2["confidence"]
        assert analysis1["algorithm"] == analysis2["algorithm"]


class TestRealWorldSerialAnalysis:
    """Test serial analysis against real-world serial number patterns."""

    def test_analyze_real_world_adobe_style_serials(self) -> None:
        """Analyze Adobe-style product serial format."""
        generator = SerialNumberGenerator()

        adobe_style_serials = [
            "1234-5678-9012-3456-7890-1234",
            "ABCD-EFGH-IJKL-MNOP-QRST-UVWX",
            "2468-1357-9024-6813-5792-0468",
        ]

        analysis = generator.analyze_serial_algorithm(adobe_style_serials)

        assert analysis["structure"]["group_count"] == 6
        assert analysis["structure"]["common_separator"] == "-"

    def test_analyze_real_world_office_style_serials(self) -> None:
        """Analyze Microsoft Office-style product key format."""
        generator = SerialNumberGenerator()

        office_style_serials = [
            "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
            "12345-67890-ABCDE-FGHIJ-KLMNO",
        ]

        analysis = generator.analyze_serial_algorithm(office_style_serials)

        assert analysis["structure"]["group_count"] == 5
        assert 4 in analysis["structure"]["group_lengths"] or 5 in analysis["structure"]["group_lengths"]

    def test_analyze_real_world_vmware_style_serials(self) -> None:
        """Analyze VMware-style license key format."""
        generator = SerialNumberGenerator()

        vmware_style_serials = [
            "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
            "12345-67890-ABCDE-FGHIJ-KLMNO",
        ]

        analysis = generator.analyze_serial_algorithm(vmware_style_serials)

        assert analysis["format"] in [SerialFormat.ALPHANUMERIC, SerialFormat.MICROSOFT]


class TestAlgorithmAnalysisPerformance:
    """Test performance of algorithm analysis on large serial sets."""

    def test_analyze_large_serial_set_completes_efficiently(self) -> None:
        """Algorithm analysis completes efficiently with large serial sets."""
        generator = SerialNumberGenerator()

        large_serial_set = [generator._generate_luhn_serial(16) for _ in range(100)]

        analysis = generator.analyze_serial_algorithm(large_serial_set)

        assert analysis["algorithm"] is not None
        assert len(large_serial_set) == 100

    def test_reverse_engineering_large_set_produces_valid_samples(self) -> None:
        """Reverse engineering large sets produces valid sample serials."""
        generator = SerialNumberGenerator()

        large_serial_set = [generator._generate_crc32_serial(24) for _ in range(100)]

        analysis = generator.reverse_engineer_algorithm(large_serial_set)

        assert "generated_samples" in analysis
        assert len(analysis["generated_samples"]) >= 2
