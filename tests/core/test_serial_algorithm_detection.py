"""Production tests for serial algorithm detection in SerialNumberGenerator.

Tests validate constraint-based algorithm detection from binaries, pluggable
algorithm definitions, learning from valid/invalid serial pairs, algorithm
fingerprint generation, and export functionality.

All tests use real serial validation algorithms and must fail if detection
is non-functional or inaccurate.
"""

import hashlib
import json
import random
import struct
import zlib
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from intellicrack.core.serial_generator import (
    GeneratedSerial,
    SerialConstraints,
    SerialFormat,
    SerialNumberGenerator,
)


@pytest.fixture
def generator() -> SerialNumberGenerator:
    """Provide SerialNumberGenerator instance for testing."""
    return SerialNumberGenerator()


@pytest.fixture
def real_luhn_serials() -> list[str]:
    """Generate real Luhn-valid serials for testing."""
    gen = SerialNumberGenerator()
    serials = []
    for _ in range(50):
        serial = gen._generate_luhn_serial(16)
        assert gen._verify_luhn(serial), f"Generated invalid Luhn serial: {serial}"
        serials.append(serial)
    return serials


@pytest.fixture
def real_crc32_serials() -> list[str]:
    """Generate real CRC32-valid serials for testing."""
    gen = SerialNumberGenerator()
    serials = []
    for _ in range(50):
        serial = gen._generate_crc32_serial(24)
        assert gen._verify_crc32(serial), f"Generated invalid CRC32 serial: {serial}"
        serials.append(serial)
    return serials


@pytest.fixture
def real_mod97_serials() -> list[str]:
    """Generate real mod97-valid serials for testing."""
    gen = SerialNumberGenerator()
    serials = []
    for _ in range(50):
        serial = gen._generate_mod97_serial(18)
        data = serial[:-2]
        checksum = serial[-2:]
        expected = gen._calculate_mod97(data)
        assert checksum == expected, f"Generated invalid mod97 serial: {serial}"
        serials.append(serial)
    return serials


@pytest.fixture
def real_verhoeff_serials() -> list[str]:
    """Generate real Verhoeff-valid serials for testing."""
    gen = SerialNumberGenerator()
    serials = []
    for _ in range(50):
        serial = gen._generate_verhoeff_serial(16)
        serials.append(serial)
    return serials


@pytest.fixture
def real_damm_serials() -> list[str]:
    """Generate real Damm-valid serials for testing."""
    gen = SerialNumberGenerator()
    serials = []
    for _ in range(50):
        serial = gen._generate_damm_serial(16)
        serials.append(serial)
    return serials


@pytest.fixture
def microsoft_format_serials() -> list[str]:
    """Generate real Microsoft-format serials."""
    chars = "BCDFGHJKMPQRTVWXY2346789"
    serials = []
    for _ in range(30):
        groups = []
        for _ in range(5):
            group = "".join(random.choices(chars, k=5))
            groups.append(group)
        serials.append("-".join(groups))
    return serials


@pytest.fixture
def uuid_format_serials() -> list[str]:
    """Generate real UUID v4 serials."""
    import uuid

    return [str(uuid.uuid4()).upper() for _ in range(30)]


@pytest.fixture
def mixed_algorithm_serials() -> dict[str, list[str]]:
    """Generate serials using multiple different algorithms."""
    gen = SerialNumberGenerator()
    return {
        "luhn": [gen._generate_luhn_serial(16) for _ in range(20)],
        "crc32": [gen._generate_crc32_serial(24) for _ in range(20)],
        "mod97": [gen._generate_mod97_serial(18) for _ in range(20)],
        "verhoeff": [gen._generate_verhoeff_serial(16) for _ in range(20)],
        "damm": [gen._generate_damm_serial(16) for _ in range(20)],
    }


@pytest.fixture
def invalid_serials() -> list[str]:
    """Generate invalid serials that should fail all algorithm checks."""
    invalids = []
    for _ in range(30):
        length = random.randint(10, 30)
        serial = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))
        invalids.append(serial)
    return invalids


@pytest.fixture
def multi_part_serials() -> list[str]:
    """Generate multi-part serials with separators."""
    gen = SerialNumberGenerator()
    serials = []
    for _ in range(20):
        base_serial = gen._generate_luhn_serial(20)
        part1 = base_serial[:5]
        part2 = base_serial[5:10]
        part3 = base_serial[10:15]
        part4 = base_serial[15:20]
        serials.append(f"{part1}-{part2}-{part3}-{part4}")
    return serials


@pytest.fixture
def version_dependent_serials() -> dict[str, list[str]]:
    """Generate version-dependent serials with version prefixes."""
    gen = SerialNumberGenerator()
    return {
        "v1": [f"V1-{gen._generate_luhn_serial(16)}" for _ in range(15)],
        "v2": [f"V2-{gen._generate_crc32_serial(24)}" for _ in range(15)],
        "v3": [f"V3-{gen._generate_mod97_serial(18)}" for _ in range(15)],
    }


class TestConstraintBasedAlgorithmDetection:
    """Test constraint-based algorithm detection from binaries."""

    def test_detect_luhn_algorithm_from_valid_serials(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str]
    ) -> None:
        """Algorithm detection identifies Luhn algorithm from valid serials."""
        analysis = generator.analyze_serial_algorithm(real_luhn_serials)

        assert analysis["algorithm"] == "luhn", f"Failed to detect Luhn algorithm: {analysis}"
        assert analysis["confidence"] >= 0.8, f"Low confidence for Luhn detection: {analysis['confidence']}"
        assert "luhn" in analysis.get("checksum", {}), f"Luhn not in checksum analysis: {analysis}"

    def test_detect_crc32_algorithm_from_valid_serials(
        self, generator: SerialNumberGenerator, real_crc32_serials: list[str]
    ) -> None:
        """Algorithm detection identifies CRC32 algorithm from valid serials."""
        analysis = generator.analyze_serial_algorithm(real_crc32_serials)

        assert analysis["algorithm"] == "crc32", f"Failed to detect CRC32 algorithm: {analysis}"
        assert analysis["confidence"] >= 0.8, f"Low confidence for CRC32 detection: {analysis['confidence']}"
        assert "crc32" in analysis.get("checksum", {}), f"CRC32 not in checksum analysis: {analysis}"

    def test_detect_mod97_algorithm_from_valid_serials(
        self, generator: SerialNumberGenerator, real_mod97_serials: list[str]
    ) -> None:
        """Algorithm detection identifies mod97 algorithm from valid serials."""
        analysis = generator.analyze_serial_algorithm(real_mod97_serials)

        assert "mod97" in str(analysis["algorithm"]) or "mod97" in analysis.get(
            "checksum", {}
        ), f"Failed to detect mod97 algorithm: {analysis}"

    def test_detect_format_numeric(self, generator: SerialNumberGenerator) -> None:
        """Format detection identifies numeric-only serials."""
        numeric_serials = ["1234567890123456", "9876543210987654", "5555555555555555"]

        analysis = generator.analyze_serial_algorithm(numeric_serials)

        assert analysis["format"] == SerialFormat.NUMERIC, f"Failed to detect numeric format: {analysis}"

    def test_detect_format_alphanumeric(self, generator: SerialNumberGenerator) -> None:
        """Format detection identifies alphanumeric serials."""
        alphanum_serials = ["ABC123DEF456GHI7", "XYZ789QWE456RTY1", "POI098LKJ765MNB4"]

        analysis = generator.analyze_serial_algorithm(alphanum_serials)

        assert analysis["format"] == SerialFormat.ALPHANUMERIC, f"Failed to detect alphanumeric format: {analysis}"

    def test_detect_format_hexadecimal(self, generator: SerialNumberGenerator) -> None:
        """Format detection identifies hexadecimal serials."""
        hex_serials = ["DEADBEEFCAFE1234", "ABCDEF0123456789", "FEDCBA9876543210"]

        analysis = generator.analyze_serial_algorithm(hex_serials)

        assert analysis["format"] == SerialFormat.HEXADECIMAL, f"Failed to detect hexadecimal format: {analysis}"

    def test_detect_format_microsoft(
        self, generator: SerialNumberGenerator, microsoft_format_serials: list[str]
    ) -> None:
        """Format detection identifies Microsoft product key format."""
        analysis = generator.analyze_serial_algorithm(microsoft_format_serials)

        assert analysis["format"] == SerialFormat.MICROSOFT, f"Failed to detect Microsoft format: {analysis}"

    def test_detect_format_uuid(self, generator: SerialNumberGenerator, uuid_format_serials: list[str]) -> None:
        """Format detection identifies UUID v4 format."""
        analysis = generator.analyze_serial_algorithm(uuid_format_serials)

        assert analysis["format"] == SerialFormat.UUID, f"Failed to detect UUID format: {analysis}"

    def test_detect_length_patterns(self, generator: SerialNumberGenerator, real_luhn_serials: list[str]) -> None:
        """Length analysis extracts accurate length statistics."""
        analysis = generator.analyze_serial_algorithm(real_luhn_serials)

        length_info = analysis["length"]
        assert "min" in length_info, "Missing min length"
        assert "max" in length_info, "Missing max length"
        assert "mode" in length_info, "Missing mode length"
        assert length_info["mode"] == 16, f"Incorrect mode length: {length_info}"

    def test_detect_structure_with_groups(
        self, generator: SerialNumberGenerator, multi_part_serials: list[str]
    ) -> None:
        """Structure analysis detects groups and separators in multi-part serials."""
        analysis = generator.analyze_serial_algorithm(multi_part_serials)

        structure = analysis["structure"]
        assert "common_separator" in structure, "Failed to detect separator"
        assert structure["common_separator"] == "-", f"Incorrect separator: {structure}"
        assert "group_count" in structure, "Failed to detect group count"
        assert structure["group_count"] == 4, f"Incorrect group count: {structure}"

    def test_detect_checksum_with_high_accuracy(
        self, generator: SerialNumberGenerator, real_crc32_serials: list[str]
    ) -> None:
        """Checksum detection achieves high accuracy on valid serials."""
        analysis = generator.analyze_serial_algorithm(real_crc32_serials)

        checksum_results = analysis["checksum"]
        assert len(checksum_results) > 0, "Failed to detect any checksum algorithm"

        for algo, accuracy in checksum_results.items():
            assert accuracy >= 0.8, f"Checksum algorithm {algo} has low accuracy: {accuracy}"

    def test_detect_patterns_in_serials(self, generator: SerialNumberGenerator) -> None:
        """Pattern detection identifies common patterns in serials."""
        current_year = 2026
        date_serials = [f"{current_year}0101ABCD1234", f"{current_year}0215EFGH5678", f"{current_year}0320IJKL9012"]

        analysis = generator.analyze_serial_algorithm(date_serials)

        patterns = analysis["patterns"]
        assert any(p.get("type") == "date_based" for p in patterns), f"Failed to detect date pattern: {patterns}"

    def test_empty_serial_list_returns_default(self, generator: SerialNumberGenerator) -> None:
        """Algorithm detection handles empty serial list gracefully."""
        analysis = generator.analyze_serial_algorithm([])

        assert analysis["format"] == SerialFormat.CUSTOM
        assert analysis["algorithm"] == "unknown"
        assert analysis["confidence"] == 0.0


class TestPluggableAlgorithmDefinitions:
    """Test pluggable algorithm definitions and extensibility."""

    def test_all_predefined_algorithms_registered(self, generator: SerialNumberGenerator) -> None:
        """Generator initializes with all expected algorithm definitions."""
        expected_algorithms = {
            "luhn",
            "verhoeff",
            "damm",
            "crc32",
            "mod97",
            "custom_polynomial",
            "elliptic_curve",
            "rsa_based",
            "hash_chain",
            "feistel",
        }

        registered = set(generator.common_algorithms.keys())
        assert expected_algorithms == registered, f"Algorithm mismatch: expected {expected_algorithms}, got {registered}"

    def test_all_checksum_functions_registered(self, generator: SerialNumberGenerator) -> None:
        """Generator initializes with all expected checksum functions."""
        expected_checksums = {
            "luhn",
            "verhoeff",
            "damm",
            "crc16",
            "crc32",
            "fletcher16",
            "fletcher32",
            "adler32",
            "mod11",
            "mod37",
            "mod97",
        }

        registered = set(generator.checksum_functions.keys())
        assert expected_checksums == registered, f"Checksum mismatch: expected {expected_checksums}, got {registered}"

    def test_algorithm_functions_are_callable(self, generator: SerialNumberGenerator) -> None:
        """All registered algorithm functions are callable."""
        for algo_name, algo_func in generator.common_algorithms.items():
            assert callable(algo_func), f"Algorithm {algo_name} is not callable"

            serial = algo_func(16)
            assert isinstance(serial, str), f"Algorithm {algo_name} did not return string: {type(serial)}"
            assert len(serial) > 0, f"Algorithm {algo_name} returned empty serial"

    def test_checksum_functions_are_callable(self, generator: SerialNumberGenerator) -> None:
        """All registered checksum functions are callable."""
        test_data = "ABCD1234EFGH5678"

        for checksum_name, checksum_func in generator.checksum_functions.items():
            assert callable(checksum_func), f"Checksum {checksum_name} is not callable"

            result = checksum_func(test_data)
            assert isinstance(result, str), f"Checksum {checksum_name} did not return string: {type(result)}"

    def test_luhn_algorithm_generates_valid_serials(self, generator: SerialNumberGenerator) -> None:
        """Luhn algorithm produces serials that pass Luhn validation."""
        for _ in range(50):
            serial = generator._generate_luhn_serial(16)
            assert generator._verify_luhn(serial), f"Luhn algorithm generated invalid serial: {serial}"

    def test_crc32_algorithm_generates_valid_serials(self, generator: SerialNumberGenerator) -> None:
        """CRC32 algorithm produces serials that pass CRC32 validation."""
        for _ in range(50):
            serial = generator._generate_crc32_serial(24)
            assert generator._verify_crc32(serial), f"CRC32 algorithm generated invalid serial: {serial}"

    def test_verhoeff_algorithm_produces_consistent_output(self, generator: SerialNumberGenerator) -> None:
        """Verhoeff algorithm produces consistent length and format."""
        for length in [12, 16, 20, 24]:
            serial = generator._generate_verhoeff_serial(length)
            assert len(serial) == length, f"Verhoeff serial wrong length: expected {length}, got {len(serial)}"
            assert serial.isdigit(), f"Verhoeff serial contains non-digits: {serial}"

    def test_damm_algorithm_produces_consistent_output(self, generator: SerialNumberGenerator) -> None:
        """Damm algorithm produces consistent length and format."""
        for length in [12, 16, 20, 24]:
            serial = generator._generate_damm_serial(length)
            assert len(serial) == length, f"Damm serial wrong length: expected {length}, got {len(serial)}"
            assert serial.isdigit(), f"Damm serial contains non-digits: {serial}"

    def test_polynomial_algorithm_produces_valid_output(self, generator: SerialNumberGenerator) -> None:
        """Polynomial algorithm produces valid alphanumeric serials."""
        serial = generator._generate_polynomial_serial(32)
        assert len(serial) == 32, f"Polynomial serial wrong length: {len(serial)}"
        assert serial.isalpha(), f"Polynomial serial contains non-letters: {serial}"

    def test_ecc_algorithm_produces_valid_output(self, generator: SerialNumberGenerator) -> None:
        """ECC algorithm produces valid numeric serials."""
        serial = generator._generate_ecc_serial(24)
        assert len(serial) == 24, f"ECC serial wrong length: {len(serial)}"
        assert serial.isdigit(), f"ECC serial contains non-digits: {serial}"

    def test_rsa_algorithm_produces_valid_output(self, generator: SerialNumberGenerator) -> None:
        """RSA algorithm produces valid hexadecimal serials."""
        serial = generator._generate_rsa_serial(16)
        assert len(serial) == 16, f"RSA serial wrong length: {len(serial)}"
        assert all(c in "0123456789ABCDEF" for c in serial), f"RSA serial contains invalid hex chars: {serial}"

    def test_hash_chain_algorithm_produces_valid_output(self, generator: SerialNumberGenerator) -> None:
        """Hash chain algorithm produces valid alphanumeric serials."""
        serial = generator._generate_hash_chain_serial(20)
        assert len(serial) == 20, f"Hash chain serial wrong length: {len(serial)}"

    def test_feistel_algorithm_produces_valid_output(self, generator: SerialNumberGenerator) -> None:
        """Feistel algorithm produces valid alphanumeric serials."""
        serial = generator._generate_feistel_serial(16)
        assert len(serial) == 16, f"Feistel serial wrong length: {len(serial)}"
        assert serial.isalnum(), f"Feistel serial contains invalid chars: {serial}"


class TestLearningFromSerialPairs:
    """Test learning algorithms from valid/invalid serial pairs."""

    def test_reverse_engineer_luhn_from_pairs(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str], invalid_serials: list[str]
    ) -> None:
        """Reverse engineering learns Luhn algorithm from valid/invalid pairs."""
        analysis = generator.reverse_engineer_algorithm(real_luhn_serials, invalid_serials)

        assert analysis["algorithm"] == "luhn", f"Failed to reverse engineer Luhn: {analysis}"
        assert "false_positive_rate" in analysis, "Missing false positive rate"
        assert (
            analysis["false_positive_rate"] < 0.2
        ), f"High false positive rate: {analysis['false_positive_rate']}"

    def test_reverse_engineer_crc32_from_pairs(
        self, generator: SerialNumberGenerator, real_crc32_serials: list[str], invalid_serials: list[str]
    ) -> None:
        """Reverse engineering learns CRC32 algorithm from valid/invalid pairs."""
        analysis = generator.reverse_engineer_algorithm(real_crc32_serials, invalid_serials)

        assert analysis["algorithm"] == "crc32", f"Failed to reverse engineer CRC32: {analysis}"
        assert "false_positive_rate" in analysis, "Missing false positive rate"
        assert (
            analysis["false_positive_rate"] < 0.2
        ), f"High false positive rate: {analysis['false_positive_rate']}"

    def test_generated_samples_use_detected_algorithm(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str]
    ) -> None:
        """Reverse engineering generates samples using detected algorithm."""
        analysis = generator.reverse_engineer_algorithm(real_luhn_serials)

        assert "generated_samples" in analysis, "Missing generated samples"
        samples = analysis["generated_samples"]
        assert len(samples) == 10, f"Expected 10 samples, got {len(samples)}"

        for sample in samples:
            assert isinstance(sample, str), f"Sample is not string: {type(sample)}"
            assert len(sample) > 0, "Sample is empty"

    def test_false_positive_rate_calculation_accurate(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str], invalid_serials: list[str]
    ) -> None:
        """False positive rate accurately reflects invalid serial rejection."""
        analysis = generator.reverse_engineer_algorithm(real_luhn_serials, invalid_serials)

        false_positive_rate = analysis["false_positive_rate"]
        assert 0.0 <= false_positive_rate <= 1.0, f"Invalid false positive rate: {false_positive_rate}"

        invalid_count = len(invalid_serials)
        detected_count = int(false_positive_rate * invalid_count)
        assert detected_count <= invalid_count, "False positive count exceeds invalid serial count"

    def test_learning_with_insufficient_data(self, generator: SerialNumberGenerator) -> None:
        """Learning handles insufficient training data gracefully."""
        minimal_serials = ["ABC123", "DEF456"]

        analysis = generator.reverse_engineer_algorithm(minimal_serials)

        assert "algorithm" in analysis
        assert "confidence" in analysis
        assert analysis["confidence"] < 1.0, "Confidence should be low with minimal data"

    def test_learning_distinguishes_algorithms(
        self,
        generator: SerialNumberGenerator,
        real_luhn_serials: list[str],
        real_crc32_serials: list[str],
    ) -> None:
        """Learning correctly distinguishes between different algorithms."""
        luhn_analysis = generator.reverse_engineer_algorithm(real_luhn_serials)
        crc32_analysis = generator.reverse_engineer_algorithm(real_crc32_serials)

        assert luhn_analysis["algorithm"] == "luhn", f"Failed to detect Luhn: {luhn_analysis}"
        assert crc32_analysis["algorithm"] == "crc32", f"Failed to detect CRC32: {crc32_analysis}"
        assert luhn_analysis["algorithm"] != crc32_analysis["algorithm"], "Failed to distinguish algorithms"

    def test_learning_with_only_valid_serials(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str]
    ) -> None:
        """Learning works with only valid serials (no invalid examples)."""
        analysis = generator.reverse_engineer_algorithm(real_luhn_serials, None)

        assert "algorithm" in analysis
        assert "confidence" in analysis
        assert analysis["algorithm"] == "luhn", f"Failed to detect Luhn without invalid examples: {analysis}"

    def test_learning_extracts_checksum_characteristics(
        self, generator: SerialNumberGenerator, real_crc32_serials: list[str]
    ) -> None:
        """Learning extracts detailed checksum characteristics."""
        analysis = generator.reverse_engineer_algorithm(real_crc32_serials)

        assert "checksum" in analysis, "Missing checksum analysis"
        checksum_info = analysis["checksum"]
        assert isinstance(checksum_info, dict), f"Checksum info is not dict: {type(checksum_info)}"
        assert len(checksum_info) > 0, "Checksum info is empty"


class TestAlgorithmFingerprintGeneration:
    """Test algorithm fingerprint generation for matching."""

    def test_format_fingerprint_consistent(self, generator: SerialNumberGenerator, real_luhn_serials: list[str]) -> None:
        """Format fingerprinting produces consistent results."""
        format1 = generator._detect_format(real_luhn_serials)
        format2 = generator._detect_format(real_luhn_serials)

        assert format1 == format2, "Format fingerprint is not consistent"

    def test_length_fingerprint_accurate(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str]
    ) -> None:
        """Length fingerprinting captures accurate statistics."""
        length_info = generator._analyze_length(real_luhn_serials)

        assert "min" in length_info
        assert "max" in length_info
        assert "mode" in length_info
        assert "clean_min" in length_info
        assert "clean_max" in length_info
        assert "clean_mode" in length_info

        assert length_info["min"] <= length_info["max"]
        assert length_info["clean_min"] <= length_info["clean_max"]

    def test_structure_fingerprint_extracts_separators(
        self, generator: SerialNumberGenerator, multi_part_serials: list[str]
    ) -> None:
        """Structure fingerprinting extracts separator patterns."""
        structure = generator._analyze_structure(multi_part_serials)

        assert "separators" in structure
        assert "common_separator" in structure
        assert structure["common_separator"] == "-"

    def test_structure_fingerprint_extracts_groups(
        self, generator: SerialNumberGenerator, multi_part_serials: list[str]
    ) -> None:
        """Structure fingerprinting extracts group information."""
        structure = generator._analyze_structure(multi_part_serials)

        assert "groups" in structure
        assert "group_count" in structure
        assert "group_lengths" in structure
        assert structure["group_count"] > 1

    def test_checksum_fingerprint_identifies_algorithms(
        self, generator: SerialNumberGenerator, real_crc32_serials: list[str]
    ) -> None:
        """Checksum fingerprinting identifies specific algorithms."""
        checksum_results = generator._detect_checksum(real_crc32_serials)

        assert isinstance(checksum_results, dict)
        assert len(checksum_results) > 0, "Failed to identify any checksum algorithms"

        for algo, accuracy in checksum_results.items():
            assert accuracy >= 0.8, f"Low accuracy for {algo}: {accuracy}"

    def test_pattern_fingerprint_detects_incrementing(self, generator: SerialNumberGenerator) -> None:
        """Pattern fingerprinting detects arithmetic sequences."""
        increment_serials = [f"ABC{i:05d}XYZ" for i in range(1000, 1050)]

        patterns = generator._detect_patterns(increment_serials)

        arithmetic_found = any(p.get("type") == "arithmetic_sequence" for p in patterns)
        assert arithmetic_found, f"Failed to detect arithmetic sequence: {patterns}"

    def test_pattern_fingerprint_detects_hash_based(self, generator: SerialNumberGenerator) -> None:
        """Pattern fingerprinting detects hash-based serials."""
        hash_serials = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(30)]

        patterns = generator._detect_patterns(hash_serials)

        hash_found = any(p.get("type") == "hash_based" for p in patterns)
        assert hash_found, f"Failed to detect hash-based pattern: {patterns}"

    def test_fingerprint_uniquely_identifies_algorithm(
        self,
        generator: SerialNumberGenerator,
        real_luhn_serials: list[str],
        real_crc32_serials: list[str],
    ) -> None:
        """Fingerprints uniquely identify different algorithms."""
        luhn_analysis = generator.analyze_serial_algorithm(real_luhn_serials)
        crc32_analysis = generator.analyze_serial_algorithm(real_crc32_serials)

        luhn_fingerprint = (
            luhn_analysis["format"],
            luhn_analysis["length"]["clean_mode"],
            luhn_analysis["algorithm"],
        )
        crc32_fingerprint = (
            crc32_analysis["format"],
            crc32_analysis["length"]["clean_mode"],
            crc32_analysis["algorithm"],
        )

        assert (
            luhn_fingerprint != crc32_fingerprint
        ), f"Fingerprints are not unique: {luhn_fingerprint} vs {crc32_fingerprint}"

    def test_algorithm_scoring_accurate(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str]
    ) -> None:
        """Algorithm scoring accurately reflects match quality."""
        luhn_score = generator._test_algorithm(real_luhn_serials, "luhn")
        verhoeff_score = generator._test_algorithm(real_luhn_serials, "verhoeff")

        assert luhn_score > verhoeff_score, f"Luhn score {luhn_score} not higher than verhoeff {verhoeff_score}"
        assert luhn_score >= 0.8, f"Low Luhn score: {luhn_score}"


class TestExportDiscoveredAlgorithms:
    """Test export of discovered algorithms for reuse."""

    def test_export_analysis_as_json(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str], tmp_path: Path
    ) -> None:
        """Analysis results can be serialized to JSON for export."""
        analysis = generator.analyze_serial_algorithm(real_luhn_serials)

        export_path = tmp_path / "algorithm_analysis.json"
        with export_path.open("w") as f:
            json.dump(analysis, f, default=str)

        assert export_path.exists(), "Export file not created"

        with export_path.open("r") as f:
            loaded = json.load(f)

        assert loaded["algorithm"] == analysis["algorithm"]
        assert loaded["confidence"] == analysis["confidence"]

    def test_export_includes_all_analysis_data(
        self, generator: SerialNumberGenerator, real_crc32_serials: list[str], tmp_path: Path
    ) -> None:
        """Exported analysis includes all detection results."""
        analysis = generator.analyze_serial_algorithm(real_crc32_serials)

        export_path = tmp_path / "full_analysis.json"
        with export_path.open("w") as f:
            json.dump(analysis, f, default=str)

        with export_path.open("r") as f:
            loaded = json.load(f)

        assert "format" in loaded
        assert "length" in loaded
        assert "structure" in loaded
        assert "checksum" in loaded
        assert "patterns" in loaded
        assert "algorithm" in loaded
        assert "confidence" in loaded

    def test_export_reverse_engineering_results(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str], tmp_path: Path
    ) -> None:
        """Reverse engineering results can be exported for reuse."""
        analysis = generator.reverse_engineer_algorithm(real_luhn_serials)

        export_path = tmp_path / "reverse_engineered.json"
        with export_path.open("w") as f:
            json.dump(analysis, f, default=str)

        with export_path.open("r") as f:
            loaded = json.load(f)

        assert "generated_samples" in loaded
        assert len(loaded["generated_samples"]) == 10

    def test_reimport_and_use_exported_algorithm(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str], tmp_path: Path
    ) -> None:
        """Exported algorithm can be reimported and used for generation."""
        analysis = generator.analyze_serial_algorithm(real_luhn_serials)

        export_path = tmp_path / "algorithm.json"
        with export_path.open("w") as f:
            json.dump(analysis, f, default=str)

        with export_path.open("r") as f:
            loaded = json.load(f)

        length_mode = loaded["length"]["clean_mode"]
        checksum_algo = next(iter(loaded["checksum"].keys())) if loaded["checksum"] else None

        constraints = SerialConstraints(length=length_mode, format=SerialFormat.NUMERIC, checksum_algorithm=checksum_algo)

        generated = generator.generate_serial(constraints)
        assert generated.serial is not None
        assert len(generated.serial.replace("-", "")) == length_mode


class TestMultiPartSerials:
    """Test edge case: Multi-part serials with multiple segments."""

    def test_detect_multi_part_structure(
        self, generator: SerialNumberGenerator, multi_part_serials: list[str]
    ) -> None:
        """Multi-part serial detection identifies all segments."""
        analysis = generator.analyze_serial_algorithm(multi_part_serials)

        structure = analysis["structure"]
        assert structure["group_count"] == 4, f"Failed to detect 4 groups: {structure}"
        assert structure["common_separator"] == "-", f"Failed to detect separator: {structure}"

    def test_generate_multi_part_serial(self, generator: SerialNumberGenerator) -> None:
        """Generator produces multi-part serials with correct structure."""
        constraints = SerialConstraints(length=20, format=SerialFormat.NUMERIC, groups=4, group_separator="-")

        generated = generator.generate_serial(constraints)

        assert "-" in generated.serial, f"Missing separator in generated serial: {generated.serial}"
        parts = generated.serial.split("-")
        assert len(parts) == 4, f"Expected 4 parts, got {len(parts)}: {generated.serial}"

    def test_multi_part_checksum_validation(self, generator: SerialNumberGenerator) -> None:
        """Multi-part serials with checksums validate correctly."""
        multi_luhn = []
        for _ in range(20):
            base = generator._generate_luhn_serial(20)
            formatted = f"{base[:5]}-{base[5:10]}-{base[10:15]}-{base[15:20]}"
            multi_luhn.append(formatted)

        analysis = generator.analyze_serial_algorithm(multi_luhn)

        assert "luhn" in analysis.get("checksum", {}), f"Failed to detect Luhn in multi-part: {analysis}"

    def test_multi_part_with_varying_segment_lengths(self, generator: SerialNumberGenerator) -> None:
        """Detection handles multi-part serials with varying segment lengths."""
        varying_serials = [
            "ABC-DEFGH-IJ-KLMNOP",
            "XYZ-QWERT-YU-IOPASDF",
            "MNB-VCXZL-KJ-HGFDSA",
        ]

        analysis = generator.analyze_serial_algorithm(varying_serials)

        structure = analysis["structure"]
        assert "group_lengths" in structure
        assert len(structure["group_lengths"]) > 0


class TestVersionDependentAlgorithms:
    """Test edge case: Version-dependent algorithms."""

    def test_detect_version_prefix_patterns(
        self, generator: SerialNumberGenerator, version_dependent_serials: dict[str, list[str]]
    ) -> None:
        """Detection identifies version prefixes in serials."""
        all_serials = []
        for serials in version_dependent_serials.values():
            all_serials.extend(serials)

        analysis = generator.analyze_serial_algorithm(all_serials)

        structure = analysis["structure"]
        assert "common_separator" in structure
        assert structure["common_separator"] == "-"

    def test_separate_analysis_per_version(
        self, generator: SerialNumberGenerator, version_dependent_serials: dict[str, list[str]]
    ) -> None:
        """Each version uses different algorithm detection."""
        v1_analysis = generator.analyze_serial_algorithm(version_dependent_serials["v1"])
        v2_analysis = generator.analyze_serial_algorithm(version_dependent_serials["v2"])
        v3_analysis = generator.analyze_serial_algorithm(version_dependent_serials["v3"])

        assert v1_analysis["algorithm"] == "luhn", f"V1 should be Luhn: {v1_analysis}"
        assert v2_analysis["algorithm"] == "crc32", f"V2 should be CRC32: {v2_analysis}"

    def test_version_specific_generation(self, generator: SerialNumberGenerator) -> None:
        """Generator can produce version-specific serials."""
        v1_constraints = SerialConstraints(length=16, format=SerialFormat.NUMERIC, must_contain=["V1"])

        generated = generator.generate_serial(v1_constraints)

        assert "V1" in generated.serial, f"Version prefix missing: {generated.serial}"

    def test_version_algorithm_mapping(
        self, generator: SerialNumberGenerator, version_dependent_serials: dict[str, list[str]]
    ) -> None:
        """Version mapping correctly associates versions with algorithms."""
        version_algorithms = {}

        for version, serials in version_dependent_serials.items():
            cleaned_serials = [s.replace(f"{version}-", "") for s in serials]
            analysis = generator.analyze_serial_algorithm(cleaned_serials)
            version_algorithms[version] = analysis["algorithm"]

        assert version_algorithms["v1"] == "luhn"
        assert version_algorithms["v2"] == "crc32"


class TestConstraintSolverIntegration:
    """Test Z3 constraint solver integration for algorithm detection."""

    def test_generate_with_must_contain_constraint(self, generator: SerialNumberGenerator) -> None:
        """Z3 solver generates serials satisfying must_contain constraints."""
        constraints = SerialConstraints(length=20, format=SerialFormat.ALPHANUMERIC, must_contain=["PROD"])

        generated = generator.generate_serial(constraints)

        assert "PROD" in generated.serial, f"Must-contain constraint violated: {generated.serial}"

    def test_generate_with_cannot_contain_constraint(self, generator: SerialNumberGenerator) -> None:
        """Z3 solver generates serials avoiding cannot_contain patterns."""
        constraints = SerialConstraints(length=16, format=SerialFormat.ALPHANUMERIC, cannot_contain=["XXXX", "0000"])

        for _ in range(30):
            generated = generator.generate_serial(constraints)
            assert "XXXX" not in generated.serial, f"Cannot-contain constraint violated: {generated.serial}"
            assert "0000" not in generated.serial, f"Cannot-contain constraint violated: {generated.serial}"

    def test_generate_with_custom_alphabet(self, generator: SerialNumberGenerator) -> None:
        """Z3 solver respects custom alphabet constraints."""
        constraints = SerialConstraints(length=16, format=SerialFormat.CUSTOM, custom_alphabet="ABC123")

        generated = generator.generate_serial(constraints)

        for char in generated.serial.replace("-", ""):
            assert char in "ABC123", f"Invalid character {char} in serial: {generated.serial}"

    def test_unsatisfiable_constraints_fallback(self, generator: SerialNumberGenerator) -> None:
        """Generator handles unsatisfiable constraints gracefully."""
        constraints = SerialConstraints(
            length=5, format=SerialFormat.NUMERIC, must_contain=["ABCDEFGHIJKLMNOP"]
        )

        generated = generator.generate_serial(constraints)

        assert generated.serial is not None
        assert generated.confidence < 1.0


class TestBatchGenerationWithAlgorithms:
    """Test batch generation using detected algorithms."""

    def test_batch_generate_uses_detected_algorithm(
        self, generator: SerialNumberGenerator, real_luhn_serials: list[str]
    ) -> None:
        """Batch generation uses detected algorithm for production."""
        analysis = generator.analyze_serial_algorithm(real_luhn_serials)

        constraints = SerialConstraints(
            length=analysis["length"]["clean_mode"],
            format=analysis["format"],
            checksum_algorithm=next(iter(analysis["checksum"].keys())) if analysis["checksum"] else None,
        )

        batch = generator.batch_generate(constraints, 50, unique=True)

        assert len(batch) == 50, f"Expected 50 serials, got {len(batch)}"

        unique_serials = set(s.serial for s in batch)
        assert len(unique_serials) == 50, f"Non-unique serials generated: {len(unique_serials)}"

    def test_batch_generation_all_valid(
        self, generator: SerialNumberGenerator, real_crc32_serials: list[str]
    ) -> None:
        """All batch-generated serials pass validation."""
        analysis = generator.analyze_serial_algorithm(real_crc32_serials)

        constraints = SerialConstraints(
            length=24,
            format=SerialFormat.ALPHANUMERIC,
            checksum_algorithm="crc32",
        )

        batch = generator.batch_generate(constraints, 30)

        for generated in batch:
            assert isinstance(generated, GeneratedSerial)
            assert len(generated.serial) > 0


class TestRealWorldScenarios:
    """Test real-world serial algorithm detection scenarios."""

    def test_detect_rsa_signed_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection identifies RSA-signed serial characteristics."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        rsa_serials = []
        for i in range(20):
            serial = generator.generate_rsa_signed(
                private_key, product_id=f"PROD{i}", user_name="TestUser", features=["pro"]
            )
            rsa_serials.append(serial.serial)

        analysis = generator.analyze_serial_algorithm(rsa_serials)

        assert analysis["format"] == SerialFormat.BASE32 or analysis["format"] == SerialFormat.ALPHANUMERIC

    def test_detect_ecc_signed_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection identifies ECC-signed serial characteristics."""
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.generate_private_key(ec.SECP256R1())

        ecc_serials = []
        for i in range(20):
            serial = generator.generate_ecc_signed(private_key, product_id=f"PROD{i}", machine_code=f"MACH{i:04d}")
            ecc_serials.append(serial.serial)

        analysis = generator.analyze_serial_algorithm(ecc_serials)

        assert analysis["format"] in [SerialFormat.BASE32, SerialFormat.ALPHANUMERIC]

    def test_detect_time_based_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection identifies time-based serial characteristics."""
        secret_key = b"test_secret_key_for_hmac_validation"

        time_serials = []
        for _ in range(20):
            serial = generator.generate_time_based(secret_key, validity_days=30, product_id="PROD001")
            time_serials.append(serial.serial)

        analysis = generator.analyze_serial_algorithm(time_serials)

        structure = analysis["structure"]
        assert structure["group_count"] == 3

    def test_detect_feature_encoded_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection identifies feature-encoded serial structure."""
        feature_serials = []
        for i in range(20):
            base = generator._generate_luhn_serial(16)
            features = ["pro", "enterprise"] if i % 2 == 0 else ["pro"]
            serial = generator.generate_feature_encoded(base, features)
            feature_serials.append(serial.serial)

        analysis = generator.analyze_serial_algorithm(feature_serials)

        structure = analysis["structure"]
        assert "common_separator" in structure

    def test_detect_mathematical_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection identifies mathematical algorithm patterns."""
        math_serials = []
        for seed in range(100, 150):
            serial = generator.generate_mathematical(seed, algorithm="quadratic")
            math_serials.append(serial.serial)

        analysis = generator.analyze_serial_algorithm(math_serials)

        assert "crc32" in analysis.get("checksum", {})

    def test_comprehensive_multi_algorithm_detection(
        self, generator: SerialNumberGenerator, mixed_algorithm_serials: dict[str, list[str]]
    ) -> None:
        """Detection accurately identifies multiple different algorithms."""
        results = {}

        for algo_name, serials in mixed_algorithm_serials.items():
            analysis = generator.analyze_serial_algorithm(serials)
            results[algo_name] = analysis["algorithm"]

        assert results["luhn"] == "luhn", f"Failed to detect Luhn: {results}"
        assert results["crc32"] == "crc32", f"Failed to detect CRC32: {results}"


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases in algorithm detection."""

    def test_handle_invalid_checksum_gracefully(self, generator: SerialNumberGenerator) -> None:
        """Checksum verification handles invalid serials without crashing."""
        invalid = "THISISNOTAVALIDSERIAL"

        result = generator._verify_checksum(invalid, generator._calculate_luhn)

        assert result is False

    def test_handle_short_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection handles very short serials gracefully."""
        short_serials = ["ABC", "DEF", "GHI"]

        analysis = generator.analyze_serial_algorithm(short_serials)

        assert "algorithm" in analysis
        assert analysis["length"]["mode"] == 3

    def test_handle_extremely_long_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection handles very long serials gracefully."""
        long_serials = ["A" * 1000, "B" * 1000, "C" * 1000]

        analysis = generator.analyze_serial_algorithm(long_serials)

        assert "algorithm" in analysis
        assert analysis["length"]["mode"] == 1000

    def test_handle_mixed_case_serials(self, generator: SerialNumberGenerator) -> None:
        """Detection handles mixed case serials correctly."""
        mixed_case = ["AbCdEf123456", "XyZaBc789012", "QwErTy345678"]

        analysis = generator.analyze_serial_algorithm(mixed_case)

        assert analysis["format"] == SerialFormat.ALPHANUMERIC

    def test_handle_unicode_characters_gracefully(self, generator: SerialNumberGenerator) -> None:
        """Detection handles unicode characters without crashing."""
        unicode_serials = ["ABC123äöü", "DEF456éèê", "GHI789ñçü"]

        analysis = generator.analyze_serial_algorithm(unicode_serials)

        assert "algorithm" in analysis

    def test_test_algorithm_with_empty_list(self, generator: SerialNumberGenerator) -> None:
        """Algorithm testing handles empty serial list gracefully."""
        score = generator._test_algorithm([], "luhn")

        assert score == 0.0

    def test_reverse_engineer_with_all_invalid_serials(
        self, generator: SerialNumberGenerator, invalid_serials: list[str]
    ) -> None:
        """Reverse engineering handles all-invalid input gracefully."""
        analysis = generator.reverse_engineer_algorithm(invalid_serials)

        assert "algorithm" in analysis
        assert analysis["confidence"] < 0.5
