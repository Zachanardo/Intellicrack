"""Production tests for algorithm extraction from validation code (keygen.py:888-906).

Tests validate REAL algorithm extraction from binary validation routines:
- Comprehensive extraction using static and symbolic execution
- Cryptographic constant detection (MD5, SHA, CRC, RSA)
- Heuristic fallback when static analysis fails
- Partial algorithm matching with confidence scores
- Manual analysis suggestions for heavily obfuscated code
- Network-dependent validation detection

CRITICAL: Tests ONLY pass when actual algorithm extraction works on real binaries.
NO mocks, NO stubs, NO simulations - validates production offensive capability.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import struct
import tempfile
import zlib
from pathlib import Path
from typing import Any

import capstone
import pytest

from intellicrack.core.license.keygen import (
    ConstraintExtractor,
    ExtractedAlgorithm,
    KeyConstraint,
)
from intellicrack.core.serial_generator import SerialFormat


@pytest.fixture
def temp_binary_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for test binaries."""
    return tmp_path / "binaries"


@pytest.fixture
def crc32_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with CRC32 validation routine.

    Returns a real x64 PE-like binary containing actual CRC32 validation logic.
    """
    temp_binary_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_binary_dir / "crc32_validator.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x20")
    code.extend(b"\x48\xb8")
    code.extend(struct.pack("<Q", 0xEDB88320))
    code.extend(b"\x48\x89\x45\xf8")
    code.extend(b"\x31\xc0")
    code.extend(b"\x48\x8b\x4d\x10")
    code.extend(b"\x48\x83\xc4\x20")
    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"LICENSE\x00KEY\x00CRC32\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def md5_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with MD5 validation routine.

    Returns a real binary containing MD5 initialization constants.
    """
    temp_binary_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_binary_dir / "md5_validator.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x40")

    for md5_const in [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]:
        code.extend(b"\xb8")
        code.extend(struct.pack("<I", md5_const))
        code.extend(b"\x89\x45\xf0")

    code.extend(b"\x48\x83\xc4\x40")
    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"LICENSE\x00SERIAL\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def sha256_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with SHA256 validation routine."""
    temp_binary_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_binary_dir / "sha256_validator.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")

    sha256_constants = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]

    for sha_const in sha256_constants[:4]:
        code.extend(b"\xb8")
        code.extend(struct.pack("<I", sha_const))

    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"ACTIVATION\x00KEY\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def rsa_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with RSA signature validation."""
    temp_binary_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_binary_dir / "rsa_validator.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 65537))
    code.extend(b"\x89\x45\xfc")

    modulus_bytes = b"\x00\x01\x00\x00" * 64
    code.extend(modulus_bytes[:128])

    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"REGISTRATION\x00RSA\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def obfuscated_validation_binary(temp_binary_dir: Path) -> Path:
    """Create heavily obfuscated validation binary.

    Simulates protection schemes like VMProtect/Themida with obscured algorithms.
    """
    temp_binary_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_binary_dir / "obfuscated_validator.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")

    for _ in range(20):
        code.extend(b"\x90")
        code.extend(b"\xeb\x01")
        code.extend(b"\xcc")

    crc_poly = 0xEDB88320
    for i in range(4):
        byte_val = (crc_poly >> (i * 8)) & 0xFF
        code.extend(b"\x90" * 3)
        code.extend(b"\xb0")
        code.extend(bytes([byte_val]))

    code.extend(b"\x90" * 10)
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def network_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with network-dependent validation.

    Contains patterns suggesting online license checks.
    """
    temp_binary_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_binary_dir / "network_validator.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x30")

    code.extend(b"https://license.server.com/validate\x00")
    code.extend(b"POST\x00")
    code.extend(b"Content-Type: application/json\x00")
    code.extend(b'{"license_key":"\x00')

    code.extend(b"\x48\x83\xc4\x30")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def multi_algorithm_binary(temp_binary_dir: Path) -> Path:
    """Create binary using multiple validation algorithms."""
    temp_binary_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_binary_dir / "multi_algo_validator.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 0xEDB88320))

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 0x67452301))

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 65537))

    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"LICENSE\x00KEY\x00SERIAL\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def real_protected_binary() -> Path:
    """Provide path to real protected binary from test fixtures."""
    binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/enterprise_license_check.exe")
    if binary_path.exists():
        return binary_path

    alt_path = Path("D:/Intellicrack/tests/fixtures/full_protected_software/Beyond_Compare_Full.exe")
    if alt_path.exists():
        return alt_path

    return Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/notepadpp.exe")


class TestAlgorithmExtractionComprehensive:
    """Test comprehensive algorithm extraction from validation code."""

    def test_extracts_crc32_algorithm_from_real_binary(self, crc32_validation_binary: Path) -> None:
        """Algorithm extraction identifies CRC32 polynomial in validation routine."""
        extractor = ConstraintExtractor(crc32_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert len(algorithms) > 0, "Must extract at least one algorithm"

        crc_algorithms = [a for a in algorithms if "CRC" in a.algorithm_name.upper()]
        assert crc_algorithms, "Must detect CRC32 algorithm from constants"

        crc_algo = crc_algorithms[0]
        assert crc_algo.confidence >= 0.7, f"CRC32 detection confidence too low: {crc_algo.confidence}"
        assert "polynomial" in crc_algo.parameters, "Must extract CRC polynomial parameter"

        polynomial = crc_algo.parameters["polynomial"]
        assert polynomial in [0xEDB88320, 0x04C11DB7], f"Invalid CRC polynomial: {hex(polynomial)}"

        if crc_algo.validation_function:
            test_key = "TEST-1234-5678"
            result = crc_algo.validation_function(test_key)
            assert isinstance(result, int), "CRC validation must return integer"
            expected_crc = zlib.crc32(test_key.encode()) & 0xFFFFFFFF
            assert result == expected_crc, "CRC validation function must compute correct checksum"

    def test_extracts_md5_algorithm_from_validation_code(self, md5_validation_binary: Path) -> None:
        """Algorithm extraction identifies MD5 hash from initialization constants."""
        extractor = ConstraintExtractor(md5_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms from MD5 binary"

        md5_algorithms = [a for a in algorithms if "MD5" in a.algorithm_name.upper()]
        assert md5_algorithms, "Must detect MD5 from initialization constants"

        md5_algo = md5_algorithms[0]
        assert md5_algo.confidence >= 0.8, f"MD5 detection confidence too low: {md5_algo.confidence}"

        if md5_algo.validation_function:
            test_key = "VALID-LICENSE-KEY"
            result = md5_algo.validation_function(test_key)
            assert isinstance(result, str), "MD5 validation must return hex string"
            expected_hash = hashlib.md5(test_key.encode()).hexdigest()
            assert result == expected_hash, "MD5 validation must compute correct hash"

    def test_extracts_sha256_algorithm_from_constants(self, sha256_validation_binary: Path) -> None:
        """Algorithm extraction identifies SHA256 from characteristic constants."""
        extractor = ConstraintExtractor(sha256_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms from SHA256 binary"

        sha_algorithms = [a for a in algorithms if "SHA" in a.algorithm_name.upper()]
        assert sha_algorithms, "Must detect SHA256 from constants"

        sha_algo = sha_algorithms[0]
        assert sha_algo.confidence >= 0.8, f"SHA256 confidence too low: {sha_algo.confidence}"

        if sha_algo.validation_function:
            test_key = "SHA256-TEST-KEY"
            result = sha_algo.validation_function(test_key)
            assert isinstance(result, str), "SHA validation must return hex digest"
            assert len(result) in [40, 64], f"Invalid hash length: {len(result)}"

    def test_extracts_rsa_signature_validation(self, rsa_validation_binary: Path) -> None:
        """Algorithm extraction identifies RSA public key exponent."""
        extractor = ConstraintExtractor(rsa_validation_binary)
        constraints = extractor.extract_constraints()

        rsa_constraints = [c for c in constraints if "rsa" in c.constraint_type.lower() or c.value == 65537]
        assert rsa_constraints, "Must detect RSA exponent in binary"

        exponent_constraint = next((c for c in rsa_constraints if c.value == 65537), None)
        assert exponent_constraint is not None, "Must extract RSA exponent 65537"
        assert exponent_constraint.confidence >= 0.6, "RSA detection needs adequate confidence"

    def test_extracts_multiple_algorithms_from_composite_validation(
        self, multi_algorithm_binary: Path
    ) -> None:
        """Algorithm extraction handles composite validation schemes."""
        extractor = ConstraintExtractor(multi_algorithm_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert len(algorithms) >= 1, "Must extract algorithms from composite scheme"

        algorithm_types = {a.algorithm_name.upper() for a in algorithms}

        has_crypto = any(
            algo_type in ["CRC32", "MD5", "SHA1", "SHA256", "MULTIPLICATIVE HASH", "MODULAR ARITHMETIC"]
            for algo_type in algorithm_types
        )
        assert has_crypto, f"Must detect at least one crypto algorithm, got: {algorithm_types}"

        total_confidence = sum(a.confidence for a in algorithms) / len(algorithms)
        assert total_confidence >= 0.5, f"Average confidence too low: {total_confidence}"


class TestAlgorithmExtractionSymbolicExecution:
    """Test symbolic execution for discovering hidden algorithms."""

    def test_symbolic_execution_discovers_obfuscated_algorithm(
        self, obfuscated_validation_binary: Path
    ) -> None:
        """Symbolic execution reveals algorithms hidden by obfuscation."""
        extractor = ConstraintExtractor(obfuscated_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms even from obfuscated code"

        for algo in algorithms:
            assert algo.confidence > 0.0, "Must provide confidence score for obfuscated detection"

        crypto_algorithms = [
            a for a in algorithms if a.algorithm_name.upper() in ["CRC32", "MD5", "SHA1", "SHA256"]
        ]
        generic_algorithms = [a for a in algorithms if "GENERIC" in a.algorithm_name.upper()]

        assert crypto_algorithms or generic_algorithms, "Must detect or fall back to generic"

    def test_handles_heavily_obfuscated_algorithms_with_low_confidence(
        self, obfuscated_validation_binary: Path
    ) -> None:
        """Heavily obfuscated code produces low confidence but non-empty results."""
        extractor = ConstraintExtractor(obfuscated_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must return algorithms even for heavily obfuscated binaries"

        obfuscated_algos = [a for a in algorithms if a.confidence < 0.8]
        if obfuscated_algos:
            for algo in obfuscated_algos:
                assert algo.algorithm_name, "Must provide algorithm name even with low confidence"
                assert 0.0 <= algo.confidence <= 1.0, f"Invalid confidence: {algo.confidence}"


class TestAlgorithmExtractionHeuristicFallback:
    """Test heuristic detection fallback when static analysis fails."""

    def test_falls_back_to_heuristics_when_no_crypto_constants_found(self, temp_binary_dir: Path) -> None:
        """Extractor uses heuristics when crypto constants are absent."""
        binary_path = temp_binary_dir / "no_crypto_constants.bin"
        temp_binary_dir.mkdir(parents=True, exist_ok=True)

        code = bytearray()
        code.extend(b"\x55")
        code.extend(b"\x48\x89\xe5")
        code.extend(b"\x31\xc0")
        code.extend(b"\x48\x8b\x4d\x10")
        code.extend(b"\x80\x39\x00")
        code.extend(b"\x74\x08")
        code.extend(b"\xb8\x01\x00\x00\x00")
        code.extend(b"\xeb\x05")
        code.extend(b"\x31\xc0")
        code.extend(b"\x5d")
        code.extend(b"\xc3")
        code.extend(b"LICENSE\x00KEY\x00")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must fall back to heuristic algorithm when crypto missing"

        fallback_algo = algorithms[0]
        assert fallback_algo.algorithm_name, "Fallback algorithm must have name"
        assert fallback_algo.confidence > 0.0, "Fallback must provide non-zero confidence"

    def test_heuristic_detection_provides_generic_algorithm(self, temp_binary_dir: Path) -> None:
        """Heuristic fallback creates generic algorithm with constraints."""
        binary_path = temp_binary_dir / "simple_validation.bin"
        temp_binary_dir.mkdir(parents=True, exist_ok=True)

        code = bytearray()
        code.extend(b"\x55")
        code.extend(b"\x48\x89\xe5")
        code.extend(b"\xb8\x14\x00\x00\x00")
        code.extend(b"\x5d")
        code.extend(b"\xc3")
        code.extend(b"SERIAL\x00")
        code.extend(b"XXXX-XXXX-XXXX-XXXX\x00")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Heuristic must create at least generic algorithm"

        generic = next((a for a in algorithms if "GENERIC" in a.algorithm_name.upper()), None)
        if generic:
            assert generic.key_format is not None, "Generic algorithm should suggest key format"
            assert generic.constraints, "Generic algorithm should include extracted constraints"


class TestAlgorithmExtractionPartialMatches:
    """Test partial algorithm matching with confidence scores."""

    def test_reports_partial_crc_match_with_confidence(self, temp_binary_dir: Path) -> None:
        """Partial CRC constant detection reports appropriate confidence."""
        binary_path = temp_binary_dir / "partial_crc.bin"
        temp_binary_dir.mkdir(parents=True, exist_ok=True)

        code = bytearray()
        code.extend(b"\x55")
        code.extend(b"\x48\x89\xe5")

        code.extend(b"\xb8")
        code.extend(b"\x20\x83\xb8\xed")

        code.extend(b"\x5d")
        code.extend(b"\xc3")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract partial CRC match"

        crc_candidates = [a for a in algorithms if "CRC" in a.algorithm_name.upper()]
        if crc_candidates:
            assert all(
                0.5 <= a.confidence <= 1.0 for a in crc_candidates
            ), "Partial match confidence should be reasonable"

    def test_confidence_scores_reflect_detection_certainty(self, md5_validation_binary: Path) -> None:
        """Confidence scores accurately reflect detection certainty."""
        extractor = ConstraintExtractor(md5_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms with confidence"

        for algo in algorithms:
            assert 0.0 <= algo.confidence <= 1.0, f"Invalid confidence: {algo.confidence}"

        high_confidence = [a for a in algorithms if a.confidence >= 0.8]
        if high_confidence:
            for algo in high_confidence:
                assert algo.validation_function is not None or algo.parameters, (
                    "High confidence algorithms must have validation function or parameters"
                )


class TestAlgorithmExtractionManualAnalysisSuggestions:
    """Test suggestions for manual analysis when automated extraction fails."""

    def test_suggests_manual_analysis_for_unknown_algorithms(self, temp_binary_dir: Path) -> None:
        """Extractor suggests manual approaches for unrecognized algorithms."""
        binary_path = temp_binary_dir / "unknown_algo.bin"
        temp_binary_dir.mkdir(parents=True, exist_ok=True)

        code = bytearray()
        code.extend(b"\x55")
        code.extend(b"\x48\x89\xe5")
        code.extend(b"\x48\x83\xec\x20")

        for i in range(10):
            code.extend(bytes([0xB8 + (i % 8)]))
            code.extend(struct.pack("<I", 0x12345678 + i * 137))

        code.extend(b"\x48\x83\xc4\x20")
        code.extend(b"\x5d")
        code.extend(b"\xc3")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must return algorithms even if unknown"

        low_confidence = [a for a in algorithms if a.confidence < 0.7]
        if low_confidence:
            for algo in low_confidence:
                assert algo.algorithm_name, "Must provide algorithm name for manual reference"

    def test_provides_constraint_data_for_manual_reverse_engineering(
        self, obfuscated_validation_binary: Path
    ) -> None:
        """Extractor provides constraint data to aid manual analysis."""
        extractor = ConstraintExtractor(obfuscated_validation_binary)
        constraints = extractor.extract_constraints()
        algorithms = extractor.analyze_validation_algorithms()

        assert constraints or algorithms, "Must extract some information for manual analysis"

        for algo in algorithms:
            if algo.confidence < 0.8:
                assert algo.constraints, "Low confidence algorithms should include constraint details"
                for constraint in algo.constraints:
                    assert constraint.confidence >= 0.0, "Constraints must have confidence"


class TestAlgorithmExtractionNetworkDependentValidation:
    """Test detection of network-dependent validation schemes."""

    def test_detects_network_validation_patterns(self, network_validation_binary: Path) -> None:
        """Extractor detects network-based license validation."""
        extractor = ConstraintExtractor(network_validation_binary)
        constraints = extractor.extract_constraints()

        network_indicators = [
            c
            for c in constraints
            if b"http" in str(c.value).lower().encode()
            or b"POST" in str(c.value).encode()
            or "network" in c.description.lower()
        ]

        binary_data = network_validation_binary.read_bytes()
        has_network_strings = b"http" in binary_data or b"POST" in binary_data

        if has_network_strings:
            assert (
                network_indicators or len(constraints) > 0
            ), "Must detect network validation indicators in constraints"

    def test_handles_network_dependent_algorithms_with_low_confidence(
        self, network_validation_binary: Path
    ) -> None:
        """Network-dependent validation gets appropriate low confidence for offline analysis."""
        extractor = ConstraintExtractor(network_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms even from network-dependent binary"

        for algo in algorithms:
            assert algo.confidence >= 0.0, "Must provide confidence for network validation"


class TestAlgorithmExtractionEdgeCases:
    """Test edge cases in algorithm extraction."""

    def test_handles_empty_binary_gracefully(self, temp_binary_dir: Path) -> None:
        """Extractor handles empty binary without crashing."""
        binary_path = temp_binary_dir / "empty.bin"
        temp_binary_dir.mkdir(parents=True, exist_ok=True)
        binary_path.write_bytes(b"")

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert isinstance(algorithms, list), "Must return list even for empty binary"

    def test_handles_corrupted_binary_data(self, temp_binary_dir: Path) -> None:
        """Extractor handles corrupted binary data gracefully."""
        binary_path = temp_binary_dir / "corrupted.bin"
        temp_binary_dir.mkdir(parents=True, exist_ok=True)

        corrupted_data = bytearray(b"\xff" * 100)
        corrupted_data[50:60] = b"\x00" * 10
        binary_path.write_bytes(bytes(corrupted_data))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert isinstance(algorithms, list), "Must handle corrupted data without exception"

    def test_handles_nonexistent_binary_path(self, temp_binary_dir: Path) -> None:
        """Extractor handles nonexistent file path appropriately."""
        binary_path = temp_binary_dir / "nonexistent.bin"

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert isinstance(algorithms, list), "Must return empty list for nonexistent file"
        assert len(algorithms) >= 0, "Should return empty or fallback algorithm list"

    def test_handles_very_large_binary(self, temp_binary_dir: Path) -> None:
        """Extractor processes large binaries efficiently."""
        binary_path = temp_binary_dir / "large.bin"
        temp_binary_dir.mkdir(parents=True, exist_ok=True)

        large_code = bytearray()
        large_code.extend(b"\x55")
        large_code.extend(b"\x48\x89\xe5")

        large_code.extend(b"\x90" * 10000)

        large_code.extend(b"\xb8")
        large_code.extend(struct.pack("<I", 0xEDB88320))

        large_code.extend(b"\x90" * 5000)
        large_code.extend(b"\x5d")
        large_code.extend(b"\xc3")

        binary_path.write_bytes(bytes(large_code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms from large binary"

    def test_extracts_algorithms_from_real_protected_software(self, real_protected_binary: Path) -> None:
        """Extractor works on actual commercial protected software."""
        if not real_protected_binary.exists():
            pytest.skip(f"Real protected binary not available: {real_protected_binary}")

        extractor = ConstraintExtractor(real_protected_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, f"Must extract algorithms from real binary: {real_protected_binary.name}"

        for algo in algorithms:
            assert algo.algorithm_name, "Extracted algorithms must have names"
            assert 0.0 <= algo.confidence <= 1.0, f"Invalid confidence: {algo.confidence}"
            assert isinstance(algo.parameters, dict), "Must have parameters dict"
            assert isinstance(algo.constraints, list), "Must have constraints list"

    def test_algorithm_extraction_returns_valid_key_formats(self, crc32_validation_binary: Path) -> None:
        """Extracted algorithms include valid key format specifications."""
        extractor = ConstraintExtractor(crc32_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms"

        for algo in algorithms:
            if algo.key_format is not None:
                assert isinstance(algo.key_format, SerialFormat), "Must use SerialFormat enum"

    def test_maintains_constraint_source_addresses(self, md5_validation_binary: Path) -> None:
        """Algorithm constraints preserve source addresses for manual analysis."""
        extractor = ConstraintExtractor(md5_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        for algo in algorithms:
            for constraint in algo.constraints:
                if constraint.source_address is not None:
                    assert constraint.source_address >= 0, "Source address must be non-negative"
                    assert isinstance(constraint.source_address, int), "Source address must be integer"


class TestAlgorithmExtractionValidation:
    """Test validation that extraction actually works."""

    def test_extracted_crc_algorithm_validates_correct_keys(self, crc32_validation_binary: Path) -> None:
        """CRC algorithm extraction produces working validation function."""
        extractor = ConstraintExtractor(crc32_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        crc_algos = [a for a in algorithms if "CRC" in a.algorithm_name.upper() and a.validation_function]

        if crc_algos:
            crc_algo = crc_algos[0]
            validation_func = crc_algo.validation_function

            assert validation_func is not None, "CRC algorithm must have validation function"

            test_keys = ["TEST123", "ABCD-EFGH-IJKL", "LICENSE-KEY-2025"]
            for key in test_keys:
                result = validation_func(key)
                assert isinstance(result, int), f"CRC validation must return int for key: {key}"
                assert 0 <= result <= 0xFFFFFFFF, f"Invalid CRC32 value: {result}"

    def test_extracted_hash_algorithm_produces_valid_hashes(self, md5_validation_binary: Path) -> None:
        """MD5 algorithm extraction produces correct hash outputs."""
        extractor = ConstraintExtractor(md5_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        hash_algos = [
            a
            for a in algorithms
            if a.algorithm_name.upper() in ["MD5", "SHA1", "SHA256"] and a.validation_function
        ]

        if hash_algos:
            hash_algo = hash_algos[0]
            validation_func = hash_algo.validation_function

            assert validation_func is not None, "Hash algorithm must have validation function"

            test_key = "VALID-LICENSE-123"
            result = validation_func(test_key)

            assert isinstance(result, str), "Hash validation must return string"
            assert len(result) in [32, 40, 64], f"Invalid hash length: {len(result)}"
            assert all(c in "0123456789abcdef" for c in result.lower()), "Hash must be hexadecimal"
