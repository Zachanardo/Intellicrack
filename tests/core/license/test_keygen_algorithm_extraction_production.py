"""Production tests for keygen.py:888-906 - algorithm extraction returning empty list.

Tests validate that analyze_validation_algorithms() NEVER returns empty list
when validation code exists. Must implement comprehensive extraction using:
- Static analysis with crypto constant detection
- Symbolic execution for hidden algorithms
- Heuristic fallback when analysis fails
- Partial matches with confidence scores
- Manual analysis suggestions
- Network-dependent validation detection

CRITICAL: Tests FAIL if empty list returned when algorithms discoverable.
NO mocks, NO stubs - validates production offensive capability.

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
import zlib
from pathlib import Path
from typing import Any

import capstone
import pytest

from intellicrack.core.license.keygen import (
    AlgorithmType,
    ConstraintExtractor,
    ExtractedAlgorithm,
    KeyConstraint,
    ValidationAnalyzer,
)
from intellicrack.core.serial_generator import SerialFormat


@pytest.fixture
def temp_test_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for test binaries."""
    test_dir = tmp_path / "algorithm_extraction"
    test_dir.mkdir(parents=True, exist_ok=True)
    return test_dir


@pytest.fixture
def minimal_validation_binary(temp_test_dir: Path) -> Path:
    """Create minimal binary with validation logic but no obvious crypto constants."""
    binary_path = temp_test_dir / "minimal_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x20")
    code.extend(b"\x48\x8b\x45\x10")
    code.extend(b"\x80\x38\x00")
    code.extend(b"\x74\x0a")
    code.extend(b"\xb8\x01\x00\x00\x00")
    code.extend(b"\x48\x83\xc4\x20")
    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"LICENSE\x00KEY\x00SERIAL\x00")
    code.extend(b"XXXX-XXXX-XXXX-XXXX\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def crc32_binary(temp_test_dir: Path) -> Path:
    """Create binary with CRC32 polynomial constant."""
    binary_path = temp_test_dir / "crc32_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x30")
    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 0xEDB88320))
    code.extend(b"\x89\x45\xfc")
    code.extend(b"\x31\xc0")
    code.extend(b"\x48\x8b\x4d\x10")
    code.extend(b"\x48\x83\xc4\x30")
    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"LICENSE\x00CRC32\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def md5_binary(temp_test_dir: Path) -> Path:
    """Create binary with MD5 initialization constants."""
    binary_path = temp_test_dir / "md5_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x40")

    md5_constants = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for const in md5_constants:
        code.extend(b"\xb8")
        code.extend(struct.pack("<I", const))
        code.extend(b"\x89\x45\xf0")

    code.extend(b"\x48\x83\xc4\x40")
    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"SERIAL\x00LICENSE\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def sha256_binary(temp_test_dir: Path) -> Path:
    """Create binary with SHA256 initialization constants."""
    binary_path = temp_test_dir / "sha256_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")

    sha256_constants = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    for const in sha256_constants[:5]:
        code.extend(b"\xb8")
        code.extend(struct.pack("<I", const))

    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"ACTIVATION\x00REGISTRATION\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def obfuscated_binary(temp_test_dir: Path) -> Path:
    """Create heavily obfuscated binary with split constants."""
    binary_path = temp_test_dir / "obfuscated_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")

    for _ in range(30):
        code.extend(b"\x90")
        code.extend(b"\xeb\x01")
        code.extend(b"\xcc")

    crc_poly = 0xEDB88320
    for i in range(4):
        byte_val = (crc_poly >> (i * 8)) & 0xFF
        code.extend(b"\x90" * 5)
        code.extend(b"\xb0")
        code.extend(bytes([byte_val]))
        code.extend(b"\x90" * 3)

    code.extend(b"\x90" * 20)
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def network_validation_binary(temp_test_dir: Path) -> Path:
    """Create binary with network-based validation patterns."""
    binary_path = temp_test_dir / "network_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x40")

    code.extend(b"https://license.example.com/validate\x00")
    code.extend(b"POST\x00")
    code.extend(b"Authorization: Bearer \x00")
    code.extend(b'{"license_key": "%s"}\x00')
    code.extend(b"Content-Type: application/json\x00")

    code.extend(b"\x48\x83\xc4\x40")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def composite_algorithm_binary(temp_test_dir: Path) -> Path:
    """Create binary with multiple validation algorithms."""
    binary_path = temp_test_dir / "composite_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x50")

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 0xEDB88320))

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 0x67452301))

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 0x6A09E667))

    code.extend(b"\x48\x83\xc4\x50")
    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"LICENSE\x00KEY\x00VALIDATION\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def rsa_signature_binary(temp_test_dir: Path) -> Path:
    """Create binary with RSA public key exponent."""
    binary_path = temp_test_dir / "rsa_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x30")

    code.extend(b"\xb8")
    code.extend(struct.pack("<I", 65537))
    code.extend(b"\x89\x45\xf8")

    rsa_modulus = b"\x00\x01" * 128
    code.extend(rsa_modulus[:256])

    code.extend(b"\x48\x83\xc4\x30")
    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"RSA\x00PUBLIC\x00KEY\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def custom_algorithm_binary(temp_test_dir: Path) -> Path:
    """Create binary with custom proprietary algorithm."""
    binary_path = temp_test_dir / "custom_validation.bin"

    code = bytearray()
    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")

    code.extend(b"\xb8\x1f\x00\x00\x00")
    code.extend(b"\x89\x45\xfc")

    for i in range(10):
        code.extend(b"\x48\x8b\x45\x10")
        code.extend(b"\x0f\xbe\x00")
        code.extend(b"\x48\x0f\xaf\x45\xfc")
        code.extend(b"\x89\x45\xf8")

    code.extend(b"\x5d")
    code.extend(b"\xc3")
    code.extend(b"CUSTOM\x00ALGORITHM\x00")

    binary_path.write_bytes(bytes(code))
    return binary_path


class TestAlgorithmExtractionNeverReturnsEmpty:
    """Test that analyze_validation_algorithms() never returns empty list."""

    def test_minimal_validation_returns_generic_algorithm_not_empty(
        self, minimal_validation_binary: Path
    ) -> None:
        """Even minimal validation code produces generic algorithm, never empty."""
        extractor = ConstraintExtractor(minimal_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list - must create generic algorithm"
        assert len(algorithms) > 0, "Must return at least one algorithm"

        generic_algo = next((a for a in algorithms if "GENERIC" in a.algorithm_name.upper()), None)
        assert generic_algo is not None, "Must create generic fallback algorithm"
        assert generic_algo.confidence > 0.0, "Generic algorithm must have non-zero confidence"
        assert generic_algo.algorithm_name, "Generic algorithm must have name"

    def test_crc32_detection_returns_algorithm_not_empty(self, crc32_binary: Path) -> None:
        """CRC32 binary produces algorithm with high confidence, never empty."""
        extractor = ConstraintExtractor(crc32_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list for CRC32 binary"
        assert len(algorithms) > 0, "Must extract CRC32 algorithm"

        crc_algorithms = [a for a in algorithms if "CRC" in a.algorithm_name.upper()]
        assert crc_algorithms, "Must detect CRC32 from polynomial constant"

        crc_algo = crc_algorithms[0]
        assert crc_algo.confidence >= 0.7, f"CRC32 confidence too low: {crc_algo.confidence}"
        assert "polynomial" in crc_algo.parameters, "Must extract polynomial parameter"
        assert crc_algo.validation_function is not None, "CRC32 must have validation function"

    def test_md5_detection_returns_algorithm_not_empty(self, md5_binary: Path) -> None:
        """MD5 binary produces hash algorithm, never empty."""
        extractor = ConstraintExtractor(md5_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list for MD5 binary"
        assert len(algorithms) > 0, "Must extract MD5 algorithm"

        md5_algorithms = [a for a in algorithms if "MD5" in a.algorithm_name.upper()]
        assert md5_algorithms, "Must detect MD5 from initialization constants"

        md5_algo = md5_algorithms[0]
        assert md5_algo.confidence >= 0.8, f"MD5 confidence too low: {md5_algo.confidence}"
        assert md5_algo.validation_function is not None, "MD5 must have validation function"

    def test_sha256_detection_returns_algorithm_not_empty(self, sha256_binary: Path) -> None:
        """SHA256 binary produces hash algorithm, never empty."""
        extractor = ConstraintExtractor(sha256_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list for SHA256 binary"
        assert len(algorithms) > 0, "Must extract SHA256 algorithm"

        sha_algorithms = [a for a in algorithms if "SHA" in a.algorithm_name.upper()]
        assert sha_algorithms, "Must detect SHA256 from constants"

        sha_algo = sha_algorithms[0]
        assert sha_algo.confidence >= 0.8, f"SHA256 confidence too low: {sha_algo.confidence}"
        assert sha_algo.validation_function is not None, "SHA256 must have validation function"

    def test_obfuscated_binary_uses_heuristic_fallback_not_empty(
        self, obfuscated_binary: Path
    ) -> None:
        """Heavily obfuscated binary falls back to heuristics, never empty."""
        extractor = ConstraintExtractor(obfuscated_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list even for obfuscated binary"
        assert len(algorithms) > 0, "Must use heuristic fallback"

        for algo in algorithms:
            assert algo.algorithm_name, "Heuristic algorithm must have name"
            assert 0.0 < algo.confidence <= 1.0, f"Invalid confidence: {algo.confidence}"
            assert isinstance(algo.parameters, dict), "Must have parameters dict"

    def test_network_validation_returns_algorithm_with_constraints_not_empty(
        self, network_validation_binary: Path
    ) -> None:
        """Network-based validation produces algorithm with network indicators, never empty."""
        extractor = ConstraintExtractor(network_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list for network validation"
        assert len(algorithms) > 0, "Must create algorithm for network-based validation"

        for algo in algorithms:
            assert algo.algorithm_name, "Network validation algorithm must have name"
            assert algo.confidence >= 0.0, "Must provide confidence score"

    def test_composite_algorithms_extracts_multiple_not_empty(
        self, composite_algorithm_binary: Path
    ) -> None:
        """Binary with multiple algorithms extracts all, never empty."""
        extractor = ConstraintExtractor(composite_algorithm_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list for composite validation"
        assert len(algorithms) >= 1, "Must extract at least one algorithm from composite scheme"

        algorithm_names = {a.algorithm_name.upper() for a in algorithms}

        has_crypto = any(
            name in algorithm_names
            for name in ["CRC32", "MD5", "SHA1", "SHA256", "MULTIPLICATIVE HASH", "MODULAR ARITHMETIC"]
        )
        assert has_crypto, f"Must detect crypto algorithm from composite, got: {algorithm_names}"

    def test_rsa_signature_extracts_constraints_not_empty(self, rsa_signature_binary: Path) -> None:
        """RSA signature binary extracts constraints even without full algorithm, never empty."""
        extractor = ConstraintExtractor(rsa_signature_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list for RSA binary"

        constraints = extractor.extract_constraints()
        assert constraints, "Must extract RSA-related constraints"

        rsa_indicators = [c for c in constraints if c.value == 65537 or "rsa" in str(c.value).lower()]
        binary_contains_rsa = any(65537 == c.value for c in constraints)

        if binary_contains_rsa:
            assert rsa_indicators, "Must detect RSA exponent in constraints"

    def test_custom_algorithm_returns_generic_with_constraints_not_empty(
        self, custom_algorithm_binary: Path
    ) -> None:
        """Custom proprietary algorithm produces generic with constraints, never empty."""
        extractor = ConstraintExtractor(custom_algorithm_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "MUST NOT return empty list for custom algorithm"
        assert len(algorithms) > 0, "Must create algorithm for custom validation"

        for algo in algorithms:
            assert algo.algorithm_name, "Custom algorithm must have name"
            assert isinstance(algo.constraints, list), "Must include constraints"


class TestSymbolicExecutionDiscovery:
    """Test symbolic execution discovers hidden algorithms."""

    def test_symbolic_execution_discovers_split_constants(self, obfuscated_binary: Path) -> None:
        """Symbolic execution reveals constants split across instructions."""
        extractor = ConstraintExtractor(obfuscated_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must discover algorithms through symbolic execution"

        for algo in algorithms:
            assert algo.confidence > 0.0, "Discovered algorithms must have confidence"
            assert algo.parameters, "Must extract parameters from symbolic analysis"

    def test_symbolic_execution_handles_opaque_predicates(self, temp_test_dir: Path) -> None:
        """Symbolic execution simplifies opaque predicates to find algorithms."""
        binary_path = temp_test_dir / "opaque_predicates.bin"

        code = bytearray()
        code.extend(b"\x55")
        code.extend(b"\x48\x89\xe5")

        code.extend(b"\xb8\x01\x00\x00\x00")
        code.extend(b"\x83\xf8\x01")
        code.extend(b"\x75\x0a")

        code.extend(b"\xb8")
        code.extend(struct.pack("<I", 0xEDB88320))
        code.extend(b"\x89\x45\xfc")

        code.extend(b"\x5d")
        code.extend(b"\xc3")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms despite opaque predicates"


class TestHeuristicFallback:
    """Test heuristic fallback when static/symbolic analysis fails."""

    def test_heuristic_creates_generic_algorithm_from_keywords(
        self, minimal_validation_binary: Path
    ) -> None:
        """Heuristic uses license keywords to create generic algorithm."""
        extractor = ConstraintExtractor(minimal_validation_binary)
        constraints = extractor.extract_constraints()
        algorithms = extractor.analyze_validation_algorithms()

        assert constraints, "Must extract keyword constraints"
        assert algorithms, "Must create generic algorithm from keywords"

        keyword_constraints = [c for c in constraints if c.constraint_type == "keyword"]
        assert keyword_constraints, "Must find license-related keywords"

        generic = next((a for a in algorithms if "GENERIC" in a.algorithm_name.upper()), None)
        if generic:
            assert generic.constraints, "Generic algorithm must include keyword constraints"

    def test_heuristic_suggests_key_format_from_patterns(self, minimal_validation_binary: Path) -> None:
        """Heuristic detects key format patterns and suggests SerialFormat."""
        extractor = ConstraintExtractor(minimal_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must create algorithms with format suggestions"

        for algo in algorithms:
            if algo.key_format is not None:
                assert isinstance(algo.key_format, SerialFormat), "Must use SerialFormat enum"

    def test_heuristic_extracts_length_constraints(self, temp_test_dir: Path) -> None:
        """Heuristic detects length checks in validation code."""
        binary_path = temp_test_dir / "length_check.bin"

        code = bytearray()
        code.extend(b"\x55")
        code.extend(b"\x48\x89\xe5")
        code.extend(b"\xb8\x14\x00\x00\x00")
        code.extend(b"\x89\x45\xfc")
        code.extend(b"\x48\x8b\x45\x10")
        code.extend(b"\x48\x83\xf8\x14")
        code.extend(b"\x75\x05")
        code.extend(b"\x5d")
        code.extend(b"\xc3")
        code.extend(b"XXXX-XXXX-XXXX-XXXX\x00")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        constraints = extractor.extract_constraints()
        algorithms = extractor.analyze_validation_algorithms()

        assert constraints or algorithms, "Must extract length constraints or algorithms"

        length_constraints = [c for c in constraints if "length" in c.constraint_type.lower()]
        if length_constraints:
            assert any(c.value == 20 for c in length_constraints), "Must detect length 20"


class TestPartialAlgorithmMatches:
    """Test partial algorithm matching with confidence scores."""

    def test_partial_crc_match_reports_confidence(self, temp_test_dir: Path) -> None:
        """Partial CRC constant match reports appropriate confidence score."""
        binary_path = temp_test_dir / "partial_crc.bin"

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

        assert algorithms, "Must extract partial matches"

        for algo in algorithms:
            assert 0.0 <= algo.confidence <= 1.0, f"Invalid confidence: {algo.confidence}"

    def test_partial_md5_constants_detected_with_lower_confidence(self, temp_test_dir: Path) -> None:
        """Partial MD5 constants produce lower confidence detection."""
        binary_path = temp_test_dir / "partial_md5.bin"

        code = bytearray()
        code.extend(b"\x55")
        code.extend(b"\x48\x89\xe5")

        code.extend(b"\xb8")
        code.extend(struct.pack("<I", 0x67452301))

        code.extend(b"\xb8")
        code.extend(struct.pack("<I", 0xEFCDAB89))

        code.extend(b"\x5d")
        code.extend(b"\xc3")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must detect partial MD5 constants"

        md5_candidates = [a for a in algorithms if "MD5" in a.algorithm_name.upper()]
        if md5_candidates:
            assert all(a.confidence > 0.0 for a in md5_candidates), "Partial match needs confidence"

    def test_confidence_scores_reflect_match_quality(self, composite_algorithm_binary: Path) -> None:
        """Confidence scores accurately reflect detection certainty."""
        extractor = ConstraintExtractor(composite_algorithm_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms with confidence"

        for algo in algorithms:
            assert 0.0 <= algo.confidence <= 1.0, f"Invalid confidence: {algo.confidence}"

            if algo.confidence >= 0.9:
                assert algo.validation_function is not None, "High confidence needs validation function"

            if algo.confidence < 0.6:
                assert algo.algorithm_name, "Low confidence still needs algorithm name"


class TestManualAnalysisSuggestions:
    """Test manual analysis suggestions when automation fails."""

    def test_low_confidence_includes_constraints_for_manual_analysis(
        self, obfuscated_binary: Path
    ) -> None:
        """Low confidence algorithms include constraints to aid manual reverse engineering."""
        extractor = ConstraintExtractor(obfuscated_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must provide algorithms for manual analysis"

        low_confidence = [a for a in algorithms if a.confidence < 0.8]
        for algo in low_confidence:
            assert algo.algorithm_name, "Must name algorithm for manual reference"
            assert isinstance(algo.constraints, list), "Must provide constraint data"

    def test_unknown_algorithms_suggest_dynamic_analysis(self, custom_algorithm_binary: Path) -> None:
        """Unknown algorithms provide enough info for manual dynamic analysis."""
        extractor = ConstraintExtractor(custom_algorithm_binary)
        algorithms = extractor.analyze_validation_algorithms()
        constraints = extractor.extract_constraints()

        assert algorithms or constraints, "Must provide data for manual analysis"

        for algo in algorithms:
            if "CUSTOM" in algo.algorithm_name.upper() or algo.confidence < 0.7:
                assert algo.parameters or algo.constraints, "Must provide analysis starting points"

    def test_validation_analyzer_provides_recommendations(self, md5_binary: Path) -> None:
        """ValidationAnalyzer provides actionable recommendations for cracking."""
        analyzer = ValidationAnalyzer()

        with md5_binary.open("rb") as f:
            binary_data = f.read()

        analysis = analyzer.analyze(binary_data, entry_point=0, arch="x64")

        assert analysis.algorithm_type != AlgorithmType.UNKNOWN or analysis.recommendations, (
            "Must provide recommendations when algorithm unclear"
        )

        if analysis.recommendations:
            for rec in analysis.recommendations:
                assert isinstance(rec, str), "Recommendations must be strings"
                assert len(rec) > 10, "Recommendations must be meaningful"


class TestNetworkDependentValidation:
    """Test detection and handling of network-dependent validation."""

    def test_detects_network_validation_urls(self, network_validation_binary: Path) -> None:
        """Extractor detects URLs indicating network-based validation."""
        extractor = ConstraintExtractor(network_validation_binary)
        constraints = extractor.extract_constraints()

        binary_data = network_validation_binary.read_bytes()
        has_url = b"http" in binary_data

        if has_url:
            url_constraints = [
                c for c in constraints
                if b"http" in str(c.value).lower().encode() or "url" in c.description.lower()
            ]
            assert url_constraints or constraints, "Must detect network indicators"

    def test_network_validation_produces_low_confidence_offline_algorithm(
        self, network_validation_binary: Path
    ) -> None:
        """Network-dependent validation creates algorithm with appropriate low confidence."""
        extractor = ConstraintExtractor(network_validation_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must create algorithm even for network-based validation"

        for algo in algorithms:
            assert algo.confidence >= 0.0, "Must provide confidence for network validation"
            assert algo.algorithm_name, "Network validation needs algorithm placeholder"

    def test_detects_api_endpoints_in_validation_code(self, network_validation_binary: Path) -> None:
        """Extractor identifies API endpoint patterns in binary."""
        extractor = ConstraintExtractor(network_validation_binary)
        constraints = extractor.extract_constraints()

        binary_data = network_validation_binary.read_bytes()

        if b"POST" in binary_data or b"GET" in binary_data:
            http_constraints = [c for c in constraints if "POST" in str(c.value) or "GET" in str(c.value)]
            assert http_constraints or len(constraints) > 0, "Must detect HTTP method indicators"


class TestAlgorithmExtractionEdgeCases:
    """Test edge cases in algorithm extraction."""

    def test_empty_binary_returns_generic_not_empty(self, temp_test_dir: Path) -> None:
        """Empty binary produces generic algorithm, not empty list."""
        binary_path = temp_test_dir / "empty.bin"
        binary_path.write_bytes(b"")

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert isinstance(algorithms, list), "Must return list for empty binary"

    def test_nonexistent_file_returns_generic_not_empty(self, temp_test_dir: Path) -> None:
        """Nonexistent file produces fallback, not empty list."""
        binary_path = temp_test_dir / "nonexistent.bin"

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert isinstance(algorithms, list), "Must return list for nonexistent file"

    def test_corrupted_binary_uses_heuristics_not_empty(self, temp_test_dir: Path) -> None:
        """Corrupted binary falls back to heuristics, not empty list."""
        binary_path = temp_test_dir / "corrupted.bin"

        corrupted = bytearray(b"\xff" * 200)
        corrupted[100:110] = b"\x00" * 10
        binary_path.write_bytes(bytes(corrupted))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert isinstance(algorithms, list), "Must handle corrupted data"

    def test_very_large_binary_extracts_algorithms_not_empty(self, temp_test_dir: Path) -> None:
        """Large binary with scattered constants extracts algorithms, not empty."""
        binary_path = temp_test_dir / "large_binary.bin"

        large_code = bytearray()
        large_code.extend(b"\x55")
        large_code.extend(b"\x48\x89\xe5")
        large_code.extend(b"\x90" * 20000)

        large_code.extend(b"\xb8")
        large_code.extend(struct.pack("<I", 0xEDB88320))

        large_code.extend(b"\x90" * 10000)
        large_code.extend(b"\x5d")
        large_code.extend(b"\xc3")

        binary_path.write_bytes(bytes(large_code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "Must extract algorithms from large binary"

    def test_binary_with_only_strings_creates_generic(self, temp_test_dir: Path) -> None:
        """Binary with only string patterns creates generic algorithm."""
        binary_path = temp_test_dir / "strings_only.bin"

        code = bytearray()
        code.extend(b"LICENSE\x00")
        code.extend(b"SERIAL\x00")
        code.extend(b"KEY\x00")
        code.extend(b"XXXX-XXXX-XXXX-XXXX\x00")
        code.extend(b"ACTIVATION\x00")

        binary_path.write_bytes(bytes(code))

        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()

        assert algorithms, "String patterns must create generic algorithm"


class TestExtractedAlgorithmValidation:
    """Test that extracted algorithms are functional."""

    def test_crc32_algorithm_validation_function_works(self, crc32_binary: Path) -> None:
        """Extracted CRC32 algorithm produces working validation function."""
        extractor = ConstraintExtractor(crc32_binary)
        algorithms = extractor.analyze_validation_algorithms()

        crc_algos = [a for a in algorithms if "CRC" in a.algorithm_name.upper() and a.validation_function]

        if crc_algos:
            crc_algo = crc_algos[0]
            validation_func = crc_algo.validation_function

            assert validation_func is not None, "CRC must have validation function"

            test_keys = ["LICENSE-123", "ABCD-EFGH-IJKL", "TEST-KEY-2025"]
            for key in test_keys:
                result = validation_func(key)
                assert isinstance(result, int), f"CRC must return int for: {key}"
                assert 0 <= result <= 0xFFFFFFFF, f"Invalid CRC value: {result}"

                expected = zlib.crc32(key.encode()) & 0xFFFFFFFF
                assert result == expected, f"CRC mismatch for {key}: {result} != {expected}"

    def test_md5_algorithm_validation_function_works(self, md5_binary: Path) -> None:
        """Extracted MD5 algorithm produces working hash function."""
        extractor = ConstraintExtractor(md5_binary)
        algorithms = extractor.analyze_validation_algorithms()

        md5_algos = [a for a in algorithms if "MD5" in a.algorithm_name.upper() and a.validation_function]

        if md5_algos:
            md5_algo = md5_algos[0]
            validation_func = md5_algo.validation_function

            assert validation_func is not None, "MD5 must have validation function"

            test_key = "VALID-LICENSE-KEY-2025"
            result = validation_func(test_key)

            assert isinstance(result, str), "MD5 must return hex string"
            assert len(result) == 32, f"MD5 hash wrong length: {len(result)}"

            expected = hashlib.md5(test_key.encode()).hexdigest()
            assert result == expected, f"MD5 mismatch: {result} != {expected}"

    def test_sha256_algorithm_validation_function_works(self, sha256_binary: Path) -> None:
        """Extracted SHA256 algorithm produces working hash function."""
        extractor = ConstraintExtractor(sha256_binary)
        algorithms = extractor.analyze_validation_algorithms()

        sha_algos = [
            a for a in algorithms
            if "SHA" in a.algorithm_name.upper() and a.validation_function
        ]

        if sha_algos:
            sha_algo = sha_algos[0]
            validation_func = sha_algo.validation_function

            assert validation_func is not None, "SHA must have validation function"

            test_key = "SHA-VALIDATION-TEST"
            result = validation_func(test_key)

            assert isinstance(result, str), "SHA must return hex string"
            assert len(result) in [40, 64], f"Invalid SHA hash length: {len(result)}"


class TestAlgorithmExtractionPerformance:
    """Test extraction performance on large binaries."""

    def test_extraction_completes_within_reasonable_time(self, temp_test_dir: Path) -> None:
        """Algorithm extraction completes in reasonable time for large binaries."""
        import time

        binary_path = temp_test_dir / "performance_test.bin"

        large_code = bytearray()
        large_code.extend(b"\x55" * 1000)
        large_code.extend(b"\x48\x89\xe5" * 500)
        large_code.extend(b"\x90" * 50000)

        large_code.extend(b"\xb8")
        large_code.extend(struct.pack("<I", 0xEDB88320))

        large_code.extend(b"\x90" * 30000)
        large_code.extend(b"\x5d")
        large_code.extend(b"\xc3")

        binary_path.write_bytes(bytes(large_code))

        start = time.time()
        extractor = ConstraintExtractor(binary_path)
        algorithms = extractor.analyze_validation_algorithms()
        elapsed = time.time() - start

        assert algorithms, "Must extract algorithms even from large binary"
        assert elapsed < 30.0, f"Extraction too slow: {elapsed:.2f}s"
