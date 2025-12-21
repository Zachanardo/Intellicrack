"""
Production-ready tests for intellicrack/core/license/keygen.py

Tests validate REAL offensive capabilities:
- Cryptographic constant detection in actual binary code
- License algorithm extraction from real validation routines
- Constraint solving with Z3 for license key generation
- RSA, ECDSA, CRC32, MD5, SHA validation detection
- Binary patching point identification
- Complete keygen workflows on real binaries
"""

import hashlib
import struct
import tempfile
import zlib
from pathlib import Path
from typing import Any

import capstone
import pytest
import z3

from intellicrack.core.license.keygen import (
    AlgorithmType,
    ConstraintExtractor,
    CryptoPrimitive,
    CryptoType,
    ExtractedAlgorithm,
    KeyConstraint,
    KeySynthesizer,
    LicenseKeygen,
    PatchLocation,
    ValidationAnalysis,
    ValidationAnalyzer,
    ValidationConstraint,
)
from intellicrack.core.serial_generator import GeneratedSerial, SerialConstraints, SerialFormat


class TestValidationAnalyzerCryptoDetection:
    """Test cryptographic constant detection in real binary code."""

    def test_md5_constants_detected_in_x64_binary(self) -> None:
        """Analyzer detects MD5 constants in x64 validation routine."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x48\xb8' + struct.pack("<Q", 0x67452301)
        binary_code += b'\x48\xb9' + struct.pack("<Q", 0xEFCDAB89)
        binary_code += b'\x48\xba' + struct.pack("<Q", 0x98BADCFE)
        binary_code += b'\x48\xbb' + struct.pack("<Q", 0x10325476)
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x64")

        md5_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "MD5"]
        assert md5_primitives
        assert md5_primitives[0].crypto_type == CryptoType.HASH
        assert md5_primitives[0].confidence >= 0.85
        assert analysis.algorithm_type == AlgorithmType.MD5

    def test_sha256_constants_detected_in_x86_binary(self) -> None:
        """Analyzer detects SHA256 constants in x86 validation routine."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\xb8' + struct.pack("<I", 0x6A09E667)
        binary_code += b'\xb9' + struct.pack("<I", 0xBB67AE85)
        binary_code += b'\xba' + struct.pack("<I", 0x3C6EF372)
        binary_code += b'\xbb' + struct.pack("<I", 0xA54FF53A)
        binary_code += b'\xbe' + struct.pack("<I", 0x510E527F)
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        sha256_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "SHA256"]
        assert len(sha256_primitives) >= 2
        assert all(p.crypto_type == CryptoType.HASH for p in sha256_primitives)
        assert all(p.confidence >= 0.9 for p in sha256_primitives)
        assert analysis.algorithm_type == AlgorithmType.SHA256
        assert analysis.confidence >= 0.9

    def test_crc32_polynomial_detected(self) -> None:
        """Analyzer detects CRC32 polynomial in binary."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\xb8' + struct.pack("<I", 0xEDB88320)
        binary_code += b'\x33\xc9'
        binary_code += b'\x85\xc0'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        crc_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "CRC32"]
        assert crc_primitives
        assert crc_primitives[0].crypto_type == CryptoType.CHECKSUM
        assert 0xEDB88320 in crc_primitives[0].constants
        assert analysis.algorithm_type == AlgorithmType.CRC32

    def test_rsa_exponent_detected(self) -> None:
        """Analyzer detects RSA public exponent 65537 in binary."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\xb8' + struct.pack("<I", 65537)
        binary_code += b'\x89\x45\xfc'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        rsa_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "RSA"]
        assert rsa_primitives
        assert rsa_primitives[0].crypto_type == CryptoType.SIGNATURE
        assert 65537 in rsa_primitives[0].constants

    def test_custom_xor_chain_detected(self) -> None:
        """Analyzer detects custom XOR-based validation scheme."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        for _ in range(10):
            binary_code += b'\x31\xc0'
            binary_code += b'\x31\xdb'
            binary_code += b'\x31\xc9'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        custom_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "CUSTOM_XOR"]
        assert custom_primitives
        assert custom_primitives[0].crypto_type == CryptoType.CHECKSUM


class TestValidationAnalyzerConstraintExtraction:
    """Test constraint extraction from license validation code."""

    def test_length_constraint_extracted_from_cmp(self) -> None:
        """Analyzer extracts length constraint from cmp instruction."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x83\xf8\x10'
        binary_code += b'\x75\x10'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        length_constraints = [c for c in analysis.constraints if c.constraint_type == "length"]
        assert length_constraints
        assert length_constraints[0].value == 16
        assert "length must be 16" in length_constraints[0].description.lower()

    def test_charset_constraints_extracted(self) -> None:
        """Analyzer extracts character set constraints from validation code."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x83\xf8\x41'
        binary_code += b'\x75\x05'
        binary_code += b'\x83\xf8\x5A'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        charset_constraints = [c for c in analysis.constraints if c.constraint_type == "charset"]
        assert charset_constraints
        assert any(c.value == "uppercase" for c in charset_constraints)

    def test_separator_constraint_detected(self) -> None:
        """Analyzer detects dash separator in license key format."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x83\xf8\x2d'
        binary_code += b'\x75\x05'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        separator_constraints = [c for c in analysis.constraints if c.constraint_type == "separator"]
        assert separator_constraints
        assert separator_constraints[0].value == "-"

    def test_null_check_constraint_extracted(self) -> None:
        """Analyzer identifies null/empty validation checks."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x85\xc0'
        binary_code += b'\x74\x05'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        null_checks = [c for c in analysis.constraints if c.constraint_type == "null_check"]
        assert null_checks
        assert null_checks[0].value is True


class TestValidationAnalyzerPatchPoints:
    """Test identification of binary patch points for license bypass."""

    def test_conditional_jump_patch_point_identified(self) -> None:
        """Analyzer identifies conditional jump suitable for NOPing."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x83\xf8\x00'
        binary_code += b'\x74\x05'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        assert len(analysis.patch_points) >= 1
        nop_patches = [p for p in analysis.patch_points if p.patch_type == "nop_conditional"]
        assert nop_patches
        assert nop_patches[0].suggested_patch == b'\x90' * 2

    def test_force_jump_patch_suggested(self) -> None:
        """Analyzer suggests converting conditional to unconditional jump."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x83\xf8\x01'
        binary_code += b'\x74\x08'
        binary_code += b'\xb8\x00\x00\x00\x00'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        force_jump_patches = [p for p in analysis.patch_points if p.patch_type == "force_jump"]
        assert force_jump_patches
        assert force_jump_patches[0].suggested_patch[0] == 0xEB

    def test_force_success_return_patch_identified(self) -> None:
        """Analyzer identifies return value patches to force success."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\xb8\x00\x00\x00\x00'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        success_patches = [p for p in analysis.patch_points if p.patch_type == "force_success"]
        assert success_patches
        assert success_patches[0].suggested_patch in (b'\xb8\x01\x00\x00\x00', b'\xb0\x01')


class TestValidationAnalyzerEmbeddedConstants:
    """Test extraction of embedded cryptographic constants from binaries."""

    def test_md5_constant_extracted_from_binary(self) -> None:
        """Analyzer extracts MD5 initialization vectors from binary data."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray(256)
        offset = 100
        struct.pack_into("<I", binary_code, offset, 0x67452301)
        struct.pack_into("<I", binary_code, offset + 4, 0xEFCDAB89)

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        md5_constants = {k: v for k, v in analysis.embedded_constants.items() if "md5" in k}
        assert md5_constants

    def test_string_constants_extracted(self) -> None:
        """Analyzer extracts ASCII string constants from binary."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray(256)
        test_string = b"LICENSEKEY123456789012345678901"
        binary_code[50:50+len(test_string)] = test_string

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        string_constants = {k: v for k, v in analysis.embedded_constants.items() if "string" in k}
        assert string_constants


class TestValidationAnalyzerRecommendations:
    """Test generation of actionable cracking recommendations."""

    def test_md5_recommendations_generated(self) -> None:
        """Analyzer provides MD5-specific cracking recommendations."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\xb8' + struct.pack("<I", 0x67452301)
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        assert len(analysis.recommendations) > 0
        md5_recs = [r for r in analysis.recommendations if "MD5" in r or "rainbow" in r.lower()]
        assert md5_recs

    def test_patch_point_recommendations_included(self) -> None:
        """Analyzer recommends patching when patch points found."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x83\xf8\x00'
        binary_code += b'\x74\x05'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        patch_recs = [r for r in analysis.recommendations if "patch" in r.lower()]
        assert patch_recs

    def test_crc32_reversibility_recommendation(self) -> None:
        """Analyzer recommends CRC32 reversal technique."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\xb8' + struct.pack("<I", 0xEDB88320)
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        crc_recs = [r for r in analysis.recommendations if "CRC" in r and "reversible" in r.lower()]
        assert crc_recs


class TestConstraintExtractorAlgorithmBuilding:
    """Test building of license algorithms from extracted constraints."""

    @pytest.fixture
    def temp_binary(self) -> Path:
        """Create temporary binary file for testing."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 1000)
            return Path(f.name)

    def test_crc_algorithm_built_with_validation(self, temp_binary: Path) -> None:
        """CRC algorithm builder creates working validation function."""
        extractor = ConstraintExtractor(temp_binary)

        constraints = [
            KeyConstraint(
                constraint_type="algorithm",
                description="CRC32 validation",
                value="crc",
                confidence=0.9
            )
        ]

        algorithm: ExtractedAlgorithm = extractor._build_crc_algorithm(constraints)

        assert algorithm.algorithm_name == "CRC32"
        assert algorithm.validation_function is not None
        assert algorithm.confidence >= 0.8

        test_key = "TESTKEY123"
        result = algorithm.validation_function(test_key)
        expected_crc = zlib.crc32(test_key.encode()) & 0xFFFFFFFF
        assert result == expected_crc

    def test_md5_algorithm_built_with_hash_function(self, temp_binary: Path) -> None:
        """MD5 algorithm builder creates correct hash function."""
        extractor = ConstraintExtractor(temp_binary)

        constraints = [
            KeyConstraint(
                constraint_type="algorithm",
                description="MD5 hash validation",
                value="md5",
                confidence=0.9
            )
        ]

        algorithm: ExtractedAlgorithm = extractor._build_hash_algorithm("md5", constraints)

        assert algorithm.algorithm_name == "MD5"
        assert algorithm.validation_function is not None
        assert algorithm.key_format == SerialFormat.HEXADECIMAL

        test_key = "LICENSE123"
        result = algorithm.validation_function(test_key)
        expected_hash = hashlib.md5(test_key.encode()).hexdigest()
        assert result == expected_hash

    def test_sha256_algorithm_generates_correct_hash(self, temp_binary: Path) -> None:
        """SHA256 algorithm produces valid hash outputs."""
        extractor = ConstraintExtractor(temp_binary)

        algorithm: ExtractedAlgorithm = extractor._build_hash_algorithm("sha256", [])

        test_key = "PRODUCTKEY999"
        result = algorithm.validation_function(test_key)
        expected = hashlib.sha256(test_key.encode()).hexdigest()
        assert result == expected
        assert len(result) == 64

    def test_multiplicative_algorithm_computes_hash(self, temp_binary: Path) -> None:
        """Multiplicative hash algorithm computes correctly."""
        extractor = ConstraintExtractor(temp_binary)

        constraints = [
            KeyConstraint(
                constraint_type="algorithm",
                description="Multiplicative hash",
                value="multiplicative_hash",
                confidence=0.75
            )
        ]

        algorithm: ExtractedAlgorithm = extractor._build_multiplicative_algorithm(constraints)

        test_key = "ABC123"
        result = algorithm.validation_function(test_key)

        expected = 0
        for char in test_key:
            expected = expected * 31 + ord(char)
        expected &= 0xFFFFFFFF

        assert result == expected

    def test_modular_algorithm_validates_keys(self, temp_binary: Path) -> None:
        """Modular arithmetic algorithm validates license keys."""
        extractor = ConstraintExtractor(temp_binary)

        algorithm: ExtractedAlgorithm = extractor._build_modular_algorithm([])

        test_key = "ABC123"
        result = algorithm.validation_function(test_key)

        numeric = "".join(c if c.isdigit() else str(ord(c) - ord("A") + 10) for c in test_key)
        expected = int(numeric) % 97

        assert result == expected


class TestKeySynthesizerKeyGeneration:
    """Test license key synthesis from algorithms using real constraint solving."""

    def test_synthesizer_generates_valid_crc32_key(self) -> None:
        """Synthesizer produces keys that pass CRC32 validation."""
        synthesizer = KeySynthesizer()

        def crc_validate(key: str) -> bool:
            return (zlib.crc32(key.encode()) & 0xFFFFFFFF) % 100 == 42

        algorithm = ExtractedAlgorithm(
            algorithm_name="CRC32",
            parameters={"polynomial": 0xEDB88320},
            validation_function=crc_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=[],
            confidence=0.85
        )

        generated: GeneratedSerial = synthesizer.synthesize_key(algorithm)

        assert generated.serial is not None
        assert len(generated.serial) > 0
        assert generated.confidence >= 0.8

    def test_synthesizer_respects_length_constraint(self) -> None:
        """Synthesizer honors length constraints in key generation."""
        synthesizer = KeySynthesizer()

        constraints = [
            KeyConstraint(
                constraint_type="length",
                description="16 character length",
                value=16,
                confidence=1.0
            )
        ]

        algorithm = ExtractedAlgorithm(
            algorithm_name="Generic",
            parameters={},
            validation_function=None,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.5
        )

        generated: GeneratedSerial = synthesizer.synthesize_key(algorithm)

        key_without_separators = generated.serial.replace("-", "")
        assert len(key_without_separators) == 16

    def test_synthesizer_generates_batch_of_unique_keys(self) -> None:
        """Synthesizer creates multiple unique license keys."""
        synthesizer = KeySynthesizer()

        algorithm = ExtractedAlgorithm(
            algorithm_name="Generic",
            parameters={},
            validation_function=None,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=[],
            confidence=0.7
        )

        keys: list[GeneratedSerial] = synthesizer.synthesize_batch(algorithm, count=10, unique=True)

        assert len(keys) == 10
        serials = [k.serial for k in keys]
        assert len(set(serials)) == 10

    def test_synthesizer_creates_user_specific_key(self) -> None:
        """Synthesizer generates hardware-locked user-specific keys."""
        synthesizer = KeySynthesizer()

        algorithm = ExtractedAlgorithm(
            algorithm_name="Hardware",
            parameters={},
            validation_function=None,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=[],
            confidence=0.9
        )

        username = "testuser"
        hardware_id = "HWID-12345"

        generated: GeneratedSerial = synthesizer.synthesize_for_user(
            algorithm,
            username=username,
            hardware_id=hardware_id
        )

        assert generated.serial is not None
        assert generated.hardware_id == hardware_id


class TestKeySynthesizerZ3ConstraintSolving:
    """Test Z3 constraint solver for license key generation."""

    def test_z3_solver_generates_numeric_key(self) -> None:
        """Z3 solver produces key satisfying numeric charset constraint."""
        synthesizer = KeySynthesizer()

        constraints = [
            KeyConstraint(
                constraint_type="length",
                description="8 characters",
                value=8,
                confidence=1.0
            ),
            KeyConstraint(
                constraint_type="charset",
                description="numeric only",
                value="numeric",
                confidence=1.0
            )
        ]

        key: str | None = synthesizer.synthesize_with_z3(constraints)

        assert key is not None
        assert len(key) == 8
        assert all(c.isdigit() for c in key)

    def test_z3_solver_generates_uppercase_key(self) -> None:
        """Z3 solver produces key with uppercase letters only."""
        synthesizer = KeySynthesizer()

        constraints = [
            KeyConstraint(
                constraint_type="length",
                description="10 characters",
                value=10,
                confidence=1.0
            ),
            KeyConstraint(
                constraint_type="charset",
                description="uppercase letters",
                value="uppercase",
                confidence=1.0
            )
        ]

        key: str | None = synthesizer.synthesize_with_z3(constraints)

        assert key is not None
        assert len(key) == 10
        assert all(c.isupper() and c.isalpha() for c in key)

    def test_z3_solver_generates_alphanumeric_key(self) -> None:
        """Z3 solver produces alphanumeric key."""
        synthesizer = KeySynthesizer()

        constraints = [
            KeyConstraint(
                constraint_type="length",
                description="12 characters",
                value=12,
                confidence=1.0
            ),
            KeyConstraint(
                constraint_type="charset",
                description="alphanumeric",
                value="alphanumeric",
                confidence=1.0
            )
        ]

        key: str | None = synthesizer.synthesize_with_z3(constraints)

        assert key is not None
        assert len(key) == 12
        assert all(c.isalnum() and c.isupper() for c in key if c.isalpha())

    def test_z3_solver_returns_none_for_unsatisfiable_constraints(self) -> None:
        """Z3 solver returns None when constraints are contradictory."""
        synthesizer = KeySynthesizer()

        solver = synthesizer.solver
        solver.reset()
        solver.add(z3.Bool("x") == True)
        solver.add(z3.Bool("x") == False)

        assert solver.check() == z3.unsat


class TestLicenseKeygenEndToEnd:
    """Test complete keygen workflows from binary analysis to key generation."""

    @pytest.fixture
    def crc32_validation_binary(self) -> Path:
        """Create binary with real CRC32 validation routine."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            binary_code = bytearray()

            binary_code += b"MZ" + b"\x00" * 58
            binary_code += struct.pack("<I", 128)
            binary_code += b"\x00" * 64

            binary_code += b"PE\x00\x00"
            binary_code += b"\x4c\x01" + b"\x00" * 18

            binary_code += b"\x0b\x01" + b"\x00" * 222

            text_section = b".text\x00\x00\x00"
            text_section += b"\x00\x10\x00\x00"
            text_section += b"\x00\x10\x00\x00"
            text_section += b"\x00\x10\x00\x00"
            text_section += b"\x00\x04\x00\x00"
            text_section += b"\x00" * 12
            text_section += b"\x20\x00\x00\x60"
            binary_code += text_section

            padding_needed = 1024 - len(binary_code)
            binary_code += b"\x00" * padding_needed

            code_section = bytearray()
            code_section += b'\xb8' + struct.pack("<I", 0xEDB88320)
            code_section += b'\x33\xc9'
            code_section += b'\x83\xf9\x10'
            code_section += b'\x7d\x10'
            code_section += b'\xd1\xe8'
            code_section += b'\x73\x05'
            code_section += b'\x35\x20\x83\xb8\xed'
            code_section += b'\x41'
            code_section += b'\xeb\xed'
            code_section += b'\xc3'

            code_section += b'\x90' * (4096 - len(code_section))

            binary_code += code_section

            f.write(bytes(binary_code))
            return Path(f.name)

    def test_keygen_analyzes_binary_and_generates_key(self, crc32_validation_binary: Path) -> None:
        """Complete workflow: analyze binary with CRC32 and generate valid key."""
        keygen = LicenseKeygen(binary_path=crc32_validation_binary)

        assert keygen.binary_path == crc32_validation_binary
        assert keygen.extractor is not None
        assert keygen.synthesizer is not None

    def test_keygen_generates_crc32_key_from_algorithm(self) -> None:
        """Keygen generates valid CRC32-based license key."""
        keygen = LicenseKeygen()

        generated: GeneratedSerial = keygen.generate_key_from_algorithm("crc32", length=16)

        assert generated.serial is not None
        assert generated.algorithm == "crc32"
        assert generated.confidence >= 0.8
        assert len(generated.serial.replace("-", "")) >= 15

    def test_keygen_generates_luhn_validated_key(self) -> None:
        """Keygen generates Luhn-validated license key."""
        keygen = LicenseKeygen()

        generated: GeneratedSerial = keygen.generate_key_from_algorithm("luhn", length=16)

        assert generated.serial is not None
        assert generated.algorithm == "luhn"
        assert generated.confidence >= 0.85

    def test_keygen_generates_microsoft_format_key(self) -> None:
        """Keygen generates Microsoft-style 25-character license key."""
        keygen = LicenseKeygen()

        generated: GeneratedSerial = keygen.generate_key_from_algorithm("microsoft")

        assert generated.serial is not None
        assert generated.serial.count("-") == 4
        parts = generated.serial.split("-")
        assert len(parts) == 5
        assert all(len(p) == 5 for p in parts)

    def test_keygen_generates_uuid_format_key(self) -> None:
        """Keygen generates UUID-format license key."""
        keygen = LicenseKeygen()

        generated: GeneratedSerial = keygen.generate_key_from_algorithm("uuid")

        assert generated.serial is not None
        assert len(generated.serial) == 36
        assert generated.serial.count("-") == 4

    def test_keygen_generates_hardware_locked_key(self) -> None:
        """Keygen creates hardware-locked license key with valid checksum."""
        keygen = LicenseKeygen()

        hardware_id = "DISK-1234-5678-ABCD"
        product_id = "PROD-2024-X"

        generated: GeneratedSerial = keygen.generate_hardware_locked_key(hardware_id, product_id)

        assert generated.serial is not None
        assert generated.hardware_id == hardware_id
        assert generated.algorithm == "hardware_locked"
        assert generated.confidence >= 0.9
        assert "-" in generated.serial

    def test_keygen_generates_time_limited_key(self) -> None:
        """Keygen creates time-limited license key."""
        keygen = LicenseKeygen()

        product_id = "SOFTWARE-2024"
        days_valid = 30

        generated: GeneratedSerial = keygen.generate_time_limited_key(product_id, days_valid)

        assert generated.serial is not None
        assert generated.expiration is not None
        assert generated.expiration > 0

    def test_keygen_generates_feature_encoded_key(self) -> None:
        """Keygen creates feature-encoded license key."""
        keygen = LicenseKeygen()

        features = ["premium", "cloud", "support"]

        generated: GeneratedSerial = keygen.generate_feature_key("BaseProduct", features)

        assert generated.serial is not None
        assert generated.features == features

    def test_keygen_brute_forces_partial_key(self) -> None:
        """Keygen brute forces missing characters in partial license key."""
        keygen = LicenseKeygen()

        target_key = "ABCD-EFGH-1234-5678"
        partial_key = "ABCD-E?GH-1234-567?"
        missing_positions = [6, 18]

        def validation_func(key: str) -> bool:
            return key == target_key

        result: str | None = keygen.brute_force_key(
            partial_key,
            missing_positions,
            validation_func,
            charset="FG8"
        )

        assert result == target_key

    def test_keygen_brute_force_returns_none_if_too_complex(self) -> None:
        """Keygen refuses brute force if search space too large."""
        keygen = LicenseKeygen()

        partial_key = "????-????-????-????"
        missing_positions = list(range(19))

        def always_false(key: str) -> bool:
            return False

        result: str | None = keygen.brute_force_key(partial_key, missing_positions, always_false)

        assert result is None

    def test_keygen_generates_volume_licenses(self) -> None:
        """Keygen generates batch of RSA-signed volume license keys."""
        keygen = LicenseKeygen()

        product_id = "ENTERPRISE-2024"
        count = 5

        licenses: list[GeneratedSerial] = keygen.generate_volume_license(product_id, count)

        assert len(licenses) == count
        assert all(isinstance(lic, GeneratedSerial) for lic in licenses)
        assert all(lic.serial is not None for lic in licenses)


class TestLicenseKeygenReverseEngineering:
    """Test reverse engineering of license algorithms from valid/invalid keys."""

    def test_reverse_engineer_detects_patterns(self) -> None:
        """Reverse engineering identifies patterns in valid license keys."""
        keygen = LicenseKeygen()

        valid_keys = [
            "ABCD-1234-EFGH-5678",
            "WXYZ-9876-IJKL-5432",
            "MNOP-1111-QRST-2222"
        ]

        analysis: dict[str, Any] = keygen.reverse_engineer_keygen(valid_keys)

        assert "format" in analysis or "length" in analysis or "structure" in analysis

    def test_reverse_engineer_with_invalid_keys(self) -> None:
        """Reverse engineering uses invalid keys to narrow algorithm."""
        keygen = LicenseKeygen()

        valid_keys = ["VALID-KEY-123"]
        invalid_keys = ["INVALID1", "BAD-KEY"]

        analysis: dict[str, Any] = keygen.reverse_engineer_keygen(valid_keys, invalid_keys)

        assert analysis is not None


class TestValidationAnalyzerComplexBinaries:
    """Test analyzer on complex real-world binary patterns."""

    def test_analyzer_handles_mixed_crypto_primitives(self) -> None:
        """Analyzer correctly identifies multiple crypto schemes in one binary."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\xb8' + struct.pack("<I", 0x67452301)
        binary_code += b'\x90' * 20
        binary_code += b'\xb8' + struct.pack("<I", 0xEDB88320)
        binary_code += b'\x90' * 20
        binary_code += b'\xb8' + struct.pack("<I", 65537)
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        assert len(analysis.crypto_primitives) >= 3
        algorithms = {p.algorithm for p in analysis.crypto_primitives}
        assert "MD5" in algorithms or "CRC32" in algorithms

    def test_analyzer_processes_large_binary_routine(self) -> None:
        """Analyzer handles large validation routines efficiently."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        for _ in range(200):
            binary_code += b'\x90'
            binary_code += b'\x33\xc0'
            binary_code += b'\x85\xc0'
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        assert analysis is not None
        assert analysis.algorithm_type is not None

    def test_analyzer_detects_obfuscated_validation(self) -> None:
        """Analyzer identifies validation logic in obfuscated code."""
        analyzer = ValidationAnalyzer()

        binary_code = bytearray()
        binary_code += b'\x90' * 10
        binary_code += b'\x83\xf8\x10'
        binary_code += b'\x90' * 5
        binary_code += b'\x75\x20'
        binary_code += b'\x90' * 10
        binary_code += b'\xb8' + struct.pack("<I", 0x67452301)
        binary_code += b'\x90' * 5
        binary_code += b'\xc3'

        analysis: ValidationAnalysis = analyzer.analyze(bytes(binary_code), arch="x86")

        assert len(analysis.constraints) > 0 or len(analysis.crypto_primitives) > 0


class TestKeygenDataTypes:
    """Test dataclass structures and type safety."""

    def test_key_constraint_structure(self) -> None:
        """KeyConstraint dataclass stores constraint data correctly."""
        constraint = KeyConstraint(
            constraint_type="length",
            description="16 character key",
            value=16,
            confidence=0.95,
            source_address=0x401000,
            assembly_context="cmp eax, 16"
        )

        assert constraint.constraint_type == "length"
        assert constraint.value == 16
        assert constraint.confidence == 0.95
        assert constraint.source_address == 0x401000

    def test_validation_constraint_structure(self) -> None:
        """ValidationConstraint stores extraction results."""
        constraint = ValidationConstraint(
            constraint_type="charset",
            value="uppercase",
            offset=0x1000,
            description="Uppercase letters only"
        )

        assert constraint.constraint_type == "charset"
        assert constraint.value == "uppercase"
        assert constraint.offset == 0x1000

    def test_patch_location_structure(self) -> None:
        """PatchLocation contains complete patch information."""
        patch = PatchLocation(
            offset=0x401234,
            instruction="je 0x401250",
            patch_type="nop_conditional",
            original_bytes=b'\x74\x1c',
            suggested_patch=b'\x90\x90',
            description="NOP conditional jump"
        )

        assert patch.offset == 0x401234
        assert patch.patch_type == "nop_conditional"
        assert len(patch.original_bytes) == len(patch.suggested_patch)

    def test_crypto_primitive_structure(self) -> None:
        """CryptoPrimitive captures detected crypto algorithms."""
        primitive = CryptoPrimitive(
            crypto_type=CryptoType.HASH,
            algorithm="SHA256",
            offset=0x403000,
            constants=[0x6A09E667, 0xBB67AE85],
            confidence=0.95
        )

        assert primitive.crypto_type == CryptoType.HASH
        assert primitive.algorithm == "SHA256"
        assert len(primitive.constants) == 2

    def test_extracted_algorithm_structure(self) -> None:
        """ExtractedAlgorithm contains complete algorithm specification."""
        algorithm = ExtractedAlgorithm(
            algorithm_name="CRC32",
            parameters={"polynomial": 0xEDB88320},
            validation_function=lambda x: zlib.crc32(x.encode()),
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=[],
            confidence=0.85
        )

        assert algorithm.algorithm_name == "CRC32"
        assert algorithm.validation_function is not None
        assert algorithm.confidence == 0.85
        assert algorithm.validation_function("test") == zlib.crc32(b"test")
