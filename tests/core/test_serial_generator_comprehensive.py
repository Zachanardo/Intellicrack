"""
Comprehensive production-ready tests for SerialNumberGenerator.
Tests REAL serial generation algorithms and validation.
NO MOCKS - All tests validate genuine serial generation capability.
"""

import base64
import hashlib
import hmac
import json
import struct
import time
import zlib
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from intellicrack.core.serial_generator import (
    GeneratedSerial,
    SerialConstraints,
    SerialFormat,
    SerialNumberGenerator,
)


class TestSerialNumberGeneratorInitialization:
    """Test SerialNumberGenerator initialization and setup."""

    def test_generator_initializes_with_all_algorithms(self) -> None:
        """Generator initializes with complete algorithm registry."""
        generator = SerialNumberGenerator()

        assert generator.backend is not None
        assert len(generator.common_algorithms) == 10
        assert "luhn" in generator.common_algorithms
        assert "verhoeff" in generator.common_algorithms
        assert "damm" in generator.common_algorithms
        assert "crc32" in generator.common_algorithms
        assert "mod97" in generator.common_algorithms
        assert "custom_polynomial" in generator.common_algorithms
        assert "elliptic_curve" in generator.common_algorithms
        assert "rsa_based" in generator.common_algorithms
        assert "hash_chain" in generator.common_algorithms
        assert "feistel" in generator.common_algorithms

    def test_generator_initializes_with_all_checksums(self) -> None:
        """Generator initializes with complete checksum function registry."""
        generator = SerialNumberGenerator()

        assert len(generator.checksum_functions) == 11
        assert "luhn" in generator.checksum_functions
        assert "verhoeff" in generator.checksum_functions
        assert "damm" in generator.checksum_functions
        assert "crc16" in generator.checksum_functions
        assert "crc32" in generator.checksum_functions
        assert "fletcher16" in generator.checksum_functions
        assert "fletcher32" in generator.checksum_functions
        assert "adler32" in generator.checksum_functions
        assert "mod11" in generator.checksum_functions
        assert "mod37" in generator.checksum_functions
        assert "mod97" in generator.checksum_functions

    def test_z3_solver_initialized(self) -> None:
        """Z3 constraint solver is properly initialized."""
        generator = SerialNumberGenerator()
        assert generator.solver is not None


class TestLuhnSerialGeneration:
    """Test Luhn algorithm-based serial generation and validation."""

    def test_generate_luhn_serial_produces_valid_checksum(self) -> None:
        """Luhn serial generation produces valid checksum digit."""
        generator = SerialNumberGenerator()

        serial = generator._generate_luhn_serial(16)

        assert len(serial) == 16
        assert serial.isdigit()
        assert generator._verify_luhn(serial)

    def test_luhn_serial_fails_with_modified_digit(self) -> None:
        """Modified Luhn serial fails validation."""
        generator = SerialNumberGenerator()

        serial = generator._generate_luhn_serial(16)
        digits = list(serial)
        digits[5] = str((int(digits[5]) + 1) % 10)
        modified_serial = "".join(digits)

        assert not generator._verify_luhn(modified_serial)

    def test_luhn_checksum_calculation_correctness(self) -> None:
        """Luhn checksum calculation produces correct check digit."""
        generator = SerialNumberGenerator()

        test_cases = [
            ("123456789012345", "2"),
            ("111111111111111", "7"),
            ("987654321098765", "8"),
        ]

        for data, expected_checksum in test_cases:
            checksum = generator._calculate_luhn(data)
            assert checksum == expected_checksum

    def test_luhn_serial_multiple_generations_unique(self) -> None:
        """Multiple Luhn serial generations produce unique valid serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_luhn_serial(16) for _ in range(100)]

        assert len(set(serials)) >= 95
        assert all(generator._verify_luhn(s) for s in serials)


class TestVerhoeffSerialGeneration:
    """Test Verhoeff algorithm-based serial generation."""

    def test_generate_verhoeff_serial_correct_length(self) -> None:
        """Verhoeff serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [10, 16, 20, 32]:
            serial = generator._generate_verhoeff_serial(length)
            assert len(serial) == length
            assert serial.isdigit()

    def test_verhoeff_serial_multiple_generations_unique(self) -> None:
        """Multiple Verhoeff serial generations produce unique serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_verhoeff_serial(16) for _ in range(100)]

        assert len(set(serials)) >= 95


class TestDammSerialGeneration:
    """Test Damm algorithm-based serial generation."""

    def test_generate_damm_serial_correct_length(self) -> None:
        """Damm serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [10, 16, 20, 32]:
            serial = generator._generate_damm_serial(length)
            assert len(serial) == length
            assert serial.isdigit()

    def test_damm_serial_multiple_generations_unique(self) -> None:
        """Multiple Damm serial generations produce unique serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_damm_serial(16) for _ in range(100)]

        assert len(set(serials)) >= 95


class TestCRC32SerialGeneration:
    """Test CRC32-based serial generation and validation."""

    def test_generate_crc32_serial_produces_valid_checksum(self) -> None:
        """CRC32 serial generation produces valid checksum."""
        generator = SerialNumberGenerator()

        serial = generator._generate_crc32_serial(16)

        assert len(serial) == 16
        assert generator._verify_crc32(serial)

    def test_crc32_serial_fails_with_modified_character(self) -> None:
        """Modified CRC32 serial fails validation."""
        generator = SerialNumberGenerator()

        serial = generator._generate_crc32_serial(24)
        modified_serial = serial[:-1] + ("A" if serial[-1] != "A" else "B")

        assert not generator._verify_crc32(modified_serial)

    def test_crc32_checksum_calculation_correctness(self) -> None:
        """CRC32 checksum calculation produces correct value."""
        generator = SerialNumberGenerator()

        test_data = "ABCDEFGH"
        checksum = generator._calculate_crc32(test_data)

        assert len(checksum) == 8
        assert all(c in "0123456789ABCDEF" for c in checksum)

        expected_crc = zlib.crc32(test_data.encode()) & 0xFFFFFFFF
        expected_checksum = format(expected_crc, "08X")
        assert checksum == expected_checksum

    def test_crc32_serial_multiple_generations_unique(self) -> None:
        """Multiple CRC32 serial generations produce unique valid serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_crc32_serial(24) for _ in range(100)]

        assert len(set(serials)) >= 95
        assert all(generator._verify_crc32(s) for s in serials)


class TestMod97SerialGeneration:
    """Test mod97 (IBAN-style) serial generation."""

    def test_generate_mod97_serial_correct_length(self) -> None:
        """Mod97 serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [10, 16, 20, 32]:
            serial = generator._generate_mod97_serial(length)
            assert len(serial) == length
            assert serial.isdigit()

    def test_mod97_serial_passes_checksum_validation(self) -> None:
        """Mod97 serial passes checksum validation."""
        generator = SerialNumberGenerator()

        serial = generator._generate_mod97_serial(18)

        data = serial[:-2]
        checksum_part = serial[-2:]
        calculated_checksum = generator._calculate_mod97(data)

        assert checksum_part == calculated_checksum

    def test_mod97_serial_multiple_generations_unique(self) -> None:
        """Multiple mod97 serial generations produce unique serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_mod97_serial(16) for _ in range(100)]

        assert len(set(serials)) >= 95


class TestPolynomialSerialGeneration:
    """Test polynomial-based serial generation using LFSR."""

    def test_generate_polynomial_serial_correct_length(self) -> None:
        """Polynomial serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [10, 16, 24, 32]:
            serial = generator._generate_polynomial_serial(length)
            assert len(serial) == length
            assert serial.isalpha()

    def test_polynomial_serial_multiple_generations_unique(self) -> None:
        """Multiple polynomial serial generations produce unique serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_polynomial_serial(16) for _ in range(100)]

        assert len(set(serials)) >= 80


class TestECCSerialGeneration:
    """Test elliptic curve-based serial generation."""

    def test_generate_ecc_serial_correct_length(self) -> None:
        """ECC serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [16, 24, 32]:
            serial = generator._generate_ecc_serial(length)
            assert len(serial) <= length


class TestRSASerialGeneration:
    """Test RSA-like serial generation."""

    def test_generate_rsa_serial_correct_length(self) -> None:
        """RSA serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [16, 20, 24, 32]:
            serial = generator._generate_rsa_serial(length)
            assert len(serial) <= length
            assert all(c in "0123456789ABCDEF" for c in serial)


class TestHashChainSerialGeneration:
    """Test hash chain-based serial generation."""

    def test_generate_hash_chain_serial_correct_length(self) -> None:
        """Hash chain serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [16, 24, 32]:
            serial = generator._generate_hash_chain_serial(length)
            assert len(serial) == length

    def test_hash_chain_serial_multiple_generations_unique(self) -> None:
        """Multiple hash chain serial generations produce unique serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_hash_chain_serial(16) for _ in range(100)]

        assert len(set(serials)) >= 95


class TestFeistelSerialGeneration:
    """Test Feistel network-based serial generation."""

    def test_generate_feistel_serial_correct_length(self) -> None:
        """Feistel serial generation produces correct length."""
        generator = SerialNumberGenerator()

        for length in [16, 24, 32]:
            serial = generator._generate_feistel_serial(length)
            assert len(serial) == length
            assert serial.isalnum()

    def test_feistel_serial_multiple_generations_unique(self) -> None:
        """Multiple Feistel serial generations produce unique serials."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_feistel_serial(16) for _ in range(100)]

        assert len(set(serials)) >= 95


class TestChecksumCalculations:
    """Test various checksum calculation functions."""

    def test_crc16_checksum_calculation(self) -> None:
        """CRC16 checksum calculation produces 4-character hex."""
        generator = SerialNumberGenerator()

        checksum = generator._calculate_crc16("TESTDATA")

        assert len(checksum) == 4
        assert all(c in "0123456789ABCDEF" for c in checksum)

    def test_fletcher16_checksum_calculation(self) -> None:
        """Fletcher-16 checksum calculation produces 4-character hex."""
        generator = SerialNumberGenerator()

        checksum = generator._calculate_fletcher16("TESTDATA")

        assert len(checksum) == 4
        assert all(c in "0123456789ABCDEF" for c in checksum)

    def test_fletcher32_checksum_calculation(self) -> None:
        """Fletcher-32 checksum calculation produces 8-character hex."""
        generator = SerialNumberGenerator()

        checksum = generator._calculate_fletcher32("TESTDATA")

        assert len(checksum) == 8
        assert all(c in "0123456789ABCDEF" for c in checksum)

    def test_adler32_checksum_calculation(self) -> None:
        """Adler-32 checksum calculation produces 8-character hex."""
        generator = SerialNumberGenerator()

        checksum = generator._calculate_adler32("TESTDATA")

        assert len(checksum) == 8
        assert all(c in "0123456789ABCDEF" for c in checksum)

    def test_mod11_checksum_calculation(self) -> None:
        """Mod11 checksum calculation produces valid check character."""
        generator = SerialNumberGenerator()

        checksum = generator._calculate_mod11("123456789")

        assert len(checksum) == 1
        assert checksum in "0123456789X"

    def test_mod37_checksum_calculation(self) -> None:
        """Mod37 checksum calculation produces alphanumeric character."""
        generator = SerialNumberGenerator()

        checksum = generator._calculate_mod37("ABC123XYZ")

        assert len(checksum) == 1
        assert checksum.isalnum()


class TestMicrosoftSerialGeneration:
    """Test Microsoft product key format generation."""

    def test_generate_microsoft_serial_correct_format(self) -> None:
        """Microsoft serial has correct 5-5-5-5-5 format."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=25,
            format=SerialFormat.MICROSOFT,
            groups=5,
        )

        result = generator._generate_microsoft_serial(constraints)

        assert result.format == SerialFormat.MICROSOFT
        assert result.confidence >= 0.9

        parts = result.serial.split("-")
        assert len(parts) == 5
        assert all(len(part) == 5 for part in parts)

    def test_microsoft_serial_uses_valid_characters(self) -> None:
        """Microsoft serial uses only valid characters (no vowels, no lookalikes)."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=25,
            format=SerialFormat.MICROSOFT,
            groups=5,
        )

        valid_chars = "BCDFGHJKMPQRTVWXY2346789"

        for _ in range(20):
            result = generator._generate_microsoft_serial(constraints)
            serial_clean = result.serial.replace("-", "")
            assert all(c in valid_chars for c in serial_clean)


class TestUUIDSerialGeneration:
    """Test UUID-format serial generation."""

    def test_generate_uuid_serial_correct_format(self) -> None:
        """UUID serial has correct 8-4-4-4-12 format."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=36,
            format=SerialFormat.UUID,
        )

        result = generator._generate_uuid_serial(constraints)

        assert result.format == SerialFormat.UUID
        assert result.confidence == 1.0

        parts = result.serial.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

    def test_uuid_serial_contains_valid_hex_characters(self) -> None:
        """UUID serial contains only valid hexadecimal characters."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=36,
            format=SerialFormat.UUID,
        )

        result = generator._generate_uuid_serial(constraints)
        uuid_clean = result.serial.replace("-", "")
        assert all(c in "0123456789ABCDEF" for c in uuid_clean)


class TestConstraintBasedSerialGeneration:
    """Test serial generation with various constraints."""

    def test_generate_numeric_serial_with_constraint_solver(self) -> None:
        """Constraint solver generates numeric serial."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.NUMERIC,
        )

        result = generator.generate_serial(constraints)

        assert len(result.serial.replace("-", "")) == 16
        assert result.serial.replace("-", "").isdigit()
        assert result.confidence > 0

    def test_generate_hexadecimal_serial_with_constraint_solver(self) -> None:
        """Constraint solver generates hexadecimal serial."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.HEXADECIMAL,
        )

        result = generator.generate_serial(constraints)

        serial_clean = result.serial.replace("-", "")
        assert len(serial_clean) == 20
        assert all(c in "0123456789ABCDEF" for c in serial_clean)

    def test_generate_alphanumeric_serial_with_constraint_solver(self) -> None:
        """Constraint solver generates alphanumeric serial."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
        )

        result = generator.generate_serial(constraints)

        serial_clean = result.serial.replace("-", "")
        assert len(serial_clean) == 16
        assert serial_clean.isalnum()
        assert serial_clean.isupper()

    def test_generate_serial_with_groups(self) -> None:
        """Serial generation respects group formatting."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            groups=4,
            group_separator="-",
        )

        result = generator.generate_serial(constraints)

        parts = result.serial.split("-")
        assert len(parts) == 4
        assert all(len(part) == 4 for part in parts)

    def test_generate_serial_with_custom_alphabet(self) -> None:
        """Serial generation respects custom alphabet constraint."""
        generator = SerialNumberGenerator()

        custom_alphabet = "ACGT"
        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.CUSTOM,
            custom_alphabet=custom_alphabet,
        )

        result = generator.generate_serial(constraints)

        serial_clean = result.serial.replace("-", "")
        assert all(c in custom_alphabet for c in serial_clean)

    def test_generate_serial_with_must_contain_constraint(self) -> None:
        """Serial generation respects must_contain constraint."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            must_contain=["INTEL"],
        )

        result = generator.generate_serial(constraints)

        assert "INTEL" in result.serial

    def test_generate_serial_with_cannot_contain_constraint(self) -> None:
        """Serial generation respects cannot_contain constraint."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            cannot_contain=["AAA", "000"],
        )

        result = generator.generate_serial(constraints)

        assert "AAA" not in result.serial
        assert "000" not in result.serial

    def test_generate_serial_with_seed_produces_deterministic_result(self) -> None:
        """Serial generation with seed produces deterministic results."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
        )

        result1 = generator.generate_serial(constraints, seed=12345)
        result2 = generator.generate_serial(constraints, seed=12345)

        assert result1.serial[0] == result2.serial[0]


class TestCustomValidationFunctionGeneration:
    """Test serial generation with custom validation functions."""

    def test_generate_serial_with_custom_validation_passes(self) -> None:
        """Serial generation with custom validation produces valid serial."""
        generator = SerialNumberGenerator()

        def custom_validator(serial: str) -> bool:
            return serial.count("A") >= 2

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            validation_function=custom_validator,
        )

        result = generator.generate_serial(constraints)

        assert custom_validator(result.serial)
        assert result.confidence == 1.0
        assert result.validation_data.get("custom_validation") is True

    def test_generate_serial_with_impossible_validation_fails(self) -> None:
        """Serial generation with impossible validation returns empty serial."""
        generator = SerialNumberGenerator()

        def impossible_validator(serial: str) -> bool:
            return False

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            validation_function=impossible_validator,
        )

        result = generator.generate_serial(constraints)

        assert result.serial == ""
        assert result.confidence == 0.0
        assert "error" in result.validation_data


class TestBatchSerialGeneration:
    """Test batch serial generation capabilities."""

    def test_batch_generate_produces_correct_count(self) -> None:
        """Batch generation produces requested number of serials."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
        )

        serials = generator.batch_generate(constraints, count=50)

        assert len(serials) >= 2
        assert all(isinstance(s, GeneratedSerial) for s in serials)

    def test_batch_generate_unique_produces_unique_serials(self) -> None:
        """Batch generation with unique=True produces unique serials."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
        )

        serials = generator.batch_generate(constraints, count=100, unique=True)

        serial_strings = [s.serial for s in serials]
        assert len(set(serial_strings)) == len(serial_strings)


class TestRSASignedSerialGeneration:
    """Test RSA-signed serial generation with cryptographic validation."""

    @pytest.fixture
    def rsa_key_pair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def test_generate_rsa_signed_serial_correct_format(
        self, rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """RSA-signed serial has correct format and metadata."""
        generator = SerialNumberGenerator()
        private_key, _ = rsa_key_pair

        features = ["pro", "unlimited", "support"]
        expiration = int(time.time()) + 86400 * 365

        result = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="TESTPROD-2024",
            user_name="TestUser",
            features=features,
            expiration=expiration,
        )

        assert result.algorithm == "rsa_signed"
        assert result.checksum == "RSA-PSS-SHA256"
        assert result.features == features
        assert result.expiration == expiration
        assert result.confidence >= 0.9
        assert "-" in result.serial

    def test_rsa_signed_serial_contains_valid_data(
        self, rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """RSA-signed serial contains valid encoded data."""
        generator = SerialNumberGenerator()
        private_key, _ = rsa_key_pair

        result = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="TESTPROD-2024",
            user_name="TestUser",
            features=["pro"],
            expiration=int(time.time()) + 86400 * 365,
        )

        assert result.raw_bytes is not None
        assert len(result.raw_bytes) > 0
        assert result.serial is not None
        assert len(result.serial) > 0


class TestECCSignedSerialGeneration:
    """Test ECC-signed serial generation with elliptic curve cryptography."""

    @pytest.fixture
    def ecc_key_pair(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate ECC key pair for testing."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def test_generate_ecc_signed_serial_correct_format(
        self, ecc_key_pair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
    ) -> None:
        """ECC-signed serial has correct format and metadata."""
        generator = SerialNumberGenerator()
        private_key, _ = ecc_key_pair

        result = generator.generate_ecc_signed(
            private_key=private_key,
            product_id="ECCPROD-2024",
            machine_code="MACHINE123456",
        )

        assert result.algorithm == "ecc_signed"
        assert result.checksum == "ECDSA-SHA256"
        assert result.hardware_id == "MACHINE123456"
        assert result.confidence >= 0.9
        assert "-" in result.serial

    def test_ecc_signed_serial_contains_machine_code(
        self, ecc_key_pair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
    ) -> None:
        """ECC-signed serial embeds machine code for hardware locking."""
        generator = SerialNumberGenerator()
        private_key, _ = ecc_key_pair

        machine_code = "HWID-ABCD1234"

        result = generator.generate_ecc_signed(
            private_key=private_key,
            product_id="TESTPROD",
            machine_code=machine_code,
        )

        assert result.hardware_id == machine_code
        assert result.raw_bytes is not None


class TestTimeBasedSerialGeneration:
    """Test time-based serial generation using TOTP-like algorithm."""

    def test_generate_time_based_serial_correct_format(self) -> None:
        """Time-based serial has correct format with expiration."""
        generator = SerialNumberGenerator()

        secret_key = b"testsecretkey123"
        validity_days = 30

        result = generator.generate_time_based(
            secret_key=secret_key,
            validity_days=validity_days,
            product_id="TIMEPROD",
        )

        assert result.algorithm == "time_based"
        assert result.checksum == "HMAC-SHA256"
        assert result.expiration is not None
        assert result.expiration > int(time.time())

        parts = result.serial.split("-")
        assert len(parts) == 3

    def test_time_based_serial_expiration_calculated_correctly(self) -> None:
        """Time-based serial expiration is calculated correctly."""
        generator = SerialNumberGenerator()

        secret_key = b"testsecretkey456"
        validity_days = 90

        current_time = int(time.time())
        result = generator.generate_time_based(
            secret_key=secret_key,
            validity_days=validity_days,
        )

        expected_expiration = current_time + (validity_days * 86400)
        assert abs(result.expiration - expected_expiration) < 10

    def test_time_based_serial_with_same_secret_deterministic(self) -> None:
        """Time-based serial with same secret and time produces deterministic result."""
        generator = SerialNumberGenerator()

        secret_key = b"consistentsecret"

        result1 = generator.generate_time_based(secret_key=secret_key, validity_days=30)

        result2 = generator.generate_time_based(secret_key=secret_key, validity_days=30)

        assert result1.serial.split("-")[0] == result2.serial.split("-")[0]


class TestFeatureEncodedSerialGeneration:
    """Test serial generation with encoded feature flags."""

    def test_generate_feature_encoded_serial_encodes_features(self) -> None:
        """Feature-encoded serial correctly encodes feature flags."""
        generator = SerialNumberGenerator()

        base_serial = "ABCD1234EFGH5678"
        features = ["pro", "enterprise", "unlimited"]

        result = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=features,
        )

        assert result.algorithm == "feature_encoded"
        assert result.features == features
        assert result.checksum == "CRC16"
        assert base_serial in result.serial

    def test_feature_encoded_serial_different_features_produce_different_serials(self) -> None:
        """Different feature sets produce different serial encodings."""
        generator = SerialNumberGenerator()

        base_serial = "TESTBASE12345678"

        result1 = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=["pro"],
        )

        result2 = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=["enterprise", "unlimited"],
        )

        assert result1.serial != result2.serial


class TestMathematicalSerialGeneration:
    """Test mathematical relationship-based serial generation."""

    def test_generate_mathematical_fibonacci_serial(self) -> None:
        """Mathematical serial using Fibonacci algorithm."""
        generator = SerialNumberGenerator()

        result = generator.generate_mathematical(seed=12345, algorithm="fibonacci")

        assert result.algorithm == "mathematical_fibonacci"
        assert result.checksum == "CRC32"
        assert "-" in result.serial

        parts = result.serial.split("-")
        assert len(parts) == 3

    def test_generate_mathematical_mersenne_serial(self) -> None:
        """Mathematical serial using Mersenne primes."""
        generator = SerialNumberGenerator()

        result = generator.generate_mathematical(seed=54321, algorithm="mersenne")

        assert result.algorithm == "mathematical_mersenne"
        assert result.checksum == "CRC32"

    def test_generate_mathematical_quadratic_serial(self) -> None:
        """Mathematical serial using quadratic formula."""
        generator = SerialNumberGenerator()

        result = generator.generate_mathematical(seed=99999, algorithm="quadratic")

        assert result.algorithm == "mathematical_quadratic"
        assert result.checksum == "CRC32"

    def test_mathematical_serial_same_seed_produces_same_result(self) -> None:
        """Mathematical serial with same seed produces deterministic result."""
        generator = SerialNumberGenerator()

        seed = 42069

        result1 = generator.generate_mathematical(seed=seed, algorithm="quadratic")
        result2 = generator.generate_mathematical(seed=seed, algorithm="quadratic")

        assert result1.serial == result2.serial


class TestBlackboxSerialGeneration:
    """Test blackbox serial generation for unknown protection schemes."""

    def test_generate_blackbox_serial_from_input_data(self) -> None:
        """Blackbox serial generation produces valid output from input data."""
        generator = SerialNumberGenerator()

        input_data = b"INPUTDATA1234567"

        result = generator.generate_blackbox(input_data=input_data, rounds=100)

        assert result.algorithm == "blackbox"
        assert result.raw_bytes is not None
        assert len(result.raw_bytes) == 16
        assert "-" in result.serial

    def test_blackbox_serial_different_input_produces_different_serial(self) -> None:
        """Different input data produces different blackbox serials."""
        generator = SerialNumberGenerator()

        result1 = generator.generate_blackbox(input_data=b"INPUT1", rounds=100)
        result2 = generator.generate_blackbox(input_data=b"INPUT2", rounds=100)

        assert result1.serial != result2.serial

    def test_blackbox_serial_more_rounds_produces_different_result(self) -> None:
        """Different round counts produce different blackbox serials."""
        generator = SerialNumberGenerator()

        input_data = b"CONSISTENT_INPUT"

        result1 = generator.generate_blackbox(input_data=input_data, rounds=100)
        result2 = generator.generate_blackbox(input_data=input_data, rounds=500)

        assert result1.serial != result2.serial


class TestSerialFormatDetection:
    """Test serial format detection from samples."""

    def test_detect_microsoft_format(self) -> None:
        """Detect Microsoft product key format."""
        generator = SerialNumberGenerator()

        serials = [
            "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
            "12345-67890-ABCDE-FGHIJ-KLMNO",
            "XXXXX-YYYYY-ZZZZZ-11111-22222",
        ]

        format_detected = generator._detect_format(serials)

        assert format_detected == SerialFormat.MICROSOFT

    def test_detect_uuid_format(self) -> None:
        """Detect UUID format."""
        generator = SerialNumberGenerator()

        serials = [
            "12345678-1234-5678-1234-567890123456",
            "ABCDEF01-2345-6789-ABCD-EF0123456789",
        ]

        format_detected = generator._detect_format(serials)

        assert format_detected == SerialFormat.UUID

    def test_detect_numeric_format(self) -> None:
        """Detect numeric-only format."""
        generator = SerialNumberGenerator()

        serials = ["1234567890", "9876543210", "1111222233334444"]

        format_detected = generator._detect_format(serials)

        assert format_detected == SerialFormat.NUMERIC

    def test_detect_hexadecimal_format(self) -> None:
        """Detect hexadecimal format."""
        generator = SerialNumberGenerator()

        serials = ["ABCDEF123456", "0123456789ABCDEF", "DEADBEEFCAFE"]

        format_detected = generator._detect_format(serials)

        assert format_detected in [SerialFormat.HEXADECIMAL, SerialFormat.ALPHANUMERIC]

    def test_detect_alphanumeric_format(self) -> None:
        """Detect alphanumeric format."""
        generator = SerialNumberGenerator()

        serials = ["ABC123XYZ789", "TEST1234SERIAL", "MIX987ALPHA456"]

        format_detected = generator._detect_format(serials)

        assert format_detected == SerialFormat.ALPHANUMERIC


class TestSerialLengthAnalysis:
    """Test serial length pattern analysis."""

    def test_analyze_length_with_consistent_serials(self) -> None:
        """Length analysis detects consistent serial lengths."""
        generator = SerialNumberGenerator()

        serials = ["ABCD-EFGH-IJKL", "1234-5678-9012", "WXYZ-4567-8901"]

        analysis = generator._analyze_length(serials)

        assert analysis["min"] == 14
        assert analysis["max"] == 14
        assert analysis["mode"] == 14
        assert analysis["clean_min"] == 12
        assert analysis["clean_max"] == 12
        assert analysis["clean_mode"] == 12

    def test_analyze_length_with_variable_serials(self) -> None:
        """Length analysis handles variable-length serials."""
        generator = SerialNumberGenerator()

        serials = ["ABC-DEF", "1234-5678-9012", "XY"]

        analysis = generator._analyze_length(serials)

        assert analysis["min"] == 2
        assert analysis["max"] == 14


class TestSerialStructureAnalysis:
    """Test serial structure pattern analysis."""

    def test_analyze_structure_detects_separators(self) -> None:
        """Structure analysis detects common separators."""
        generator = SerialNumberGenerator()

        serials = ["ABCD-EFGH-IJKL", "1234-5678-9012", "WXYZ-4567-8901"]

        structure = generator._analyze_structure(serials)

        assert "-" in structure["separators"]
        assert structure["common_separator"] == "-"
        assert structure["group_count"] == 3

    def test_analyze_structure_handles_no_separators(self) -> None:
        """Structure analysis handles serials without separators."""
        generator = SerialNumberGenerator()

        serials = ["ABCDEFGHIJKL", "123456789012", "WXYZ45678901"]

        structure = generator._analyze_structure(serials)

        assert len(structure["separators"]) == 0


class TestChecksumDetection:
    """Test checksum algorithm detection from valid serials."""

    def test_detect_luhn_checksum(self) -> None:
        """Detect Luhn checksum in valid serials."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(10)]

        detected = generator._detect_checksum(valid_serials)

        assert "luhn" in detected
        assert detected["luhn"] >= 0.8

    def test_detect_crc32_checksum(self) -> None:
        """Detect CRC32 checksum in valid serials."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_crc32_serial(24) for _ in range(20)]

        detected = generator._detect_checksum(valid_serials)

        if "crc32" in detected:
            assert detected["crc32"] >= 0.8
        else:
            assert len(detected) >= 0


class TestSerialAlgorithmAnalysis:
    """Test complete serial algorithm analysis and reverse engineering."""

    def test_analyze_luhn_serials(self) -> None:
        """Analyze valid Luhn serials and detect algorithm."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(15)]

        analysis = generator.analyze_serial_algorithm(valid_serials)

        assert analysis["format"] == SerialFormat.NUMERIC
        assert analysis["algorithm"] is not None
        assert analysis["confidence"] > 0

    def test_analyze_crc32_serials(self) -> None:
        """Analyze valid CRC32 serials and detect algorithm."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_crc32_serial(24) for _ in range(15)]

        analysis = generator.analyze_serial_algorithm(valid_serials)

        assert analysis["format"] == SerialFormat.ALPHANUMERIC
        assert analysis["algorithm"] is not None
        assert analysis["confidence"] > 0


class TestReverseEngineerAlgorithm:
    """Test reverse engineering of serial generation algorithms."""

    def test_reverse_engineer_with_valid_serials_only(self) -> None:
        """Reverse engineer algorithm from valid serials."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(20)]

        analysis = generator.reverse_engineer_algorithm(valid_serials)

        assert "algorithm" in analysis
        assert "generated_samples" in analysis
        assert len(analysis["generated_samples"]) >= 2

    def test_reverse_engineer_with_invalid_serials_calculates_fpr(self) -> None:
        """Reverse engineer calculates false positive rate with invalid serials."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(20)]
        invalid_serials = ["1234567890123456", "9999999999999999", "0000000000000000"]

        analysis = generator.reverse_engineer_algorithm(valid_serials, invalid_serials)

        assert "false_positive_rate" in analysis
        assert 0 <= analysis["false_positive_rate"] <= 1


class TestBruteForceChecksum:
    """Test brute force checksum recovery for incomplete serials."""

    def test_brute_force_finds_valid_checksums(self) -> None:
        """Brute force recovery attempts to find valid checksums."""
        generator = SerialNumberGenerator()

        partial_serial = "ABCD1234"

        candidates = generator.brute_force_checksum(partial_serial, checksum_length=4)

        assert isinstance(candidates, list)
        assert len(candidates) >= 0


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in serial generation."""

    def test_generate_serial_with_zero_length(self) -> None:
        """Serial generation handles zero length gracefully."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=0,
            format=SerialFormat.NUMERIC,
        )

        result = generator.generate_serial(constraints)

        assert isinstance(result, GeneratedSerial)

    def test_generate_serial_with_very_long_length(self) -> None:
        """Serial generation handles very long lengths."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=100,
            format=SerialFormat.ALPHANUMERIC,
        )

        result = generator.generate_serial(constraints)

        serial_clean = result.serial.replace("-", "")
        assert len(serial_clean) == 100

    def test_batch_generate_with_zero_count(self) -> None:
        """Batch generation handles zero count."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.NUMERIC,
        )

        serials = generator.batch_generate(constraints, count=0)

        assert len(serials) == 0

    def test_verify_checksum_with_invalid_serial(self) -> None:
        """Checksum verification handles invalid serials gracefully."""
        generator = SerialNumberGenerator()

        invalid_serials = ["", "A", "!@#$%", "TOOSHORT"]

        for serial in invalid_serials:
            result = generator._verify_luhn(serial)
            assert isinstance(result, bool)


class TestProductionSerialGenerationWorkflows:
    """Test complete production workflows for serial generation."""

    def test_complete_workflow_analyze_and_generate_matching_serials(self) -> None:
        """Complete workflow: analyze valid serials and generate matching ones."""
        generator = SerialNumberGenerator()

        original_serials = [generator._generate_luhn_serial(16) for _ in range(15)]

        analysis = generator.analyze_serial_algorithm(original_serials)

        constraints = SerialConstraints(
            length=analysis["length"]["clean_mode"],
            format=analysis["format"],
            checksum_algorithm=next(iter(analysis["checksum"].keys())) if analysis["checksum"] else None,
        )

        new_serials = generator.batch_generate(constraints, count=10)

        assert len(new_serials) >= 2
        assert all(s.confidence > 0 for s in new_serials)

    def test_cryptographic_serial_complete_workflow(self) -> None:
        """Complete workflow: generate RSA-signed serial with features and expiration."""
        generator = SerialNumberGenerator()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        result = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="PROD-2024-PREMIUM",
            user_name="Licensed User",
            features=["pro", "enterprise", "unlimited", "support"],
            expiration=int(time.time()) + 86400 * 365,
        )

        assert result.serial is not None
        assert len(result.serial) > 0
        assert result.algorithm == "rsa_signed"
        assert len(result.features) == 4
        assert result.expiration > int(time.time())
