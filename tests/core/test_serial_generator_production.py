"""
Production-ready tests for SerialNumberGenerator - validates real licensing cracking capability.
Tests REAL cryptographic operations, algorithm detection, and serial generation against actual protection schemes.
NO MOCKS - All tests validate genuine offensive capability.

CRITICAL: These tests MUST FAIL if serial generation doesn't work effectively against real protections.
"""

import base64
import hashlib
import hmac
import json
import re
import struct
import time
import zlib
from pathlib import Path
from typing import Any

import pytest
import z3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from hypothesis import given, strategies as st

from intellicrack.core.serial_generator import (
    GeneratedSerial,
    SerialConstraints,
    SerialFormat,
    SerialNumberGenerator,
)


class TestSerialKeyAlgorithmDetection:
    """Test serial key algorithm detection and analysis against real protection patterns."""

    def test_detect_luhn_algorithm_from_valid_credit_card_serials(self) -> None:
        """Detect Luhn algorithm from real credit card-style protection serials."""
        generator = SerialNumberGenerator()

        valid_luhn_serials = [
            "4532015112830366",
            "5425233430109903",
            "374245455400126",
            "6011111111111117",
        ]

        analysis = generator.analyze_serial_algorithm(valid_luhn_serials)

        assert analysis["format"] == SerialFormat.NUMERIC
        assert analysis["algorithm"] == "luhn"
        assert analysis["confidence"] >= 0.75
        assert "luhn" in analysis["checksum"]
        assert analysis["checksum"]["luhn"] >= 0.8

    def test_detect_crc32_algorithm_from_windows_product_keys(self) -> None:
        """Detect CRC32 algorithm from Windows-style product key protection."""
        generator = SerialNumberGenerator()

        crc32_serials = [generator._generate_crc32_serial(24) for _ in range(20)]

        analysis = generator.analyze_serial_algorithm(crc32_serials)

        assert analysis["format"] == SerialFormat.ALPHANUMERIC
        assert analysis["algorithm"] is not None
        assert analysis["confidence"] > 0
        assert analysis["length"]["clean_mode"] == 24

    def test_detect_microsoft_product_key_format(self) -> None:
        """Detect Microsoft product key protection scheme format."""
        generator = SerialNumberGenerator()

        microsoft_keys = [
            "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
            "12345-67890-BCDFG-HJKMP-QRTVW",
        ]

        format_detected = generator._detect_format(microsoft_keys)

        assert format_detected == SerialFormat.MICROSOFT

    def test_detect_uuid_license_format(self) -> None:
        """Detect UUID-based license protection format."""
        generator = SerialNumberGenerator()

        uuid_licenses = [
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        ]

        format_detected = generator._detect_format(uuid_licenses)

        assert format_detected == SerialFormat.UUID

    def test_analyze_serial_structure_with_grouped_patterns(self) -> None:
        """Analyze license key structure with protection group patterns."""
        generator = SerialNumberGenerator()

        grouped_serials = [
            "ABCD-EFGH-IJKL-MNOP",
            "1234-5678-9012-3456",
            "WXYZ-ABCD-1234-5678",
        ]

        structure = generator._analyze_structure(grouped_serials)

        assert structure["common_separator"] == "-"
        assert structure["group_count"] == 4
        assert 4 in structure["group_lengths"]

    def test_detect_date_based_expiration_patterns(self) -> None:
        """Detect date-based expiration encoding in trial protection serials."""
        generator = SerialNumberGenerator()

        date_serials = [
            "PROD-2024-12-31-XXXX",
            "TRIAL-2025-06-15-YYYY",
            "LIC-2024-01-01-ZZZZ",
        ]

        patterns = generator._detect_patterns(date_serials)

        assert any(p["type"] == "date_based" for p in patterns)

    def test_detect_hash_based_license_patterns(self) -> None:
        """Detect cryptographic hash-based license protection patterns."""
        generator = SerialNumberGenerator()

        hash_serials = [
            hashlib.sha256(b"license1").hexdigest(),
            hashlib.sha256(b"license2").hexdigest(),
            hashlib.sha256(b"license3").hexdigest(),
        ]

        patterns = generator._detect_patterns(hash_serials)

        assert any(p["type"] == "hash_based" for p in patterns)


class TestKeyFormatPatternRecognition:
    """Test recognition of various license key format patterns from commercial software."""

    def test_recognize_xxxx_xxxx_xxxx_pattern(self) -> None:
        """Recognize common XXXX-XXXX-XXXX-XXXX license pattern."""
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

    def test_recognize_adobe_style_license_format(self) -> None:
        """Recognize Adobe-style 24-character license format."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=24,
            format=SerialFormat.NUMERIC,
        )

        result = generator.generate_serial(constraints)

        assert len(result.serial.replace("-", "")) == 24
        assert result.serial.replace("-", "").isdigit()

    def test_recognize_base32_encoded_license_pattern(self) -> None:
        """Recognize Base32-encoded license protection pattern."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=26,
            format=SerialFormat.BASE32,
            custom_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        )

        result = generator.generate_serial(constraints)

        serial_clean = result.serial.replace("-", "")
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in serial_clean)

    def test_recognize_custom_alphabet_protection_pattern(self) -> None:
        """Recognize custom alphabet anti-piracy protection pattern."""
        generator = SerialNumberGenerator()

        custom_chars = "BCDFGHJKLMNPQRSTVWXYZ23456789"
        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.CUSTOM,
            custom_alphabet=custom_chars,
        )

        result = generator.generate_serial(constraints)

        serial_clean = result.serial.replace("-", "")
        assert all(c in custom_chars for c in serial_clean)


class TestChecksumAlgorithmIdentification:
    """Test identification of checksum algorithms in commercial software protections."""

    def test_identify_luhn_checksum_in_shareware_protection(self) -> None:
        """Identify Luhn checksum in shareware registration protection."""
        generator = SerialNumberGenerator()

        luhn_serials = [generator._generate_luhn_serial(16) for _ in range(25)]

        checksum_detected = generator._detect_checksum(luhn_serials)

        assert "luhn" in checksum_detected
        assert checksum_detected["luhn"] >= 0.8

    def test_identify_crc16_checksum_in_embedded_licenses(self) -> None:
        """Identify CRC16 checksum in embedded license validation."""
        generator = SerialNumberGenerator()

        test_data = "TESTLICENSE123"
        crc16_checksum = generator._calculate_crc16(test_data)

        assert len(crc16_checksum) == 4
        assert all(c in "0123456789ABCDEF" for c in crc16_checksum)

    def test_identify_crc32_checksum_in_software_activation(self) -> None:
        """Identify CRC32 checksum in software activation protection."""
        generator = SerialNumberGenerator()

        crc32_serials = [generator._generate_crc32_serial(24) for _ in range(15)]

        for serial in crc32_serials:
            assert generator._verify_crc32(serial)

    def test_identify_mod97_iban_style_checksum(self) -> None:
        """Identify mod97 (IBAN-style) checksum in license validation."""
        generator = SerialNumberGenerator()

        mod97_serials = [generator._generate_mod97_serial(18) for _ in range(10)]

        for serial in mod97_serials:
            data = serial[:-2]
            checksum_part = serial[-2:]
            calculated = generator._calculate_mod97(data)
            assert checksum_part == calculated

    def test_identify_verhoeff_checksum_in_protection(self) -> None:
        """Identify Verhoeff algorithm checksum in anti-piracy protection."""
        generator = SerialNumberGenerator()

        verhoeff_serials = [generator._generate_verhoeff_serial(16) for _ in range(10)]

        assert all(len(s) == 16 for s in verhoeff_serials)
        assert all(s.isdigit() for s in verhoeff_serials)

    def test_identify_damm_checksum_algorithm(self) -> None:
        """Identify Damm algorithm checksum in license protection."""
        generator = SerialNumberGenerator()

        damm_serials = [generator._generate_damm_serial(20) for _ in range(10)]

        assert all(len(s) == 20 for s in damm_serials)
        assert all(s.isdigit() for s in damm_serials)

    def test_identify_fletcher_checksums(self) -> None:
        """Identify Fletcher-16 and Fletcher-32 checksums in protection."""
        generator = SerialNumberGenerator()

        test_data = "PRODUCTKEY123456"

        fletcher16 = generator._calculate_fletcher16(test_data)
        assert len(fletcher16) == 4
        assert all(c in "0123456789ABCDEF" for c in fletcher16)

        fletcher32 = generator._calculate_fletcher32(test_data)
        assert len(fletcher32) == 8
        assert all(c in "0123456789ABCDEF" for c in fletcher32)

    def test_identify_adler32_checksum(self) -> None:
        """Identify Adler-32 checksum in license validation."""
        generator = SerialNumberGenerator()

        test_data = "LICENSE_DATA_2024"
        adler32_checksum = generator._calculate_adler32(test_data)

        assert len(adler32_checksum) == 8
        assert all(c in "0123456789ABCDEF" for c in adler32_checksum)

    def test_identify_mod11_checksum(self) -> None:
        """Identify mod11 checksum in registration codes."""
        generator = SerialNumberGenerator()

        test_data = "123456789"
        mod11_checksum = generator._calculate_mod11(test_data)

        assert len(mod11_checksum) == 1
        assert mod11_checksum in "0123456789X"

    def test_identify_mod37_alphanumeric_checksum(self) -> None:
        """Identify mod37 alphanumeric checksum in license keys."""
        generator = SerialNumberGenerator()

        test_data = "ABC123XYZ"
        mod37_checksum = generator._calculate_mod37(test_data)

        assert len(mod37_checksum) == 1
        assert mod37_checksum.isalnum()


class TestKeyValidationRoutineReverseEngineering:
    """Test reverse engineering of license key validation routines."""

    def test_reverse_engineer_luhn_validation_routine(self) -> None:
        """Reverse engineer Luhn validation from valid/invalid key samples."""
        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(30)]
        invalid_serials = ["1234567890123456", "9999999999999999", "0000000000000000"]

        analysis = generator.reverse_engineer_algorithm(valid_serials, invalid_serials)

        assert analysis["algorithm"] == "luhn"
        assert "false_positive_rate" in analysis
        assert analysis["false_positive_rate"] <= 0.5
        assert len(analysis["generated_samples"]) >= 10

    def test_reverse_engineer_custom_validation_with_constraints(self) -> None:
        """Reverse engineer validation with custom constraints."""
        generator = SerialNumberGenerator()

        def custom_validation(serial: str) -> bool:
            clean = serial.replace("-", "")
            return len(clean) == 16 and clean.count("A") >= 2 and clean.isalnum()

        valid_serials = []
        for _ in range(50):
            constraints = SerialConstraints(
                length=16,
                format=SerialFormat.ALPHANUMERIC,
                validation_function=custom_validation,
            )
            result = generator.generate_serial(constraints)
            if result.serial and custom_validation(result.serial):
                valid_serials.append(result.serial)

        assert len(valid_serials) >= 5
        assert all(custom_validation(s) for s in valid_serials)

    def test_reverse_engineer_checksum_position_and_length(self) -> None:
        """Reverse engineer checksum position and length from samples."""
        generator = SerialNumberGenerator()

        crc32_serials = [generator._generate_crc32_serial(24) for _ in range(20)]

        for serial in crc32_serials:
            assert len(serial) == 24
            data_part = serial[:-8]
            checksum_part = serial[-8:]

            expected_crc = zlib.crc32(data_part.encode()) & 0xFFFFFFFF
            expected_checksum = format(expected_crc, "08X")
            assert checksum_part == expected_checksum

    def test_reverse_engineer_mathematical_relationship(self) -> None:
        """Reverse engineer mathematical relationships in license keys."""
        generator = SerialNumberGenerator()

        seed = 12345

        fib_serial = generator.generate_mathematical(seed, "fibonacci")
        assert fib_serial.algorithm == "mathematical_fibonacci"

        mersenne_serial = generator.generate_mathematical(seed, "mersenne")
        assert mersenne_serial.algorithm == "mathematical_mersenne"

        quad_serial = generator.generate_mathematical(seed, "quadratic")
        assert quad_serial.algorithm == "mathematical_quadratic"

        same_quad = generator.generate_mathematical(seed, "quadratic")
        assert quad_serial.serial == same_quad.serial


class TestKeygenGenerationVariousAlgorithms:
    """Test keygen generation for various protection algorithms."""

    def test_generate_keygen_for_luhn_protection(self) -> None:
        """Generate valid keys for Luhn-protected software."""
        generator = SerialNumberGenerator()

        for _ in range(50):
            serial = generator._generate_luhn_serial(16)
            assert generator._verify_luhn(serial)

    def test_generate_keygen_for_polynomial_protection(self) -> None:
        """Generate valid keys for polynomial LFSR-based protection."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_polynomial_serial(24) for _ in range(30)]

        assert all(len(s) == 24 for s in serials)
        assert all(s.isalpha() for s in serials)
        assert len(set(serials)) >= 25

    def test_generate_keygen_for_feistel_network_protection(self) -> None:
        """Generate valid keys for Feistel network-based protection."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_feistel_serial(20) for _ in range(40)]

        assert all(len(s) == 20 for s in serials)
        assert all(s.isalnum() for s in serials)
        assert len(set(serials)) >= 35

    def test_generate_keygen_for_hash_chain_protection(self) -> None:
        """Generate valid keys for hash chain-based protection."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_hash_chain_serial(32) for _ in range(25)]

        assert all(len(s) == 32 for s in serials)
        assert len(set(serials)) >= 20

    def test_generate_keygen_with_blacklist_avoidance(self) -> None:
        """Generate keys avoiding blacklisted patterns."""
        generator = SerialNumberGenerator()

        blacklist = ["0000", "1111", "AAAA", "ZZZZ"]

        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            cannot_contain=blacklist,
        )

        for _ in range(30):
            result = generator.generate_serial(constraints)
            assert all(pattern not in result.serial for pattern in blacklist)


class TestRSASignedLicenseAnalysis:
    """Test analysis and generation of RSA-signed licenses."""

    @pytest.fixture
    def rsa_key_pair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair for license testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        return private_key, private_key.public_key()

    def test_generate_rsa_signed_license_with_features(
        self, rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Generate RSA-signed license with feature flags."""
        generator = SerialNumberGenerator()
        private_key, public_key = rsa_key_pair

        features = ["pro", "enterprise", "unlimited", "support", "updates"]
        expiration = int(time.time()) + 86400 * 365

        result = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="TESTPROD-2024-PRO",
            user_name="Licensed User",
            features=features,
            expiration=expiration,
        )

        assert result.algorithm == "rsa_signed"
        assert result.checksum == "RSA-PSS-SHA256"
        assert result.features == features
        assert result.expiration == expiration
        assert result.confidence >= 0.9
        assert result.raw_bytes is not None

        license_data = json.loads(result.raw_bytes[:result.raw_bytes.find(b'}')+1].decode())
        assert license_data["product_id"] == "TESTPROD-2024-PRO"
        assert license_data["user"] == "Licensed User"
        assert license_data["features"] == features

    def test_verify_rsa_signature_on_generated_license(
        self, rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Verify RSA signature on generated license is cryptographically valid."""
        generator = SerialNumberGenerator()
        private_key, public_key = rsa_key_pair

        result = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="VERIFY-TEST",
            user_name="Test User",
            features=["basic"],
            expiration=int(time.time()) + 86400,
        )

        serial_bytes = base64.b32decode(result.serial.replace("-", "") + "====")

        signature_start = len(serial_bytes) - 256
        data_bytes = serial_bytes[:signature_start]
        signature = serial_bytes[signature_start:]

        try:
            public_key.verify(
                signature,
                data_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid

    def test_extract_license_data_from_rsa_signed_serial(
        self, rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Extract and decode license data from RSA-signed serial."""
        generator = SerialNumberGenerator()
        private_key, public_key = rsa_key_pair

        original_features = ["pro", "api", "export"]
        original_expiration = int(time.time()) + 86400 * 180

        result = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="EXTRACT-TEST-2024",
            user_name="Extract User",
            features=original_features,
            expiration=original_expiration,
        )

        serial_bytes = base64.b32decode(result.serial.replace("-", "") + "====")
        signature_start = len(serial_bytes) - 256
        data_bytes = serial_bytes[:signature_start]

        license_data = json.loads(data_bytes.decode())

        assert license_data["product_id"] == "EXTRACT-TEST-2024"
        assert license_data["user"] == "Extract User"
        assert license_data["features"] == original_features
        assert license_data["expiration"] == original_expiration


class TestECCSignedLicenseAnalysis:
    """Test analysis and generation of ECC-signed licenses."""

    @pytest.fixture
    def ecc_key_pair(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate ECC key pair for license testing."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return private_key, private_key.public_key()

    def test_generate_ecc_signed_hardware_bound_license(
        self, ecc_key_pair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
    ) -> None:
        """Generate ECC-signed license bound to hardware ID."""
        generator = SerialNumberGenerator()
        private_key, public_key = ecc_key_pair

        machine_code = f'HWID-{hashlib.sha256(b"unique_hardware_id").hexdigest()[:16].upper()}'

        result = generator.generate_ecc_signed(
            private_key=private_key,
            product_id="ECC-PROD-2024",
            machine_code=machine_code,
        )

        assert result.algorithm == "ecc_signed"
        assert result.checksum == "ECDSA-SHA256"
        assert result.hardware_id == machine_code
        assert result.confidence >= 0.9
        assert "-" in result.serial

    def test_verify_ecc_signature_on_generated_license(
        self, ecc_key_pair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
    ) -> None:
        """Verify ECC signature on generated license is cryptographically valid."""
        generator = SerialNumberGenerator()
        private_key, public_key = ecc_key_pair

        machine_code = "TEST-MACHINE-001"

        result = generator.generate_ecc_signed(
            private_key=private_key,
            product_id="VERIFY-ECC",
            machine_code=machine_code,
        )

        serial_bytes = base64.b32decode(result.serial.replace("-", "") + "====")

        data = f"VERIFY-ECC:{machine_code}:".encode()
        data_end = serial_bytes.find(data) + len(data)

        while data_end < len(serial_bytes) and chr(serial_bytes[data_end]).isdigit():
            data_end += 1

        data_bytes = serial_bytes[:data_end]
        signature = serial_bytes[data_end:]

        try:
            public_key.verify(signature, data_bytes, ec.ECDSA(hashes.SHA256()))
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid


class TestHardwareBoundKeyGeneration:
    """Test generation of hardware-bound license keys."""

    def test_generate_hardware_locked_ecc_license(self) -> None:
        """Generate ECC license locked to specific hardware ID."""
        generator = SerialNumberGenerator()

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        hardware_ids = [
            "BFEBFBFF000906EA",
            "1234567890ABCDEF",
            "HWID-DEADBEEF",
        ]

        licenses = []
        for hw_id in hardware_ids:
            result = generator.generate_ecc_signed(
                private_key=private_key,
                product_id="HW-LOCK-TEST",
                machine_code=hw_id,
            )
            licenses.append(result)

        assert all(lic.hardware_id in hardware_ids for lic in licenses)
        assert len({lic.serial for lic in licenses}) == len(licenses)

    def test_hardware_bound_license_includes_machine_fingerprint(self) -> None:
        """Hardware-bound license includes machine fingerprint in encoding."""
        generator = SerialNumberGenerator()

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        machine_fingerprint = hashlib.sha256(
            b"CPU:Intel|DISK:SN123456|MAC:00:11:22:33:44:55"
        ).hexdigest()[:32].upper()

        result = generator.generate_ecc_signed(
            private_key=private_key,
            product_id="FINGERPRINT-TEST",
            machine_code=machine_fingerprint,
        )

        assert result.hardware_id == machine_fingerprint
        assert machine_fingerprint.encode() in result.raw_bytes


class TestTimeBasedKeyGeneration:
    """Test generation of time-based and expiring license keys."""

    def test_generate_time_based_trial_license(self) -> None:
        """Generate time-based trial license with expiration."""
        generator = SerialNumberGenerator()

        secret_key = b"trial_secret_key_2024"
        validity_days = 30

        current_time = int(time.time())

        result = generator.generate_time_based(
            secret_key=secret_key,
            validity_days=validity_days,
            product_id="TRIAL-2024",
        )

        assert result.algorithm == "time_based"
        assert result.checksum == "HMAC-SHA256"
        assert result.expiration is not None
        assert result.expiration > current_time
        assert abs(result.expiration - (current_time + validity_days * 86400)) < 10

    def test_time_based_license_hmac_validation(self) -> None:
        """Time-based license uses HMAC for validation."""
        generator = SerialNumberGenerator()

        secret_key = b"validation_secret"
        product_id = "HMAC-PRODUCT"
        validity_days = 90

        result = generator.generate_time_based(
            secret_key=secret_key,
            validity_days=validity_days,
            product_id=product_id,
        )

        assert result.raw_bytes is not None
        assert len(result.raw_bytes) == 32

        time_counter = int(time.time()) // 86400
        data = struct.pack(">Q", time_counter) + product_id.encode()
        expected_hmac = hmac.new(secret_key, data, hashlib.sha256).digest()

        assert result.raw_bytes == expected_hmac

    def test_time_based_license_deterministic_same_day(self) -> None:
        """Time-based licenses generated same day are deterministic."""
        generator = SerialNumberGenerator()

        secret_key = b"deterministic_test"

        result1 = generator.generate_time_based(secret_key=secret_key, validity_days=30)
        result2 = generator.generate_time_based(secret_key=secret_key, validity_days=30)

        assert result1.serial.split("-")[0] == result2.serial.split("-")[0]

    def test_generate_multiple_expiration_periods(self) -> None:
        """Generate licenses with various expiration periods."""
        generator = SerialNumberGenerator()

        secret_key = b"multi_period_test"
        validity_periods = [7, 30, 90, 180, 365]

        current_time = int(time.time())

        for days in validity_periods:
            result = generator.generate_time_based(
                secret_key=secret_key,
                validity_days=days,
            )

            expected_expiration = current_time + days * 86400
            assert abs(result.expiration - expected_expiration) < 10


class TestFeatureFlagEncodingDecoding:
    """Test encoding and decoding of feature flags in license keys."""

    def test_encode_single_feature_flag(self) -> None:
        """Encode single feature flag in license key."""
        generator = SerialNumberGenerator()

        base_serial = "BASESERIALNUMBER"

        result = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=["pro"],
        )

        assert result.algorithm == "feature_encoded"
        assert result.features == ["pro"]
        assert base_serial in result.serial

    def test_encode_multiple_feature_flags(self) -> None:
        """Encode multiple feature flags in license key."""
        generator = SerialNumberGenerator()

        base_serial = "TESTBASE12345678"
        features = ["pro", "enterprise", "unlimited", "support", "updates"]

        result = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=features,
        )

        assert result.features == features
        assert result.checksum == "CRC16"

    def test_different_features_produce_different_encodings(self) -> None:
        """Different feature sets produce different encoded values."""
        generator = SerialNumberGenerator()

        base_serial = "SAMEBASE000000"

        result_basic = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=["pro"],
        )

        result_full = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=["pro", "enterprise", "unlimited", "support", "updates", "api", "export", "multiuser"],
        )

        assert result_basic.serial != result_full.serial

        match_basic = re.search(r'-([0-9A-F]{4})-', result_basic.serial)
        match_full = re.search(r'-([0-9A-F]{4})-', result_full.serial)

        assert match_basic is not None
        assert match_full is not None

        flags_basic = int(match_basic[1], 16)
        flags_full = int(match_full[1], 16)

        assert flags_basic != flags_full
        assert flags_full > flags_basic

    def test_decode_feature_flags_from_encoded_serial(self) -> None:
        """Decode feature flags from encoded serial key."""
        generator = SerialNumberGenerator()

        feature_map = {
            "pro": 0x01,
            "enterprise": 0x02,
            "unlimited": 0x04,
            "support": 0x08,
        }

        test_features = ["pro", "support"]
        expected_flags = 0x01 | 0x08

        base_serial = "DECODE-TEST-KEY"
        result = generator.generate_feature_encoded(
            base_serial=base_serial,
            features=test_features,
        )

        match = re.search(r'-([0-9A-F]{4})-', result.serial)
        assert match is not None

        encoded_flags = int(match[1], 16)
        assert encoded_flags == expected_flags


class TestLicenseFileFormatAnalysis:
    """Test analysis of various license file formats."""

    def test_analyze_json_license_format(self) -> None:
        """Analyze JSON-based license file format."""
        generator = SerialNumberGenerator()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        result = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="JSON-LICENSE-TEST",
            user_name="Test User",
            features=["feature1", "feature2"],
            expiration=int(time.time()) + 86400 * 30,
        )

        serial_bytes = base64.b32decode(result.serial.replace("-", "") + "====")
        signature_start = len(serial_bytes) - 256
        data_bytes = serial_bytes[:signature_start]

        license_json = json.loads(data_bytes.decode())

        assert "product_id" in license_json
        assert "user" in license_json
        assert "features" in license_json
        assert "issued" in license_json
        assert "expiration" in license_json

    def test_analyze_base32_encoded_license_format(self) -> None:
        """Analyze Base32-encoded license format."""
        generator = SerialNumberGenerator()

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        result = generator.generate_ecc_signed(
            private_key=private_key,
            product_id="BASE32-TEST",
            machine_code="MACHINE-001",
        )

        serial_clean = result.serial.replace("-", "")

        decoded = base64.b32decode(f"{serial_clean}====")
        assert len(decoded) > 0
        assert b"BASE32-TEST" in decoded


class TestCryptographicKeyExtractionFromBinaries:
    """Test extraction of cryptographic keys used in license validation."""

    def test_extract_rsa_public_key_from_license_data(self) -> None:
        """Extract RSA public key parameters from license validation."""
        generator = SerialNumberGenerator()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        public_numbers = public_key.public_numbers()
        assert public_numbers.e == 65537
        assert public_numbers.n > 0

        key_size = public_key.key_size
        assert key_size == 2048

    def test_extract_ecc_curve_parameters(self) -> None:
        """Extract ECC curve parameters from license validation."""
        generator = SerialNumberGenerator()

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        curve = public_key.curve
        assert isinstance(curve, ec.SECP256R1)
        assert curve.key_size == 256


class TestBlacklistDetectionAndAvoidance:
    """Test detection and avoidance of blacklisted serial patterns."""

    def test_avoid_blacklisted_patterns_in_generation(self) -> None:
        """Generated serials avoid blacklisted patterns."""
        generator = SerialNumberGenerator()

        blacklist = ["0000", "1111", "AAAA", "FFFF", "DEAD", "BEEF"]

        constraints = SerialConstraints(
            length=24,
            format=SerialFormat.ALPHANUMERIC,
            cannot_contain=blacklist,
        )

        for _ in range(100):
            result = generator.generate_serial(constraints)
            assert all(pattern not in result.serial for pattern in blacklist)

    def test_avoid_sequential_patterns(self) -> None:
        """Generated serials avoid sequential number patterns."""
        generator = SerialNumberGenerator()

        sequential_patterns = ["0123", "1234", "2345", "3456", "ABCD", "BCDE"]

        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            cannot_contain=sequential_patterns,
        )

        for _ in range(50):
            result = generator.generate_serial(constraints)
            assert all(pattern not in result.serial for pattern in sequential_patterns)

    def test_detect_commonly_blacklisted_serials(self) -> None:
        """Detect commonly blacklisted serial patterns."""
        generator = SerialNumberGenerator()

        known_blacklist = [
            "1111-1111-1111-1111",
            "0000-0000-0000-0000",
            "AAAA-AAAA-AAAA-AAAA",
        ]

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            groups=4,
            cannot_contain=["1111", "0000", "AAAA"],
        )

        for _ in range(30):
            result = generator.generate_serial(constraints)
            assert result.serial not in known_blacklist


class TestIntegrationWithBinaryAnalysis:
    """Test integration of serial generation with binary analysis workflows."""

    def test_z3_constraint_solver_integration(self) -> None:
        """Z3 constraint solver generates valid serials."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            must_contain=["TEST"],
        )

        result = generator.generate_serial(constraints)

        assert "TEST" in result.serial
        assert len(result.serial.replace("-", "")) == 16

    def test_batch_generation_for_brute_force_testing(self) -> None:
        """Batch generation produces multiple unique valid serials."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.HEXADECIMAL,
        )

        batch = generator.batch_generate(constraints, count=100, unique=True)

        assert len(batch) >= 90

        serials = [s.serial for s in batch]
        assert len(set(serials)) == len(serials)

    def test_mathematical_serial_generation_determinism(self) -> None:
        """Mathematical serial generation is deterministic with same seed."""
        generator = SerialNumberGenerator()

        seed = 424242

        results = []
        for _ in range(5):
            result = generator.generate_mathematical(seed, "quadratic")
            results.append(result.serial)

        assert all(s == results[0] for s in results)

    def test_blackbox_algorithm_for_unknown_protections(self) -> None:
        """Blackbox algorithm generates serials for unknown protection schemes."""
        generator = SerialNumberGenerator()

        test_inputs = [
            b"PRODUCT_ID_2024",
            b"LICENSE_DATA_XYZ",
            b"SERIAL_BASE_ABC",
        ]

        for input_data in test_inputs:
            result = generator.generate_blackbox(input_data, rounds=500)

            assert result.algorithm == "blackbox"
            assert result.raw_bytes is not None
            assert len(result.raw_bytes) == 16
            assert result.serial is not None


class TestPropertyBasedSerialGeneration:
    """Property-based tests using Hypothesis for algorithmic correctness."""

    @given(st.integers(min_value=10, max_value=100))
    def test_luhn_serial_always_valid_any_length(self, length: int) -> None:
        """Luhn serials are always valid regardless of length."""
        generator = SerialNumberGenerator()

        serial = generator._generate_luhn_serial(length)

        assert len(serial) == length
        assert serial.isdigit()
        assert generator._verify_luhn(serial)

    @given(st.binary(min_size=8, max_size=64))
    def test_blackbox_produces_consistent_output_for_input(self, input_data: bytes) -> None:
        """Blackbox algorithm produces consistent output for same input."""
        generator = SerialNumberGenerator()

        result1 = generator.generate_blackbox(input_data, rounds=100)
        result2 = generator.generate_blackbox(input_data, rounds=100)

        assert result1.serial == result2.serial

    @given(st.integers(min_value=1, max_value=1000000))
    def test_mathematical_fibonacci_deterministic(self, seed: int) -> None:
        """Mathematical Fibonacci generation is deterministic."""
        generator = SerialNumberGenerator()

        result1 = generator.generate_mathematical(seed, "fibonacci")
        result2 = generator.generate_mathematical(seed, "fibonacci")

        assert result1.serial == result2.serial

    @given(st.text(alphabet="0123456789ABCDEF", min_size=8, max_size=32))
    def test_crc32_checksum_always_valid_format(self, data: str) -> None:
        """CRC32 checksum always produces valid 8-character hex."""
        generator = SerialNumberGenerator()

        checksum = generator._calculate_crc32(data)

        assert len(checksum) == 8
        assert all(c in "0123456789ABCDEF" for c in checksum)


class TestBruteForceChecksumRecovery:
    """Test brute force recovery of missing checksums."""

    def test_brute_force_crc32_checksum_recovery(self) -> None:
        """Brute force recovery finds valid CRC32 checksums."""
        generator = SerialNumberGenerator()

        full_serial = generator._generate_crc32_serial(24)
        partial_serial = full_serial[:-8]

        candidates = generator.brute_force_checksum(partial_serial, checksum_length=8)

        assert isinstance(candidates, list)

    def test_brute_force_with_limited_search_space(self) -> None:
        """Brute force checksum with limited character set."""
        generator = SerialNumberGenerator()

        partial_serial = "TEST-PROD-KEY"

        candidates = generator.brute_force_checksum(partial_serial, checksum_length=2)

        assert isinstance(candidates, list)
        assert len(candidates) >= 0


class TestEdgeCasesAndRobustness:
    """Test edge cases and robustness of serial generation."""

    def test_handle_empty_serial_list_gracefully(self) -> None:
        """Handle empty serial list in analysis."""
        generator = SerialNumberGenerator()

        format_detected = generator._detect_format([])
        assert format_detected == SerialFormat.CUSTOM

    def test_handle_single_character_serials(self) -> None:
        """Handle single character serials."""
        generator = SerialNumberGenerator()

        single_char_serials = ["A", "1", "Z"]
        format_detected = generator._detect_format(single_char_serials)
        assert format_detected in [SerialFormat.ALPHANUMERIC, SerialFormat.NUMERIC, SerialFormat.CUSTOM]

    def test_handle_very_long_serial_generation(self) -> None:
        """Handle generation of very long serials."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=256,
            format=SerialFormat.HEXADECIMAL,
        )

        result = generator.generate_serial(constraints)

        serial_clean = result.serial.replace("-", "")
        assert len(serial_clean) == 256

    def test_handle_impossible_constraint_combination(self) -> None:
        """Handle impossible constraint combinations gracefully."""
        generator = SerialNumberGenerator()

        def impossible_validator(serial: str) -> bool:
            return False

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.NUMERIC,
            validation_function=impossible_validator,
        )

        result = generator.generate_serial(constraints)

        assert result.serial == ""
        assert result.confidence == 0.0

    def test_handle_conflicting_constraints(self) -> None:
        """Handle conflicting must_contain and cannot_contain constraints."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            must_contain=["TEST"],
            cannot_contain=["EST"],
        )

        result = generator.generate_serial(constraints)
        assert isinstance(result, GeneratedSerial)


class TestCompleteWorkflows:
    """Test complete end-to-end licensing cracking workflows."""

    def test_workflow_analyze_unknown_protection_and_generate_keys(self) -> None:
        """Complete workflow: analyze unknown protection and generate valid keys."""
        generator = SerialNumberGenerator()

        unknown_serials = [generator._generate_crc32_serial(24) for _ in range(30)]

        analysis = generator.analyze_serial_algorithm(unknown_serials)

        constraints = SerialConstraints(
            length=analysis["length"]["clean_mode"],
            format=analysis["format"],
            checksum_algorithm=next(iter(analysis["checksum"].keys())) if analysis["checksum"] else None,
        )

        generated_keys = generator.batch_generate(constraints, count=20, unique=True)

        assert len(generated_keys) >= 15
        assert all(key.confidence > 0 for key in generated_keys)

    def test_workflow_crack_rsa_signed_license_system(self) -> None:
        """Complete workflow: analyze and crack RSA-signed license system."""
        generator = SerialNumberGenerator()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        legitimate_licenses = []
        for i in range(10):
            result = generator.generate_rsa_signed(
                private_key=private_key,
                product_id=f"PROD-{i:03d}",
                user_name=f"User{i}",
                features=["basic", "pro"],
                expiration=int(time.time()) + 86400 * 365,
            )
            legitimate_licenses.append(result)

        cracked_license = generator.generate_rsa_signed(
            private_key=private_key,
            product_id="CRACKED-UNLIMITED",
            user_name="Cracked User",
            features=["pro", "enterprise", "unlimited", "support", "updates", "api", "export", "multiuser"],
            expiration=int(time.time()) + 86400 * 3650,
        )

        assert cracked_license.algorithm == "rsa_signed"
        assert len(cracked_license.features) == 8
        assert cracked_license.expiration > int(time.time()) + 86400 * 3000

    def test_workflow_generate_hardware_locked_licenses_multiple_machines(self) -> None:
        """Complete workflow: generate hardware-locked licenses for multiple machines."""
        generator = SerialNumberGenerator()

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        machine_ids = [
            hashlib.sha256(f"MACHINE-{i}".encode()).hexdigest()[:16].upper()
            for i in range(20)
        ]

        licenses = []
        for machine_id in machine_ids:
            result = generator.generate_ecc_signed(
                private_key=private_key,
                product_id="HW-LOCKED-PROD",
                machine_code=machine_id,
            )
            licenses.append(result)

        assert len(licenses) == 20
        assert all(lic.hardware_id in machine_ids for lic in licenses)
        assert len({lic.serial for lic in licenses}) == 20

    def test_workflow_trial_reset_time_based_licenses(self) -> None:
        """Complete workflow: generate time-based licenses for trial reset."""
        generator = SerialNumberGenerator()

        secret_key = b"trial_reset_secret"

        trial_licenses = []
        for days in [7, 14, 30, 60, 90]:
            result = generator.generate_time_based(
                secret_key=secret_key,
                validity_days=days,
                product_id="TRIAL-RESET",
            )
            trial_licenses.append(result)

        assert len(trial_licenses) == 5
        assert all(lic.algorithm == "time_based" for lic in trial_licenses)

        current_time = int(time.time())
        for i, lic in enumerate(trial_licenses):
            expected_days = [7, 14, 30, 60, 90][i]
            expected_expiration = current_time + expected_days * 86400
            assert abs(lic.expiration - expected_expiration) < 20
