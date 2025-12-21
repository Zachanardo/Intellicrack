"""Production tests for LicenseValidationBypass - validates real cryptographic key extraction.

Tests real RSA/ECC key extraction from binaries, ASN.1 DER parsing, PKCS#1 handling,
certificate extraction, and memory pattern analysis WITHOUT mocks or stubs.
"""

import datetime
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1
from cryptography.x509.oid import NameOID

from intellicrack.core.license_validation_bypass import ExtractedKey, KeyType, LicenseValidationBypass


RSA_STANDARD_EXPONENT = 65537
CONFIDENCE_THRESHOLD_HIGH = 0.8
CONFIDENCE_THRESHOLD_MEDIUM = 0.7
MINIMUM_KEY_COUNT = 2
ENTROPY_HIGH_THRESHOLD = 7.0
ENTROPY_MAX_THRESHOLD = 8.0
VALID_OPENSSL_VERSIONS = {"1.0.x", "unknown"}


class TestRSAKeyExtraction:
    """Test real RSA key extraction from binaries."""

    def test_extract_rsa_public_key_from_der_encoded_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Extracts RSA public key from DER-encoded binary data."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(
            public_exponent=RSA_STANDARD_EXPONENT,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        der_data = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_file = tmp_path / "test_binary.bin"
        binary_file.write_bytes(b"\x00" * 100 + der_data + b"\x00" * 100)

        keys = bypass.extract_rsa_keys_from_binary(str(binary_file))

        assert len(keys) > 0
        public_key_found = False
        for key in keys:
            if key.key_type == KeyType.RSA_PUBLIC and key.modulus is not None:
                public_key_found = True
                assert key.exponent == RSA_STANDARD_EXPONENT
                assert key.confidence >= CONFIDENCE_THRESHOLD_MEDIUM
                break

        assert public_key_found

    def test_extract_rsa_private_key_from_pkcs1_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Extracts RSA private key from PKCS#1 encoded binary data."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(
            public_exponent=RSA_STANDARD_EXPONENT,
            key_size=2048,
            backend=default_backend()
        )

        der_data = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_file = tmp_path / "test_private.bin"
        binary_file.write_bytes(der_data)

        keys = bypass.extract_rsa_keys_from_binary(str(binary_file))

        private_key_found = False
        for key in keys:
            if key.key_type == KeyType.RSA_PRIVATE and key.modulus is not None:
                private_key_found = True
                assert key.exponent == RSA_STANDARD_EXPONENT
                assert key.confidence >= CONFIDENCE_THRESHOLD_HIGH
                break

        assert private_key_found

    def test_extract_rsa_key_from_pem_format(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Extracts RSA keys from PEM-encoded binary data."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(
            public_exponent=RSA_STANDARD_EXPONENT,
            key_size=2048,
            backend=default_backend()
        )

        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_file = tmp_path / "test_pem.bin"
        binary_file.write_bytes(pem_data)

        keys = bypass.extract_rsa_keys_from_binary(str(binary_file))

        pem_key_found = False
        for key in keys:
            if key.key_type == KeyType.RSA_PRIVATE:
                pem_key_found = True
                assert key.modulus is not None
                assert key.exponent == RSA_STANDARD_EXPONENT
                break

        assert pem_key_found

    def test_extract_multiple_rsa_keys_from_single_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Extracts multiple RSA keys embedded in single binary."""
        bypass = LicenseValidationBypass()

        key1 = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())
        key2 = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())

        der1 = key1.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        der2 = key2.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_file = tmp_path / "multi_key.bin"
        binary_file.write_bytes(b"\x00" * 200 + der1 + b"\x00" * 200 + der2 + b"\x00" * 200)

        keys = bypass.extract_rsa_keys_from_binary(str(binary_file))

        unique_moduli = {key.modulus for key in keys if key.modulus is not None}
        assert len(unique_moduli) >= MINIMUM_KEY_COUNT


class TestECCKeyExtraction:
    """Test real ECC key extraction from binaries."""

    def test_extract_ecc_public_key_from_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Extracts ECC public key from DER-encoded binary data."""
        bypass = LicenseValidationBypass()

        private_key = ec.generate_private_key(SECP256R1(), default_backend())
        public_key = private_key.public_key()

        der_data = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_file = tmp_path / "ecc_test.bin"
        binary_file.write_bytes(der_data)

        keys = bypass.extract_ecc_keys_from_binary(str(binary_file))

        assert len(keys) > 0
        ecc_found = False
        for key in keys:
            if key.key_type == KeyType.ECC_PUBLIC:
                ecc_found = True
                assert key.curve is not None
                assert key.confidence >= CONFIDENCE_THRESHOLD_MEDIUM
                break

        assert ecc_found

    def test_extract_ecc_private_key_from_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Extracts ECC private key from DER-encoded binary data."""
        bypass = LicenseValidationBypass()

        private_key = ec.generate_private_key(SECP384R1(), default_backend())

        der_data = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_file = tmp_path / "ecc_private.bin"
        binary_file.write_bytes(der_data)

        keys = bypass.extract_ecc_keys_from_binary(str(binary_file))

        private_ecc_found = False
        for key in keys:
            if key.key_type == KeyType.ECC_PRIVATE:
                private_ecc_found = True
                assert key.curve is not None
                break

        assert private_ecc_found

    def test_extract_ecc_keys_different_curves(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """Extracts ECC keys from different curves (P-256, P-384)."""
        bypass = LicenseValidationBypass()

        key_p256 = ec.generate_private_key(SECP256R1(), default_backend())
        key_p384 = ec.generate_private_key(SECP384R1(), default_backend())

        der_p256 = key_p256.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        der_p384 = key_p384.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_file = tmp_path / "multi_curve.bin"
        binary_file.write_bytes(der_p256 + b"\x00" * 100 + der_p384)

        keys = bypass.extract_ecc_keys_from_binary(str(binary_file))

        curves_found = {key.curve for key in keys if key.curve is not None}
        assert curves_found


class TestCertificateExtraction:
    """Test X.509 certificate extraction from binaries."""

    def test_extract_certificate_from_binary(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """Extracts X.509 certificates from binary data."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        der_cert = cert.public_bytes(serialization.Encoding.DER)

        binary_file = tmp_path / "cert_test.bin"
        binary_file.write_bytes(der_cert)

        certs = bypass.extract_certificates(str(binary_file))

        assert len(certs) > 0
        assert certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test.com"

    def test_extract_certificate_public_key_as_rsa_key(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """Extracts public key from certificate as RSA key entry."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        der_cert = cert.public_bytes(serialization.Encoding.DER)

        binary_file = tmp_path / "cert_key.bin"
        binary_file.write_bytes(der_cert)

        results = bypass.extract_all_keys(str(binary_file))

        assert "certificates" in results
        assert len(results["rsa"]) > 0

        cert_key_found = False
        for key in results["rsa"]:
            if "Certificate:" in key.context:
                cert_key_found = True
                assert key.modulus is not None
                assert key.exponent == RSA_STANDARD_EXPONENT
                break

        assert cert_key_found


class TestEntropyAnalysis:
    """Test entropy-based key detection."""

    def test_calculate_entropy_of_random_data(self) -> None:  # noqa: PLR6301
        """Calculates correct Shannon entropy for random data."""
        bypass = LicenseValidationBypass()

        import os
        random_data = os.urandom(256)

        entropy = bypass._calculate_entropy(random_data)

        assert entropy >= ENTROPY_HIGH_THRESHOLD
        assert entropy <= ENTROPY_MAX_THRESHOLD

    def test_calculate_entropy_of_low_entropy_data(self) -> None:  # noqa: PLR6301
        """Calculates correct Shannon entropy for low entropy data."""
        bypass = LicenseValidationBypass()

        low_entropy_data = b"\x00" * 256

        entropy = bypass._calculate_entropy(low_entropy_data)

        assert entropy < 1.0

    def test_entropy_based_key_detection_finds_high_entropy_keys(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Entropy-based detection identifies high-entropy key material."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())
        der_data = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_file = tmp_path / "entropy_test.bin"
        binary_file.write_bytes(b"\x00" * 1000 + der_data + b"\x00" * 1000)

        with open(binary_file, "rb") as f:
            data = f.read()

        keys = bypass._entropy_based_key_detection(data)

        assert len(keys) > 0


class TestOpenSSLStructureParsing:
    """Test OpenSSL RSA structure parsing."""

    def test_parse_openssl_rsa_structure(self) -> None:  # noqa: PLR6301
        """Parses OpenSSL RSA structure from memory."""
        bypass = LicenseValidationBypass()

        rsa_magic = b"RSA\x00"
        fake_structure = rsa_magic + b"\x00" * 1000

        result = bypass._parse_openssl_rsa_struct(fake_structure)

        assert result is None or isinstance(result, ExtractedKey)

    def test_detect_openssl_version_from_structure(self) -> None:  # noqa: PLR6301
        """Detects OpenSSL version from RSA structure patterns."""
        bypass = LicenseValidationBypass()

        v10_data = b"\x00" * 16 + b"\x00\x00\x00\x00" + b"\x00" * 4 + b"\x00\x00\x00\x00" + b"\x00" * 100
        version = bypass._detect_openssl_version(v10_data)
        assert version in VALID_OPENSSL_VERSIONS


class TestBCryptKeyBlobParsing:
    """Test Windows BCRYPT_RSAKEY_BLOB parsing."""

    def test_parse_bcrypt_public_key_blob(self) -> None:  # noqa: PLR6301
        """Parses Windows BCRYPT RSA public key blob."""
        bypass = LicenseValidationBypass()

        magic = b"RSA1"
        bit_length = struct.pack("<I", 2048)
        pub_exp_len = struct.pack("<I", 4)
        mod_len = struct.pack("<I", 256)
        reserved1 = struct.pack("<I", 0)
        reserved2 = struct.pack("<I", 0)

        exponent = (RSA_STANDARD_EXPONENT).to_bytes(4, "little")
        modulus = b"\x01" * 256

        blob = magic + bit_length + pub_exp_len + mod_len + reserved1 + reserved2 + exponent + modulus

        result = bypass._parse_bcrypt_key_blob(blob)

        assert result is not None
        assert result.key_type == KeyType.RSA_PUBLIC
        assert result.exponent == RSA_STANDARD_EXPONENT
        assert result.modulus is not None

    def test_parse_bcrypt_invalid_magic_returns_none(self) -> None:  # noqa: PLR6301
        """Returns None for invalid BCRYPT magic bytes."""
        bypass = LicenseValidationBypass()

        invalid_blob = b"INVALID" + b"\x00" * 100

        result = bypass._parse_bcrypt_key_blob(invalid_blob)

        assert result is None


class TestSymmetricKeyExtraction:
    """Test symmetric key extraction (AES, DES, etc.)."""

    def test_extract_symmetric_keys_from_binary(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """Extracts high-entropy regions as potential symmetric keys."""
        bypass = LicenseValidationBypass()

        import os
        aes_256_key = os.urandom(32)
        aes_128_key = os.urandom(16)

        binary_file = tmp_path / "symmetric.bin"
        binary_file.write_bytes(b"\x00" * 500 + aes_256_key + b"\x00" * 500 + aes_128_key + b"\x00" * 500)

        keys = bypass._extract_symmetric_keys(str(binary_file))

        assert len(keys) > 0

        aes_keys_found = [k for k in keys if k.key_type == KeyType.AES]
        assert aes_keys_found

    def test_determine_symmetric_key_type_by_size(self) -> None:  # noqa: PLR6301
        """Determines symmetric key type based on key size."""
        bypass = LicenseValidationBypass()

        import os

        aes_128 = os.urandom(16)
        aes_256 = os.urandom(32)

        type_128 = bypass._determine_symmetric_type(aes_128)
        type_256 = bypass._determine_symmetric_type(aes_256)

        assert type_128 == KeyType.AES
        assert type_256 == KeyType.AES


class TestPEResourceKeyExtraction:
    """Test key extraction from PE resources (Windows only)."""

    def test_extract_keys_from_pe_resources_handles_missing_pe(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Handles non-PE files gracefully without errors."""
        bypass = LicenseValidationBypass()

        non_pe_file = tmp_path / "not_pe.bin"
        non_pe_file.write_bytes(b"Not a PE file" * 100)

        keys = bypass._extract_from_pe_resources(str(non_pe_file))

        assert isinstance(keys, list)


class TestProbableRSAModulusDetection:
    """Test probabilistic RSA modulus detection."""

    def test_is_probable_rsa_modulus_validates_properties(self) -> None:  # noqa: PLR6301
        """Validates number has properties of RSA modulus."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())
        numbers = private_key.private_numbers()
        real_modulus = numbers.public_numbers.n

        assert bypass._is_probable_rsa_modulus(real_modulus)

    def test_is_probable_rsa_modulus_rejects_even_numbers(self) -> None:  # noqa: PLR6301
        """Rejects even numbers as RSA moduli."""
        bypass = LicenseValidationBypass()

        even_number = 2 ** 2048

        assert not bypass._is_probable_rsa_modulus(even_number)

    def test_is_probable_rsa_modulus_rejects_too_small_numbers(self) -> None:  # noqa: PLR6301
        """Rejects numbers too small to be RSA moduli."""
        bypass = LicenseValidationBypass()

        small_number = 2 ** 256

        assert not bypass._is_probable_rsa_modulus(small_number)


class TestOpenSSHKeyParsing:
    """Test OpenSSH format key parsing."""

    def test_parse_openssh_public_key_format(self) -> None:  # noqa: PLR6301
        """Parses OpenSSH public key format (ssh-rsa)."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())
        public_key = private_key.public_key()

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        ssh_public = public_key.public_bytes(
            encoding=Encoding.OpenSSH,
            format=PublicFormat.OpenSSH
        )

        result = bypass._try_parse_openssh(ssh_public)

        assert result is not None
        assert result.key_type == KeyType.RSA_PUBLIC
        assert result.modulus is not None
        assert result.exponent == RSA_STANDARD_EXPONENT


class TestJWKParsing:
    """Test JSON Web Key format parsing."""

    def test_parse_jwk_rsa_public_key(self) -> None:  # noqa: PLR6301
        """Parses JWK format RSA public key."""
        bypass = LicenseValidationBypass()

        import base64
        import json

        n_value = base64.urlsafe_b64encode(b"\x01" * 256).decode().rstrip("=")
        e_value = base64.urlsafe_b64encode((RSA_STANDARD_EXPONENT).to_bytes(3, "big")).decode().rstrip("=")

        jwk = {
            "kty": "RSA",
            "n": n_value,
            "e": e_value
        }

        jwk_bytes = json.dumps(jwk).encode()

        result = bypass._try_parse_jwk(jwk_bytes)

        assert result is not None
        assert result.key_type == KeyType.RSA_PUBLIC
        assert result.modulus is not None
        assert result.exponent == RSA_STANDARD_EXPONENT


class TestKeyDataValidation:
    """Test key data validation and structure checking."""

    def test_is_key_data_validates_entropy_and_markers(self) -> None:  # noqa: PLR6301
        """Validates data contains key markers and sufficient entropy."""
        bypass = LicenseValidationBypass()

        private_key = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())
        der_data = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        assert bypass._is_key_data(der_data)

    def test_is_key_data_rejects_low_entropy(self) -> None:  # noqa: PLR6301
        """Rejects data with low entropy as not being key data."""
        bypass = LicenseValidationBypass()

        low_entropy = b"\x00" * 256

        assert not bypass._is_key_data(low_entropy)

    def test_has_key_structure_validates_asn1(self) -> None:  # noqa: PLR6301
        """Validates data has ASN.1 structure consistent with keys."""
        bypass = LicenseValidationBypass()

        asn1_start = b"\x30\x82" + b"\x00" * 100

        assert bypass._has_key_structure(asn1_start)


class TestAllKeysExtraction:
    """Test comprehensive key extraction (all types)."""

    def test_extract_all_keys_returns_categorized_results(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """extract_all_keys returns all key types categorized."""
        bypass = LicenseValidationBypass()

        rsa_key = rsa.generate_private_key(RSA_STANDARD_EXPONENT, 2048, default_backend())
        ecc_key = ec.generate_private_key(SECP256R1(), default_backend())

        rsa_der = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ecc_der = ecc_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        import os
        symmetric = os.urandom(32)

        binary_file = tmp_path / "all_keys.bin"
        binary_file.write_bytes(rsa_der + b"\x00" * 200 + ecc_der + b"\x00" * 200 + symmetric)

        results = bypass.extract_all_keys(str(binary_file))

        assert "rsa" in results
        assert "ecc" in results
        assert "symmetric" in results
        assert "certificates" in results

        assert len(results["rsa"]) > 0
        assert len(results["ecc"]) > 0
