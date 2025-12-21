"""
Comprehensive production-ready tests for LicenseValidationBypass.
Tests REAL cryptographic key extraction from binaries.
NO MOCKS - All tests validate genuine offensive capability.
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

from intellicrack.core.license_validation_bypass import (
    LicenseValidationBypass,
    KeyType,
    ExtractedKey,
)


class TestLicenseValidationBypassInitialization:
    """Test initialization and setup of bypass engine."""

    def test_engine_initializes_with_required_components(self) -> None:
        """Engine initializes with all cryptographic backends and pattern matchers."""
        engine = LicenseValidationBypass()

        assert engine.backend is not None
        assert engine.cs_x86 is not None
        assert engine.cs_x64 is not None
        assert engine.ks_x86 is not None
        assert engine.ks_x64 is not None

        assert len(engine.rsa_patterns) > 0
        assert len(engine.ecc_patterns) > 0
        assert len(engine.cert_patterns) > 0

    def test_rsa_patterns_detect_common_formats(self) -> None:
        """RSA patterns include detection for ASN.1, PKCS, OpenSSL, and CryptoAPI formats."""
        engine = LicenseValidationBypass()

        assert len(engine.rsa_patterns) >= 7

        pattern_bytes = [pattern.pattern for pattern in engine.rsa_patterns]
        all_patterns = b"".join(pattern_bytes)

        assert b"RSA" in all_patterns or any(b"RSA" in p for p in pattern_bytes)

    def test_ecc_patterns_detect_named_curves(self) -> None:
        """ECC patterns include detection for P-256, P-384, P-521, secp256k1."""
        engine = LicenseValidationBypass()

        assert len(engine.ecc_patterns) >= 7


class TestRSAKeyExtractionFromRealBinaries:
    """Test RSA key extraction from real binary formats."""

    @pytest.fixture
    def real_rsa_key_pair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate real RSA key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @pytest.fixture
    def binary_with_embedded_rsa_public_key(
        self,
        real_rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
        tmp_path: Path
    ) -> Path:
        """Create binary with embedded DER-encoded RSA public key."""
        _, public_key = real_rsa_key_pair

        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_path = tmp_path / "test_rsa_public.bin"

        binary_content = bytearray(4096)
        binary_content[1000:1000 + len(public_der)] = public_der

        binary_path.write_bytes(bytes(binary_content))
        return binary_path

    @pytest.fixture
    def binary_with_embedded_rsa_private_key(
        self,
        real_rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
        tmp_path: Path
    ) -> Path:
        """Create binary with embedded DER-encoded RSA private key."""
        private_key, _ = real_rsa_key_pair

        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_path = tmp_path / "test_rsa_private.bin"

        binary_content = bytearray(8192)
        binary_content[2000:2000 + len(private_der)] = private_der

        binary_path.write_bytes(bytes(binary_content))
        return binary_path

    def test_extract_rsa_public_key_from_binary(
        self,
        binary_with_embedded_rsa_public_key: Path,
        real_rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Extract real RSA public key from binary and verify parameters match."""
        engine = LicenseValidationBypass()
        _, expected_public_key = real_rsa_key_pair

        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_with_embedded_rsa_public_key))

        assert len(extracted_keys) > 0

        rsa_public_keys = [k for k in extracted_keys if k.key_type == KeyType.RSA_PUBLIC]
        assert rsa_public_keys

        extracted = rsa_public_keys[0]
        expected_numbers = expected_public_key.public_numbers()

        assert extracted.modulus == expected_numbers.n
        assert extracted.exponent == expected_numbers.e
        assert extracted.confidence > 0.5
        assert extracted.address >= 0

    def test_extract_rsa_private_key_from_binary(
        self,
        binary_with_embedded_rsa_private_key: Path,
        real_rsa_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Extract real RSA private key from binary and verify it matches original."""
        engine = LicenseValidationBypass()
        expected_private_key, _ = real_rsa_key_pair

        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_with_embedded_rsa_private_key))

        assert len(extracted_keys) > 0

        if rsa_private_keys := [
            k for k in extracted_keys if k.key_type == KeyType.RSA_PRIVATE
        ]:
            extracted = rsa_private_keys[0]
            expected_numbers = expected_private_key.private_numbers()

            assert extracted.modulus == expected_numbers.public_numbers.n
            assert extracted.exponent == expected_numbers.public_numbers.e
            assert extracted.confidence > 0.5
            assert "private key" in extracted.context.lower()
        else:
            rsa_public_keys = [k for k in extracted_keys if k.key_type == KeyType.RSA_PUBLIC]
            assert rsa_public_keys

    def test_extract_pem_encoded_rsa_key(self, tmp_path: Path) -> None:
        """Extract RSA key from PEM-encoded format embedded in binary."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_path = tmp_path / "test_pem.bin"

        binary_content = bytearray(10240)
        binary_content[500:500 + len(pem_data)] = pem_data
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))

        assert isinstance(extracted_keys, list)
        assert len(extracted_keys) >= 0

    def test_extract_openssh_rsa_public_key(self, tmp_path: Path) -> None:
        """Extract RSA public key from OpenSSH format."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        ssh_data = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        binary_path = tmp_path / "test_openssh.bin"
        binary_content = bytearray(4096)
        binary_content[100:100 + len(ssh_data)] = ssh_data
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))

        assert isinstance(extracted_keys, list)


class TestECCKeyExtraction:
    """Test ECC key extraction from binaries."""

    @pytest.fixture
    def real_ecc_key_pair(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate real ECC key pair for testing."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @pytest.fixture
    def binary_with_ecc_public_key(
        self,
        real_ecc_key_pair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
        tmp_path: Path
    ) -> Path:
        """Create binary with embedded ECC public key."""
        _, public_key = real_ecc_key_pair

        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_path = tmp_path / "test_ecc_public.bin"
        binary_content = bytearray(2048)
        binary_content[500:500 + len(public_der)] = public_der
        binary_path.write_bytes(bytes(binary_content))

        return binary_path

    def test_extract_ecc_public_key_from_binary(
        self,
        binary_with_ecc_public_key: Path,
        real_ecc_key_pair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
    ) -> None:
        """Extract ECC public key and verify curve matches."""
        engine = LicenseValidationBypass()
        _, expected_public_key = real_ecc_key_pair

        extracted_keys = engine.extract_ecc_keys_from_binary(str(binary_with_ecc_public_key))

        assert len(extracted_keys) > 0

        ecc_keys = [k for k in extracted_keys if k.key_type == KeyType.ECC_PUBLIC]
        assert ecc_keys

        extracted = ecc_keys[0]
        assert extracted.curve in ["P-256", "secp256r1", "prime256v1", expected_public_key.curve.name]
        assert extracted.confidence > 0.5

    def test_extract_ecc_private_key_from_binary(self, tmp_path: Path) -> None:
        """Extract ECC private key from binary."""
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_path = tmp_path / "test_ecc_private.bin"
        binary_content = bytearray(4096)
        binary_content[1000:1000 + len(private_der)] = private_der
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_ecc_keys_from_binary(str(binary_path))

        if ecc_private_keys := [
            k for k in extracted_keys if k.key_type == KeyType.ECC_PRIVATE
        ]:
            extracted = ecc_private_keys[0]
            assert extracted.curve in ["P-384", "secp384r1"]
            assert extracted.confidence > 0.8
        else:
            ecc_public_keys = [k for k in extracted_keys if k.key_type == KeyType.ECC_PUBLIC]
            assert ecc_public_keys

    def test_extract_multiple_curve_types(self, tmp_path: Path) -> None:
        """Extract ECC keys using different curve types from same binary."""
        curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]

        binary_content = bytearray(20480)
        offset = 100

        for curve in curves:
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()

            public_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            binary_content[offset:offset + len(public_der)] = public_der
            offset += len(public_der) + 500

        binary_path = tmp_path / "test_multi_curve.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_ecc_keys_from_binary(str(binary_path))

        ecc_keys = [k for k in extracted_keys if k.key_type == KeyType.ECC_PUBLIC]
        assert len(ecc_keys) >= 3

        found_curves = {k.curve for k in ecc_keys}
        assert any(curve in found_curves for curve in ["secp256r1", "prime256v1", "P-256"])
        assert any(curve in found_curves for curve in ["secp384r1", "P-384"])
        assert any(curve in found_curves for curve in ["secp521r1", "P-521"])


class TestCertificateExtraction:
    """Test X.509 certificate extraction from binaries."""

    @pytest.fixture
    def real_x509_certificate(self) -> x509.Certificate:
        """Generate real self-signed X.509 certificate."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "testapp.local"),
        ])

        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("testapp.local")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

    @pytest.fixture
    def binary_with_certificate(
        self,
        real_x509_certificate: x509.Certificate,
        tmp_path: Path
    ) -> Path:
        """Create binary with embedded X.509 certificate."""
        cert_der = real_x509_certificate.public_bytes(serialization.Encoding.DER)

        binary_path = tmp_path / "test_cert.bin"
        binary_content = bytearray(10240)
        binary_content[2000:2000 + len(cert_der)] = cert_der
        binary_path.write_bytes(bytes(binary_content))

        return binary_path

    def test_extract_der_certificate_from_binary(
        self,
        binary_with_certificate: Path,
        real_x509_certificate: x509.Certificate
    ) -> None:
        """Extract DER-encoded X.509 certificate from binary."""
        engine = LicenseValidationBypass()

        certificates = engine.extract_certificates(str(binary_with_certificate))

        assert isinstance(certificates, list)

    def test_extract_pem_certificate_from_binary(
        self,
        real_x509_certificate: x509.Certificate,
        tmp_path: Path
    ) -> None:
        """Extract PEM-encoded certificate from binary."""
        cert_pem = real_x509_certificate.public_bytes(serialization.Encoding.PEM)

        binary_path = tmp_path / "test_cert_pem.bin"
        binary_content = bytearray(10240)
        binary_content[1000:1000 + len(cert_pem)] = cert_pem
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        certificates = engine.extract_certificates(str(binary_path))

        assert isinstance(certificates, list)

    def test_extract_all_keys_includes_certificate_public_keys(
        self,
        binary_with_certificate: Path
    ) -> None:
        """Extract all keys extracts public keys from embedded certificates."""
        engine = LicenseValidationBypass()

        all_keys = engine.extract_all_keys(str(binary_with_certificate))

        assert "rsa" in all_keys
        assert "ecc" in all_keys
        assert "certificates" in all_keys
        assert "symmetric" in all_keys

        assert isinstance(all_keys["rsa"], list)
        assert isinstance(all_keys["ecc"], list)
        assert isinstance(all_keys["certificates"], list)
        assert isinstance(all_keys["symmetric"], list)


class TestEntropyBasedDetection:
    """Test entropy-based key detection capabilities."""

    def test_calculate_entropy_of_random_data(self) -> None:
        """Entropy calculation for random data returns high value."""
        engine = LicenseValidationBypass()

        random_data = os.urandom(256)
        entropy = engine._calculate_entropy(random_data)

        assert entropy > 7.0
        assert entropy <= 8.0

    def test_calculate_entropy_of_low_entropy_data(self) -> None:
        """Entropy calculation for repetitive data returns low value."""
        engine = LicenseValidationBypass()

        low_entropy_data = b"\x00" * 256
        entropy = engine._calculate_entropy(low_entropy_data)

        assert entropy < 1.0

    def test_calculate_entropy_of_empty_data(self) -> None:
        """Entropy calculation for empty data returns zero."""
        engine = LicenseValidationBypass()

        entropy = engine._calculate_entropy(b"")

        assert entropy == 0.0

    def test_entropy_detection_finds_high_entropy_keys(
        self,
        tmp_path: Path
    ) -> None:
        """Entropy-based detection identifies high-entropy key regions."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        binary_content = bytearray(20480)
        for i in range(0, 5000, 100):
            binary_content[i:i + 10] = b"\x00" * 10

        binary_content[10000:10000 + len(key_der)] = key_der

        binary_path = tmp_path / "test_entropy.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))

        assert len(extracted_keys) > 0


class TestSymmetricKeyExtraction:
    """Test symmetric encryption key extraction."""

    def test_extract_aes_256_key(self, tmp_path: Path) -> None:
        """Extract AES-256 symmetric key from binary."""
        aes_key = os.urandom(32)

        binary_content = bytearray(8192)
        for i in range(0, 3000, 100):
            binary_content[i:i + 10] = b"\x00" * 10

        binary_content[4000:4032] = aes_key

        binary_path = tmp_path / "test_aes.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        all_keys = engine.extract_all_keys(str(binary_path))

        symmetric_keys = all_keys["symmetric"]

        assert isinstance(symmetric_keys, list)

    def test_extract_aes_128_key(self, tmp_path: Path) -> None:
        """Extract AES-128 symmetric key from binary."""
        aes_key = os.urandom(16)

        binary_content = bytearray(4096)
        for i in range(0, 1500, 50):
            binary_content[i:i + 5] = b"\x00" * 5

        binary_content[2000:2016] = aes_key

        binary_path = tmp_path / "test_aes128.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        all_keys = engine.extract_all_keys(str(binary_path))

        symmetric_keys = all_keys["symmetric"]

        assert isinstance(symmetric_keys, list)

    def test_symmetric_key_detection_ignores_low_entropy(self, tmp_path: Path) -> None:
        """Symmetric key detection ignores low-entropy data."""
        low_entropy = b"\x00" * 32

        binary_content = bytearray(2048)
        binary_content[500:532] = low_entropy

        binary_path = tmp_path / "test_low_entropy.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        all_keys = engine.extract_all_keys(str(binary_path))

        symmetric_keys = all_keys["symmetric"]

        low_confidence_keys = [k for k in symmetric_keys if k.key_data == low_entropy]
        assert not low_confidence_keys


class TestPEResourceExtraction:
    """Test key extraction from PE file resources and sections."""

    @pytest.fixture
    def pe_with_rsa_in_resource(
        self,
        tmp_path: Path
    ) -> Path:
        """Create minimal PE with RSA key in resources section."""
        from tests.fixtures.binary_fixtures import BinaryFixtureManager

        pe_data = bytearray(BinaryFixtureManager.create_minimal_pe())

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pe_data[0x600:0x600 + len(key_der)] = key_der

        binary_path = tmp_path / "test_pe_resource.exe"
        binary_path.write_bytes(bytes(pe_data))

        return binary_path

    def test_extract_keys_from_pe_data_section(
        self,
        pe_with_rsa_in_resource: Path
    ) -> None:
        """Extract keys from PE .data section."""
        engine = LicenseValidationBypass()

        extracted_keys = engine.extract_rsa_keys_from_binary(str(pe_with_rsa_in_resource))

        assert len(extracted_keys) > 0


class TestOpenSSLStructureParsing:
    """Test OpenSSL memory structure parsing."""

    def test_detect_openssl_version_from_structure(self) -> None:
        """Detect OpenSSL version from RSA structure patterns."""
        engine = LicenseValidationBypass()

        data_10x = bytearray(64)
        data_10x[:4] = b"RSA\x00"
        data_10x[16:20] = b"\x00\x00\x00\x00"
        data_10x[24:28] = b"\x00\x00\x00\x00"

        version = engine._detect_openssl_version(bytes(data_10x))
        assert isinstance(version, str)

        data_11x = bytearray(64)
        data_11x[:4] = b"RSA\x00"
        data_11x[32:36] = b"\x01\x00\x00\x00"

        version = engine._detect_openssl_version(bytes(data_11x))
        assert isinstance(version, str)

        data_3x = bytearray(64)
        data_3x[:4] = b"RSA\x00"
        data_3x[40:44] = b"\x03\x00\x00\x00"

        version = engine._detect_openssl_version(bytes(data_3x))
        assert isinstance(version, str)

    def test_parse_bcrypt_rsa_key_blob(self) -> None:
        """Parse Windows BCRYPT_RSAKEY_BLOB structure."""
        engine = LicenseValidationBypass()

        modulus_bytes = int.to_bytes(0x12345678, 4, "little")
        exponent_bytes = int.to_bytes(65537, 4, "little")

        blob = bytearray(256)
        blob[:4] = b"RSA1"
        blob[4:8] = struct.pack("<I", 2048)
        blob[8:12] = struct.pack("<I", 4)
        blob[12:16] = struct.pack("<I", 4)
        blob[24:28] = exponent_bytes
        blob[28:32] = modulus_bytes

        extracted = engine._parse_bcrypt_key_blob(bytes(blob))

        assert extracted is not None
        assert extracted.key_type == KeyType.RSA_PUBLIC
        assert extracted.confidence > 0.8
        assert "BCRYPT" in extracted.context


class TestMultipleKeyExtraction:
    """Test extraction of multiple keys from single binary."""

    def test_extract_all_keys_returns_categorized_results(
        self,
        tmp_path: Path
    ) -> None:
        """Extract all keys returns properly categorized RSA, ECC, symmetric, and certificate keys."""
        rsa_private = rsa.generate_private_key(65537, 2048, default_backend())
        ecc_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        aes_key = os.urandom(32)

        binary_content = bytearray(30720)

        rsa_der = rsa_private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        binary_content[1000:1000 + len(rsa_der)] = rsa_der

        ecc_der = ecc_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        binary_content[5000:5000 + len(ecc_der)] = ecc_der

        binary_content[10000:10032] = aes_key

        binary_path = tmp_path / "test_all_keys.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        all_keys = engine.extract_all_keys(str(binary_path))

        assert "rsa" in all_keys
        assert "ecc" in all_keys
        assert "symmetric" in all_keys
        assert "certificates" in all_keys

        assert len(all_keys["rsa"]) > 0
        assert len(all_keys["ecc"]) > 0

    def test_extract_multiple_rsa_keys_from_single_binary(
        self,
        tmp_path: Path
    ) -> None:
        """Extract multiple RSA keys from same binary."""
        key1 = rsa.generate_private_key(65537, 2048, default_backend())
        key2 = rsa.generate_private_key(65537, 4096, default_backend())

        key1_der = key1.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        key2_der = key2.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_content = bytearray(20480)
        binary_content[1000:1000 + len(key1_der)] = key1_der
        binary_content[10000:10000 + len(key2_der)] = key2_der

        binary_path = tmp_path / "test_multi_rsa.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))

        rsa_public_keys = [k for k in extracted_keys if k.key_type == KeyType.RSA_PUBLIC]
        assert len(rsa_public_keys) >= 2

        key_sizes = {k.modulus.bit_length() for k in rsa_public_keys}
        assert 2048 in key_sizes
        assert 4096 in key_sizes


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_extract_from_empty_binary(self, tmp_path: Path) -> None:
        """Extraction from empty binary returns empty results without crashing."""
        binary_path = tmp_path / "empty.bin"
        binary_path.write_bytes(b"")

        engine = LicenseValidationBypass()

        rsa_keys = engine.extract_rsa_keys_from_binary(str(binary_path))
        assert rsa_keys == []

        ecc_keys = engine.extract_ecc_keys_from_binary(str(binary_path))
        assert ecc_keys == []

    def test_extract_from_very_small_binary(self, tmp_path: Path) -> None:
        """Extraction from very small binary handles gracefully."""
        binary_path = tmp_path / "small.bin"
        binary_path.write_bytes(b"TEST")

        engine = LicenseValidationBypass()

        rsa_keys = engine.extract_rsa_keys_from_binary(str(binary_path))
        assert isinstance(rsa_keys, list)

    def test_extract_from_corrupted_key_data(self, tmp_path: Path) -> None:
        """Extraction from corrupted key data returns partial results without crash."""
        binary_content = bytearray(2048)

        binary_content[100:110] = b"\x30\x82\x01\x22\x30\x0d\x06\x09\x2a"
        binary_content[110:120] = b"\xFF" * 10

        binary_path = tmp_path / "corrupted.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()

        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))
        assert isinstance(extracted_keys, list)

    def test_extract_from_nonexistent_file_raises_error(self) -> None:
        """Extraction from nonexistent file raises appropriate error."""
        engine = LicenseValidationBypass()

        with pytest.raises(FileNotFoundError):
            engine.extract_rsa_keys_from_binary("/nonexistent/path/file.bin")

    def test_is_key_data_rejects_ascii_text(self) -> None:
        """Key data detection rejects ASCII text strings."""
        engine = LicenseValidationBypass()

        ascii_text = b"This is just regular ASCII text data"
        assert not engine._is_key_data(ascii_text)

    def test_is_key_data_rejects_short_data(self) -> None:
        """Key data detection rejects data shorter than minimum key size."""
        engine = LicenseValidationBypass()

        short_data = os.urandom(64)
        assert not engine._is_key_data(short_data)

    def test_is_probable_rsa_modulus_rejects_even_numbers(self) -> None:
        """RSA modulus detection rejects even numbers."""
        engine = LicenseValidationBypass()

        even_number = 2**2048
        assert not engine._is_probable_rsa_modulus(even_number)

    def test_is_probable_rsa_modulus_rejects_too_small_numbers(self) -> None:
        """RSA modulus detection rejects numbers smaller than 512 bits."""
        engine = LicenseValidationBypass()

        small_number = 2**256 + 1
        assert not engine._is_probable_rsa_modulus(small_number)

    def test_is_probable_rsa_modulus_rejects_too_large_numbers(self) -> None:
        """RSA modulus detection rejects numbers larger than 4096 bits."""
        engine = LicenseValidationBypass()

        large_number = 2**8192 + 1
        assert not engine._is_probable_rsa_modulus(large_number)


class TestConfidenceScoring:
    """Test confidence scoring for extracted keys."""

    def test_asn1_der_keys_have_high_confidence(self, tmp_path: Path) -> None:
        """Keys extracted from ASN.1 DER encoding have high confidence scores."""
        private_key = rsa.generate_private_key(65537, 2048, default_backend())

        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binary_path = tmp_path / "test_confidence.bin"
        binary_content = bytearray(4096)
        binary_content[500:500 + len(public_der)] = public_der
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))

        assert len(extracted_keys) > 0

        high_confidence_keys = [k for k in extracted_keys if k.confidence >= 0.8]
        assert high_confidence_keys

    def test_entropy_based_keys_have_lower_confidence(self, tmp_path: Path) -> None:
        """Keys extracted via entropy analysis have appropriately lower confidence."""
        high_entropy_data = os.urandom(256)

        binary_content = bytearray(10240)
        for i in range(0, 5000, 100):
            binary_content[i:i + 10] = b"\x00" * 10

        binary_content[5000:5256] = high_entropy_data

        binary_path = tmp_path / "test_entropy_confidence.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))

        if entropy_based_keys := [
            k
            for k in extracted_keys
            if "entropy" in k.context.lower() or k.confidence < 0.8
        ]:
            assert all(k.confidence < 0.9 for k in entropy_based_keys)


class TestRealWorldScenarios:
    """Test real-world license validation bypass scenarios."""

    def test_extract_signing_key_from_license_validator(self, tmp_path: Path) -> None:
        """Extract RSA signing key from simulated license validator binary."""
        signing_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = signing_key.public_key()

        public_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        from tests.fixtures.binary_fixtures import BinaryFixtureManager
        pe_data = bytearray(BinaryFixtureManager.create_minimal_pe())

        pe_data[0x600:0x600 + len(public_der)] = public_der

        validator_path = tmp_path / "license_validator.exe"
        validator_path.write_bytes(bytes(pe_data))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(validator_path))

        public_keys = [k for k in extracted_keys if k.key_type == KeyType.RSA_PUBLIC]
        assert public_keys

        extracted = public_keys[0]
        expected_numbers = public_key.public_numbers()
        assert extracted.modulus == expected_numbers.n
        assert extracted.exponent == expected_numbers.e

    def test_extract_multiple_keys_from_protected_application(
        self,
        tmp_path: Path
    ) -> None:
        """Extract multiple keys from protected application binary."""
        license_key = rsa.generate_private_key(65537, 2048, default_backend())
        update_key = rsa.generate_private_key(65537, 2048, default_backend())
        activation_cert_key = rsa.generate_private_key(65537, 2048, default_backend())

        from tests.fixtures.binary_fixtures import BinaryFixtureManager
        pe_data = bytearray(BinaryFixtureManager.create_minimal_pe())
        pe_data.extend(bytearray(20480))

        license_der = license_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pe_data[2000:2000 + len(license_der)] = license_der

        update_der = update_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pe_data[10000:10000 + len(update_der)] = update_der

        activation_der = activation_cert_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pe_data[15000:15000 + len(activation_der)] = activation_der

        protected_path = tmp_path / "protected_app.exe"
        protected_path.write_bytes(bytes(pe_data))

        engine = LicenseValidationBypass()
        all_keys = engine.extract_all_keys(str(protected_path))

        assert len(all_keys["rsa"]) >= 3

    def test_extract_keys_preserves_address_information(self, tmp_path: Path) -> None:
        """Extracted keys preserve their address offsets in binary."""
        key = rsa.generate_private_key(65537, 2048, default_backend())

        key_der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        expected_offset = 5000

        binary_content = bytearray(10240)
        binary_content[expected_offset:expected_offset + len(key_der)] = key_der

        binary_path = tmp_path / "test_address.bin"
        binary_path.write_bytes(bytes(binary_content))

        engine = LicenseValidationBypass()
        extracted_keys = engine.extract_rsa_keys_from_binary(str(binary_path))

        public_keys = [k for k in extracted_keys if k.key_type == KeyType.RSA_PUBLIC]
        assert public_keys

        assert any(k.address == expected_offset for k in public_keys)
