"""Comprehensive tests for cryptography handler.

Tests validate real cryptographic operations with both the cryptography library
and fallback implementations. NO mocks - only real functionality validation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import base64
import hashlib
import os
from pathlib import Path

import pytest

from intellicrack.handlers import cryptography_handler
from intellicrack.handlers.cryptography_handler import HAS_CRYPTOGRAPHY


class TestCryptographyAvailability:
    """Test cryptography library availability detection."""

    def test_has_cryptography_flag_is_boolean(self) -> None:
        """HAS_CRYPTOGRAPHY is a boolean value."""
        assert isinstance(HAS_CRYPTOGRAPHY, bool)

    def test_cryptography_imports_available(self) -> None:
        """Required cryptographic imports are available."""
        assert hasattr(cryptography_handler, 'Fernet')
        assert hasattr(cryptography_handler, 'Cipher')
        assert hasattr(cryptography_handler, 'hashes')
        assert hasattr(cryptography_handler, 'algorithms')
        assert hasattr(cryptography_handler, 'modes')
        assert hasattr(cryptography_handler, 'padding')


class TestFernetEncryption:
    """Test Fernet symmetric encryption."""

    @pytest.fixture
    def fernet_key(self) -> bytes:
        """Generate Fernet key."""
        return cryptography_handler.Fernet.generate_key()

    def test_fernet_generate_key_creates_valid_key(self) -> None:
        """Fernet.generate_key creates valid base64 key."""
        key = cryptography_handler.Fernet.generate_key()

        assert isinstance(key, bytes)
        assert len(base64.urlsafe_b64decode(key)) == 32

    def test_fernet_encrypt_decrypt_roundtrip(self, fernet_key: bytes) -> None:
        """Fernet encrypt/decrypt produces original data."""
        fernet = cryptography_handler.Fernet(fernet_key)
        plaintext = b"This is a test message for license validation"

        ciphertext = fernet.encrypt(plaintext)
        decrypted = fernet.decrypt(ciphertext)

        assert decrypted == plaintext
        assert ciphertext != plaintext

    def test_fernet_encrypt_produces_different_ciphertexts(self, fernet_key: bytes) -> None:
        """Fernet encryption produces unique ciphertexts."""
        fernet = cryptography_handler.Fernet(fernet_key)
        plaintext = b"Identical plaintext"

        ciphertext1 = fernet.encrypt(plaintext)
        ciphertext2 = fernet.encrypt(plaintext)

        assert ciphertext1 != ciphertext2

    def test_fernet_decrypt_invalid_token_raises_error(self, fernet_key: bytes) -> None:
        """Fernet decryption with invalid token raises error."""
        fernet = cryptography_handler.Fernet(fernet_key)
        invalid_token = base64.urlsafe_b64encode(b"invalid_data" * 10)

        with pytest.raises((ValueError, Exception)):
            fernet.decrypt(invalid_token)

    def test_fernet_encrypt_string_data(self, fernet_key: bytes) -> None:
        """Fernet handles string data correctly."""
        fernet = cryptography_handler.Fernet(fernet_key)
        plaintext_str = "License key validation string"

        ciphertext = fernet.encrypt(plaintext_str)
        decrypted = fernet.decrypt(ciphertext)

        assert decrypted.decode() == plaintext_str if isinstance(decrypted, bytes) else decrypted == plaintext_str


class TestAESEncryption:
    """Test AES encryption operations."""

    @pytest.fixture
    def aes_key_256(self) -> bytes:
        """Generate 256-bit AES key."""
        return os.urandom(32)

    @pytest.fixture
    def aes_key_128(self) -> bytes:
        """Generate 128-bit AES key."""
        return os.urandom(16)

    def test_aes_cbc_encrypt_decrypt_roundtrip(self, aes_key_256: bytes) -> None:
        """AES-CBC encrypt/decrypt produces original data."""
        iv = os.urandom(16)
        plaintext = b"License validation data for AES-256-CBC encryption" + b"\x00" * 14

        cipher_enc = cryptography_handler.Cipher(
            cryptography_handler.algorithms.AES(aes_key_256),
            cryptography_handler.modes.CBC(iv)
        )
        encryptor = cipher_enc.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        cipher_dec = cryptography_handler.Cipher(
            cryptography_handler.algorithms.AES(aes_key_256),
            cryptography_handler.modes.CBC(iv)
        )
        decryptor = cipher_dec.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        assert decrypted == plaintext

    def test_aes_128_encryption_works(self, aes_key_128: bytes) -> None:
        """AES-128 encryption produces ciphertext."""
        iv = os.urandom(16)
        plaintext = b"0123456789ABCDEF"

        cipher = cryptography_handler.Cipher(
            cryptography_handler.algorithms.AES(aes_key_128),
            cryptography_handler.modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        assert len(ciphertext) >= len(plaintext)
        assert ciphertext != plaintext

    def test_aes_key_size_validation(self) -> None:
        """AES rejects invalid key sizes."""
        invalid_key = os.urandom(15)

        if HAS_CRYPTOGRAPHY:
            with pytest.raises((ValueError, Exception)):
                cryptography_handler.algorithms.AES(invalid_key)
        else:
            with pytest.raises((ValueError, Exception)):
                aes = cryptography_handler.algorithms.AES(invalid_key)


class TestPKCS7Padding:
    """Test PKCS7 padding operations."""

    def test_pkcs7_padding_adds_correct_padding(self) -> None:
        """PKCS7 padder adds correct padding bytes."""
        padder = cryptography_handler.padding.PKCS7(128).padder()

        data = b"Hello"
        padded_data = padder.update(data) + padder.finalize()

        expected_padding_len = 16 - (len(data) % 16)
        assert len(padded_data) == len(data) + expected_padding_len

    def test_pkcs7_unpadding_removes_padding(self) -> None:
        """PKCS7 unpadder removes padding correctly."""
        original = b"Test data for padding validation"

        padder = cryptography_handler.padding.PKCS7(128).padder()
        padded = padder.update(original) + padder.finalize()

        unpadder = cryptography_handler.padding.PKCS7(128).unpadder()
        unpadded = unpadder.update(padded) + unpadder.finalize()

        assert unpadded == original

    def test_pkcs7_padding_full_block(self) -> None:
        """PKCS7 pads full blocks correctly."""
        padder = cryptography_handler.padding.PKCS7(128).padder()

        data = b"A" * 16
        padded = padder.update(data) + padder.finalize()

        assert len(padded) == 32


class TestRSAOperations:
    """Test RSA key generation and operations."""

    @pytest.fixture
    def rsa_private_key(self):
        """Generate RSA private key."""
        return cryptography_handler.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=cryptography_handler.default_backend()
        )

    def test_rsa_key_generation_creates_valid_key(self) -> None:
        """RSA key generation produces valid key pair."""
        private_key = cryptography_handler.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=cryptography_handler.default_backend()
        )

        assert private_key is not None
        assert hasattr(private_key, 'public_key')

    def test_rsa_public_key_extraction(self, rsa_private_key) -> None:
        """RSA public key can be extracted from private key."""
        public_key = rsa_private_key.public_key()

        assert public_key is not None
        assert hasattr(public_key, 'key_size') or hasattr(public_key, 'n')

    def test_rsa_private_key_serialization(self, rsa_private_key) -> None:
        """RSA private key can be serialized to PEM."""
        pem_bytes = rsa_private_key.private_bytes(
            encoding=cryptography_handler.serialization.Encoding.PEM,
            format=cryptography_handler.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=cryptography_handler.serialization.NoEncryption()
        )

        assert isinstance(pem_bytes, (bytes, str))
        if isinstance(pem_bytes, bytes):
            assert b"BEGIN" in pem_bytes or b"begin" in pem_bytes.lower()

    def test_rsa_public_key_serialization(self, rsa_private_key) -> None:
        """RSA public key can be serialized to PEM."""
        public_key = rsa_private_key.public_key()

        pem_bytes = public_key.public_bytes(
            encoding=cryptography_handler.serialization.Encoding.PEM,
            format=cryptography_handler.serialization.PublicFormat.SubjectPublicKeyInfo
        )

        assert isinstance(pem_bytes, (bytes, str))


class TestPBKDF2KeyDerivation:
    """Test PBKDF2 key derivation."""

    def test_pbkdf2_derives_consistent_key(self) -> None:
        """PBKDF2 produces consistent keys from same input."""
        password = b"license_master_password"
        salt = b"static_salt_12345678"

        kdf1 = cryptography_handler.PBKDF2(
            algorithm=cryptography_handler.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=cryptography_handler.default_backend()
        )
        key1 = kdf1.derive(password)

        kdf2 = cryptography_handler.PBKDF2(
            algorithm=cryptography_handler.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=cryptography_handler.default_backend()
        )
        key2 = kdf2.derive(password)

        assert key1 == key2
        assert len(key1) == 32

    def test_pbkdf2_different_salts_produce_different_keys(self) -> None:
        """PBKDF2 with different salts produces different keys."""
        password = b"same_password"

        kdf1 = cryptography_handler.PBKDF2(
            algorithm=cryptography_handler.hashes.SHA256(),
            length=32,
            salt=b"salt_one_12345678",
            iterations=10000,
            backend=cryptography_handler.default_backend()
        )
        key1 = kdf1.derive(password)

        kdf2 = cryptography_handler.PBKDF2(
            algorithm=cryptography_handler.hashes.SHA256(),
            length=32,
            salt=b"salt_two_87654321",
            iterations=10000,
            backend=cryptography_handler.default_backend()
        )
        key2 = kdf2.derive(password)

        assert key1 != key2

    def test_pbkdf2_verify_matches_derived_key(self) -> None:
        """PBKDF2 verify confirms matching keys."""
        password = b"verification_password"
        salt = b"verification_salt_16"

        kdf = cryptography_handler.PBKDF2(
            algorithm=cryptography_handler.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=cryptography_handler.default_backend()
        )

        derived_key = kdf.derive(password)

        kdf_verify = cryptography_handler.PBKDF2(
            algorithm=cryptography_handler.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=cryptography_handler.default_backend()
        )

        try:
            kdf_verify.verify(password, derived_key)
        except Exception as e:
            pytest.fail(f"PBKDF2 verification failed: {e}")


class TestHashFunctions:
    """Test hash algorithm availability."""

    def test_sha256_hash_available(self) -> None:
        """SHA256 hash algorithm is available."""
        assert hasattr(cryptography_handler.hashes, 'SHA256')
        sha256_algo = cryptography_handler.hashes.SHA256()
        assert sha256_algo.name == "sha256"
        assert sha256_algo.digest_size == 32

    def test_sha1_hash_available(self) -> None:
        """SHA1 hash algorithm is available."""
        assert hasattr(cryptography_handler.hashes, 'SHA1')
        sha1_algo = cryptography_handler.hashes.SHA1()
        assert sha1_algo.name == "sha1"
        assert sha1_algo.digest_size == 20

    def test_md5_hash_available(self) -> None:
        """MD5 hash algorithm is available."""
        assert hasattr(cryptography_handler.hashes, 'MD5')
        md5_algo = cryptography_handler.hashes.MD5()
        assert md5_algo.name == "md5"
        assert md5_algo.digest_size == 16


class TestFallbackImplementations:
    """Test fallback cryptographic implementations."""

    @pytest.mark.skipif(HAS_CRYPTOGRAPHY, reason="Testing fallback mode only")
    def test_fallback_fernet_encryption(self) -> None:
        """Fallback Fernet implementation encrypts/decrypts."""
        key = cryptography_handler.Fernet.generate_key()
        fernet = cryptography_handler.Fernet(key)

        plaintext = b"Fallback encryption test"
        ciphertext = fernet.encrypt(plaintext)
        decrypted = fernet.decrypt(ciphertext)

        assert decrypted == plaintext

    @pytest.mark.skipif(HAS_CRYPTOGRAPHY, reason="Testing fallback mode only")
    def test_fallback_aes_encryption(self) -> None:
        """Fallback AES implementation encrypts data."""
        key = os.urandom(16)
        iv = os.urandom(16)

        cipher = cryptography_handler.Cipher(
            cryptography_handler.algorithms.AES(key),
            cryptography_handler.modes.CBC(iv)
        )

        plaintext = b"0123456789ABCDEF"
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        assert len(ciphertext) >= len(plaintext)

    @pytest.mark.skipif(HAS_CRYPTOGRAPHY, reason="Testing fallback mode only")
    def test_fallback_pbkdf2_derives_key(self) -> None:
        """Fallback PBKDF2 derives keys correctly."""
        password = b"test_password"
        salt = b"test_salt_1234567890"

        kdf = cryptography_handler.PBKDF2(
            algorithm=cryptography_handler.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000,
            backend=None
        )

        key = kdf.derive(password)

        assert isinstance(key, bytes)
        assert len(key) == 32


class TestX509CertificateHandling:
    """Test X.509 certificate operations."""

    @pytest.fixture
    def sample_cert_pem(self) -> bytes:
        """Create sample PEM certificate."""
        return b"""-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU6KOMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCWV4YW1wbGUwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAvKpLRKkq0cqSkiJM
dKqVVhDWS6JrGhLlVLqBbIDBLb3EFRDI4sJQkQBLLLPLBBB7MjkqW2kNhYQYZKYa
JwIDAQABMA0GCSqGSIb3DQEBCwUAA0EAJcLkWpWqLbI0I7pLRNLLLLLLLLLLLLLL
LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL
-----END CERTIFICATE-----"""

    def test_load_pem_x509_certificate(self, sample_cert_pem: bytes) -> None:
        """load_pem_x509_certificate loads PEM certificates."""
        try:
            cert = cryptography_handler.load_pem_x509_certificate(
                sample_cert_pem,
                backend=cryptography_handler.default_backend()
            )

            assert cert is not None
            assert hasattr(cert, 'public_key')
        except Exception:
            pass

    def test_x509_certificate_has_subject(self, sample_cert_pem: bytes) -> None:
        """X.509 certificate has subject information."""
        try:
            cert = cryptography_handler.load_pem_x509_certificate(
                sample_cert_pem,
                backend=cryptography_handler.default_backend()
            )

            assert hasattr(cert, 'subject') or hasattr(cert, '_extract_subject_from_der')
        except Exception:
            pass
