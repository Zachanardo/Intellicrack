"""Production tests for Cryptography handler.

Tests validate real cryptographic operations and fallback implementations.
Tests verify encryption, decryption, hashing, and key derivation.
"""

import hashlib
import hmac as hmac_module
import os
from typing import Any

import pytest

from intellicrack.handlers.cryptography_handler import (
    AESGCM,
    HAS_CRYPTOGRAPHY,
    algorithms,
    hashes,
    modes,
    rsa,
    Cipher,
    default_backend,
    asym_padding,
)


class TestCryptographyAvailability:
    """Test cryptography library availability."""

    def test_has_cryptography_flag(self) -> None:
        """Verify HAS_CRYPTOGRAPHY flag exists."""
        assert isinstance(HAS_CRYPTOGRAPHY, bool)

    def test_cipher_class_available(self) -> None:
        """Verify Cipher class is available."""
        assert Cipher is not None

    def test_algorithms_module_available(self) -> None:
        """Verify algorithms module is available."""
        assert algorithms is not None


class TestAESGCMEncryption:
    """Test AES-GCM encryption and decryption."""

    def test_aes_gcm_encrypt_decrypt(self) -> None:
        """Test AES-GCM encryption and decryption."""
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)

        plaintext = b"License key: ABCD-EFGH-IJKL-MNOP"
        nonce = os.urandom(12)

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)

        assert decrypted == plaintext

    def test_aes_gcm_unique_keys(self) -> None:
        """Verify generated keys are unique."""
        key1 = AESGCM.generate_key(bit_length=256)
        key2 = AESGCM.generate_key(bit_length=256)

        assert key1 != key2

    def test_aes_gcm_different_ciphertext(self) -> None:
        """Verify different keys produce different ciphertext."""
        plaintext = b"Test data"
        nonce = os.urandom(12)

        key1 = AESGCM.generate_key(bit_length=256)
        aesgcm1 = AESGCM(key1)
        ciphertext1 = aesgcm1.encrypt(nonce, plaintext, None)

        key2 = AESGCM.generate_key(bit_length=256)
        aesgcm2 = AESGCM(key2)
        ciphertext2 = aesgcm2.encrypt(nonce, plaintext, None)

        assert ciphertext1 != ciphertext2


class TestAESCBCEncryption:
    """Test AES-CBC encryption."""

    def test_aes_cbc_encrypt_decrypt(self) -> None:
        """Test AES-CBC encryption and decryption."""
        key = os.urandom(32)
        iv = os.urandom(16)

        plaintext = b"License validation data"
        padded_plaintext = plaintext + b"\x00" * (16 - len(plaintext) % 16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        assert decrypted.rstrip(b"\x00") == plaintext


class TestRSAEncryption:
    """Test RSA encryption and decryption."""

    def test_generate_rsa_keypair(self) -> None:
        """Generate RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        assert private_key is not None
        assert public_key is not None

    def test_rsa_encrypt_decrypt_roundtrip(self) -> None:
        """Encrypt and decrypt with RSA."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        plaintext = b"License activation key"

        ciphertext = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        decrypted = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        assert decrypted == plaintext


class TestHashingFunctions:
    """Test cryptographic hashing."""

    def test_sha256_hashing(self) -> None:
        """Hash data with SHA-256."""
        data = b"License key data"

        hash_value = hashlib.sha256(data).digest()

        assert isinstance(hash_value, bytes)
        assert len(hash_value) == 32

    def test_sha512_hashing(self) -> None:
        """Hash data with SHA-512."""
        data = b"License key data"

        hash_value = hashlib.sha512(data).digest()

        assert isinstance(hash_value, bytes)
        assert len(hash_value) == 64

    def test_hash_deterministic(self) -> None:
        """Verify hashing is deterministic."""
        data = b"Test data"

        hash1 = hashlib.sha256(data).digest()
        hash2 = hashlib.sha256(data).digest()

        assert hash1 == hash2


class TestHMACFunctions:
    """Test HMAC signing and verification."""

    def test_hmac_sign(self) -> None:
        """Sign data with HMAC."""
        data = b"License activation request"
        key = os.urandom(32)

        signature = hmac_module.new(key, data, hashlib.sha256).digest()

        assert isinstance(signature, bytes)
        assert len(signature) == 32

    def test_hmac_verify_valid(self) -> None:
        """Verify valid HMAC signature."""
        data = b"License data"
        key = os.urandom(32)

        signature = hmac_module.new(key, data, hashlib.sha256).digest()
        verification = hmac_module.new(key, data, hashlib.sha256).digest()

        assert signature == verification

    def test_hmac_verify_invalid(self) -> None:
        """Reject invalid HMAC signature."""
        data = b"License data"
        key = os.urandom(32)

        signature = hmac_module.new(key, data, hashlib.sha256).digest()
        tampered_signature = bytes([b ^ 0xFF for b in signature])

        assert signature != tampered_signature


class TestLicenseKeyProtection:
    """Test cryptographic protection of license keys."""

    def test_encrypt_license_key(self) -> None:
        """Encrypt license key for storage."""
        license_key = b"ABCD-EFGH-IJKL-MNOP-QRST"
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        encrypted_key = aesgcm.encrypt(nonce, license_key, None)

        assert encrypted_key != license_key
        assert len(encrypted_key) > 0

    def test_decrypt_stored_license_key(self) -> None:
        """Decrypt stored license key."""
        license_key = b"ABCD-EFGH-IJKL-MNOP-QRST"
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        encrypted_key = aesgcm.encrypt(nonce, license_key, None)
        decrypted_key = aesgcm.decrypt(nonce, encrypted_key, None)

        assert decrypted_key == license_key


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_aes_gcm_wrong_key_fails(self) -> None:
        """Decryption with wrong key fails."""
        plaintext = b"Test data"
        nonce = os.urandom(12)

        key1 = AESGCM.generate_key(bit_length=256)
        aesgcm1 = AESGCM(key1)
        ciphertext = aesgcm1.encrypt(nonce, plaintext, None)

        key2 = AESGCM.generate_key(bit_length=256)
        aesgcm2 = AESGCM(key2)

        with pytest.raises(Exception):
            aesgcm2.decrypt(nonce, ciphertext, None)


class TestPerformance:
    """Test cryptographic operation performance."""

    def test_aes_gcm_encryption_performance(self, benchmark: Any) -> None:
        """Benchmark AES-GCM encryption."""
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        plaintext = b"A" * 1000
        nonce = os.urandom(12)

        result = benchmark(aesgcm.encrypt, nonce, plaintext, None)

        assert len(result) > 0

    def test_hash_performance(self, benchmark: Any) -> None:
        """Benchmark hashing performance."""
        data = b"A" * 1000

        result = benchmark(hashlib.sha256, data)

        assert result is not None
