"""
Unit tests for Crypto Utils with REAL cryptographic operations.
Tests REAL encryption, decryption, hashing, and key operations.
NO MOCKS - ALL TESTS USE REAL CRYPTO AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path
import os

from intellicrack.utils.crypto_utils import CryptoUtils
from tests.base_test import IntellicrackTestBase


class TestCryptoUtils(IntellicrackTestBase):
    """Test cryptographic utilities with REAL operations."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real crypto utils."""
        self.crypto = CryptoUtils()
        self.test_data = b"This is test data for encryption!"
        self.test_key = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes for AES-256
        
    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption."""
        # Encrypt data
        encrypted = self.crypto.aes_encrypt(self.test_data, self.test_key)
        
        self.assert_real_output(encrypted)
        assert encrypted != self.test_data
        assert len(encrypted) > len(self.test_data)  # Includes IV
        
        # Decrypt data
        decrypted = self.crypto.aes_decrypt(encrypted, self.test_key)
        
        assert decrypted == self.test_data
        
    def test_aes_modes(self):
        """Test different AES modes."""
        modes = ['CBC', 'ECB', 'CFB', 'OFB', 'CTR']
        
        for mode in modes:
            encrypted = self.crypto.aes_encrypt(
                self.test_data,
                self.test_key,
                mode=mode
            )
            
            self.assert_real_output(encrypted)
            
            decrypted = self.crypto.aes_decrypt(
                encrypted,
                self.test_key,
                mode=mode
            )
            
            assert decrypted == self.test_data
            
    def test_rsa_key_generation(self):
        """Test RSA key pair generation."""
        # Generate key pair
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        
        self.assert_real_output(private_key)
        self.assert_real_output(public_key)
        
        # Validate keys
        assert b'BEGIN RSA PRIVATE KEY' in private_key
        assert b'BEGIN PUBLIC KEY' in public_key
        
        # Test encryption/decryption
        encrypted = self.crypto.rsa_encrypt(self.test_data, public_key)
        decrypted = self.crypto.rsa_decrypt(encrypted, private_key)
        
        assert decrypted == self.test_data
        
    def test_hash_functions(self):
        """Test various hash functions."""
        hash_funcs = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']
        
        for func in hash_funcs:
            hash_value = self.crypto.hash_data(self.test_data, algorithm=func)
            
            self.assert_real_output(hash_value)
            
            # Validate hash properties
            if func == 'md5':
                assert len(hash_value) == 32  # 128 bits in hex
            elif func == 'sha1':
                assert len(hash_value) == 40  # 160 bits in hex
            elif func == 'sha256':
                assert len(hash_value) == 64  # 256 bits in hex
            elif func == 'sha512':
                assert len(hash_value) == 128  # 512 bits in hex
                
    def test_hmac_generation(self):
        """Test HMAC generation and verification."""
        # Generate HMAC
        hmac_value = self.crypto.generate_hmac(
            self.test_data,
            self.test_key,
            algorithm='sha256'
        )
        
        self.assert_real_output(hmac_value)
        assert len(hmac_value) == 64  # SHA256 HMAC
        
        # Verify HMAC
        is_valid = self.crypto.verify_hmac(
            self.test_data,
            hmac_value,
            self.test_key,
            algorithm='sha256'
        )
        
        assert is_valid == True
        
        # Test tampering detection
        tampered_data = self.test_data + b"tampered"
        is_valid = self.crypto.verify_hmac(
            tampered_data,
            hmac_value,
            self.test_key,
            algorithm='sha256'
        )
        
        assert is_valid == False
        
    def test_key_derivation(self):
        """Test key derivation functions."""
        password = b"MySecretPassword123!"
        salt = os.urandom(16)
        
        # PBKDF2
        key1 = self.crypto.derive_key_pbkdf2(
            password,
            salt,
            iterations=100000,
            key_length=32
        )
        
        self.assert_real_output(key1)
        assert len(key1) == 32
        
        # Same password and salt should produce same key
        key2 = self.crypto.derive_key_pbkdf2(
            password,
            salt,
            iterations=100000,
            key_length=32
        )
        
        assert key1 == key2
        
        # Different salt should produce different key
        key3 = self.crypto.derive_key_pbkdf2(
            password,
            os.urandom(16),
            iterations=100000,
            key_length=32
        )
        
        assert key1 != key3
        
    def test_digital_signatures(self):
        """Test digital signature creation and verification."""
        # Generate key pair
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        
        # Sign data
        signature = self.crypto.sign_data(self.test_data, private_key)
        
        self.assert_real_output(signature)
        assert len(signature) > 0
        
        # Verify signature
        is_valid = self.crypto.verify_signature(
            self.test_data,
            signature,
            public_key
        )
        
        assert is_valid == True
        
        # Test tampering
        tampered_data = self.test_data + b"tampered"
        is_valid = self.crypto.verify_signature(
            tampered_data,
            signature,
            public_key
        )
        
        assert is_valid == False
        
    def test_elliptic_curve_crypto(self):
        """Test elliptic curve cryptography."""
        # Generate EC key pair
        private_key, public_key = self.crypto.generate_ec_keypair('secp256r1')
        
        self.assert_real_output(private_key)
        self.assert_real_output(public_key)
        
        # ECDSA signature
        signature = self.crypto.ec_sign(self.test_data, private_key)
        is_valid = self.crypto.ec_verify(self.test_data, signature, public_key)
        
        assert is_valid == True
        
    def test_stream_cipher(self):
        """Test stream cipher operations."""
        # ChaCha20
        key = os.urandom(32)
        nonce = os.urandom(12)
        
        encrypted = self.crypto.chacha20_encrypt(
            self.test_data,
            key,
            nonce
        )
        
        self.assert_real_output(encrypted)
        assert encrypted != self.test_data
        
        # Decrypt
        decrypted = self.crypto.chacha20_decrypt(
            encrypted,
            key,
            nonce
        )
        
        assert decrypted == self.test_data
        
    def test_password_hashing(self):
        """Test secure password hashing."""
        password = "MySecurePassword123!"
        
        # Hash password (bcrypt)
        hashed = self.crypto.hash_password(password)
        
        self.assert_real_output(hashed)
        assert hashed != password
        assert len(hashed) > 50  # bcrypt produces long hashes
        
        # Verify password
        is_valid = self.crypto.verify_password(password, hashed)
        assert is_valid == True
        
        # Wrong password
        is_valid = self.crypto.verify_password("WrongPassword", hashed)
        assert is_valid == False
        
    def test_random_generation(self):
        """Test cryptographically secure random generation."""
        # Random bytes
        random_bytes = self.crypto.generate_random_bytes(32)
        
        self.assert_real_output(random_bytes)
        assert len(random_bytes) == 32
        
        # Should be different each time
        random_bytes2 = self.crypto.generate_random_bytes(32)
        assert random_bytes != random_bytes2
        
        # Random key
        random_key = self.crypto.generate_random_key(256)
        assert len(random_key) == 32  # 256 bits = 32 bytes
        
    def test_base64_encoding(self):
        """Test base64 encoding/decoding."""
        # Standard base64
        encoded = self.crypto.base64_encode(self.test_data)
        
        self.assert_real_output(encoded)
        assert isinstance(encoded, str)
        
        decoded = self.crypto.base64_decode(encoded)
        assert decoded == self.test_data
        
        # URL-safe base64
        url_encoded = self.crypto.base64_url_encode(self.test_data)
        assert '+' not in url_encoded
        assert '/' not in url_encoded
        
    def test_hex_encoding(self):
        """Test hex encoding/decoding."""
        # Encode to hex
        hex_data = self.crypto.to_hex(self.test_data)
        
        self.assert_real_output(hex_data)
        assert all(c in '0123456789abcdef' for c in hex_data)
        
        # Decode from hex
        decoded = self.crypto.from_hex(hex_data)
        assert decoded == self.test_data
        
    def test_key_wrapping(self):
        """Test key wrapping/unwrapping."""
        # Generate KEK (Key Encryption Key)
        kek = self.crypto.generate_random_key(256)
        
        # Generate key to wrap
        key_to_wrap = self.crypto.generate_random_key(256)
        
        # Wrap key
        wrapped = self.crypto.wrap_key(key_to_wrap, kek)
        
        self.assert_real_output(wrapped)
        assert wrapped != key_to_wrap
        assert len(wrapped) > len(key_to_wrap)
        
        # Unwrap key
        unwrapped = self.crypto.unwrap_key(wrapped, kek)
        assert unwrapped == key_to_wrap
        
    def test_file_encryption(self):
        """Test file encryption/decryption."""
        # Create test file
        test_file = Path("test_file.txt")
        test_file.write_bytes(b"Secret file contents")
        
        try:
            # Encrypt file
            encrypted_file = Path("test_file.enc")
            self.crypto.encrypt_file(
                test_file,
                encrypted_file,
                self.test_key
            )
            
            assert encrypted_file.exists()
            assert encrypted_file.read_bytes() != test_file.read_bytes()
            
            # Decrypt file
            decrypted_file = Path("test_file_dec.txt")
            self.crypto.decrypt_file(
                encrypted_file,
                decrypted_file,
                self.test_key
            )
            
            assert decrypted_file.read_bytes() == test_file.read_bytes()
            
        finally:
            # Cleanup
            for f in [test_file, encrypted_file, decrypted_file]:
                if f.exists():
                    f.unlink()
                    
    def test_certificate_operations(self):
        """Test X.509 certificate operations."""
        # Generate self-signed certificate
        cert, private_key = self.crypto.generate_self_signed_cert(
            common_name="test.example.com",
            days=365
        )
        
        self.assert_real_output(cert)
        assert b'BEGIN CERTIFICATE' in cert
        
        # Parse certificate
        cert_info = self.crypto.parse_certificate(cert)
        assert cert_info['subject']['CN'] == 'test.example.com'
        assert cert_info['issuer']['CN'] == 'test.example.com'  # Self-signed
        
    def test_key_exchange(self):
        """Test Diffie-Hellman key exchange."""
        # Generate DH parameters
        params = self.crypto.generate_dh_parameters()
        
        # Alice generates key pair
        alice_private, alice_public = self.crypto.generate_dh_keypair(params)
        
        # Bob generates key pair
        bob_private, bob_public = self.crypto.generate_dh_keypair(params)
        
        # Exchange and derive shared secret
        alice_shared = self.crypto.derive_dh_shared_secret(
            alice_private,
            bob_public,
            params
        )
        
        bob_shared = self.crypto.derive_dh_shared_secret(
            bob_private,
            alice_public,
            params
        )
        
        self.assert_real_output(alice_shared)
        assert alice_shared == bob_shared  # Same shared secret
        
    def test_timing_safe_comparison(self):
        """Test timing-safe comparison."""
        data1 = b"secret_value_123"
        data2 = b"secret_value_123"
        data3 = b"different_value"
        
        # Same data
        result = self.crypto.timing_safe_compare(data1, data2)
        assert result == True
        
        # Different data
        result = self.crypto.timing_safe_compare(data1, data3)
        assert result == False