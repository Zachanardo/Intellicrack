"""
Tests for real cryptographic operations in Intellicrack.

This module contains comprehensive tests for real cryptographic operations
including encryption, decryption, hashing, digital signatures, certificate
operations, key derivation functions, and secure random number generation.
The tests validate that the cryptographic components function properly
for security research and binary analysis tasks.
"""

import pytest
import tempfile
import os
import time
import base64
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from pathlib import Path
from intellicrack.handlers.cryptography_handler import (
    HAS_CRYPTOGRAPHY,
    x509,
    hashes,
    serialization,
    rsa,
    asym_padding as padding,
    Cipher,
    algorithms,
    modes,
    default_backend
)

if HAS_CRYPTOGRAPHY:
    from cryptography.x509.oid import NameOID
else:
    # Define fallback for NameOID when cryptography is not available
    class NameOID:  # type: ignore[no-redef]
        COUNTRY_NAME = None
        STATE_OR_PROVINCE_NAME = None
        LOCALITY_NAME = None
        ORGANIZATION_NAME = None
        COMMON_NAME = None

from typing import Any, Generator

from intellicrack.utils.secrets_manager import SecretsManager
from intellicrack.utils.binary.certificate_extractor import CertificateExtractor
from intellicrack.utils.protection.certificate_utils import CertificateUtils  # type: ignore[attr-defined]
from intellicrack.utils.core.siphash24_replacement import siphash24
from intellicrack.core.app_context import AppContext


class TestRealCryptoOperations:
    """Functional tests for REAL cryptographic operations."""

    @pytest.fixture
    def test_certificate_data(self) -> dict[str, Any]:
        """Create REAL X.509 certificate for testing."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Certificate details
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        # Generate certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("test.example.com"),
                x509.DNSName("*.example.com"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

        return {
            'certificate': cert,
            'private_key': private_key,
            'cert_pem': cert.public_bytes(serialization.Encoding.PEM),
            'key_pem': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        }

    @pytest.fixture
    def test_secrets_file(self) -> Generator[str, None, None]:
        """Create temporary secrets storage file."""
        temp_file = tempfile.NamedTemporaryFile(
            suffix='.secrets',
            delete=False,
            mode='w'
        )
        temp_file.close()
        yield temp_file.name
        try:
            os.unlink(temp_file.name)
        except Exception:
            pass

    @pytest.fixture
    def app_context(self) -> AppContext:
        """Create REAL application context."""
        context = AppContext()
        context.initialize()  # type: ignore[attr-defined]
        return context

    def test_real_secrets_management(self, test_secrets_file: str, app_context: AppContext) -> None:
        """Test REAL secrets storage and retrieval."""
        secrets_manager = SecretsManager(storage_path=test_secrets_file)  # type: ignore[call-arg]

        # Test various secret types
        test_secrets = {
            'api_key': 'sk-1234567890abcdef',
            'password': 'SuperSecret123!@#',
            'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature',
            'private_key': 'BEGIN RSA PRIVATE KEY...',
            'connection_string': 'mongodb://user:pass@host:27017/db'
        }

        # Store secrets
        for key, value in test_secrets.items():
            store_result = secrets_manager.store_secret(key, value)  # type: ignore[attr-defined]
            assert store_result is not None, f"Storing {key} must succeed"
            assert store_result['success'], f"Storing {key} must be successful"
            assert 'encrypted' in store_result, "Result must indicate encryption"
            assert store_result['encrypted'], "Secrets must be encrypted"

        # Retrieve secrets
        for key, expected_value in test_secrets.items():
            retrieved = secrets_manager.get_secret(key)  # type: ignore[attr-defined]
            assert retrieved is not None, f"Retrieving {key} must succeed"
            assert retrieved == expected_value, f"Retrieved {key} must match"

        # List all secrets
        all_secrets = secrets_manager.list_secrets()  # type: ignore[attr-defined]
        assert all_secrets is not None, "Listing secrets must succeed"
        assert len(all_secrets) == len(test_secrets), "All secrets must be listed"
        assert set(all_secrets) == set(test_secrets.keys()), "All keys must be present"

        # Update secret
        update_result = secrets_manager.update_secret(  # type: ignore[attr-defined]
            'api_key',
            'sk-updated-1234567890'
        )
        assert update_result['success'], "Update must succeed"

        updated_value = secrets_manager.get_secret('api_key')  # type: ignore[attr-defined]
        assert updated_value == 'sk-updated-1234567890', "Updated value must match"

        # Delete secret
        delete_result = secrets_manager.delete_secret('token')  # type: ignore[attr-defined]
        assert delete_result['success'], "Delete must succeed"

        deleted_value = secrets_manager.get_secret('token')  # type: ignore[attr-defined]
        assert deleted_value is None, "Deleted secret must not be retrievable"

        # Test secret rotation
        rotation_result = secrets_manager.rotate_secret(  # type: ignore[attr-defined]
            'password',
            'NewSuperSecret456!@#'
        )
        assert rotation_result is not None, "Rotation must succeed"
        assert 'old_value_backup' in rotation_result, "Must backup old value"
        assert rotation_result['success'], "Rotation must be successful"

    def test_real_certificate_operations(
        self, test_certificate_data: dict[str, Any], app_context: AppContext
    ) -> None:
        """Test REAL certificate extraction and validation."""
        cert_extractor = CertificateExtractor()
        cert_utils = CertificateUtils()

        # Extract certificate info
        cert_info = cert_extractor.extract_certificate_info(  # type: ignore[attr-defined]
            test_certificate_data['cert_pem']
        )
        assert cert_info is not None, "Certificate extraction must succeed"
        assert 'subject' in cert_info, "Must extract subject"
        assert 'issuer' in cert_info, "Must extract issuer"
        assert 'serial_number' in cert_info, "Must extract serial number"
        assert 'not_before' in cert_info, "Must extract validity start"
        assert 'not_after' in cert_info, "Must extract validity end"
        assert 'signature_algorithm' in cert_info, "Must extract signature algorithm"

        # Verify certificate details
        assert cert_info['subject']['CN'] == 'test.example.com', "CN must match"
        assert cert_info['subject']['O'] == 'Test Corp', "Organization must match"

        # Validate certificate
        validation_result = cert_utils.validate_certificate(
            test_certificate_data['cert_pem']
        )
        assert validation_result is not None, "Validation must succeed"
        assert 'valid' in validation_result, "Must indicate validity"
        assert 'checks' in validation_result, "Must include validation checks"

        # Check specific validations
        checks = validation_result['checks']
        assert 'date_valid' in checks, "Must check date validity"
        assert 'signature_valid' in checks, "Must check signature"
        assert 'key_usage' in checks, "Must check key usage"

        # Extract public key
        pubkey_result = cert_extractor.extract_public_key(  # type: ignore[attr-defined]
            test_certificate_data['cert_pem']
        )
        assert pubkey_result is not None, "Public key extraction must succeed"
        assert 'key_type' in pubkey_result, "Must identify key type"
        assert 'key_size' in pubkey_result, "Must identify key size"
        assert pubkey_result['key_type'] == 'RSA', "Key type must be RSA"
        assert pubkey_result['key_size'] == 2048, "Key size must be 2048"

    def test_real_hash_operations(self, app_context: AppContext) -> None:
        """Test REAL hashing operations."""
        # Test data
        test_data = b"The quick brown fox jumps over the lazy dog"
        test_key = b"secret_key_123"

        # Test various hash algorithms
        hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha3_256': hashlib.sha3_256
        }

        hash_results: dict[str, str] = {}
        for algo_name, algo_func in hash_algorithms.items():
            if hasattr(hashlib, algo_name) or algo_name.startswith('sha3'):
                hasher = algo_func()
                hasher.update(test_data)
                hash_results[algo_name] = hasher.hexdigest()

        # Verify known hash values
        assert hash_results['md5'] == '9e107d9d372bb6826bd81d3542a419d6'
        assert hash_results['sha1'] == '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'
        assert hash_results['sha256'] == 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'

        # Test HMAC
        hmac_result = hmac.new(test_key, test_data, hashlib.sha256).hexdigest()
        assert len(hmac_result) == 64, "HMAC-SHA256 must be 64 hex chars"

        # Test incremental hashing
        incremental_hasher = hashlib.sha256()
        chunks = [test_data[i:i+10] for i in range(0, len(test_data), 10)]
        for chunk in chunks:
            incremental_hasher.update(chunk)

        incremental_result = incremental_hasher.hexdigest()
        assert incremental_result == hash_results['sha256'], \
            "Incremental hash must match single hash"

        # Test SipHash24
        siphash_key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        siphash_result: int | bytes = siphash24(siphash_key, test_data)
        assert siphash_result is not None, "SipHash24 must succeed"
        if isinstance(siphash_result, int):
            assert 0 <= siphash_result < 2**64, "SipHash24 must be 64-bit value"

    def test_real_encryption_operations(self, app_context: AppContext) -> None:
        """Test REAL encryption and decryption operations."""
        # Test symmetric encryption (AES)
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)   # 128-bit IV
        plaintext = b"Secret message that needs encryption!"

        # Pad plaintext to block size
        block_size = 16
        pad_length = block_size - (len(plaintext) % block_size)
        padded_plaintext = plaintext + bytes([pad_length]) * pad_length

        # Encrypt with AES-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        assert len(ciphertext) == len(padded_plaintext), "Ciphertext size must match padded plaintext"
        assert ciphertext != plaintext, "Ciphertext must differ from plaintext"

        # Decrypt
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        pad_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-pad_length]

        assert decrypted == plaintext, "Decrypted text must match original"

        # Test AES-GCM (authenticated encryption)
        gcm_key = os.urandom(32)
        gcm_nonce = os.urandom(12)

        gcm_cipher = Cipher(
            algorithms.AES(gcm_key),
            modes.GCM(gcm_nonce),
            backend=default_backend()
        )
        gcm_encryptor = gcm_cipher.encryptor()
        gcm_ciphertext = gcm_encryptor.update(plaintext) + gcm_encryptor.finalize()
        gcm_tag = gcm_encryptor.tag

        assert len(gcm_tag) == 16, "GCM tag must be 128 bits"

        # Decrypt with authentication
        gcm_decryptor = Cipher(
            algorithms.AES(gcm_key),
            modes.GCM(gcm_nonce, gcm_tag),
            backend=default_backend()
        ).decryptor()

        gcm_decrypted = gcm_decryptor.update(gcm_ciphertext) + gcm_decryptor.finalize()
        assert gcm_decrypted == plaintext, "GCM decrypted text must match original"

    def test_real_key_derivation(self, app_context: AppContext) -> None:
        """Test REAL key derivation functions."""
        from cryptography.hazmat.primitives import kdf
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        password = b"user_password_123"
        salt = os.urandom(16)

        # PBKDF2
        pbkdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        pbkdf2_key = pbkdf2.derive(password)
        assert len(pbkdf2_key) == 32, "PBKDF2 key must be 32 bytes"

        # Verify same password produces same key
        pbkdf2_verify = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        pbkdf2_verify.verify(password, pbkdf2_key)  # Should not raise

        # Scrypt
        scrypt = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        scrypt_key = scrypt.derive(password)
        assert len(scrypt_key) == 32, "Scrypt key must be 32 bytes"
        assert scrypt_key != pbkdf2_key, "Different KDFs must produce different keys"

    def test_real_digital_signatures(
        self, test_certificate_data: dict[str, Any], app_context: AppContext
    ) -> None:
        """Test REAL digital signature operations."""
        private_key = test_certificate_data['private_key']
        public_key = private_key.public_key()

        message = b"Important message to sign"

        # Sign message
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        assert signature is not None, "Signature must be created"
        assert len(signature) == 256, "RSA-2048 signature must be 256 bytes"

        # Verify signature
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid, "Signature must be valid"

        # Test invalid signature
        tampered_message = b"Tampered message"
        try:
            public_key.verify(
                signature,
                tampered_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            tampered_valid = True
        except Exception:
            tampered_valid = False

        assert not tampered_valid, "Tampered message must not verify"

    def test_real_secure_random_generation(self, app_context: AppContext) -> None:
        """Test REAL secure random number generation."""
        # Generate various random data
        random_bytes = os.urandom(32)
        assert len(random_bytes) == 32, "Random bytes must be correct length"

        # Verify randomness (basic statistical test)
        byte_counts: dict[int, int] = {}
        for byte in random_bytes:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        # No byte should appear too frequently in 32 bytes
        max_count = max(byte_counts.values())
        assert max_count <= 4, "Random bytes should have good distribution"

        # Generate random integers
        random_ints = []
        for _ in range(100):
            # Random 32-bit integer
            rand_int = int.from_bytes(os.urandom(4), byteorder='big')
            random_ints.append(rand_int)

        # Check uniqueness (should be mostly unique)
        unique_count = len(set(random_ints))
        assert unique_count >= 95, "Random integers should be mostly unique"

        # Generate secure tokens
        tokens = []
        for _ in range(10):
            token = base64.urlsafe_b64encode(os.urandom(24)).decode('ascii')
            tokens.append(token)
            assert len(token) == 32, "Token must be 32 chars (base64 of 24 bytes)"

        # All tokens should be unique
        assert len(set(tokens)) == 10, "All tokens must be unique"

    def test_real_password_hashing(self, app_context: AppContext) -> None:
        """Test REAL password hashing and verification."""
        secrets_manager = SecretsManager()

        passwords = [
            "simple123",
            "Complex!Pass123",
            "超級密碼123",  # Unicode password
            "a" * 100,  # Long password
            ""  # Empty password
        ]

        hashed_passwords: dict[str, Any] = {}

        # Hash passwords
        for password in passwords:
            hash_result = secrets_manager.hash_password(password)  # type: ignore[attr-defined]
            assert hash_result is not None, f"Hashing '{password}' must succeed"
            assert 'hash' in hash_result, "Result must contain hash"
            assert 'salt' in hash_result, "Result must contain salt"
            assert 'algorithm' in hash_result, "Result must specify algorithm"

            hashed_passwords[password] = hash_result

            # Verify hash format
            hash_value = hash_result['hash']
            assert len(hash_value) > 0, "Hash must not be empty"
            assert hash_value != password, "Hash must differ from plaintext"

        # Verify passwords
        for password, hash_info in hashed_passwords.items():
            verify_result = secrets_manager.verify_password(  # type: ignore[attr-defined]
                password,
                hash_info['hash'],
                hash_info['salt']
            )
            assert verify_result is not None, f"Verification of '{password}' must succeed"
            assert verify_result['valid'], f"Password '{password}' must verify correctly"

        # Test wrong passwords
        for password, hash_info in hashed_passwords.items():
            wrong_password = f"{password}_wrong"
            verify_result = secrets_manager.verify_password(  # type: ignore[attr-defined]
                wrong_password,
                hash_info['hash'],
                hash_info['salt']
            )
            assert not verify_result['valid'], "Wrong password must not verify"

        # Test hash uniqueness
        hash1 = secrets_manager.hash_password("test123")  # type: ignore[attr-defined]
        hash2 = secrets_manager.hash_password("test123")  # type: ignore[attr-defined]
        assert hash1['hash'] != hash2['hash'], "Same password must produce different hashes"
        assert hash1['salt'] != hash2['salt'], "Each hash must have unique salt"

    def test_real_certificate_chain_validation(self, app_context: AppContext) -> None:
        """Test REAL certificate chain validation."""
        cert_utils = CertificateUtils()

        # Create certificate chain (root -> intermediate -> leaf)
        # Root CA
        root_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        root_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Org")
        ])
        root_cert = x509.CertificateBuilder().subject_name(
            root_name
        ).issuer_name(
            root_name
        ).public_key(
            root_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(root_key, hashes.SHA256(), default_backend())

        # Intermediate CA
        intermediate_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        intermediate_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Org")
        ])
        intermediate_cert = x509.CertificateBuilder().subject_name(
            intermediate_name
        ).issuer_name(
            root_name
        ).public_key(
            intermediate_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=1825)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        ).sign(root_key, hashes.SHA256(), default_backend())

        # Validate chain
        chain_result = cert_utils.validate_certificate_chain([
            root_cert.public_bytes(serialization.Encoding.PEM),
            intermediate_cert.public_bytes(serialization.Encoding.PEM)
        ])

        assert chain_result is not None, "Chain validation must succeed"
        assert 'valid' in chain_result, "Must indicate chain validity"
        assert 'chain_length' in chain_result, "Must report chain length"
        assert chain_result['chain_length'] == 2, "Chain length must be 2"
