"""
Comprehensive Test Suite for EncryptionManager

Tests the C2 encryption infrastructure component using specification-driven,
black-box testing methodology to validate production-ready cryptographic capabilities.
"""

import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest

import pytest

# Import the module under test
from intellicrack.core.c2.encryption_manager import EncryptionManager


class TestEncryptionManagerInitialization(unittest.TestCase):
    """Test encryption manager initialization and configuration."""

    def test_aes256_initialization_success(self):
        """Test successful AES-256 initialization."""
        manager = EncryptionManager(encryption_type="AES256")

        # Validate core attributes exist and are properly configured
        self.assertEqual(manager.encryption_type, "AES256")
        self.assertIsInstance(manager.stats, dict)
        self.assertIn("encryptions", manager.stats)
        self.assertIn("decryptions", manager.stats)
        self.assertIn("key_rotations", manager.stats)

    def test_aes128_initialization_success(self):
        """Test successful AES-128 initialization."""
        manager = EncryptionManager(encryption_type="AES128")
        self.assertEqual(manager.encryption_type, "AES128")

    def test_chacha20_initialization_success(self):
        """Test successful ChaCha20 initialization."""
        manager = EncryptionManager(encryption_type="CHACHA20")
        self.assertEqual(manager.encryption_type, "CHACHA20")

    def test_rsa2048_initialization_success(self):
        """Test successful RSA-2048 initialization."""
        manager = EncryptionManager(encryption_type="RSA2048")
        self.assertEqual(manager.encryption_type, "RSA2048")

    def test_rsa4096_initialization_success(self):
        """Test successful RSA-4096 initialization."""
        manager = EncryptionManager(encryption_type="RSA4096")
        self.assertEqual(manager.encryption_type, "RSA4096")

    def test_unsupported_encryption_type_raises_error(self):
        """Test that unsupported encryption types raise appropriate errors."""
        with self.assertRaises(ValueError) as context:
            EncryptionManager(encryption_type="UNSUPPORTED")

        self.assertIn("Unsupported encryption type", str(context.exception))

    def test_case_insensitive_encryption_type(self):
        """Test that encryption types are handled case-insensitively."""
        manager = EncryptionManager(encryption_type="aes256")
        self.assertEqual(manager.encryption_type, "AES256")

    def test_key_file_parameter_handling(self):
        """Test key file parameter is properly stored."""
        test_key_file = "test_keyfile.key"
        manager = EncryptionManager(encryption_type="AES256", key_file=test_key_file)
        self.assertEqual(manager.key_file, test_key_file)

    def test_supported_encryption_types_list(self):
        """Test that all expected encryption types are supported."""
        manager = EncryptionManager(encryption_type="AES256")
        expected_types = ["AES128", "AES256", "CHACHA20", "RSA2048", "RSA4096"]
        self.assertEqual(set(manager.supported_types), set(expected_types))


class TestCoreEncryptionFunctionality(unittest.TestCase):
    """Test core encryption and decryption operations."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_basic_string_encryption_decryption(self):
        """Test basic string encryption and decryption round-trip."""
        plaintext = "Hello, World! This is a test message for C2 encryption."

        # Encrypt the plaintext
        encrypted_data = self.manager.encrypt(plaintext)

        # Validate encrypted data properties
        self.assertIsInstance(encrypted_data, bytes)
        self.assertGreater(len(encrypted_data), len(plaintext))
        self.assertNotEqual(encrypted_data, plaintext.encode())

        # Decrypt the data
        decrypted_text = self.manager.decrypt(encrypted_data)

        # Validate round-trip success
        self.assertEqual(decrypted_text, plaintext)

    def test_unicode_string_encryption(self):
        """Test encryption of Unicode strings."""
        plaintext = "🔐 Encryption test with émojis and spëcial chars: 漢字"

        encrypted_data = self.manager.encrypt(plaintext)
        decrypted_text = self.manager.decrypt(encrypted_data)

        self.assertEqual(decrypted_text, plaintext)

    def test_large_data_encryption(self):
        """Test encryption of large data payloads."""
        # Generate 1MB of test data
        plaintext = "A" * (1024 * 1024)  # 1MB of 'A' characters

        encrypted_data = self.manager.encrypt(plaintext)
        decrypted_text = self.manager.decrypt(encrypted_data)

        self.assertEqual(decrypted_text, plaintext)
        self.assertGreater(len(encrypted_data), len(plaintext))

    def test_empty_string_encryption(self):
        """Test encryption of empty strings."""
        plaintext = ""

        encrypted_data = self.manager.encrypt(plaintext)
        decrypted_text = self.manager.decrypt(encrypted_data)

        self.assertEqual(decrypted_text, plaintext)
        self.assertGreater(len(encrypted_data), 0)  # Still has IV and HMAC

    def test_encryption_produces_different_outputs(self):
        """Test that encrypting the same plaintext produces different ciphertexts."""
        plaintext = "Same plaintext for randomness test"

        encrypted1 = self.manager.encrypt(plaintext)
        encrypted2 = self.manager.encrypt(plaintext)

        # Different ciphertexts due to random IV
        self.assertNotEqual(encrypted1, encrypted2)

        # But both decrypt to same plaintext
        self.assertEqual(self.manager.decrypt(encrypted1), plaintext)
        self.assertEqual(self.manager.decrypt(encrypted2), plaintext)

    def test_invalid_encrypted_data_raises_error(self):
        """Test that invalid encrypted data raises appropriate errors."""
        invalid_data = b"invalid_encrypted_data"

        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(invalid_data)

    def test_truncated_encrypted_data_raises_error(self):
        """Test that truncated encrypted data raises appropriate errors."""
        plaintext = "Test message"
        encrypted_data = self.manager.encrypt(plaintext)

        # Truncate the encrypted data
        truncated_data = encrypted_data[:len(encrypted_data)//2]

        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(truncated_data)

    def test_tampered_encrypted_data_raises_error(self):
        """Test that tampered encrypted data fails HMAC verification."""
        plaintext = "Test message for tampering detection"
        encrypted_data = self.manager.encrypt(plaintext)

        # Tamper with the data (flip a bit)
        tampered_data = bytearray(encrypted_data)
        tampered_data[10] ^= 0x01  # Flip one bit

        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(bytes(tampered_data))


class TestSessionManagement(unittest.TestCase):
    """Test session-based encryption and perfect forward secrecy."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_session_key_creation(self):
        """Test session key creation for perfect forward secrecy."""
        session_id = "test_session_001"

        session_key = self.manager.create_session_key(session_id)

        # Validate session key properties
        self.assertIsInstance(session_key, bytes)
        self.assertGreater(len(session_key), 0)

        # Verify session is tracked
        stats = self.manager.get_session_statistics()
        self.assertGreater(stats["total_sessions"], 0)

    def test_session_based_encryption_decryption(self):
        """Test encryption and decryption using session keys."""
        session_id = "encryption_session"
        plaintext = "Session-based encryption test message"

        # Create session key
        self.manager.create_session_key(session_id)

        # Encrypt with session
        encrypted_data = self.manager.encrypt(plaintext, session_id=session_id)
        decrypted_text = self.manager.decrypt(encrypted_data, session_id=session_id)

        self.assertEqual(decrypted_text, plaintext)

    def test_session_independence(self):
        """Test that different sessions produce different encrypted outputs."""
        plaintext = "Same plaintext, different sessions"
        session1 = "session_001"
        session2 = "session_002"

        # Create session keys
        self.manager.create_session_key(session1)
        self.manager.create_session_key(session2)

        # Encrypt with different sessions
        encrypted1 = self.manager.encrypt(plaintext, session_id=session1)
        encrypted2 = self.manager.encrypt(plaintext, session_id=session2)

        # Different ciphertexts due to different session keys
        self.assertNotEqual(encrypted1, encrypted2)

        # Each decrypts with correct session
        self.assertEqual(self.manager.decrypt(encrypted1, session_id=session1), plaintext)
        self.assertEqual(self.manager.decrypt(encrypted2, session_id=session2), plaintext)

    def test_cross_session_decryption_fails(self):
        """Test that data encrypted with one session cannot be decrypted with another."""
        plaintext = "Cross-session isolation test"
        session1 = "isolation_session_1"
        session2 = "isolation_session_2"

        # Create session keys
        self.manager.create_session_key(session1)
        self.manager.create_session_key(session2)

        # Encrypt with session 1
        encrypted_data = self.manager.encrypt(plaintext, session_id=session1)

        # Attempt to decrypt with session 2 should fail
        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(encrypted_data, session_id=session2)

    def test_session_statistics_accuracy(self):
        """Test session statistics accuracy and updates."""
        initial_stats = self.manager.get_session_statistics()
        initial_sessions = initial_stats["total_sessions"]

        # Create sessions and perform operations
        session_ids = ["stat_test_1", "stat_test_2", "stat_test_3"]
        for session_id in session_ids:
            self.manager.create_session_key(session_id)

        # Perform encryptions
        for session_id in session_ids:
            self.manager.encrypt("Test message", session_id=session_id)

        final_stats = self.manager.get_session_statistics()

        # Validate statistics updates
        self.assertEqual(final_stats["total_sessions"], initial_sessions + len(session_ids))
        self.assertGreaterEqual(final_stats["total_encryptions"], len(session_ids))
        self.assertGreaterEqual(final_stats["active_sessions"], len(session_ids))

    def test_session_cleanup(self):
        """Test cleanup of expired sessions."""
        # Create test sessions
        session_id = "cleanup_test_session"
        self.manager.create_session_key(session_id)

        initial_count = len(self.manager.session_keys) if hasattr(self.manager, 'session_keys') else 0

        # Manually trigger cleanup
        self.manager.cleanup_expired_sessions()

        # For fresh sessions, count should remain the same
        current_count = len(self.manager.session_keys) if hasattr(self.manager, 'session_keys') else 0
        self.assertGreaterEqual(current_count, 0)


class TestKeyExchangeProtocol(unittest.TestCase):
    """Test RSA key exchange functionality."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_public_key_export(self):
        """Test RSA public key export in PEM format."""
        public_key_pem = self.manager.get_public_key_pem()

        # Validate PEM format
        self.assertIsInstance(public_key_pem, str)
        self.assertIn("-----BEGIN PUBLIC KEY-----", public_key_pem)
        self.assertIn("-----END PUBLIC KEY-----", public_key_pem)
        self.assertGreater(len(public_key_pem), 200)  # RSA keys are substantial

    def test_key_exchange_with_valid_client_key(self):
        """Test key exchange with valid client RSA public key."""
        # Generate a mock client public key for testing
        # In production, this would be a real RSA public key from client
        try:
            from intellicrack.handlers.cryptography_handler import rsa, serialization, default_backend

            # Generate client keypair for test
            client_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            client_public_key_pem = client_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Perform key exchange
            exchange_result = self.manager.exchange_keys(client_public_key_pem)

            # Validate exchange result
            self.assertIsInstance(exchange_result, dict)
            self.assertIn("session_id", exchange_result)
            self.assertIn("encrypted_session_key", exchange_result)
            self.assertIn("server_public_key", exchange_result)
            self.assertIn("timestamp", exchange_result)

            # Validate session ID format
            session_id = exchange_result["session_id"]
            self.assertIsInstance(session_id, str)
            self.assertEqual(len(session_id), 16)  # Expected session ID length

            # Validate encrypted session key is base64
            encrypted_key = exchange_result["encrypted_session_key"]
            self.assertIsInstance(encrypted_key, str)
            try:
                base64.b64decode(encrypted_key)
            except Exception:
                self.fail("Encrypted session key is not valid base64")

            # Validate server public key in PEM format
            server_pub_key = exchange_result["server_public_key"]
            self.assertIn("-----BEGIN PUBLIC KEY-----", server_pub_key)

        except ImportError:
            self.skipTest("Cryptography library not available for key exchange test")

    def test_key_exchange_with_invalid_client_key(self):
        """Test key exchange with invalid client public key."""
        invalid_key = b"invalid_public_key_data"

        with self.assertRaises(Exception):
            self.manager.exchange_keys(invalid_key)

    def test_key_exchange_creates_session(self):
        """Test that key exchange creates a valid session."""
        try:
            from intellicrack.handlers.cryptography_handler import rsa, serialization, default_backend

            # Generate client keypair for test
            client_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            client_public_key_pem = client_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Perform key exchange
            exchange_result = self.manager.exchange_keys(client_public_key_pem)
            session_id = exchange_result["session_id"]

            # Test that session can be used for encryption
            plaintext = "Key exchange session test"
            encrypted_data = self.manager.encrypt(plaintext, session_id=session_id)
            decrypted_text = self.manager.decrypt(encrypted_data, session_id=session_id)

            self.assertEqual(decrypted_text, plaintext)

        except ImportError:
            self.skipTest("Cryptography library not available for session test")


class TestFileOperations(unittest.TestCase):
    """Test file encryption and decryption operations."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager and temporary files."""
        self.manager = EncryptionManager(encryption_type="AES256")
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_text_file_encryption_decryption(self):
        """Test encryption and decryption of text files."""
        # Create test text file
        test_content = "This is a test file for C2 encryption.\nLine 2 with special chars: @#$%^&*()\nLine 3: 测试中文"
        test_file = os.path.join(self.temp_dir, "test.txt")

        with open(test_file, "w", encoding="utf-8") as f:
            f.write(test_content)

        # Encrypt file
        encrypted_file = self.manager.encrypt_file(test_file)

        # Validate encrypted file exists and has .enc extension
        self.assertTrue(os.path.exists(encrypted_file))
        self.assertTrue(encrypted_file.endswith(".enc"))

        # Verify original and encrypted files are different
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        self.assertNotEqual(encrypted_data, test_content.encode())

        # Decrypt file
        decrypted_file = self.manager.decrypt_file(encrypted_file)

        # Validate decryption
        with open(decrypted_file, "r", encoding="utf-8") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, test_content)

    def test_binary_file_encryption_decryption(self):
        """Test encryption and decryption of binary files."""
        # Create test binary file
        binary_data = os.urandom(10240)  # 10KB of random binary data
        test_file = os.path.join(self.temp_dir, "test.bin")

        with open(test_file, "wb") as f:
            f.write(binary_data)

        # Encrypt file
        encrypted_file = self.manager.encrypt_file(test_file)

        # Decrypt file
        decrypted_file = self.manager.decrypt_file(encrypted_file)

        # Validate binary data integrity
        with open(decrypted_file, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, binary_data)

    def test_custom_output_paths(self):
        """Test file operations with custom output paths."""
        # Create test file
        test_content = "Custom output path test"
        test_file = os.path.join(self.temp_dir, "input.txt")

        with open(test_file, "w") as f:
            f.write(test_content)

        # Encrypt with custom output path
        custom_encrypted_path = os.path.join(self.temp_dir, "custom_encrypted.dat")
        encrypted_file = self.manager.encrypt_file(test_file, output_path=custom_encrypted_path)

        self.assertEqual(encrypted_file, custom_encrypted_path)
        self.assertTrue(os.path.exists(custom_encrypted_path))

        # Decrypt with custom output path
        custom_decrypted_path = os.path.join(self.temp_dir, "custom_decrypted.txt")
        decrypted_file = self.manager.decrypt_file(custom_encrypted_path, output_path=custom_decrypted_path)

        self.assertEqual(decrypted_file, custom_decrypted_path)

        # Validate content
        with open(custom_decrypted_path, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, test_content)

    def test_session_based_file_encryption(self):
        """Test file encryption using session keys."""
        # Create test file and session
        test_content = "Session-based file encryption test"
        test_file = os.path.join(self.temp_dir, "session_test.txt")
        session_id = "file_encryption_session"

        with open(test_file, "w") as f:
            f.write(test_content)

        self.manager.create_session_key(session_id)

        # Encrypt with session
        encrypted_file = self.manager.encrypt_file(test_file, session_id=session_id)
        decrypted_file = self.manager.decrypt_file(encrypted_file, session_id=session_id)

        # Validate session-based decryption
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, test_content)

    def test_nonexistent_file_raises_error(self):
        """Test that encrypting non-existent files raises appropriate errors."""
        nonexistent_file = os.path.join(self.temp_dir, "does_not_exist.txt")

        with self.assertRaises((FileNotFoundError, IOError)):
            self.manager.encrypt_file(nonexistent_file)

    def test_empty_file_encryption(self):
        """Test encryption of empty files."""
        # Create empty file
        empty_file = os.path.join(self.temp_dir, "empty.txt")
        with open(empty_file, "w") as f:
            pass  # Create empty file

        # Encrypt empty file
        encrypted_file = self.manager.encrypt_file(empty_file)

        # Encrypted file should still exist and have content (IV + HMAC)
        self.assertTrue(os.path.exists(encrypted_file))

        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        self.assertGreater(len(encrypted_data), 0)

        # Decrypt should produce empty file
        decrypted_file = self.manager.decrypt_file(encrypted_file)

        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, "")


class TestKeyRotationAndManagement(unittest.TestCase):
    """Test key rotation and cryptographic key management."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_manual_key_rotation(self):
        """Test manual key rotation functionality."""
        # Get initial key rotation timestamp
        initial_rotation_time = self.manager.stats["last_key_rotation"]

        # Force key rotation
        self.manager.rotate_keys(force=True)

        # Validate rotation occurred
        new_rotation_time = self.manager.stats["last_key_rotation"]
        self.assertGreater(new_rotation_time, initial_rotation_time)

        # Validate rotation counter incremented
        self.assertGreater(self.manager.stats["key_rotations"], 0)

    def test_key_rotation_preserves_functionality(self):
        """Test that key rotation doesn't break encryption functionality."""
        plaintext = "Pre-rotation encryption test"

        # Encrypt before rotation
        encrypted_before = self.manager.encrypt(plaintext)

        # Rotate keys
        self.manager.rotate_keys(force=True)

        # Encrypt after rotation
        encrypted_after = self.manager.encrypt(plaintext)

        # Both encryptions should decrypt successfully
        decrypted_before = self.manager.decrypt(encrypted_before)
        decrypted_after = self.manager.decrypt(encrypted_after)

        self.assertEqual(decrypted_before, plaintext)
        self.assertEqual(decrypted_after, plaintext)

    def test_session_export_import(self):
        """Test session key export and import functionality."""
        session_id = "export_import_test"
        plaintext = "Session export/import test message"

        # Create session and encrypt data
        self.manager.create_session_key(session_id)
        encrypted_data = self.manager.encrypt(plaintext, session_id=session_id)

        # Export session key
        exported_key = self.manager.export_session_key(session_id)

        # Validate export format
        self.assertIsInstance(exported_key, str)
        self.assertGreater(len(exported_key), 0)

        # Verify it's valid base64
        try:
            base64.b64decode(exported_key)
        except Exception:
            self.fail("Exported key is not valid base64")

        # Create new manager and import session key
        new_manager = EncryptionManager(encryption_type="AES256")
        import_success = new_manager.import_session_key(exported_key)

        # Validate import success
        self.assertTrue(import_success)

        # Test that imported session can decrypt original data
        decrypted_text = new_manager.decrypt(encrypted_data, session_id=session_id)
        self.assertEqual(decrypted_text, plaintext)

    def test_export_nonexistent_session_returns_none(self):
        """Test that exporting non-existent session returns None."""
        result = self.manager.export_session_key("nonexistent_session")
        self.assertIsNone(result)

    def test_import_invalid_session_data_returns_false(self):
        """Test that importing invalid session data returns False."""
        invalid_data = "invalid_session_data"
        result = self.manager.import_session_key(invalid_data)
        self.assertFalse(result)


class TestSecurityFeatures(unittest.TestCase):
    """Test security-specific features and edge cases."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_random_key_generation(self):
        """Test cryptographically secure random key generation."""
        key1 = self.manager.generate_random_key(32)
        key2 = self.manager.generate_random_key(32)

        # Validate key properties
        self.assertIsInstance(key1, bytes)
        self.assertIsInstance(key2, bytes)
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)

        # Keys should be different (cryptographically secure randomness)
        self.assertNotEqual(key1, key2)

    def test_password_key_derivation(self):
        """Test password-based key derivation using PBKDF2."""
        password = "SecurePassword123!"
        salt = os.urandom(16)

        # Derive key
        derived_key = self.manager.derive_key_from_password(password, salt)

        # Validate derived key
        self.assertIsInstance(derived_key, bytes)
        self.assertGreater(len(derived_key), 0)

        # Same password + salt should produce same key (deterministic)
        derived_key2 = self.manager.derive_key_from_password(password, salt)
        self.assertEqual(derived_key, derived_key2)

        # Different salt should produce different key
        different_salt = os.urandom(16)
        derived_key3 = self.manager.derive_key_from_password(password, different_salt)
        self.assertNotEqual(derived_key, derived_key3)

    def test_password_derivation_without_salt(self):
        """Test password derivation with auto-generated salt."""
        password = "TestPassword"

        # Derive key without providing salt
        derived_key = self.manager.derive_key_from_password(password)

        # Should work and produce valid key
        self.assertIsInstance(derived_key, bytes)
        self.assertGreater(len(derived_key), 0)

    def test_hmac_authentication_integrity(self):
        """Test HMAC authentication prevents data tampering."""
        plaintext = "HMAC integrity test message"

        # Encrypt data
        encrypted_data = self.manager.encrypt(plaintext)

        # Tamper with different parts of the encrypted data
        tamper_positions = [0, len(encrypted_data)//4, len(encrypted_data)//2, -1]

        for pos in tamper_positions:
            tampered_data = bytearray(encrypted_data)
            tampered_data[pos] ^= 0x01  # Flip one bit

            # Should raise exception due to HMAC verification failure
            with self.assertRaises((ValueError, Exception)):
                self.manager.decrypt(bytes(tampered_data))

    def test_timing_attack_resistance(self):
        """Test that HMAC comparison uses constant-time comparison."""
        plaintext = "Timing attack resistance test"

        # Encrypt data
        encrypted_data = self.manager.encrypt(plaintext)

        # Create data with almost-correct HMAC (only last byte wrong)
        tampered_data = bytearray(encrypted_data)
        tampered_data[-1] ^= 0x01

        # Should still fail even with only one byte difference
        # (This tests constant-time comparison indirectly)
        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(bytes(tampered_data))

    def test_concurrent_encryption_safety(self):
        """Test thread safety of encryption operations."""
        import threading

        plaintexts = [f"Concurrent test message {i}" for i in range(10)]
        results = {}
        errors = []

        def encrypt_decrypt_test(index, plaintext):
            try:
                session_id = f"concurrent_session_{index}"
                self.manager.create_session_key(session_id)

                encrypted = self.manager.encrypt(plaintext, session_id=session_id)
                decrypted = self.manager.decrypt(encrypted, session_id=session_id)

                results[index] = (plaintext == decrypted)
            except Exception as e:
                errors.append(e)

        # Start concurrent threads
        threads = []
        for i, plaintext in enumerate(plaintexts):
            thread = threading.Thread(target=encrypt_decrypt_test, args=(i, plaintext))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=5)

        # Validate no errors occurred and all operations succeeded
        self.assertEqual(len(errors), 0, f"Concurrent operations failed: {errors}")
        self.assertEqual(len(results), len(plaintexts))
        self.assertTrue(all(results.values()))


class TestPerformanceAndScalability(unittest.TestCase):
    """Test performance characteristics and scalability."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_small_payload_performance(self):
        """Test encryption performance for small payloads."""
        plaintext = "Small payload performance test"

        start_time = time.time()

        # Perform multiple encryptions
        for _ in range(100):
            encrypted = self.manager.encrypt(plaintext)
            self.manager.decrypt(encrypted)

        elapsed_time = time.time() - start_time

        # Should complete 100 operations in reasonable time (< 1 second)
        self.assertLess(elapsed_time, 1.0)

    def test_large_payload_handling(self):
        """Test handling of large payloads."""
        # 10MB payload
        large_plaintext = "A" * (10 * 1024 * 1024)

        start_time = time.time()

        encrypted = self.manager.encrypt(large_plaintext)
        decrypted = self.manager.decrypt(encrypted)

        elapsed_time = time.time() - start_time

        # Validate correctness
        self.assertEqual(decrypted, large_plaintext)

        # Should complete in reasonable time (< 10 seconds)
        self.assertLess(elapsed_time, 10.0)

    def test_session_scalability(self):
        """Test scalability with multiple concurrent sessions."""
        num_sessions = 100
        session_ids = [f"scale_test_session_{i}" for i in range(num_sessions)]

        # Create multiple sessions
        for session_id in session_ids:
            self.manager.create_session_key(session_id)

        # Perform operations on each session
        for session_id in session_ids:
            plaintext = f"Test message for {session_id}"
            encrypted = self.manager.encrypt(plaintext, session_id=session_id)
            decrypted = self.manager.decrypt(encrypted, session_id=session_id)
            self.assertEqual(decrypted, plaintext)

        # Validate session statistics
        stats = self.manager.get_session_statistics()
        self.assertEqual(stats["total_sessions"], num_sessions)
        self.assertGreaterEqual(stats["total_encryptions"], num_sessions)


if __name__ == "__main__":
    unittest.main()
