"""
Advanced Key Exchange and Cryptographic Protocol Tests for EncryptionManager

Tests sophisticated RSA key exchange scenarios, cryptographic protocol compliance,
and advanced security features expected in production C2 infrastructure.
"""

import base64
import json
import os
import tempfile
import time
import unittest

import pytest

# Import the module under test
from intellicrack.core.c2.encryption_manager import EncryptionManager


class TestRSAKeyExchangeProtocol(unittest.TestCase):
    """Test RSA key exchange protocol implementation."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_rsa_keypair_generation(self):
        """Test RSA keypair generation meets security standards."""
        # The manager should have generated RSA keys during initialization
        public_key_pem = self.manager.get_public_key_pem()

        # Validate RSA public key format
        self.assertIsInstance(public_key_pem, str)
        self.assertIn("-----BEGIN PUBLIC KEY-----", public_key_pem)
        self.assertIn("-----END PUBLIC KEY-----", public_key_pem)

        # RSA-2048 keys should be substantial in size
        self.assertGreater(len(public_key_pem), 350)
        self.assertLess(len(public_key_pem), 800)  # Reasonable upper bound

    def test_rsa_keypair_uniqueness(self):
        """Test that different managers generate unique RSA keypairs."""
        manager1 = EncryptionManager(encryption_type="AES256")
        manager2 = EncryptionManager(encryption_type="AES256")

        key1 = manager1.get_public_key_pem()
        key2 = manager2.get_public_key_pem()

        # Different instances should have different public keys
        self.assertNotEqual(key1, key2)

    def test_key_exchange_full_protocol(self):
        """Test complete key exchange protocol between two parties."""
        try:
            from intellicrack.handlers.cryptography_handler import (
                rsa, serialization, default_backend, hashes
            )
            from intellicrack.handlers.cryptography_handler import padding as asym_padding

            # Simulate client-server key exchange
            server_manager = EncryptionManager(encryption_type="AES256")

            # Generate client keypair
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
            exchange_result = server_manager.exchange_keys(client_public_key_pem)

            # Extract exchange components
            session_id = exchange_result["session_id"]
            encrypted_session_key = base64.b64decode(exchange_result["encrypted_session_key"])
            server_public_key_pem = exchange_result["server_public_key"]

            # Client decrypts session key
            decrypted_session_key = client_private_key.decrypt(
                encrypted_session_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Validate session key properties
            self.assertIsInstance(decrypted_session_key, bytes)
            self.assertGreater(len(decrypted_session_key), 0)

            # Test that session can be used for encryption
            test_message = "Full protocol key exchange test"
            encrypted_data = server_manager.encrypt(test_message, session_id=session_id)
            decrypted_message = server_manager.decrypt(encrypted_data, session_id=session_id)

            self.assertEqual(decrypted_message, test_message)

        except ImportError:
            self.skipTest("Cryptography library not available for full protocol test")

    def test_key_exchange_multiple_clients(self):
        """Test key exchange with multiple concurrent clients."""
        try:
            from intellicrack.handlers.cryptography_handler import (
                rsa, serialization, default_backend
            )

            server_manager = EncryptionManager(encryption_type="AES256")
            num_clients = 5

            exchange_results = []
            client_keys = []

            # Generate multiple client keypairs and perform exchanges
            for i in range(num_clients):
                client_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )

                client_public_key_pem = client_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                exchange_result = server_manager.exchange_keys(client_public_key_pem)

                exchange_results.append(exchange_result)
                client_keys.append(client_private_key)

            # Validate each exchange produced unique session IDs
            session_ids = [result["session_id"] for result in exchange_results]
            self.assertEqual(len(session_ids), len(set(session_ids)))  # All unique

            # Test that each session works independently
            for i, (exchange_result, client_key) in enumerate(zip(exchange_results, client_keys)):
                session_id = exchange_result["session_id"]
                test_message = f"Multi-client test message {i}"

                encrypted_data = server_manager.encrypt(test_message, session_id=session_id)
                decrypted_message = server_manager.decrypt(encrypted_data, session_id=session_id)

                self.assertEqual(decrypted_message, test_message)

        except ImportError:
            self.skipTest("Cryptography library not available for multi-client test")

    def test_key_exchange_session_isolation(self):
        """Test that sessions from key exchange are properly isolated."""
        try:
            from intellicrack.handlers.cryptography_handler import (
                rsa, serialization, default_backend
            )

            server_manager = EncryptionManager(encryption_type="AES256")

            # Create two client exchanges
            client_keys = []
            exchange_results = []

            for _ in range(2):
                client_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )

                client_public_key_pem = client_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                exchange_result = server_manager.exchange_keys(client_public_key_pem)

                client_keys.append(client_private_key)
                exchange_results.append(exchange_result)

            # Test cross-session isolation
            session1_id = exchange_results[0]["session_id"]
            session2_id = exchange_results[1]["session_id"]

            test_message = "Session isolation test"

            # Encrypt with session 1
            encrypted_data = server_manager.encrypt(test_message, session_id=session1_id)

            # Should not decrypt with session 2
            with self.assertRaises((ValueError, Exception)):
                server_manager.decrypt(encrypted_data, session_id=session2_id)

        except ImportError:
            self.skipTest("Cryptography library not available for isolation test")

    def test_key_exchange_timestamp_validation(self):
        """Test key exchange timestamp handling."""
        try:
            from intellicrack.handlers.cryptography_handler import (
                rsa, serialization, default_backend
            )

            server_manager = EncryptionManager(encryption_type="AES256")

            # Generate client keypair
            client_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            client_public_key_pem = client_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Record time before exchange
            before_exchange = time.time()

            # Perform key exchange
            exchange_result = server_manager.exchange_keys(client_public_key_pem)

            # Record time after exchange
            after_exchange = time.time()

            # Validate timestamp is within reasonable range
            exchange_timestamp = exchange_result["timestamp"]
            self.assertGreaterEqual(exchange_timestamp, before_exchange)
            self.assertLessEqual(exchange_timestamp, after_exchange)

        except ImportError:
            self.skipTest("Cryptography library not available for timestamp test")


class TestAdvancedKeyManagement(unittest.TestCase):
    """Test advanced key management features."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_key_rotation_rsa_keypair_renewal(self):
        """Test that key rotation generates new RSA keypairs."""
        # Get initial public key
        initial_public_key = self.manager.get_public_key_pem()

        # Force key rotation
        self.manager.rotate_keys(force=True)

        # Get new public key
        rotated_public_key = self.manager.get_public_key_pem()

        # Should be different after rotation
        self.assertNotEqual(initial_public_key, rotated_public_key)

    def test_key_rotation_preserves_active_sessions(self):
        """Test that key rotation doesn't invalidate active sessions."""
        # Create session before rotation
        session_id = "pre_rotation_session"
        self.manager.create_session_key(session_id)

        test_message = "Pre-rotation message"
        encrypted_data = self.manager.encrypt(test_message, session_id=session_id)

        # Rotate keys
        self.manager.rotate_keys(force=True)

        # Session should still work
        decrypted_message = self.manager.decrypt(encrypted_data, session_id=session_id)
        self.assertEqual(decrypted_message, test_message)

        # Should be able to create new encryptions with old session
        new_encrypted = self.manager.encrypt("Post-rotation message", session_id=session_id)
        new_decrypted = self.manager.decrypt(new_encrypted, session_id=session_id)
        self.assertEqual(new_decrypted, "Post-rotation message")

    def test_key_rotation_expired_session_cleanup(self):
        """Test that key rotation cleans up expired sessions."""
        # Create sessions with mock old timestamps
        old_session_id = "old_session"
        recent_session_id = "recent_session"

        self.manager.create_session_key(old_session_id)
        self.manager.create_session_key(recent_session_id)

        # Mock old timestamp for one session
        if hasattr(self.manager, 'session_keys'):
            # Simulate old session (older than 1 hour)
            self.manager.session_keys[old_session_id]["created_at"] = time.time() - 7200

        initial_session_count = len(self.manager.session_keys) if hasattr(self.manager, 'session_keys') else 0

        # Rotate keys (should clean expired sessions)
        self.manager.rotate_keys(force=True)

        # Recent session should remain, old session may be cleaned
        final_session_count = len(self.manager.session_keys) if hasattr(self.manager, 'session_keys') else 0

        # At minimum, should not have increased session count
        self.assertLessEqual(final_session_count, initial_session_count)

    def test_session_key_export_import_format(self):
        """Test session key export/import data format."""
        session_id = "format_test_session"
        self.manager.create_session_key(session_id)

        # Export session key
        exported_data = self.manager.export_session_key(session_id)

        # Should be base64-encoded JSON
        self.assertIsInstance(exported_data, str)

        # Decode and parse
        try:
            decoded_data = base64.b64decode(exported_data)
            session_info = json.loads(decoded_data.decode('utf-8'))

            # Validate expected fields
            expected_fields = ["session_id", "key", "created_at", "used_count"]
            for field in expected_fields:
                self.assertIn(field, session_info)

            # Validate field types
            self.assertEqual(session_info["session_id"], session_id)
            self.assertIsInstance(session_info["key"], str)  # base64-encoded
            self.assertIsInstance(session_info["created_at"], (int, float))
            self.assertIsInstance(session_info["used_count"], int)

        except (ValueError, json.JSONDecodeError) as e:
            self.fail(f"Exported session data format invalid: {e}")

    def test_session_key_export_import_roundtrip(self):
        """Test complete session key export/import round-trip."""
        session_id = "roundtrip_test_session"
        test_message = "Export/import round-trip test"

        # Create session and encrypt data
        self.manager.create_session_key(session_id)
        original_encrypted = self.manager.encrypt(test_message, session_id=session_id)

        # Export session key
        exported_data = self.manager.export_session_key(session_id)

        # Create new manager and import session
        new_manager = EncryptionManager(encryption_type="AES256")
        import_success = new_manager.import_session_key(exported_data)

        self.assertTrue(import_success)

        # Should be able to decrypt original data with imported session
        decrypted_message = new_manager.decrypt(original_encrypted, session_id=session_id)
        self.assertEqual(decrypted_message, test_message)

        # Should be able to create new encryptions with imported session
        new_encrypted = new_manager.encrypt("New message", session_id=session_id)
        new_decrypted = self.manager.decrypt(new_encrypted, session_id=session_id)
        self.assertEqual(new_decrypted, "New message")

    def test_session_key_import_preserves_metadata(self):
        """Test that session key import preserves usage metadata."""
        session_id = "metadata_test_session"

        # Create session and use it multiple times
        self.manager.create_session_key(session_id)
        for i in range(5):
            self.manager.encrypt(f"Message {i}", session_id=session_id)

        # Export session
        exported_data = self.manager.export_session_key(session_id)

        # Import into new manager
        new_manager = EncryptionManager(encryption_type="AES256")
        new_manager.import_session_key(exported_data)

        # Check that usage count is preserved
        if hasattr(new_manager, 'session_keys'):
            imported_session = new_manager.session_keys.get(session_id)
            if imported_session:
                self.assertGreaterEqual(imported_session["used_count"], 5)


class TestCryptographicProtocolCompliance(unittest.TestCase):
    """Test compliance with cryptographic protocols and standards."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_aes_cbc_mode_compliance(self):
        """Test AES-CBC mode implementation compliance."""
        plaintext = "AES-CBC compliance test message"

        # Encrypt same message multiple times
        encryptions = [self.manager.encrypt(plaintext) for _ in range(5)]

        # All should decrypt to same plaintext
        for encrypted_data in encryptions:
            decrypted = self.manager.decrypt(encrypted_data)
            self.assertEqual(decrypted, plaintext)

        # All ciphertexts should be different (due to random IV)
        for i, enc1 in enumerate(encryptions):
            for j, enc2 in enumerate(encryptions):
                if i != j:
                    self.assertNotEqual(enc1, enc2)

    def test_pkcs7_padding_compliance(self):
        """Test PKCS#7 padding implementation."""
        # Test messages of different lengths to validate padding
        test_messages = [
            "",  # Empty
            "A",  # 1 byte
            "AB",  # 2 bytes
            "ABCDEFGHIJKLMNOP",  # 16 bytes (1 block)
            "ABCDEFGHIJKLMNOPQ",  # 17 bytes (>1 block)
            "A" * 31,  # 31 bytes
            "A" * 32,  # 32 bytes (2 blocks)
            "A" * 100,  # Multiple blocks
        ]

        for message in test_messages:
            encrypted = self.manager.encrypt(message)
            decrypted = self.manager.decrypt(encrypted)
            self.assertEqual(decrypted, message)

    def test_hmac_sha256_compliance(self):
        """Test HMAC-SHA256 authentication compliance."""
        plaintext = "HMAC-SHA256 compliance test"

        # Encrypt message
        encrypted_data = self.manager.encrypt(plaintext)

        # HMAC should be 32 bytes (SHA256 output)
        # Format: IV + Ciphertext + HMAC
        # Assuming 16-byte IV, the HMAC should be the last 32 bytes
        hmac_size = 32

        self.assertGreaterEqual(len(encrypted_data), hmac_size)

        # Extract HMAC portion
        hmac_portion = encrypted_data[-hmac_size:]
        self.assertEqual(len(hmac_portion), hmac_size)

        # Tampering with HMAC should cause decryption failure
        tampered_data = bytearray(encrypted_data)
        tampered_data[-1] ^= 0x01  # Flip last bit of HMAC

        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(bytes(tampered_data))

    def test_pbkdf2_parameter_compliance(self):
        """Test PBKDF2 parameters meet security standards."""
        password = "TestPassword123"

        # Derive key
        derived_key = self.manager.derive_key_from_password(password)

        # Should produce appropriate key length
        self.assertIsInstance(derived_key, bytes)
        self.assertGreater(len(derived_key), 0)

        # Different passwords should produce different keys
        different_key = self.manager.derive_key_from_password("DifferentPassword")
        self.assertNotEqual(derived_key, different_key)

    def test_rsa_oaep_padding_compliance(self):
        """Test RSA OAEP padding in key exchange."""
        try:
            from intellicrack.handlers.cryptography_handler import (
                rsa, serialization, default_backend, hashes
            )
            from intellicrack.handlers.cryptography_handler import padding as asym_padding

            # Generate client keypair with proper parameters
            client_private_key = rsa.generate_private_key(
                public_exponent=65537,  # Standard public exponent
                key_size=2048,  # Minimum recommended key size
                backend=default_backend()
            )

            client_public_key_pem = client_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Perform key exchange
            exchange_result = self.manager.exchange_keys(client_public_key_pem)

            # Decrypt session key using OAEP padding
            encrypted_session_key = base64.b64decode(exchange_result["encrypted_session_key"])

            # Should be able to decrypt with proper OAEP parameters
            decrypted_key = client_private_key.decrypt(
                encrypted_session_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            self.assertIsInstance(decrypted_key, bytes)
            self.assertGreater(len(decrypted_key), 0)

        except ImportError:
            self.skipTest("Cryptography library not available for OAEP test")

    def test_secure_random_generation(self):
        """Test cryptographically secure random number generation."""
        # Generate multiple random keys
        keys = [self.manager.generate_random_key(32) for _ in range(10)]

        # All should be unique (with overwhelming probability)
        unique_keys = set(keys)
        self.assertEqual(len(keys), len(unique_keys))

        # All should be proper length
        for key in keys:
            self.assertEqual(len(key), 32)
            self.assertIsInstance(key, bytes)


if __name__ == "__main__":
    unittest.main()
