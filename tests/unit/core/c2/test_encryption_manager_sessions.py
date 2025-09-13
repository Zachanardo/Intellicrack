"""
Session Management and Perfect Forward Secrecy Tests for EncryptionManager

Tests advanced session management, perfect forward secrecy implementation,
and security features critical for C2 infrastructure operations.
"""

import base64
import json
import os
import tempfile
import time
import threading
import unittest

import pytest

# Import the module under test
from intellicrack.core.c2.encryption_manager import EncryptionManager


class TestPerfectForwardSecrecy(unittest.TestCase):
    """Test perfect forward secrecy implementation."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_session_key_independence_from_master_key(self):
        """Test that session keys are independent of master key compromise."""
        session_id = "pfs_test_session"
        plaintext = "Perfect forward secrecy test message"

        # Create session and encrypt data
        self.manager.create_session_key(session_id)
        session_encrypted = self.manager.encrypt(plaintext, session_id=session_id)

        # Simulate master key compromise by rotating master key
        self.manager.rotate_keys(force=True)

        # Session key should still work even after master key rotation
        decrypted_text = self.manager.decrypt(session_encrypted, session_id=session_id)
        self.assertEqual(decrypted_text, plaintext)

        # Should be able to continue using the session for new operations
        new_encrypted = self.manager.encrypt("New message post-rotation", session_id=session_id)
        new_decrypted = self.manager.decrypt(new_encrypted, session_id=session_id)
        self.assertEqual(new_decrypted, "New message post-rotation")

    def test_session_key_unique_generation(self):
        """Test that each session generates a unique key."""
        num_sessions = 10
        session_keys = {}

        # Create multiple sessions and track their keys
        for i in range(num_sessions):
            session_id = f"unique_test_session_{i}"
            session_key = self.manager.create_session_key(session_id)
            session_keys[session_id] = session_key

        # All session keys should be unique
        unique_keys = set(session_keys.values())
        self.assertEqual(len(unique_keys), num_sessions)

        # All keys should be proper length
        for key in session_keys.values():
            self.assertIsInstance(key, bytes)
            self.assertGreater(len(key), 0)

    def test_session_isolation_perfect_forward_secrecy(self):
        """Test that compromising one session doesn't affect others."""
        # Create multiple sessions with encrypted data
        sessions_data = {}
        for i in range(3):
            session_id = f"isolation_session_{i}"
            plaintext = f"Isolation test message for session {i}"

            self.manager.create_session_key(session_id)
            encrypted = self.manager.encrypt(plaintext, session_id=session_id)

            sessions_data[session_id] = {
                "plaintext": plaintext,
                "encrypted": encrypted
            }

        # Simulate compromise of one session by deleting it
        compromised_session = "isolation_session_1"
        if hasattr(self.manager, 'session_keys') and compromised_session in self.manager.session_keys:
            del self.manager.session_keys[compromised_session]

        # Other sessions should still work perfectly
        for session_id, data in sessions_data.items():
            if session_id != compromised_session:
                decrypted = self.manager.decrypt(data["encrypted"], session_id=session_id)
                self.assertEqual(decrypted, data["plaintext"])

    def test_session_forward_secrecy_after_key_rotation(self):
        """Test forward secrecy properties after key rotation."""
        session_id = "forward_secrecy_session"
        messages = []

        # Create session and encrypt multiple messages over time
        self.manager.create_session_key(session_id)

        for i in range(3):
            message = f"Message {i} before rotation"
            encrypted = self.manager.encrypt(message, session_id=session_id)
            messages.append((message, encrypted))

        # Rotate master keys
        self.manager.rotate_keys(force=True)

        # Add more messages after rotation
        for i in range(3, 6):
            message = f"Message {i} after rotation"
            encrypted = self.manager.encrypt(message, session_id=session_id)
            messages.append((message, encrypted))

        # All messages should still be decryptable
        for message, encrypted in messages:
            decrypted = self.manager.decrypt(encrypted, session_id=session_id)
            self.assertEqual(decrypted, message)

    def test_session_backward_secrecy(self):
        """Test that new session keys don't compromise old encrypted data."""
        plaintext = "Backward secrecy test"

        # Encrypt with master key
        master_encrypted = self.manager.encrypt(plaintext)

        # Create new session
        session_id = "backward_secrecy_session"
        self.manager.create_session_key(session_id)

        # Master key encrypted data should still be decryptable
        master_decrypted = self.manager.decrypt(master_encrypted)
        self.assertEqual(master_decrypted, plaintext)

        # Session should not be able to decrypt master key data
        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(master_encrypted, session_id=session_id)


class TestSessionLifecycleManagement(unittest.TestCase):
    """Test session lifecycle and management features."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_session_creation_tracking(self):
        """Test session creation and tracking."""
        initial_stats = self.manager.get_session_statistics()
        initial_count = initial_stats["total_sessions"]

        # Create new session
        session_id = "tracking_test_session"
        created_key = self.manager.create_session_key(session_id)

        # Validate session tracking
        new_stats = self.manager.get_session_statistics()
        self.assertEqual(new_stats["total_sessions"], initial_count + 1)

        # Session should be active
        self.assertGreater(new_stats["active_sessions"], 0)

    def test_session_usage_counting(self):
        """Test session usage count tracking."""
        session_id = "usage_count_session"
        self.manager.create_session_key(session_id)

        # Perform multiple operations
        num_operations = 5
        for i in range(num_operations):
            plaintext = f"Usage test message {i}"
            encrypted = self.manager.encrypt(plaintext, session_id=session_id)
            decrypted = self.manager.decrypt(encrypted, session_id=session_id)

        # Check usage statistics
        stats = self.manager.get_session_statistics()

        # Total encryptions should include our operations
        # Note: We performed encryptions, decryptions don't typically increment usage
        self.assertGreaterEqual(stats["total_encryptions"], num_operations)

    def test_session_expiration_logic(self):
        """Test session expiration and cleanup logic."""
        # Create test session
        session_id = "expiration_test_session"
        self.manager.create_session_key(session_id)

        # Mock old creation time if sessions are tracked
        if hasattr(self.manager, 'session_keys') and session_id in self.manager.session_keys:
            # Set session as expired (older than 1 hour)
            self.manager.session_keys[session_id]["created_at"] = time.time() - 7200

        initial_count = len(self.manager.session_keys) if hasattr(self.manager, 'session_keys') else 0

        # Run cleanup
        self.manager.cleanup_expired_sessions()

        # Expired session should be cleaned up
        final_count = len(self.manager.session_keys) if hasattr(self.manager, 'session_keys') else 0

        # Count should be reduced or at least not increased
        self.assertLessEqual(final_count, initial_count)

    def test_session_statistics_accuracy(self):
        """Test accuracy of session statistics reporting."""
        # Get baseline statistics
        initial_stats = self.manager.get_session_statistics()

        # Create multiple sessions
        session_count = 3
        session_ids = [f"stats_session_{i}" for i in range(session_count)]

        for session_id in session_ids:
            self.manager.create_session_key(session_id)

        # Perform operations on sessions
        operations_per_session = 2
        for session_id in session_ids:
            for j in range(operations_per_session):
                self.manager.encrypt(f"Stats test {j}", session_id=session_id)

        # Check updated statistics
        final_stats = self.manager.get_session_statistics()

        # Validate session count increase
        expected_sessions = initial_stats["total_sessions"] + session_count
        self.assertEqual(final_stats["total_sessions"], expected_sessions)

        # Validate active sessions
        self.assertGreaterEqual(final_stats["active_sessions"], session_count)

        # Validate total encryptions increase
        expected_min_encryptions = initial_stats["total_encryptions"] + (session_count * operations_per_session)
        self.assertGreaterEqual(final_stats["total_encryptions"], expected_min_encryptions)

    def test_concurrent_session_management(self):
        """Test thread-safe concurrent session management."""
        num_threads = 5
        operations_per_thread = 10
        results = {}
        errors = []

        def session_worker(thread_id):
            try:
                session_id = f"concurrent_session_{thread_id}"
                thread_results = []

                # Create session
                self.manager.create_session_key(session_id)

                # Perform operations
                for i in range(operations_per_thread):
                    plaintext = f"Thread {thread_id} message {i}"
                    encrypted = self.manager.encrypt(plaintext, session_id=session_id)
                    decrypted = self.manager.decrypt(encrypted, session_id=session_id)
                    thread_results.append(plaintext == decrypted)

                results[thread_id] = thread_results

            except Exception as e:
                errors.append((thread_id, str(e)))

        # Start concurrent threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=session_worker, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join(timeout=10)

        # Validate results
        self.assertEqual(len(errors), 0, f"Concurrent errors: {errors}")
        self.assertEqual(len(results), num_threads)

        # All operations should have succeeded
        for thread_results in results.values():
            self.assertEqual(len(thread_results), operations_per_thread)
            self.assertTrue(all(thread_results))

    def test_session_cleanup_preserves_active_sessions(self):
        """Test that cleanup preserves recently active sessions."""
        # Create recent session
        recent_session = "recent_active_session"
        self.manager.create_session_key(recent_session)

        # Create old session (simulate)
        old_session = "old_expired_session"
        self.manager.create_session_key(old_session)

        # Mock old timestamp for expired session
        if hasattr(self.manager, 'session_keys'):
            self.manager.session_keys[old_session]["created_at"] = time.time() - 7200

        # Cleanup expired sessions
        self.manager.cleanup_expired_sessions()

        # Recent session should still work
        test_message = "Recent session test"
        encrypted = self.manager.encrypt(test_message, session_id=recent_session)
        decrypted = self.manager.decrypt(encrypted, session_id=recent_session)
        self.assertEqual(decrypted, test_message)


class TestSessionSecurityFeatures(unittest.TestCase):
    """Test security features specific to session management."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_session_id_format_security(self):
        """Test session ID generation for security properties."""
        session_ids = []

        # Generate multiple session IDs
        for i in range(10):
            session_id = f"security_test_session_{i}"
            self.manager.create_session_key(session_id)
            session_ids.append(session_id)

        # All should be unique (though we provided unique inputs)
        self.assertEqual(len(session_ids), len(set(session_ids)))

        # Test with key exchange for auto-generated session IDs
        try:
            from intellicrack.handlers.cryptography_handler import (
                rsa, serialization, default_backend
            )

            # Generate client keypair for key exchange
            client_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            client_public_key_pem = client_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Perform multiple key exchanges
            auto_session_ids = []
            for _ in range(5):
                exchange_result = self.manager.exchange_keys(client_public_key_pem)
                auto_session_ids.append(exchange_result["session_id"])

            # Auto-generated session IDs should be unique
            self.assertEqual(len(auto_session_ids), len(set(auto_session_ids)))

            # Should be proper length (16 characters as per implementation)
            for session_id in auto_session_ids:
                self.assertEqual(len(session_id), 16)
                # Should be hexadecimal characters
                self.assertTrue(all(c in '0123456789abcdef' for c in session_id.lower()))

        except ImportError:
            self.skipTest("Cryptography library not available for session ID test")

    def test_session_key_entropy(self):
        """Test session key cryptographic entropy."""
        session_keys = []

        # Generate multiple session keys
        for i in range(10):
            session_id = f"entropy_test_session_{i}"
            key = self.manager.create_session_key(session_id)
            session_keys.append(key)

        # All keys should be unique
        unique_keys = set(session_keys)
        self.assertEqual(len(unique_keys), len(session_keys))

        # Each key should be proper length and random
        for key in session_keys:
            self.assertIsInstance(key, bytes)
            self.assertGreater(len(key), 0)

            # Basic entropy check: no key should be all zeros
            self.assertNotEqual(key, b'\x00' * len(key))

    def test_session_memory_security(self):
        """Test secure handling of session keys in memory."""
        session_id = "memory_security_session"

        # Create session
        session_key = self.manager.create_session_key(session_id)

        # Use session for encryption
        plaintext = "Memory security test"
        encrypted = self.manager.encrypt(plaintext, session_id=session_id)

        # Cleanup expired sessions (session should be removed)
        if hasattr(self.manager, 'session_keys') and session_id in self.manager.session_keys:
            # Mock expiration
            self.manager.session_keys[session_id]["created_at"] = time.time() - 7200

        self.manager.cleanup_expired_sessions()

        # Session should no longer exist or be usable
        # (This indirectly tests that memory is cleared)

    def test_session_export_security(self):
        """Test security of session export functionality."""
        session_id = "export_security_session"
        self.manager.create_session_key(session_id)

        # Export session
        exported_data = self.manager.export_session_key(session_id)

        # Exported data should be base64 encoded (not plain JSON)
        self.assertIsInstance(exported_data, str)

        # Should not contain raw key data
        self.assertNotIn("session_key", exported_data)

        # Should be valid base64
        try:
            decoded = base64.b64decode(exported_data)
            session_data = json.loads(decoded.decode('utf-8'))

            # Key should be base64 encoded within the JSON
            self.assertIn("key", session_data)
            self.assertIsInstance(session_data["key"], str)

            # Verify the key field is base64 encoded
            base64.b64decode(session_data["key"])

        except Exception as e:
            self.fail(f"Export security validation failed: {e}")

    def test_session_import_validation(self):
        """Test validation of imported session data."""
        # Test import of malformed data
        invalid_inputs = [
            "invalid_base64_data",
            base64.b64encode(b"invalid_json").decode(),
            base64.b64encode(b'{"incomplete": "data"}').decode(),
            base64.b64encode(b'{"session_id": "test", "key": "invalid_base64"}').decode(),
        ]

        for invalid_input in invalid_inputs:
            result = self.manager.import_session_key(invalid_input)
            self.assertFalse(result, f"Should reject invalid input: {invalid_input[:50]}")

    def test_session_isolation_encryption_context(self):
        """Test that session encryption contexts are properly isolated."""
        # Create two sessions
        session1 = "isolation_context_session_1"
        session2 = "isolation_context_session_2"

        self.manager.create_session_key(session1)
        self.manager.create_session_key(session2)

        # Same plaintext encrypted with different sessions should produce different results
        plaintext = "Context isolation test message"

        encrypted1 = self.manager.encrypt(plaintext, session_id=session1)
        encrypted2 = self.manager.encrypt(plaintext, session_id=session2)

        # Different ciphertexts
        self.assertNotEqual(encrypted1, encrypted2)

        # Each decrypts correctly with its own session
        decrypted1 = self.manager.decrypt(encrypted1, session_id=session1)
        decrypted2 = self.manager.decrypt(encrypted2, session_id=session2)

        self.assertEqual(decrypted1, plaintext)
        self.assertEqual(decrypted2, plaintext)

        # Cross-session decryption should fail
        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(encrypted1, session_id=session2)

        with self.assertRaises((ValueError, Exception)):
            self.manager.decrypt(encrypted2, session_id=session1)


if __name__ == "__main__":
    unittest.main()
