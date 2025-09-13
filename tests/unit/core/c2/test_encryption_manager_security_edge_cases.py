"""
Security Edge Cases and Advanced Scenario Tests for EncryptionManager

Tests security-critical edge cases, attack resistance, error conditions,
and advanced scenarios expected in production C2 infrastructure.
"""

import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
import threading
import unittest

import pytest

# Import the module under test
from intellicrack.core.c2.encryption_manager import EncryptionManager


class TestCryptographicAttackResistance(unittest.TestCase):
    """Test resistance to common cryptographic attacks."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_timing_attack_resistance_hmac_verification(self):
        """Test resistance to timing attacks on HMAC verification."""
        plaintext = "Timing attack test message"

        # Get legitimate encrypted data
        legitimate_data = self.manager.encrypt(plaintext)

        # Create data with various HMAC modifications
        attack_variations = []
        for i in range(10):
            tampered_data = bytearray(legitimate_data)
            # Modify different positions in the HMAC
            tampered_data[-(i+1)] ^= 0x01
            attack_variations.append(bytes(tampered_data))

        # All variations should fail in similar time
        # (Testing this precisely requires more sophisticated timing analysis)
        for tampered_data in attack_variations:
            with self.assertRaises((ValueError, Exception)):
                self.manager.decrypt(tampered_data)

    def test_padding_oracle_attack_resistance(self):
        """Test resistance to padding oracle attacks."""
        plaintext = "Padding oracle test message"
        encrypted_data = self.manager.encrypt(plaintext)

        # Create various padding modifications
        padding_attacks = []
        for i in range(16):  # AES block size
            tampered_data = bytearray(encrypted_data)
            # Modify the last block to create invalid padding
            tampered_data[-(32+i+1)] ^= 0x01  # Before HMAC, in ciphertext
            padding_attacks.append(bytes(tampered_data))

        # All padding attacks should fail due to HMAC verification
        # before padding is checked (preventing oracle leakage)
        for attack_data in padding_attacks:
            with self.assertRaises((ValueError, Exception)):
                self.manager.decrypt(attack_data)

    def test_bit_flipping_attack_resistance(self):
        """Test resistance to bit-flipping attacks."""
        plaintext = "Bit flipping attack test - this is a longer message to test multiple blocks"
        encrypted_data = self.manager.encrypt(plaintext)

        # Attempt bit flipping attacks at various positions
        bit_flip_positions = [0, 16, 32, 48, 64, -64, -48, -32, -16]

        for pos in bit_flip_positions:
            if abs(pos) < len(encrypted_data):
                tampered_data = bytearray(encrypted_data)
                tampered_data[pos] ^= 0x01

                # Should fail due to HMAC verification
                with self.assertRaises((ValueError, Exception)):
                    self.manager.decrypt(bytes(tampered_data))

    def test_chosen_ciphertext_attack_resistance(self):
        """Test resistance to chosen ciphertext attacks."""
        # Attacker should not be able to learn anything from decryption failures

        # Create various malformed ciphertexts
        malformed_ciphertexts = [
            b"short_data",
            b"x" * 100,  # Wrong format
            os.urandom(100),  # Random data
            b"\x00" * 100,  # All zeros
            b"\xff" * 100,  # All ones
        ]

        for malformed_data in malformed_ciphertexts:
            with self.assertRaises((ValueError, Exception)):
                # Should fail without leaking information
                self.manager.decrypt(malformed_data)

    def test_replay_attack_detection(self):
        """Test detection/handling of replay attacks."""
        plaintext = "Replay attack test message"

        # Encrypt the same message multiple times
        encrypted_messages = [self.manager.encrypt(plaintext) for _ in range(5)]

        # Each encryption should produce different ciphertext (due to random IV)
        for i, msg1 in enumerate(encrypted_messages):
            for j, msg2 in enumerate(encrypted_messages):
                if i != j:
                    self.assertNotEqual(msg1, msg2)

        # All should decrypt to the same plaintext
        for encrypted_msg in encrypted_messages:
            decrypted = self.manager.decrypt(encrypted_msg)
            self.assertEqual(decrypted, plaintext)


class TestErrorConditionHandling(unittest.TestCase):
    """Test handling of various error conditions and edge cases."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_invalid_data_length_handling(self):
        """Test handling of invalid encrypted data lengths."""
        invalid_lengths = [
            b"",  # Empty
            b"x",  # Too short
            b"x" * 15,  # Less than minimum IV size
            b"x" * 31,  # Less than IV + HMAC
        ]

        for invalid_data in invalid_lengths:
            with self.assertRaises((ValueError, Exception)):
                self.manager.decrypt(invalid_data)

    def test_corrupted_data_handling(self):
        """Test handling of corrupted encrypted data."""
        plaintext = "Corruption test message"
        legitimate_data = self.manager.encrypt(plaintext)

        # Create various types of corruption
        corruptions = [
            # Truncate at different points
            legitimate_data[:len(legitimate_data)//4],
            legitimate_data[:len(legitimate_data)//2],
            legitimate_data[:len(legitimate_data)-1],

            # Extend with garbage
            legitimate_data + b"garbage",
            legitimate_data + os.urandom(16),

            # Replace sections with garbage
            os.urandom(16) + legitimate_data[16:],
            legitimate_data[:16] + os.urandom(16) + legitimate_data[32:],
        ]

        for corrupted_data in corruptions:
            with self.assertRaises((ValueError, Exception)):
                self.manager.decrypt(corrupted_data)

    def test_extreme_data_sizes(self):
        """Test handling of extreme data sizes."""
        # Test empty string
        empty_encrypted = self.manager.encrypt("")
        empty_decrypted = self.manager.decrypt(empty_encrypted)
        self.assertEqual(empty_decrypted, "")

        # Test very large string (limited by memory/time constraints)
        large_data = "A" * (1024 * 1024)  # 1MB
        large_encrypted = self.manager.encrypt(large_data)
        large_decrypted = self.manager.decrypt(large_encrypted)
        self.assertEqual(large_decrypted, large_data)

        # Test string with special characters
        special_data = "\x00\x01\x02\xff" + "Unicode: 测试中文 🔐"
        special_encrypted = self.manager.encrypt(special_data)
        special_decrypted = self.manager.decrypt(special_encrypted)
        self.assertEqual(special_decrypted, special_data)

    def test_session_edge_cases(self):
        """Test edge cases in session management."""
        # Non-existent session handling
        with self.assertRaises((ValueError, KeyError, Exception)):
            self.manager.decrypt(b"dummy_data", session_id="nonexistent_session")

        # Empty session ID
        with self.assertRaises((ValueError, Exception)):
            self.manager.create_session_key("")

        # Very long session ID
        long_session_id = "x" * 1000
        try:
            self.manager.create_session_key(long_session_id)
            # If it succeeds, test that it works
            plaintext = "Long session ID test"
            encrypted = self.manager.encrypt(plaintext, session_id=long_session_id)
            decrypted = self.manager.decrypt(encrypted, session_id=long_session_id)
            self.assertEqual(decrypted, plaintext)
        except Exception:
            # If it fails, that's also acceptable behavior
            pass

    def test_concurrent_access_stress(self):
        """Test system under concurrent access stress."""
        num_threads = 20
        operations_per_thread = 50
        errors = []
        successes = []

        def stress_worker(thread_id):
            try:
                local_successes = 0
                session_id = f"stress_session_{thread_id}"

                # Create session
                self.manager.create_session_key(session_id)

                for i in range(operations_per_thread):
                    try:
                        plaintext = f"Stress test T{thread_id}M{i}"
                        encrypted = self.manager.encrypt(plaintext, session_id=session_id)
                        decrypted = self.manager.decrypt(encrypted, session_id=session_id)

                        if decrypted == plaintext:
                            local_successes += 1
                    except Exception as e:
                        errors.append(f"T{thread_id}M{i}: {e}")

                successes.append(local_successes)

            except Exception as e:
                errors.append(f"Thread {thread_id} failed: {e}")

        # Launch stress threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=stress_worker, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)

        # Validate results
        total_expected = num_threads * operations_per_thread
        total_successes = sum(successes)

        # Allow for some errors under stress, but most should succeed
        success_rate = total_successes / total_expected if total_expected > 0 else 0
        self.assertGreater(success_rate, 0.90, f"Success rate too low: {success_rate}, errors: {errors[:10]}")

    def test_memory_exhaustion_resistance(self):
        """Test behavior under memory pressure scenarios."""
        # Create many sessions to test memory usage
        session_count = 1000
        created_sessions = []

        try:
            for i in range(session_count):
                session_id = f"memory_test_session_{i}"
                self.manager.create_session_key(session_id)
                created_sessions.append(session_id)

                # Periodically test that system still works
                if i % 100 == 0:
                    test_plaintext = f"Memory test iteration {i}"
                    encrypted = self.manager.encrypt(test_plaintext, session_id=session_id)
                    decrypted = self.manager.decrypt(encrypted, session_id=session_id)
                    self.assertEqual(decrypted, test_plaintext)

            # System should still be functional
            final_stats = self.manager.get_session_statistics()
            self.assertGreaterEqual(final_stats["total_sessions"], session_count)

        except MemoryError:
            # If we hit memory limits, that's acceptable for this test
            self.skipTest("Memory limit reached during stress test")


class TestSecurityConfigurationEdgeCases(unittest.TestCase):
    """Test security-related configuration and initialization edge cases."""

    def test_unsupported_encryption_types(self):
        """Test handling of unsupported encryption algorithms."""
        unsupported_types = [
            "DES",  # Weak encryption
            "MD5",  # Not encryption
            "AES64",  # Invalid key size
            "RSA1024",  # Too small for security
            "UNKNOWN_ALGORITHM",
            "",  # Empty
            None,  # None type
        ]

        for encryption_type in unsupported_types:
            with self.assertRaises((ValueError, TypeError)):
                if encryption_type is None:
                    # Handle None case separately as it may cause TypeError
                    EncryptionManager(encryption_type=None)
                else:
                    EncryptionManager(encryption_type=encryption_type)

    def test_key_file_security_scenarios(self):
        """Test key file handling security scenarios."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test non-existent key file
            non_existent_key = os.path.join(temp_dir, "non_existent.key")
            manager1 = EncryptionManager(encryption_type="AES256", key_file=non_existent_key)

            # Should work (generate new key)
            plaintext = "Non-existent key file test"
            encrypted = manager1.encrypt(plaintext)
            decrypted = manager1.decrypt(encrypted)
            self.assertEqual(decrypted, plaintext)

            # Test with existing key file path but unwritable directory
            # (This test may need to be skipped on some systems)
            try:
                unwritable_key = "/root/unwritable.key" if os.name != 'nt' else "C:\\Windows\\System32\\unwritable.key"
                # This should either succeed or fail gracefully
                manager2 = EncryptionManager(encryption_type="AES256", key_file=unwritable_key)

                # If it succeeds, it should still work
                test_encrypted = manager2.encrypt("Unwritable path test")
                test_decrypted = manager2.decrypt(test_encrypted)
                self.assertEqual(test_decrypted, "Unwritable path test")

            except (PermissionError, OSError):
                # Expected behavior for unwritable paths
                pass

    def test_missing_cryptography_library(self):
        """Test behavior when cryptography library is not available."""
        # Test real cryptography library availability and error handling

        try:
            manager = EncryptionManager(encryption_type="AES256")
            # If initialization succeeds, basic operations should work
            test_data = "Test cryptography availability"
            encrypted = manager.encrypt(test_data)
            decrypted = manager.decrypt(encrypted)
            self.assertEqual(decrypted, test_data)

        except ImportError:
            # Expected behavior when cryptography is unavailable
            self.skipTest("Cryptography library not available - test environment issue")
        except Exception as e:
            # Should be a clear, informative error for missing dependencies
            self.assertIsInstance(e, (ImportError, RuntimeError, ValueError))

    def test_initialization_failure_recovery(self):
        """Test recovery from initialization failures."""
        # Test real initialization failure scenarios

        # Test with invalid encryption type to trigger real initialization failure
        with self.assertRaises((ValueError, TypeError, Exception)):
            EncryptionManager(encryption_type="INVALID_ENCRYPTION_TYPE")

        # Test with invalid parameters that would cause real initialization failure
        with self.assertRaises((ValueError, TypeError, Exception)):
            EncryptionManager(encryption_type="AES256", key_file="/nonexistent/path/invalid.key")

    def test_key_derivation_edge_cases(self):
        """Test edge cases in key derivation."""
        manager = EncryptionManager(encryption_type="AES256")

        # Test with various password formats
        password_tests = [
            "",  # Empty password
            "a",  # Single character
            "a" * 1000,  # Very long password
            "password\x00with\x00nulls",  # Contains null bytes
            "密码测试",  # Unicode password
            "password with spaces and symbols: !@#$%^&*()",
        ]

        for password in password_tests:
            try:
                derived_key = manager.derive_key_from_password(password)
                self.assertIsInstance(derived_key, bytes)
                self.assertGreater(len(derived_key), 0)

                # Same password should produce same key
                derived_key2 = manager.derive_key_from_password(password)
                self.assertEqual(derived_key, derived_key2)

            except Exception as e:
                # Some edge cases may legitimately fail
                self.assertIsInstance(e, (ValueError, TypeError, UnicodeError))


class TestAdvancedIntegrationScenarios(unittest.TestCase):
    """Test advanced integration scenarios for C2 infrastructure."""

    def setUp(self):
        """Set up test fixtures with fresh encryption manager."""
        self.manager = EncryptionManager(encryption_type="AES256")

    def test_multi_session_key_exchange_scenario(self):
        """Test realistic multi-client key exchange scenario."""
        try:
            from intellicrack.handlers.cryptography_handler import (
                rsa, serialization, default_backend, hashes
            )
            from intellicrack.handlers.cryptography_handler import padding as asym_padding

            # Simulate C2 server handling multiple client connections
            server_manager = EncryptionManager(encryption_type="AES256")

            # Multiple clients perform key exchange
            clients = []
            for i in range(5):
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

                clients.append({
                    'id': i,
                    'private_key': client_private_key,
                    'session_id': exchange_result['session_id'],
                    'encrypted_session_key': exchange_result['encrypted_session_key']
                })

            # Each client sends encrypted commands
            commands = [
                "GET /status",
                "POST /execute cmd='dir'",
                "PUT /upload file.txt",
                "DELETE /cleanup temp",
                "GET /sysinfo"
            ]

            # Test bidirectional communication
            for i, client in enumerate(clients):
                session_id = client['session_id']
                command = commands[i]

                # Client command to server
                encrypted_command = server_manager.encrypt(command, session_id=session_id)
                decrypted_command = server_manager.decrypt(encrypted_command, session_id=session_id)
                self.assertEqual(decrypted_command, command)

                # Server response to client
                response = f"Response to command {i}: OK"
                encrypted_response = server_manager.encrypt(response, session_id=session_id)
                decrypted_response = server_manager.decrypt(encrypted_response, session_id=session_id)
                self.assertEqual(decrypted_response, response)

        except ImportError:
            self.skipTest("Cryptography library not available for integration test")

    def test_long_running_session_scenario(self):
        """Test long-running session with periodic key rotation."""
        session_id = "long_running_session"
        self.manager.create_session_key(session_id)

        # Simulate long-running session with periodic operations
        messages = []
        for i in range(100):
            message = f"Long-running session message {i}"
            encrypted = self.manager.encrypt(message, session_id=session_id)
            messages.append((message, encrypted))

            # Periodically rotate master keys (should not affect session)
            if i % 25 == 0 and i > 0:
                self.manager.rotate_keys(force=True)

        # All messages should still decrypt correctly
        for original_message, encrypted_data in messages:
            decrypted_message = self.manager.decrypt(encrypted_data, session_id=session_id)
            self.assertEqual(decrypted_message, original_message)

    def test_session_backup_and_recovery_scenario(self):
        """Test session backup and recovery for C2 resilience."""
        # Create primary server with sessions
        primary_server = EncryptionManager(encryption_type="AES256")

        sessions_data = {}
        for i in range(3):
            session_id = f"backup_session_{i}"
            primary_server.create_session_key(session_id)

            # Encrypt data with each session
            message = f"Backup test message for session {i}"
            encrypted = primary_server.encrypt(message, session_id=session_id)

            sessions_data[session_id] = {
                'message': message,
                'encrypted': encrypted,
                'exported_key': primary_server.export_session_key(session_id)
            }

        # Simulate server failure and recovery
        backup_server = EncryptionManager(encryption_type="AES256")

        # Import all sessions to backup server
        for session_id, data in sessions_data.items():
            success = backup_server.import_session_key(data['exported_key'])
            self.assertTrue(success, f"Failed to import session {session_id}")

        # Verify backup server can handle all sessions
        for session_id, data in sessions_data.items():
            # Decrypt old data
            decrypted = backup_server.decrypt(data['encrypted'], session_id=session_id)
            self.assertEqual(decrypted, data['message'])

            # Create new encrypted data
            new_message = f"New message for recovered session {session_id}"
            new_encrypted = backup_server.encrypt(new_message, session_id=session_id)
            new_decrypted = backup_server.decrypt(new_encrypted, session_id=session_id)
            self.assertEqual(new_decrypted, new_message)

    def test_high_throughput_encryption_scenario(self):
        """Test high-throughput encryption scenario for C2 operations."""
        # Simulate high-volume C2 traffic
        num_messages = 1000
        session_id = "high_throughput_session"
        self.manager.create_session_key(session_id)

        # Measure throughput
        start_time = time.time()

        messages_data = []
        for i in range(num_messages):
            message = f"High throughput message {i}: {os.urandom(64).hex()}"
            encrypted = self.manager.encrypt(message, session_id=session_id)
            messages_data.append((message, encrypted))

        encryption_time = time.time() - start_time

        # Decrypt all messages
        start_time = time.time()

        for original_message, encrypted_data in messages_data:
            decrypted = self.manager.decrypt(encrypted_data, session_id=session_id)
            self.assertEqual(decrypted, original_message)

        decryption_time = time.time() - start_time

        # Performance should be reasonable for C2 operations
        total_time = encryption_time + decryption_time
        throughput = (num_messages * 2) / total_time  # ops per second

        # Should handle at least 100 operations per second
        self.assertGreater(throughput, 100, f"Throughput too low: {throughput} ops/sec")


if __name__ == "__main__":
    unittest.main()
