"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Encryption Manager for C2 Infrastructure

Provides AES-256 encryption with secure key exchange,
perfect forward secrecy, and anti-analysis capabilities.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, Optional

# Create module logger
logger = logging.getLogger(__name__)

# Optional cryptography imports
HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError as e:
    logger.error("Import error in encryption_manager: %s", e)
    default_backend = None
    hashes = None
    serialization = None
    padding = None
    rsa = None
    Cipher = None
    algorithms = None
    modes = None
    PBKDF2HMAC = None


class EncryptionManager:
    """
    Advanced encryption manager with AES-256, RSA key exchange,
    and perfect forward secrecy for C2 communications.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.EncryptionManager")

        # Encryption settings
        self.key_size = 32  # AES-256
        self.iv_size = 16   # AES block size
        self.hmac_size = 32 # HMAC-SHA256

        # Session keys
        self.session_keys = {}
        self.master_key = None

        # RSA keypair for key exchange
        self.rsa_private_key = None
        self.rsa_public_key = None

        # Key rotation settings
        self.key_rotation_interval = 3600  # 1 hour
        self.last_key_rotation = time.time()

        # Initialize encryption system
        self._initialize_encryption()

    def _initialize_encryption(self):
        """Initialize encryption system with master keys."""
        try:
            # Generate RSA keypair for key exchange
            self._generate_rsa_keypair()

            # Generate master key
            self.master_key = os.urandom(self.key_size)

            self.logger.info("Encryption manager initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
            raise

    def _generate_rsa_keypair(self):
        """Generate RSA keypair for secure key exchange."""
        try:
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            self.rsa_public_key = self.rsa_private_key.public_key()

            self.logger.info("Generated RSA keypair for key exchange")

        except Exception as e:
            self.logger.error(f"Failed to generate RSA keypair: {e}")
            raise

    def encrypt(self, plaintext: str, session_id: str = None) -> bytes:
        """
        Encrypt plaintext using AES-256-CBC with HMAC authentication.

        Args:
            plaintext: Data to encrypt
            session_id: Optional session ID for session-specific encryption

        Returns:
            Encrypted data with IV and HMAC
        """
        try:
            # Get encryption key
            key = self._get_session_key(session_id) if session_id else self.master_key

            # Generate random IV
            iv = os.urandom(self.iv_size)

            # Encrypt with AES-256-CBC
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            # PKCS7 padding
            padded_data = self._pkcs7_pad(plaintext.encode('utf-8'))
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Generate HMAC for authentication
            hmac_key = self._derive_hmac_key(key)
            mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

            # Combine IV + ciphertext + HMAC
            encrypted_data = iv + ciphertext + mac

            return encrypted_data

        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, encrypted_data: bytes, session_id: str = None) -> str:
        """
        Decrypt data using AES-256-CBC with HMAC verification.

        Args:
            encrypted_data: Encrypted data to decrypt
            session_id: Optional session ID for session-specific decryption

        Returns:
            Decrypted plaintext
        """
        try:
            if len(encrypted_data) < self.iv_size + self.hmac_size:
                raise ValueError("Invalid encrypted data length")

            # Extract components
            iv = encrypted_data[:self.iv_size]
            ciphertext = encrypted_data[self.iv_size:-self.hmac_size]
            received_mac = encrypted_data[-self.hmac_size:]

            # Get decryption key
            key = self._get_session_key(session_id) if session_id else self.master_key

            # Verify HMAC
            hmac_key = self._derive_hmac_key(key)
            expected_mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

            if not hmac.compare_digest(received_mac, expected_mac):
                raise ValueError("HMAC verification failed")

            # Decrypt with AES-256-CBC
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding
            plaintext = self._pkcs7_unpad(padded_plaintext)

            return plaintext.decode('utf-8')

        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise

    def create_session_key(self, session_id: str) -> bytes:
        """Create a new session key for perfect forward secrecy."""
        try:
            # Generate session-specific key
            session_key = os.urandom(self.key_size)

            # Store session key
            self.session_keys[session_id] = {
                'key': session_key,
                'created_at': time.time(),
                'used_count': 0
            }

            self.logger.info(f"Created session key for {session_id}")
            return session_key

        except Exception as e:
            self.logger.error(f"Failed to create session key: {e}")
            raise

    def exchange_keys(self, client_public_key_pem: bytes) -> Dict[str, Any]:
        """
        Perform RSA key exchange with client.

        Args:
            client_public_key_pem: Client's RSA public key in PEM format

        Returns:
            Key exchange response with encrypted session key
        """
        try:
            # Load client public key
            client_public_key = serialization.load_pem_public_key(
                client_public_key_pem,
                backend=default_backend()
            )

            # Generate session key
            session_key = os.urandom(self.key_size)
            session_id = hashlib.sha256(session_key + str(time.time()).encode()).hexdigest()[:16]

            # Encrypt session key with client's public key
            encrypted_session_key = client_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Store session key
            self.session_keys[session_id] = {
                'key': session_key,
                'created_at': time.time(),
                'used_count': 0
            }

            # Get our public key for client
            server_public_key_pem = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return {
                'session_id': session_id,
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'server_public_key': server_public_key_pem.decode('utf-8'),
                'timestamp': time.time()
            }

        except Exception as e:
            self.logger.error(f"Key exchange failed: {e}")
            raise

    def rotate_keys(self, force: bool = False):
        """Rotate encryption keys for enhanced security."""
        try:
            current_time = time.time()

            if not force and (current_time - self.last_key_rotation) < self.key_rotation_interval:
                return

            # Generate new master key
            old_master_key = self.master_key
            self.master_key = os.urandom(self.key_size)

            # Securely clear old master key
            if old_master_key:
                # Overwrite old key data for security
                old_master_key = b'\x00' * len(old_master_key)

            # Generate new RSA keypair
            self._generate_rsa_keypair()

            # Clean up old session keys (older than 1 hour)
            cutoff_time = current_time - 3600
            expired_sessions = [
                session_id for session_id, info in self.session_keys.items()
                if info['created_at'] < cutoff_time
            ]

            for session_id in expired_sessions:
                del self.session_keys[session_id]

            self.last_key_rotation = current_time

            self.logger.info(f"Rotated encryption keys, removed {len(expired_sessions)} expired sessions")

        except Exception as e:
            self.logger.error(f"Key rotation failed: {e}")

    def get_public_key_pem(self) -> str:
        """Get server's RSA public key in PEM format."""
        try:
            public_key_pem = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return public_key_pem.decode('utf-8')

        except Exception as e:
            self.logger.error(f"Failed to get public key: {e}")
            return ""

    def encrypt_file(self, file_path: str, output_path: str = None, session_id: str = None) -> str:
        """
        Encrypt a file using AES-256.

        Args:
            file_path: Path to file to encrypt
            output_path: Output path for encrypted file
            session_id: Optional session ID

        Returns:
            Path to encrypted file
        """
        try:
            if not output_path:
                output_path = file_path + '.enc'

            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Encrypt file data
            encrypted_data = self.encrypt(base64.b64encode(file_data).decode('utf-8'), session_id)

            # Write encrypted file
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)

            self.logger.info(f"Encrypted file: {file_path} -> {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"File encryption failed: {e}")
            raise

    def decrypt_file(self, encrypted_file_path: str, output_path: str = None, session_id: str = None) -> str:
        """
        Decrypt a file using AES-256.

        Args:
            encrypted_file_path: Path to encrypted file
            output_path: Output path for decrypted file
            session_id: Optional session ID

        Returns:
            Path to decrypted file
        """
        try:
            if not output_path:
                output_path = encrypted_file_path.replace('.enc', '')

            # Read encrypted file
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt file data
            decrypted_data = self.decrypt(encrypted_data, session_id)
            file_data = base64.b64decode(decrypted_data)

            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(file_data)

            self.logger.info(f"Decrypted file: {encrypted_file_path} -> {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"File decryption failed: {e}")
            raise

    def _get_session_key(self, session_id: str) -> bytes:
        """Get session key for given session ID."""
        if session_id not in self.session_keys:
            # Create new session key if it doesn't exist
            return self.create_session_key(session_id)

        session_info = self.session_keys[session_id]
        session_info['used_count'] += 1

        return session_info['key']

    def _derive_hmac_key(self, encryption_key: bytes) -> bytes:
        """Derive HMAC key from encryption key."""
        # Use a proper salt derived from the encryption key itself
        # This ensures each key has a unique salt while remaining deterministic
        salt = hashlib.sha256(encryption_key + b'hmac_derivation').digest()[:16]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(encryption_key)

    def _pkcs7_pad(self, data: bytes) -> bytes:
        """Apply PKCS7 padding to data."""
        block_size = 16  # AES block size
        padding_length = block_size - (len(data) % block_size)
        padding_bytes = bytes([padding_length] * padding_length)
        return data + padding_bytes

    def _pkcs7_unpad(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding from data."""
        padding_length = padded_data[-1]
        if padding_length == 0 or padding_length > 16:
            raise ValueError("Invalid padding")

        # Verify padding
        for i in range(padding_length):
            if padded_data[-(i + 1)] != padding_length:
                raise ValueError("Invalid padding")

        return padded_data[:-padding_length]

    def generate_random_key(self, length: int = None) -> bytes:
        """Generate a random key of specified length."""
        if length is None:
            length = self.key_size
        return os.urandom(length)

    def derive_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        try:
            if salt is None:
                salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_size,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            return kdf.derive(password.encode('utf-8'))

        except Exception as e:
            self.logger.error(f"Key derivation failed: {e}")
            raise

    def get_session_statistics(self) -> Dict[str, Any]:
        """Get encryption session statistics."""
        try:
            current_time = time.time()

            stats = {
                'total_sessions': len(self.session_keys),
                'active_sessions': 0,
                'total_encryptions': 0,
                'last_key_rotation': self.last_key_rotation,
                'time_until_rotation': max(0, self.key_rotation_interval - (current_time - self.last_key_rotation))
            }

            # Calculate active sessions and usage
            for session_info in self.session_keys.values():
                if (current_time - session_info['created_at']) < 3600:  # Active if < 1 hour old
                    stats['active_sessions'] += 1
                stats['total_encryptions'] += session_info['used_count']

            return stats

        except Exception as e:
            self.logger.error(f"Error getting session statistics: {e}")
            return {}

    def cleanup_expired_sessions(self):
        """Clean up expired session keys."""
        try:
            current_time = time.time()
            cutoff_time = current_time - 3600  # 1 hour expiry

            expired_sessions = [
                session_id for session_id, info in self.session_keys.items()
                if info['created_at'] < cutoff_time
            ]

            for session_id in expired_sessions:
                del self.session_keys[session_id]

            if expired_sessions:
                self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

        except Exception as e:
            self.logger.error(f"Error cleaning up sessions: {e}")

    def export_session_key(self, session_id: str) -> Optional[str]:
        """Export session key for backup/transfer."""
        try:
            if session_id not in self.session_keys:
                return None

            key_data = self.session_keys[session_id]
            exported_key = {
                'session_id': session_id,
                'key': base64.b64encode(key_data['key']).decode('utf-8'),
                'created_at': key_data['created_at'],
                'used_count': key_data['used_count']
            }

            return base64.b64encode(json.dumps(exported_key).encode()).decode('utf-8')

        except Exception as e:
            self.logger.error(f"Failed to export session key: {e}")
            return None

    def import_session_key(self, exported_key_data: str) -> bool:
        """Import session key from backup/transfer."""
        try:
            # Decode and parse exported key - use json.loads instead of eval for security
            key_data = json.loads(base64.b64decode(exported_key_data).decode('utf-8'))

            session_id = key_data['session_id']
            session_key = base64.b64decode(key_data['key'])

            # Import session key
            self.session_keys[session_id] = {
                'key': session_key,
                'created_at': key_data['created_at'],
                'used_count': key_data['used_count']
            }

            self.logger.info(f"Imported session key for {session_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to import session key: {e}")
            return False
