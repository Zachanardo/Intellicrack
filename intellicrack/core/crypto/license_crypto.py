"""License cryptographic operations for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any

from intellicrack.handlers.cryptography_handler import Cipher, algorithms, asym_padding, hashes, modes, rsa


DEFAULT_AES_KEY_SEED: bytes = b"intellicrack_license_key_2024"


class CryptoManager:
    """Cryptographic operations for license generation and validation.

    Provides RSA key generation, license key generation, RSA-PSS signature
    generation and verification, and AES-256-CBC encryption and decryption
    for license data protection.

    Attributes:
        logger: Logger instance for cryptographic operation tracking.
        private_key: RSA private key for signing operations.
        public_key: RSA public key for verification operations.
        aes_key: 256-bit AES key derived from seed for encryption.
    """

    def __init__(self, aes_key_seed: bytes = DEFAULT_AES_KEY_SEED) -> None:
        """Initialize cryptographic manager for license operations.

        Generates a 2048-bit RSA key pair for license signing and verification,
        and derives an AES encryption key from the provided seed for encrypting
        license data. Initializes logging for cryptographic operation tracking.

        Args:
            aes_key_seed: Seed bytes for deriving the AES-256 encryption key.
                         Defaults to the standard Intellicrack license key seed.
        """
        self.logger: logging.Logger = logging.getLogger(f"{__name__}.CryptoManager")
        self.private_key: Any = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key: Any = self.private_key.public_key()
        self.aes_key: bytes = hashlib.sha256(aes_key_seed).digest()

    def generate_license_key(self, product: str, license_type: str) -> str:
        """Generate cryptographically secure license key.

        Creates a unique license key by combining product identifier, license type,
        current timestamp, and random UUID, then hashing with SHA256 and formatting
        as a 16-character uppercase hex string with dashes.

        Args:
            product: Product identifier string for license binding.
            license_type: License type classification (e.g., 'perpetual',
                         'trial', 'subscription').

        Returns:
            Formatted license key string in format HHHH-HHHH-HHHH-HHHH
            (uppercase hexadecimal digits).
        """
        timestamp: int = int(time.time())
        random_data: str = uuid.uuid4().hex
        data: str = f"{product}:{license_type}:{timestamp}:{random_data}"
        key_hash: str = hashlib.sha256(data.encode()).hexdigest()
        return "-".join([key_hash[i : i + 4].upper() for i in range(0, 16, 4)])

    def sign_license_data(self, data: dict[str, Any]) -> str:
        """Sign license data using RSA-PSS signature with SHA256.

        Serializes the license data dictionary to JSON with sorted keys, then
        generates an RSA-PSS signature using the private key. Returns the
        signature as a hexadecimal string for transmission or storage.

        Args:
            data: License data dictionary containing key-value pairs to be signed.

        Returns:
            Hexadecimal-encoded RSA signature string, or empty string if
            signing fails.
        """
        try:
            json_data: bytes = json.dumps(data, sort_keys=True).encode()
            signature: bytes = self.private_key.sign(
                json_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return signature.hex()
        except Exception:
            self.logger.exception("License signing failed")
            return ""

    def verify_license_signature(self, data: dict[str, Any], signature: str) -> bool:
        """Verify RSA-PSS signature on license data using the public key.

        Serializes the license data dictionary to JSON with sorted keys, then
        validates the provided RSA-PSS signature against the data using the
        public key.

        Args:
            data: License data dictionary that was originally signed.
            signature: Hexadecimal-encoded RSA signature string to validate.

        Returns:
            True if signature is valid and matches the license data,
            False otherwise.
        """
        try:
            json_data: bytes = json.dumps(data, sort_keys=True).encode()
            signature_bytes: bytes = bytes.fromhex(signature)
            self.public_key.verify(
                signature_bytes,
                json_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def encrypt_license_data(self, data: str) -> str:
        """Encrypt license data using AES-256-CBC with PKCS7 padding.

        Generates a random 16-byte IV, encodes the data string to bytes, applies
        PKCS7 padding, then encrypts using AES-256 in CBC mode. Returns IV
        concatenated with encrypted data, both as hexadecimal.

        Args:
            data: License data string to encrypt.

        Returns:
            Hex-encoded string containing IV (first 32 hex chars) followed by
            encrypted data, or empty string if encryption fails.
        """
        try:
            iv: bytes = os.urandom(16)
            cipher: Any = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
            encryptor: Any = cipher.encryptor()
            padded_data: bytes = data.encode()
            padding_length: int = 16 - len(padded_data) % 16
            padded_data += bytes([padding_length]) * padding_length
            encrypted: bytes = encryptor.update(padded_data) + encryptor.finalize()
            return (iv + encrypted).hex()
        except Exception:
            self.logger.exception("License encryption failed")
            return ""

    def decrypt_license_data(self, encrypted_data: str) -> str:
        """Decrypt license data using AES-256-CBC with PKCS7 padding removal.

        Parses the hexadecimal input to extract the IV (first 16 bytes) and
        encrypted data portion, then decrypts using AES-256 in CBC mode.
        Removes PKCS7 padding from the decrypted plaintext and returns as
        a string.

        Args:
            encrypted_data: Hex-encoded encrypted data string with IV prepended.

        Returns:
            Decrypted license data string, or empty string if decryption fails.
        """
        try:
            data_bytes: bytes = bytes.fromhex(encrypted_data)
            iv: bytes = data_bytes[:16]
            encrypted: bytes = data_bytes[16:]
            cipher: Any = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
            decryptor: Any = cipher.decryptor()
            decrypted: bytes = decryptor.update(encrypted) + decryptor.finalize()
            padding_length: int = decrypted[-1]
            return decrypted[:-padding_length].decode()
        except Exception:
            self.logger.exception("License decryption failed")
            return ""
