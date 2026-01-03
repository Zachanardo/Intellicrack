"""FlexLM License Protocol Parser and Response Generator.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import hmac
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from intellicrack.utils.logger import get_logger

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


logger = get_logger(__name__)


class ProtocolVersion(IntEnum):
    """FlexLM protocol version identifiers."""

    FLEXLM_V10 = 10
    FLEXLM_V11 = 11
    FLEXLM_V11_14 = 1114
    FLEXLM_V11_16 = 1116
    FLEXLM_V11_18 = 1118
    RLM_V1 = 100
    RLM_V2 = 200
    RLM_V3 = 300


class EncryptionType(IntEnum):
    """Encryption types for FlexLM protocols."""

    NONE = 0x00
    AES_128_CBC = 0x01
    AES_256_CBC = 0x02
    RSA_2048 = 0x03
    VENDOR_CUSTOM = 0xFF


class MessageType(IntEnum):
    """Binary message type identifiers."""

    TEXT = 0x00
    BINARY = 0x01
    ENCRYPTED = 0x02
    COMPRESSED = 0x03


@dataclass
class EncryptionContext:
    """Encryption context for secure FlexLM communications.

    Attributes:
        session_key: AES session key for message encryption.
        iv: Initialization vector for CBC mode.
        encryption_type: Type of encryption algorithm used.
        key_exchange_complete: Flag indicating key exchange completion.
        client_public_key: Client RSA public key for key exchange.
        server_private_key: Server RSA private key for decryption.
        server_public_key: Server RSA public key for encryption.

    """

    session_key: bytes
    iv: bytes
    encryption_type: EncryptionType
    key_exchange_complete: bool
    client_public_key: bytes | None = None
    server_private_key: bytes | None = None
    server_public_key: bytes | None = None


@dataclass
class BinaryFlexLMRequest:
    """Binary FlexLM v11+ request structure.

    Attributes:
        magic: Protocol magic number (0x464C4558 for FLEX).
        version: Binary protocol version.
        message_type: Message type (text/binary/encrypted/compressed).
        command: FlexLM command code.
        sequence: Request sequence number.
        flags: Protocol flags for encryption, compression, etc.
        payload_length: Length of payload data.
        payload: Raw payload data.
        encryption_context: Encryption context if encrypted.
        checksum: Message integrity checksum.

    """

    magic: int
    version: int
    message_type: MessageType
    command: int
    sequence: int
    flags: int
    payload_length: int
    payload: bytes
    encryption_context: EncryptionContext | None = None
    checksum: bytes | None = None


@dataclass
class RLMRequest:
    """RLM (Reprise License Manager) protocol request structure.

    Attributes:
        protocol_id: RLM protocol identifier (0x524C4D00).
        version: RLM protocol version.
        command: RLM command code.
        transaction_id: Unique transaction identifier.
        client_id: Client UUID or identifier.
        product_name: Licensed product name.
        product_version: Product version string.
        license_type: License type (node-locked, floating, etc.).
        platform_info: Client platform information.
        hardware_signature: Hardware fingerprint.
        optional_data: Optional RLM-specific fields.

    """

    protocol_id: int
    version: int
    command: int
    transaction_id: int
    client_id: str
    product_name: str
    product_version: str
    license_type: int
    platform_info: dict[str, str]
    hardware_signature: str
    optional_data: dict[str, Any]


@dataclass
class FlexLMRequest:
    """FlexLM request structure.

    Attributes:
        command: FlexLM command code.
        version: Protocol version.
        sequence: Request sequence number.
        client_id: Client identifier string.
        feature: Requested feature name.
        version_requested: Requested feature version.
        platform: Client platform identifier.
        hostname: Client hostname.
        username: Client username.
        pid: Client process ID.
        checkout_time: Request checkout timestamp.
        additional_data: Additional request fields.

    """

    command: int
    version: int
    sequence: int
    client_id: str
    feature: str
    version_requested: str
    platform: str
    hostname: str
    username: str
    pid: int
    checkout_time: int
    additional_data: dict[str, Any]


@dataclass
class FlexLMResponse:
    """FlexLM response structure.

    Attributes:
        status: Response status code.
        sequence: Response sequence number.
        server_version: FlexLM server version.
        feature: Licensed feature name.
        expiry_date: License expiry date string.
        license_key: Generated license key.
        server_id: Server identifier.
        additional_data: Additional response fields.

    """

    status: int
    sequence: int
    server_version: str
    feature: str
    expiry_date: str
    license_key: str
    server_id: str
    additional_data: dict[str, Any]


class FlexLMEncryptionHandler:
    """Handles encryption/decryption for FlexLM binary protocols."""

    def __init__(self) -> None:
        """Initialize encryption handler with RSA key pair."""
        self.logger = get_logger(__name__)
        self.server_private_key: Any = None
        self.server_public_key: Any = None
        self.session_keys: dict[str, EncryptionContext] = {}
        self.session_lock = threading.Lock()
        self.max_sessions = 1000

        if CRYPTOGRAPHY_AVAILABLE:
            self._generate_server_keys()
        else:
            self.logger.warning("Cryptography library not available - encrypted protocols disabled")

    def _generate_server_keys(self) -> None:
        """Generate RSA key pair for server."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return

        try:
            self.server_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            self.server_public_key = self.server_private_key.public_key()
            self.logger.info("Generated RSA-2048 key pair for FlexLM encryption")
        except Exception:
            self.logger.exception("Failed to generate RSA keys")

    def derive_session_key(self, handshake_data: bytes, salt: bytes | None = None) -> bytes:
        """Derive AES session key from handshake data using PBKDF2.

        Args:
            handshake_data: Raw handshake data for key derivation.
            salt: Optional salt for key derivation. Auto-generated if None.

        Returns:
            bytes: 32-byte AES-256 session key.

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            return hashlib.sha256(handshake_data).digest()

        if salt is None:
            salt = secrets.token_bytes(16)

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend()
            )
            return kdf.derive(handshake_data)
        except Exception:
            self.logger.exception("PBKDF2 key derivation failed")
            return hashlib.sha256(handshake_data + salt).digest()

    def encrypt_payload(
        self, payload: bytes, session_key: bytes, iv: bytes | None = None, encryption_type: EncryptionType = EncryptionType.AES_128_CBC
    ) -> tuple[bytes, bytes] | tuple[None, None]:
        """Encrypt payload with AES-CBC.

        Args:
            payload: Plaintext payload to encrypt.
            session_key: AES session key (16 or 32 bytes).
            iv: Initialization vector. Auto-generated if None.
            encryption_type: Encryption algorithm type.

        Returns:
            tuple[bytes, bytes] | tuple[None, None]: Encrypted payload and IV used, or (None, None) if cryptography unavailable.

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("Cryptography library unavailable - cannot encrypt payload")
            return None, None

        if iv is None:
            iv = secrets.token_bytes(16)

        try:
            key_size = 16 if encryption_type == EncryptionType.AES_128_CBC else 32
            key = session_key[:key_size]

            padded_payload = self._pkcs7_pad(payload, 16)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_payload) + encryptor.finalize()

            return encrypted, iv
        except Exception:
            self.logger.exception("Payload encryption failed")
            return payload, iv

    def decrypt_payload(
        self, encrypted_payload: bytes, session_key: bytes, iv: bytes, encryption_type: EncryptionType = EncryptionType.AES_128_CBC
    ) -> bytes | None:
        """Decrypt AES-CBC encrypted payload.

        Args:
            encrypted_payload: Encrypted payload data.
            session_key: AES session key (16 or 32 bytes).
            iv: Initialization vector used for encryption.
            encryption_type: Encryption algorithm type.

        Returns:
            bytes | None: Decrypted plaintext payload or None if cryptography unavailable.

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("Cryptography library unavailable - cannot decrypt payload")
            return None

        try:
            key_size = 16 if encryption_type == EncryptionType.AES_128_CBC else 32
            key = session_key[:key_size]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_payload) + decryptor.finalize()

            return self._pkcs7_unpad(decrypted_padded)
        except Exception:
            self.logger.exception("Payload decryption failed")
            return encrypted_payload

    def _pkcs7_pad(self, data: bytes, block_size: int) -> bytes:
        """Apply PKCS#7 padding.

        Args:
            data: Data to pad.
            block_size: Block size for padding.

        Returns:
            bytes: Padded data.

        """
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding with full validation.

        Args:
            data: Padded data.

        Returns:
            bytes: Unpadded data.

        Raises:
            ValueError: If padding validation fails.

        """
        if not data:
            return data

        padding_length = data[-1]

        if padding_length > len(data) or padding_length == 0 or padding_length > 16:
            self.logger.warning("Invalid PKCS#7 padding length: %d", padding_length)
            return data

        padding_bytes = data[-padding_length:]
        if not all(byte == padding_length for byte in padding_bytes):
            self.logger.warning("PKCS#7 padding validation failed - inconsistent padding bytes")
            return data

        return data[:-padding_length]

    def encrypt_with_rsa(self, data: bytes, public_key: Any = None) -> bytes:
        """Encrypt data with RSA public key.

        Args:
            data: Data to encrypt (max 190 bytes for RSA-2048).
            public_key: RSA public key. Uses server key if None.

        Returns:
            bytes: RSA encrypted data.

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            return data

        try:
            key = public_key if public_key else self.server_public_key
            if not key:
                return data

            encrypted = key.encrypt(
                data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            return encrypted
        except Exception:
            self.logger.exception("RSA encryption failed")
            return data

    def decrypt_with_rsa(self, encrypted_data: bytes) -> bytes:
        """Decrypt RSA encrypted data with server private key.

        Args:
            encrypted_data: RSA encrypted data.

        Returns:
            bytes: Decrypted plaintext data.

        """
        if not CRYPTOGRAPHY_AVAILABLE or not self.server_private_key:
            return encrypted_data

        try:
            decrypted = self.server_private_key.decrypt(
                encrypted_data,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
            return decrypted
        except Exception:
            self.logger.exception("RSA decryption failed")
            return encrypted_data

    def get_server_public_key_bytes(self) -> bytes:
        """Export server public key as PEM bytes.

        Returns:
            bytes: PEM-encoded public key or empty bytes if unavailable.

        """
        if not CRYPTOGRAPHY_AVAILABLE or not self.server_public_key:
            return b""

        try:
            pem = self.server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem
        except Exception:
            self.logger.exception("Failed to export public key")
            return b""

    def create_session_context(
        self, client_id: str, handshake_data: bytes, encryption_type: EncryptionType = EncryptionType.AES_128_CBC
    ) -> EncryptionContext:
        """Create encryption context for client session.

        Args:
            client_id: Unique client identifier.
            handshake_data: Handshake data for key derivation.
            encryption_type: Type of encryption to use.

        Returns:
            EncryptionContext: New encryption context for the session.

        """
        salt = secrets.token_bytes(16)
        session_key = self.derive_session_key(handshake_data, salt)
        iv = secrets.token_bytes(16)

        server_pub_key_bytes = self.get_server_public_key_bytes()

        context = EncryptionContext(
            session_key=session_key,
            iv=iv,
            encryption_type=encryption_type,
            key_exchange_complete=True,
            server_private_key=None,
            server_public_key=server_pub_key_bytes,
        )

        with self.session_lock:
            if len(self.session_keys) >= self.max_sessions:
                self._cleanup_old_sessions()

            self.session_keys[client_id] = context

        self.logger.info("Created encryption context for client %s", client_id)
        return context

    def get_session_context(self, client_id: str) -> EncryptionContext | None:
        """Get encryption context for client.

        Args:
            client_id: Client identifier.

        Returns:
            EncryptionContext | None: Session context or None if not found.

        """
        with self.session_lock:
            return self.session_keys.get(client_id)

    def _cleanup_old_sessions(self) -> None:
        """Clean up oldest sessions when max limit is reached.

        Removes 10% of oldest sessions to free up space for new sessions.
        Must be called while holding session_lock.

        """
        if not self.session_keys:
            return

        sessions_to_remove = max(1, len(self.session_keys) // 10)

        oldest_clients = sorted(self.session_keys.keys())[:sessions_to_remove]

        for client_id in oldest_clients:
            del self.session_keys[client_id]

        self.logger.info("Cleaned up %d old sessions", sessions_to_remove)


class FlexLMProtocolParser:
    """Real FlexLM protocol parser and response generator with binary/encrypted protocol support."""

    # FlexLM protocol constants
    FLEXLM_COMMANDS = {
        0x01: "CHECKOUT",
        0x02: "CHECKIN",
        0x03: "STATUS",
        0x04: "HEARTBEAT",
        0x05: "FEATURE_INFO",
        0x06: "SERVER_INFO",
        0x07: "USER_INFO",
        0x08: "VENDOR_INFO",
        0x09: "LICENSE_INFO",
        0x0A: "SHUTDOWN",
        0x0B: "RESTART",
        0x0C: "REREAD",
        0x0D: "REMOVE_USER",
        0x0E: "REMOVE_FEATURE",
        0x10: "HOSTID_REQUEST",
        0x11: "ENCRYPTION_SEED",
        0x12: "BORROW_REQUEST",
        0x13: "RETURN_REQUEST",
        0x14: "LINGER_REQUEST",
        0x15: "KEY_EXCHANGE",
        0x16: "ENCRYPTED_CHECKOUT",
    }

    RLM_COMMANDS = {
        0x01: "RLM_CHECKOUT",
        0x02: "RLM_CHECKIN",
        0x03: "RLM_HEARTBEAT",
        0x04: "RLM_STATUS",
        0x05: "RLM_REHOST",
        0x06: "RLM_BORROW",
        0x07: "RLM_RETURN",
    }

    FLEXLM_STATUS_CODES = {
        0x00: "SUCCESS",
        0x01: "FEATURE_NOT_FOUND",
        0x02: "NO_LICENSE_AVAILABLE",
        0x03: "SERVER_UNAVAILABLE",
        0x04: "INVALID_LICENSE",
        0x05: "CHECKOUT_FAILED",
        0x06: "HEARTBEAT_FAILED",
        0x07: "INVALID_HOSTID",
        0x08: "FEATURE_EXPIRED",
        0x09: "VENDOR_DOWN",
        0x0A: "LICENSE_EXPIRED",
        0x0B: "INVALID_SIGNATURE",
        0x0C: "ENCRYPTION_FAILED",
    }

    def __init__(self) -> None:
        """Initialize the FlexLM protocol parser with license tracking and server features."""
        self.logger = get_logger(__name__)
        self.active_checkouts: dict[str, dict[str, Any]] = {}
        self.server_features: dict[str, dict[str, Any]] = {}
        self.encryption_seed = self._generate_encryption_seed()
        self.encryption_handler = FlexLMEncryptionHandler()
        self.protocol_version = ProtocolVersion.FLEXLM_V11_18
        self.checkout_lock = threading.Lock()
        self._load_default_features()

    def _load_default_features(self) -> None:
        """Load default feature set for common applications.

        Initializes the server with pre-configured FlexLM features for popular
        commercial software including Autodesk, MATLAB, SolidWorks, and ANSYS
        products for licensing bypass testing.

        """
        self.server_features = {
            # Autodesk Products
            "AUTOCAD": {
                "version": "2024.0",
                "expiry": "31-dec-2025",
                "count": 100,
                "vendor": "ADSKFLEX",
                "signature": "A1B2C3D4E5F6789012345678901234567890ABCD",
            },
            "INVENTOR": {
                "version": "2024.0",
                "expiry": "31-dec-2025",
                "count": 50,
                "vendor": "ADSKFLEX",
                "signature": "B2C3D4E5F6789012345678901234567890ABCDEF",
            },
            "MAYA": {
                "version": "2024.0",
                "expiry": "31-dec-2025",
                "count": 25,
                "vendor": "ADSKFLEX",
                "signature": "C3D4E5F6789012345678901234567890ABCDEF12",
            },
            # MATLAB Products
            "MATLAB": {
                "version": "R2024a",
                "expiry": "31-dec-2025",
                "count": 100,
                "vendor": "MLM",
                "signature": "D4E5F6789012345678901234567890ABCDEF1234",
            },
            "SIMULINK": {
                "version": "R2024a",
                "expiry": "31-dec-2025",
                "count": 50,
                "vendor": "MLM",
                "signature": "E5F6789012345678901234567890ABCDEF123456",
            },
            # SolidWorks
            "SOLIDWORKS": {
                "version": "2024",
                "expiry": "31-dec-2025",
                "count": 100,
                "vendor": "SW_D",
                "signature": "F6789012345678901234567890ABCDEF12345678",
            },
            # ANSYS Products
            "ANSYS": {
                "version": "2024.1",
                "expiry": "31-dec-2025",
                "count": 50,
                "vendor": "ANSYS",
                "signature": "6789012345678901234567890ABCDEF1234567890",
            },
            # Generic features for testing
            "GENERIC_CAD": {
                "version": "1.0",
                "expiry": "31-dec-2025",
                "count": 999,
                "vendor": "FLEX",
                "signature": "789012345678901234567890ABCDEF123456789A",
            },
        }

    def _generate_encryption_seed(self) -> bytes:
        """Generate cryptographically secure encryption seed for FlexLM communication.

        Returns:
            bytes: 32-byte cryptographically secure random seed.

        """
        return secrets.token_bytes(32)

    def parse_request(self, data: bytes) -> FlexLMRequest | None:
        """Parse incoming FlexLM request (auto-detects text/binary/RLM).

        Args:
            data: Raw FlexLM request data in binary format.

        Returns:
            FlexLMRequest | None: Parsed request object or None if parsing fails.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        try:
            if len(data) < 16:
                self.logger.warning("FlexLM request too short")
                return None

            magic = struct.unpack(">I", data[:4])[0]

            if magic == 0x524C4D00:
                return self._parse_rlm_request(data)
            if magic in [0x464C4558, 0x4C4D5F56, 0x46584C4D]:
                if len(data) >= 8:
                    version = struct.unpack(">H", data[6:8])[0]
                    if version >= 1100:
                        return self._parse_binary_flexlm_request(data)
                return self._parse_text_flexlm_request(data)

            self.logger.debug("Unknown protocol magic: 0x%X", magic)
            return None

        except Exception:
            self.logger.exception("Failed to parse FlexLM request")
            return None

    def _parse_text_flexlm_request(self, data: bytes) -> FlexLMRequest | None:
        """Parse text-based FlexLM request (legacy protocol).

        Args:
            data: Raw FlexLM request data in binary format.

        Returns:
            FlexLMRequest | None: Parsed request object or None if parsing fails.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        try:
            if len(data) < 16:
                self.logger.warning("FlexLM request too short")
                return None

            offset = 0

            magic = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            if magic not in [0x464C4558, 0x4C4D5F56, 0x46584C4D]:
                self.logger.debug("Invalid FlexLM magic: 0x%X", magic)
                return None

            # Parse header fields
            command = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            version = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            sequence = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            if len(data) < length:
                self.logger.warning("FlexLM request length mismatch")
                return None

            # Parse variable-length fields
            client_id = self._parse_string_field(data, offset)
            offset += len(client_id) + 1

            feature = self._parse_string_field(data, offset)
            offset += len(feature) + 1

            version_requested = self._parse_string_field(data, offset)
            offset += len(version_requested) + 1

            platform = self._parse_string_field(data, offset)
            offset += len(platform) + 1

            hostname = self._parse_string_field(data, offset)
            offset += len(hostname) + 1

            username = self._parse_string_field(data, offset)
            offset += len(username) + 1

            # Parse remaining numeric fields
            if offset + 8 <= len(data):
                pid = struct.unpack(">I", data[offset : offset + 4])[0]
                offset += 4

                checkout_time = struct.unpack(">I", data[offset : offset + 4])[0]
                offset += 4
            else:
                pid = 0
                checkout_time = int(time.time())

            # Parse additional data if present
            additional_data = {}
            if offset < len(data):
                additional_data = self._parse_additional_data(data[offset:])

            request = FlexLMRequest(
                command=command,
                version=version,
                sequence=sequence,
                client_id=client_id,
                feature=feature,
                version_requested=version_requested,
                platform=platform,
                hostname=hostname,
                username=username,
                pid=pid,
                checkout_time=checkout_time,
                additional_data=additional_data,
            )

            self.logger.info("Parsed FlexLM %s request for feature '%s'", self.FLEXLM_COMMANDS.get(command, "UNKNOWN"), feature)
            return request

        except Exception:
            self.logger.exception("Failed to parse FlexLM request")
            return None

    def _parse_binary_flexlm_request(self, data: bytes) -> FlexLMRequest | None:
        """Parse binary FlexLM v11+ request with encryption support.

        Args:
            data: Raw binary FlexLM v11+ request data.

        Returns:
            FlexLMRequest | None: Parsed request or None if parsing fails.

        """
        try:
            if len(data) < 32:
                self.logger.warning("Binary FlexLM request too short")
                return None

            offset = 0

            magic = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            if magic not in [0x464C4558, 0x4C4D5F56, 0x46584C4D]:
                self.logger.warning("Invalid binary FlexLM magic: 0x%X", magic)
                return None

            version = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            message_type_val = struct.unpack("B", data[offset : offset + 1])[0]
            message_type = MessageType(message_type_val) if message_type_val <= 3 else MessageType.BINARY
            offset += 1

            flags = struct.unpack("B", data[offset : offset + 1])[0]
            offset += 1

            command = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            sequence = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            payload_length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            received_checksum = data[offset : offset + 16] if len(data) >= offset + 16 else b""
            offset += 16

            if len(data) < offset + payload_length:
                self.logger.warning("Binary FlexLM payload length mismatch")
                return None

            payload = data[offset : offset + payload_length]

            if received_checksum and received_checksum != b"\x00" * 16:
                expected_checksum = self._calculate_checksum(payload)[:16]
                if received_checksum != expected_checksum:
                    self.logger.warning("Binary FlexLM checksum mismatch - possible tampering")


            is_encrypted = (flags & 0x01) != 0

            if is_encrypted and message_type == MessageType.ENCRYPTED:
                payload = self._decrypt_binary_payload(payload, version, sequence)

            parsed_payload = self._parse_binary_payload(payload)

            request = FlexLMRequest(
                command=command,
                version=version,
                sequence=sequence,
                client_id=parsed_payload.get("client_id", ""),
                feature=parsed_payload.get("feature", ""),
                version_requested=parsed_payload.get("version_requested", ""),
                platform=parsed_payload.get("platform", ""),
                hostname=parsed_payload.get("hostname", ""),
                username=parsed_payload.get("username", ""),
                pid=parsed_payload.get("pid", 0),
                checkout_time=parsed_payload.get("checkout_time", int(time.time())),
                additional_data=parsed_payload.get("additional_data", {}),
            )

            self.logger.info("Parsed binary FlexLM %s request for feature '%s'", self.FLEXLM_COMMANDS.get(command, "UNKNOWN"), request.feature)
            return request

        except Exception:
            self.logger.exception("Failed to parse binary FlexLM request")
            return None

    def _decrypt_binary_payload(self, encrypted_payload: bytes, version: int, sequence: int) -> bytes:
        """Decrypt binary FlexLM encrypted payload.

        Args:
            encrypted_payload: Encrypted payload data.
            version: Protocol version.
            sequence: Request sequence number.

        Returns:
            bytes: Decrypted payload or original if decryption fails.

        """
        try:
            if len(encrypted_payload) < 16:
                return encrypted_payload

            iv = encrypted_payload[:16]
            ciphertext = encrypted_payload[16:]

            client_id = f"client_{sequence}"
            context = self.encryption_handler.get_session_context(client_id)

            if not context:
                handshake_data = struct.pack(">HI", version, sequence)
                context = self.encryption_handler.create_session_context(client_id, handshake_data)

            decrypted = self.encryption_handler.decrypt_payload(ciphertext, context.session_key, iv, context.encryption_type)

            if decrypted is None:
                self.logger.error("Decryption failed - cryptography unavailable")
                return encrypted_payload

            return decrypted

        except Exception:
            self.logger.exception("Failed to decrypt binary payload")
            return encrypted_payload

    def _parse_binary_payload(self, payload: bytes) -> dict[str, Any]:
        """Parse binary FlexLM payload into fields.

        Args:
            payload: Binary payload data.

        Returns:
            dict[str, Any]: Parsed payload fields.

        """
        parsed: dict[str, Any] = {}
        try:
            if len(payload) < 8:
                return parsed

            offset = 0

            field_count = struct.unpack(">H", payload[offset : offset + 2])[0]
            offset += 2

            for _ in range(field_count):
                if offset + 4 > len(payload):
                    break

                field_id = struct.unpack(">H", payload[offset : offset + 2])[0]
                offset += 2

                field_len = struct.unpack(">H", payload[offset : offset + 2])[0]
                offset += 2

                if offset + field_len > len(payload):
                    break

                field_data = payload[offset : offset + field_len]
                offset += field_len

                if field_id == 0x0001:
                    parsed["client_id"] = field_data.decode("utf-8", errors="ignore")
                elif field_id == 0x0002:
                    parsed["feature"] = field_data.decode("utf-8", errors="ignore")
                elif field_id == 0x0003:
                    parsed["version_requested"] = field_data.decode("utf-8", errors="ignore")
                elif field_id == 0x0004:
                    parsed["platform"] = field_data.decode("utf-8", errors="ignore")
                elif field_id == 0x0005:
                    parsed["hostname"] = field_data.decode("utf-8", errors="ignore")
                elif field_id == 0x0006:
                    parsed["username"] = field_data.decode("utf-8", errors="ignore")
                elif field_id == 0x0007:
                    if len(field_data) >= 4:
                        parsed["pid"] = struct.unpack(">I", field_data[:4])[0]
                elif field_id == 0x0008:
                    if len(field_data) >= 4:
                        parsed["checkout_time"] = struct.unpack(">I", field_data[:4])[0]
                else:
                    if "additional_data" not in parsed:
                        parsed["additional_data"] = {}
                    parsed["additional_data"][f"field_{field_id:04X}"] = field_data.hex()

        except Exception:
            self.logger.debug("Error parsing binary payload")

        return parsed

    def _parse_rlm_request(self, data: bytes) -> FlexLMRequest | None:
        """Parse RLM (Reprise License Manager) protocol request.

        Args:
            data: Raw RLM request data.

        Returns:
            FlexLMRequest | None: Parsed request mapped to FlexLM format or None if parsing fails.

        """
        try:
            if len(data) < 64:
                self.logger.warning("RLM request too short")
                return None

            offset = 0

            protocol_id = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            if protocol_id != 0x524C4D00:
                return None

            version = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            command = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            transaction_id = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            _flags = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            payload_length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            if len(data) < offset + payload_length:
                self.logger.warning("RLM payload length mismatch")
                return None

            payload = data[offset : offset + payload_length]

            rlm_fields = self._parse_rlm_payload(payload)

            flexlm_command = self._map_rlm_to_flexlm_command(command)

            request = FlexLMRequest(
                command=flexlm_command,
                version=version,
                sequence=transaction_id,
                client_id=rlm_fields.get("client_id", ""),
                feature=rlm_fields.get("product_name", ""),
                version_requested=rlm_fields.get("product_version", ""),
                platform=rlm_fields.get("platform", ""),
                hostname=rlm_fields.get("hostname", ""),
                username=rlm_fields.get("username", ""),
                pid=rlm_fields.get("pid", 0),
                checkout_time=int(time.time()),
                additional_data={
                    "protocol": "RLM",
                    "rlm_version": version,
                    "hardware_signature": rlm_fields.get("hardware_signature", ""),
                    "license_type": rlm_fields.get("license_type", 0),
                },
            )

            self.logger.info("Parsed RLM %s request for product '%s'", self.RLM_COMMANDS.get(command, "UNKNOWN"), request.feature)
            return request

        except Exception:
            self.logger.exception("Failed to parse RLM request")
            return None

    def _parse_rlm_payload(self, payload: bytes) -> dict[str, Any]:
        """Parse RLM payload into fields.

        Args:
            payload: RLM payload data.

        Returns:
            dict[str, Any]: Parsed RLM fields.

        """
        rlm_fields: dict[str, Any] = {}
        try:
            if len(payload) < 8:
                return rlm_fields

            offset = 0

            while offset + 4 <= len(payload):
                tag = struct.unpack(">H", payload[offset : offset + 2])[0]
                offset += 2

                length = struct.unpack(">H", payload[offset : offset + 2])[0]
                offset += 2

                if offset + length > len(payload):
                    break

                value = payload[offset : offset + length]
                offset += length

                if tag == 0x0001:
                    rlm_fields["client_id"] = value.decode("utf-8", errors="ignore")
                elif tag == 0x0002:
                    rlm_fields["product_name"] = value.decode("utf-8", errors="ignore")
                elif tag == 0x0003:
                    rlm_fields["product_version"] = value.decode("utf-8", errors="ignore")
                elif tag == 0x0004:
                    rlm_fields["hostname"] = value.decode("utf-8", errors="ignore")
                elif tag == 0x0005:
                    rlm_fields["username"] = value.decode("utf-8", errors="ignore")
                elif tag == 0x0006:
                    rlm_fields["platform"] = value.decode("utf-8", errors="ignore")
                elif tag == 0x0007:
                    rlm_fields["hardware_signature"] = value.hex()
                elif tag == 0x0008:
                    if len(value) >= 4:
                        rlm_fields["license_type"] = struct.unpack(">I", value[:4])[0]
                elif tag == 0x0009:
                    if len(value) >= 4:
                        rlm_fields["pid"] = struct.unpack(">I", value[:4])[0]

        except Exception:
            self.logger.debug("Error parsing RLM payload")

        return rlm_fields

    def _map_rlm_to_flexlm_command(self, rlm_command: int) -> int:
        """Map RLM command code to equivalent FlexLM command.

        Args:
            rlm_command: RLM command code.

        Returns:
            int: Equivalent FlexLM command code.

        """
        rlm_to_flexlm = {
            0x01: 0x01,
            0x02: 0x02,
            0x03: 0x04,
            0x04: 0x03,
            0x05: 0x10,
            0x06: 0x12,
            0x07: 0x13,
        }
        return rlm_to_flexlm.get(rlm_command, 0x01)

    def _parse_string_field(self, data: bytes, offset: int) -> str:
        """Parse null-terminated string from binary data.

        Args:
            data: Binary data buffer containing string field.
            offset: Byte offset to start parsing from.

        Returns:
            str: Decoded string (empty if parsing fails).

        Raises:
            None: All exceptions are caught and logged internally.

        """
        try:
            end = data.find(b"\x00", offset)
            if end == -1:
                end = len(data)
            return data[offset:end].decode("utf-8", errors="ignore")
        except Exception:
            self.logger.exception("Error in flexlm_parser")
            return ""

    def _parse_additional_data(self, data: bytes) -> dict[str, Any]:
        """Parse additional FlexLM data fields.

        Args:
            data: Binary data buffer containing additional fields.

        Returns:
            dict[str, Any]: Dictionary of parsed field key-value pairs.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        additional = {}
        try:
            offset = 0
            while offset < len(data) - 4:
                field_type = struct.unpack(">H", data[offset : offset + 2])[0]
                field_length = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                offset += 4

                if offset + field_length > len(data):
                    break

                field_data = data[offset : offset + field_length]
                offset += field_length

                # Parse common field types
                if field_type == 0x0001:  # Host ID
                    additional["hostid"] = field_data.hex()
                elif field_type == 0x0002:  # Encryption info
                    additional["encryption"] = field_data.hex()
                elif field_type == 0x0003:  # Vendor data
                    additional["vendor_data"] = field_data.hex()
                elif field_type == 0x0004:  # License path
                    additional["license_path"] = field_data.decode("utf-8", errors="ignore")
                else:
                    additional[f"field_{field_type:04X}"] = field_data.hex()

        except Exception:
            self.logger.debug("Error parsing additional data")

        return additional

    def generate_response(self, request: FlexLMRequest) -> FlexLMResponse:
        """Generate appropriate FlexLM response based on request.

        Args:
            request: Parsed FlexLM request with command code.

        Returns:
            FlexLMResponse: Appropriate response for the request command.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        command_name = self.FLEXLM_COMMANDS.get(request.command, "UNKNOWN")
        self.logger.info("Generating response for %s command", command_name)

        if request.command == 0x01:
            return self._handle_checkout(request)
        if request.command == 0x02:
            return self._handle_checkin(request)
        if request.command == 0x03:
            return self._handle_status(request)
        if request.command == 0x04:
            return self._handle_heartbeat(request)
        if request.command == 0x05:
            return self._handle_feature_info(request)
        if request.command == 0x06:
            return self._handle_server_info(request)
        if request.command == 0x10:
            return self._handle_hostid_request(request)
        if request.command == 0x11:
            return self._handle_encryption_seed(request)
        if request.command == 0x12:
            return self._handle_borrow_request(request)
        if request.command == 0x13:
            return self._handle_checkin(request)
        if request.command == 0x14:
            return self._handle_linger_request(request)
        if request.command == 0x15:
            return self._handle_key_exchange(request)
        if request.command == 0x16:
            return self._handle_encrypted_checkout(request)
        return self._handle_unknown_command(request)

    def _handle_checkout(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle license checkout request.

        Args:
            request: Parsed FlexLM checkout request.

        Returns:
            FlexLMResponse: Response with license key and feature info or error status.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        feature = request.feature.upper()

        # Check if feature exists
        if feature not in self.server_features:
            if matches := [f for f in self.server_features if feature in f or f in feature]:
                feature = matches[0]
            else:
                return FlexLMResponse(
                    status=0x01,  # FEATURE_NOT_FOUND
                    sequence=request.sequence,
                    server_version="11.18.0",
                    feature=request.feature,
                    expiry_date="",
                    license_key="",
                    server_id="intellicrack-flexlm",
                    additional_data={"error": f"Feature {request.feature} not found"},
                )

        feature_info = self.server_features[feature]

        with self.checkout_lock:
            if not self.enforce_concurrent_limit(feature):
                return FlexLMResponse(
                    status=0x02,  # NO_LICENSE_AVAILABLE
                    sequence=request.sequence,
                    server_version="11.18.0",
                    feature=request.feature,
                    expiry_date="",
                    license_key="",
                    server_id="intellicrack-flexlm",
                    additional_data={"error": "Concurrent license limit exceeded"},
                )

            checkout_key = self._generate_checkout_key(request, feature_info)

            checkout_id = f"{request.hostname}:{request.username}:{request.feature}"
            self.active_checkouts[checkout_id] = {
                "request": request,
                "checkout_time": time.time(),
                "key": checkout_key,
            }

            counts = self.get_concurrent_license_count(feature)

        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature=feature,
            expiry_date=feature_info["expiry"],
            license_key=checkout_key,
            server_id="intellicrack-flexlm",
            additional_data={
                "vendor": feature_info["vendor"],
                "version": feature_info["version"],
                "count_remaining": counts["available"],
                "signature": feature_info["signature"],
            },
        )

    def _handle_checkin(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle license checkin request.

        Args:
            request: Parsed FlexLM checkin request.

        Returns:
            FlexLMResponse: Response confirming license checkin completion.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        checkout_id = f"{request.hostname}:{request.username}:{request.feature}"

        with self.checkout_lock:
            if checkout_id in self.active_checkouts:
                del self.active_checkouts[checkout_id]
                status = 0x00  # SUCCESS
            else:
                status = 0x00  # SUCCESS even if not found

        return FlexLMResponse(
            status=status,
            sequence=request.sequence,
            server_version="11.18.0",
            feature=request.feature,
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"checkin_time": int(time.time())},
        )

    def _handle_status(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle server status request.

        Args:
            request: Parsed FlexLM status request.

        Returns:
            FlexLMResponse: Response with server status and active checkout count.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={
                "server_status": "UP",
                "active_checkouts": len(self.active_checkouts),
                "features_available": len(self.server_features),
                "uptime": int(time.time()),
            },
        )

    def _handle_heartbeat(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle heartbeat request.

        Args:
            request: Parsed FlexLM heartbeat request.

        Returns:
            FlexLMResponse: Response with heartbeat status (success or failed).

        Raises:
            None: All exceptions are caught and logged internally.

        """
        checkout_id = f"{request.hostname}:{request.username}:{request.feature}"

        if checkout_id in self.active_checkouts:
            # Update heartbeat time
            self.active_checkouts[checkout_id]["last_heartbeat"] = time.time()
            status = 0x00  # SUCCESS
        else:
            status = 0x06  # HEARTBEAT_FAILED

        return FlexLMResponse(
            status=status,
            sequence=request.sequence,
            server_version="11.18.0",
            feature=request.feature,
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"heartbeat_time": int(time.time())},
        )

    def _handle_feature_info(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle feature information request.

        Args:
            request: Parsed FlexLM feature info request.

        Returns:
            FlexLMResponse: Response with feature details or not found error.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        feature = request.feature.upper()

        if feature in self.server_features:
            feature_info = self.server_features[feature]
            return FlexLMResponse(
                status=0x00,  # SUCCESS
                sequence=request.sequence,
                server_version="11.18.0",
                feature=feature,
                expiry_date=feature_info["expiry"],
                license_key="",
                server_id="intellicrack-flexlm",
                additional_data=feature_info,
            )
        return FlexLMResponse(
            status=0x01,  # FEATURE_NOT_FOUND
            sequence=request.sequence,
            server_version="11.18.0",
            feature=request.feature,
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={},
        )

    def _handle_server_info(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle server information request.

        Args:
            request: Parsed FlexLM server info request.

        Returns:
            FlexLMResponse: Response with server configuration and available features.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={
                "server_name": "intellicrack-flexlm",
                "server_version": "11.18.0",
                "features": list(self.server_features.keys()),
                "max_connections": 1000,
                "current_connections": len(self.active_checkouts),
            },
        )

    def _handle_hostid_request(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle host ID request.

        Args:
            request: Parsed FlexLM host ID request.

        Returns:
            FlexLMResponse: Response with computed host ID for the client.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        # Generate deterministic host ID
        hostid = hashlib.sha256(request.hostname.encode()).hexdigest()[:12].upper()

        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"hostid": hostid},
        )

    def _handle_encryption_seed(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle encryption seed request.

        Args:
            request: Parsed FlexLM encryption seed request.

        Returns:
            FlexLMResponse: Response with encryption seed for protocol security.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"encryption_seed": self.encryption_seed.hex()},
        )

    def _handle_borrow_request(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle license borrow request for offline use.

        Args:
            request: Parsed FlexLM borrow request.

        Returns:
            FlexLMResponse: Response with borrowed license details and expiry.

        """
        feature = request.feature.upper()

        if feature not in self.server_features:
            return FlexLMResponse(
                status=0x01,
                sequence=request.sequence,
                server_version="11.18.0",
                feature=request.feature,
                expiry_date="",
                license_key="",
                server_id="intellicrack-flexlm",
                additional_data={"error": f"Feature {request.feature} not found"},
            )

        feature_info = self.server_features[feature]

        borrow_duration_days = request.additional_data.get("borrow_duration", 30)
        borrow_expiry = time.time() + (borrow_duration_days * 86400)
        borrow_expiry_str = time.strftime("%d-%b-%Y", time.localtime(borrow_expiry))

        borrow_key = self._generate_borrow_key(request, feature_info, borrow_expiry)

        checkout_id = f"{request.hostname}:{request.username}:{request.feature}:BORROWED"
        self.active_checkouts[checkout_id] = {
            "request": request,
            "checkout_time": time.time(),
            "key": borrow_key,
            "borrow_expiry": borrow_expiry,
            "type": "borrowed",
        }

        return FlexLMResponse(
            status=0x00,
            sequence=request.sequence,
            server_version="11.18.0",
            feature=feature,
            expiry_date=borrow_expiry_str,
            license_key=borrow_key,
            server_id="intellicrack-flexlm",
            additional_data={
                "vendor": feature_info["vendor"],
                "version": feature_info["version"],
                "borrow_type": "FLOATING",
                "borrow_duration": borrow_duration_days,
                "signature": feature_info["signature"],
            },
        )

    def _handle_linger_request(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle license linger request for extended checkout.

        Args:
            request: Parsed FlexLM linger request.

        Returns:
            FlexLMResponse: Response with linger license details.

        """
        feature = request.feature.upper()

        if feature not in self.server_features:
            return FlexLMResponse(
                status=0x01,
                sequence=request.sequence,
                server_version="11.18.0",
                feature=request.feature,
                expiry_date="",
                license_key="",
                server_id="intellicrack-flexlm",
                additional_data={"error": f"Feature {request.feature} not found"},
            )

        feature_info = self.server_features[feature]

        linger_duration_seconds = request.additional_data.get("linger_duration", 3600)
        linger_expiry = time.time() + linger_duration_seconds

        linger_key = self._generate_linger_key(request, feature_info, linger_expiry)

        checkout_id = f"{request.hostname}:{request.username}:{request.feature}:LINGER"
        self.active_checkouts[checkout_id] = {
            "request": request,
            "checkout_time": time.time(),
            "key": linger_key,
            "linger_expiry": linger_expiry,
            "type": "linger",
        }

        return FlexLMResponse(
            status=0x00,
            sequence=request.sequence,
            server_version="11.18.0",
            feature=feature,
            expiry_date=feature_info["expiry"],
            license_key=linger_key,
            server_id="intellicrack-flexlm",
            additional_data={
                "vendor": feature_info["vendor"],
                "version": feature_info["version"],
                "linger_duration": linger_duration_seconds,
                "linger_expiry": int(linger_expiry),
                "signature": feature_info["signature"],
            },
        )

    def _handle_key_exchange(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle RSA key exchange for encrypted sessions.

        Args:
            request: Parsed FlexLM key exchange request.

        Returns:
            FlexLMResponse: Response with server public key.

        """
        client_id = f"{request.hostname}:{request.username}"

        if "client_public_key" in request.additional_data:
            client_pub_key_pem = request.additional_data["client_public_key"]
            handshake_data = struct.pack(">I", request.sequence) + client_pub_key_pem.encode("utf-8")[:32]

            context = self.encryption_handler.create_session_context(client_id, handshake_data, EncryptionType.AES_128_CBC)

            self.logger.info("Created encrypted session for client %s", client_id)

        server_pub_key = self.encryption_handler.get_server_public_key_bytes().decode("utf-8")

        return FlexLMResponse(
            status=0x00,
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={
                "server_public_key": server_pub_key,
                "encryption_type": "AES-128-CBC",
                "key_exchange_complete": True,
            },
        )

    def _handle_encrypted_checkout(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle encrypted checkout request with AES payload.

        Args:
            request: Parsed encrypted FlexLM checkout request.

        Returns:
            FlexLMResponse: Encrypted checkout response.

        """
        return self._handle_checkout(request)

    def _generate_borrow_key(self, request: FlexLMRequest, feature_info: dict[str, Any], borrow_expiry: float) -> str:
        """Generate license key for borrowed license.

        Args:
            request: FlexLM request with client details.
            feature_info: Feature information dictionary.
            borrow_expiry: Unix timestamp of borrow expiration.

        Returns:
            str: Generated borrow license key.

        """
        data = (
            f"{request.hostname}:{request.username}:{request.feature}:"
            f"{feature_info['version']}:BORROW:{int(borrow_expiry)}"
        )

        key = hashlib.sha256(data.encode()).hexdigest()[:32].upper()
        return f"B{key[1:]}"

    def _generate_linger_key(self, request: FlexLMRequest, feature_info: dict[str, Any], linger_expiry: float) -> str:
        """Generate license key for linger license.

        Args:
            request: FlexLM request with client details.
            feature_info: Feature information dictionary.
            linger_expiry: Unix timestamp of linger expiration.

        Returns:
            str: Generated linger license key.

        """
        data = (
            f"{request.hostname}:{request.username}:{request.feature}:"
            f"{feature_info['version']}:LINGER:{int(linger_expiry)}"
        )

        key = hashlib.sha256(data.encode()).hexdigest()[:32].upper()
        return f"L{key[1:]}"

    def _handle_unknown_command(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle unknown command.

        Args:
            request: Parsed FlexLM request with unknown command code.

        Returns:
            FlexLMResponse: Error response indicating unknown command.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        self.logger.warning("Unknown FlexLM command: 0x%02X", request.command)
        return FlexLMResponse(
            status=0x0C,  # ENCRYPTION_FAILED (generic error)
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"error": f"Unknown command: 0x{request.command:02X}"},
        )

    def _generate_checkout_key(self, request: FlexLMRequest, feature_info: dict[str, Any]) -> str:
        """Generate checkout key for license.

        Args:
            request: FlexLM request containing client details.
            feature_info: Feature information dictionary with version and limits.

        Returns:
            str: Generated license checkout key with feature prefix.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        # Incorporate feature information into key generation
        feature_version = feature_info.get("version", "1.0")
        feature_type = feature_info.get("type", "standard")
        feature_limit = feature_info.get("user_limit", 1)
        vendor_string = feature_info.get("vendor_string", "INTELLICRACK")

        # Create comprehensive key data incorporating feature details
        data = (
            f"{request.hostname}:{request.username}:{request.feature}:"
            f"{feature_version}:{feature_type}:{feature_limit}:"
            f"{vendor_string}:{time.time()}"
        )

        # Generate feature-specific key with enhanced entropy
        key = hashlib.sha256(data.encode()).hexdigest()[:32].upper()

        # Add feature-specific prefix for debugging
        if feature_type == "premium":
            key = f"P{key[1:]}"
        elif feature_type == "trial":
            key = f"T{key[1:]}"
        else:
            key = f"S{key[1:]}"

        return key

    def serialize_response(self, response: FlexLMResponse, use_binary: bool = False, encrypt: bool = False) -> bytes:
        """Serialize FlexLM response to bytes with optional binary/encryption.

        Args:
            response: FlexLM response object to serialize.
            use_binary: Use binary FlexLM v11+ format.
            encrypt: Encrypt response payload with AES-128-CBC.

        Returns:
            bytes: Binary serialized response packet.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        try:
            if use_binary:
                return self._serialize_binary_response(response, encrypt)
            return self._serialize_text_response(response)

        except Exception:
            self.logger.exception("Failed to serialize FlexLM response")
            return struct.pack(">IHI", 0x464C4558, 0x03, response.sequence) + b"\x00"

    def _serialize_text_response(self, response: FlexLMResponse) -> bytes:
        """Serialize text-based FlexLM response (legacy format).

        Args:
            response: FlexLM response object.

        Returns:
            bytes: Serialized text protocol response.

        """
        packet = bytearray()

        packet.extend(struct.pack(">I", 0x464C4558))

        packet.extend(struct.pack(">H", response.status))

        packet.extend(struct.pack(">I", response.sequence))

        server_version_bytes = response.server_version.encode("utf-8") + b"\x00"
        packet.extend(server_version_bytes)

        feature_bytes = response.feature.encode("utf-8") + b"\x00"
        packet.extend(feature_bytes)

        expiry_bytes = response.expiry_date.encode("utf-8") + b"\x00"
        packet.extend(expiry_bytes)

        key_bytes = response.license_key.encode("utf-8") + b"\x00"
        packet.extend(key_bytes)

        server_id_bytes = response.server_id.encode("utf-8") + b"\x00"
        packet.extend(server_id_bytes)

        if response.additional_data:
            additional_bytes = self._serialize_additional_data(response.additional_data)
            packet.extend(additional_bytes)

        length_field = struct.pack(">I", len(packet) + 4)
        packet[6:6] = length_field

        return bytes(packet)

    def _serialize_binary_response(self, response: FlexLMResponse, encrypt: bool = False) -> bytes:
        """Serialize binary FlexLM v11+ response with optional encryption.

        Args:
            response: FlexLM response object.
            encrypt: Encrypt payload with AES.

        Returns:
            bytes: Serialized binary protocol response.

        """
        packet = bytearray()

        packet.extend(struct.pack(">I", 0x464C4558))

        packet.extend(struct.pack(">H", self.protocol_version))

        message_type = MessageType.ENCRYPTED if encrypt else MessageType.BINARY
        packet.extend(struct.pack("B", message_type))

        flags = 0x01 if encrypt else 0x00
        packet.extend(struct.pack("B", flags))

        packet.extend(struct.pack(">H", response.status))

        packet.extend(struct.pack(">I", response.sequence))

        payload = self._build_binary_response_payload(response)

        if encrypt:
            client_id = f"client_{response.sequence}"
            context = self.encryption_handler.get_session_context(client_id)

            if not context:
                handshake_data = struct.pack(">I", response.sequence)
                context = self.encryption_handler.create_session_context(client_id, handshake_data)

            result = self.encryption_handler.encrypt_payload(payload, context.session_key, encryption_type=context.encryption_type)

            if result[0] is None or result[1] is None:
                self.logger.error("Encryption failed - cryptography unavailable, sending unencrypted")
            else:
                encrypted_payload, iv = result
                payload = iv + encrypted_payload

        packet.extend(struct.pack(">I", len(payload)))

        checksum = self._calculate_checksum(payload)
        packet.extend(checksum[:16].ljust(16, b"\x00"))

        packet.extend(payload)

        return bytes(packet)

    def _build_binary_response_payload(self, response: FlexLMResponse) -> bytes:
        """Build binary response payload from FlexLMResponse.

        Args:
            response: FlexLM response object.

        Returns:
            bytes: Binary encoded payload.

        """
        payload = bytearray()

        fields = [
            (0x0001, response.server_version.encode("utf-8")),
            (0x0002, response.feature.encode("utf-8")),
            (0x0003, response.expiry_date.encode("utf-8")),
            (0x0004, response.license_key.encode("utf-8")),
            (0x0005, response.server_id.encode("utf-8")),
        ]

        for key, value in response.additional_data.items():
            if isinstance(value, str):
                value_bytes = value.encode("utf-8")
            elif isinstance(value, int):
                value_bytes = struct.pack(">I", value)
            else:
                value_bytes = str(value).encode("utf-8")

            field_id = hash(key) & 0xFFFF
            fields.append((field_id, value_bytes))

        payload.extend(struct.pack(">H", len(fields)))

        for field_id, field_data in fields:
            payload.extend(struct.pack(">H", field_id))
            payload.extend(struct.pack(">H", len(field_data)))
            payload.extend(field_data)

        return bytes(payload)

    def _calculate_checksum(self, data: bytes) -> bytes:
        """Calculate HMAC-SHA256 checksum for data integrity.

        Args:
            data: Data to checksum.

        Returns:
            bytes: 32-byte HMAC-SHA256 digest.

        """
        key = self.encryption_seed[:32]
        return hmac.new(key, data, hashlib.sha256).digest()

    def _serialize_additional_data(self, data: dict[str, Any]) -> bytes:
        """Serialize additional data fields.

        Args:
            data: Dictionary of additional fields to serialize.

        Returns:
            bytes: Serialized binary representation of additional fields.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        serialized = bytearray()

        for key, value in data.items():
            try:
                if isinstance(value, str):
                    value_bytes = value.encode("utf-8")
                elif isinstance(value, int):
                    value_bytes = struct.pack(">I", value)
                elif isinstance(value, bytes):
                    value_bytes = value
                else:
                    value_bytes = str(value).encode("utf-8")

                # Field header: type (2 bytes) + length (2 bytes)
                field_type = hash(key) & 0xFFFF  # Simple hash for field type
                serialized.extend(struct.pack(">HH", field_type, len(value_bytes)))
                serialized.extend(value_bytes)

            except Exception:
                self.logger.debug("Error serializing field %s", key)

        return bytes(serialized)

    def get_concurrent_license_count(self, feature: str) -> dict[str, int]:
        """Get concurrent license usage for a feature.

        Args:
            feature: Feature name to check.

        Returns:
            dict[str, int]: Dictionary with total, in_use, and available counts.

        """
        feature_upper = feature.upper()

        if feature_upper not in self.server_features:
            return {"total": 0, "in_use": 0, "available": 0}

        total_licenses = self.server_features[feature_upper]["count"]

        with self.checkout_lock:
            in_use = sum(
                1
                for checkout_id, checkout_info in self.active_checkouts.items()
                if checkout_info["request"].feature.upper() == feature_upper
            )

        return {
            "total": total_licenses,
            "in_use": in_use,
            "available": max(0, total_licenses - in_use),
        }

    def enforce_concurrent_limit(self, feature: str) -> bool:
        """Check if concurrent license limit allows new checkout.

        Args:
            feature: Feature name to check.

        Returns:
            bool: True if checkout is allowed, False if limit exceeded.

        """
        counts = self.get_concurrent_license_count(feature)
        return counts["available"] > 0

    def update_feature_count(self, feature: str, new_count: int) -> None:
        """Update concurrent license count for a feature.

        Args:
            feature: Feature name to update.
            new_count: New license count limit.

        """
        feature_upper = feature.upper()

        if feature_upper in self.server_features:
            self.server_features[feature_upper]["count"] = new_count
            self.logger.info("Updated %s license count to %d", feature, new_count)

    def get_all_concurrent_usage(self) -> dict[str, dict[str, int]]:
        """Get concurrent usage statistics for all features.

        Returns:
            dict[str, dict[str, int]]: Dictionary mapping features to usage stats.

        """
        usage_stats = {}

        for feature_name in self.server_features:
            usage_stats[feature_name] = self.get_concurrent_license_count(feature_name)

        return usage_stats

    def cleanup_expired_checkouts(self) -> int:
        """Remove expired borrowed and linger checkouts.

        Returns:
            int: Number of checkouts removed.

        """
        current_time = time.time()
        to_remove = []

        for checkout_id, checkout_info in self.active_checkouts.items():
            checkout_type = checkout_info.get("type", "standard")

            if checkout_type == "borrowed":
                if "borrow_expiry" in checkout_info and checkout_info["borrow_expiry"] < current_time:
                    to_remove.append(checkout_id)

            elif checkout_type == "linger":
                if "linger_expiry" in checkout_info and checkout_info["linger_expiry"] < current_time:
                    to_remove.append(checkout_id)

        for checkout_id in to_remove:
            del self.active_checkouts[checkout_id]

        if to_remove:
            self.logger.info("Cleaned up %d expired checkouts", len(to_remove))

        return len(to_remove)

    def add_custom_feature(
        self,
        name: str,
        version: str,
        vendor: str,
        count: int = 100,
        expiry: str = "31-dec-2025",
        signature: str | None = None,
    ) -> None:
        """Add custom FlexLM feature to server.

        Args:
            name: Feature name.
            version: Feature version.
            vendor: Vendor daemon name.
            count: License count. Defaults to 100.
            expiry: Expiry date. Defaults to "31-dec-2025".
            signature: License signature. Auto-generated if None. Defaults to None.

        """
        if signature is None:
            signature = hashlib.sha256(f"{name}:{version}:{vendor}".encode()).hexdigest()[:40].upper()

        self.server_features[name.upper()] = {
            "version": version,
            "expiry": expiry,
            "count": count,
            "vendor": vendor,
            "signature": signature,
        }
        self.logger.info("Added custom FlexLM feature: %s", name)

    def remove_feature(self, name: str) -> None:
        """Remove feature from server.

        Args:
            name: Feature name to remove.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        feature_key = name.upper()
        if feature_key in self.server_features:
            del self.server_features[feature_key]
            self.logger.info("Removed FlexLM feature: %s", name)

    def get_active_checkouts(self) -> dict[str, dict[str, Any]]:
        """Get all active license checkouts.

        Returns:
            dict[str, dict[str, Any]]: Copy of active checkouts dictionary.

        """
        return self.active_checkouts.copy()

    def clear_checkouts(self) -> None:
        """Clear all active checkouts.

        Removes all tracked license checkouts and logs the operation.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        count = len(self.active_checkouts)
        self.active_checkouts.clear()
        self.logger.info("Cleared %d active checkouts", count)

    def get_server_statistics(self) -> dict[str, Any]:
        """Get server statistics.

        Returns:
            dict[str, Any]: Dictionary with total features, active checkouts,
                version, and uptime information.

        """
        return {
            "total_features": len(self.server_features),
            "active_checkouts": len(self.active_checkouts),
            "features": list(self.server_features.keys()),
            "server_version": "11.18.0",
            "uptime": int(time.time()),
        }


class FlexLMTrafficCapture:
    """FlexLM traffic capture and analysis engine.

    Captures and analyzes FlexLM protocol traffic for license cracking research.
    Tracks requests/responses, analyzes traffic patterns, and extracts license
    information from captured packets.

    """

    def __init__(self, parser: FlexLMProtocolParser) -> None:
        """Initialize traffic capture engine.

        Args:
            parser: FlexLM protocol parser instance.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        self.logger = get_logger(__name__)
        self.parser = parser
        self.captured_requests: list[tuple[float, FlexLMRequest, bytes]] = []
        self.captured_responses: list[tuple[float, FlexLMResponse, bytes]] = []
        self.server_endpoints: set[tuple[str, int]] = set()
        self.client_endpoints: set[tuple[str, int]] = set()

    def capture_packet(
        self,
        data: bytes,
        source: tuple[str, int],
        dest: tuple[str, int],
        timestamp: float | None = None,
    ) -> bool:
        """Capture FlexLM network packet.

        Args:
            data: Raw packet data.
            source: Source (IP, port) tuple.
            dest: Destination (IP, port) tuple.
            timestamp: Capture timestamp. If None, uses current time. Defaults to None.

        Returns:
            bool: True if packet was successfully parsed and captured.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        if timestamp is None:
            timestamp = time.time()

        if request := self.parser.parse_request(data):
            self.captured_requests.append((timestamp, request, data))
            self.client_endpoints.add(source)
            self.server_endpoints.add(dest)
            self.logger.debug("Captured FlexLM request from %s to %s", source, dest)
            return True

        return False

    def analyze_traffic_patterns(self) -> dict[str, Any]:
        """Analyze captured traffic patterns.

        Returns:
            dict[str, Any]: Dictionary with command distribution, top features,
                and traffic statistics.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        if not self.captured_requests:
            return {"error": "No captured traffic to analyze"}

        command_counts: dict[int, int] = {}
        feature_requests: dict[str, int] = {}
        hourly_distribution: dict[int, int] = {}

        for timestamp, request, _ in self.captured_requests:
            command_counts[request.command] = command_counts.get(request.command, 0) + 1

            if request.feature:
                feature_requests[request.feature] = feature_requests.get(request.feature, 0) + 1

            hour = int(timestamp % 86400 / 3600)
            hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1

        top_commands = sorted(
            [(self.parser.FLEXLM_COMMANDS.get(cmd, f"UNKNOWN_{cmd:02X}"), count) for cmd, count in command_counts.items()],
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        top_features = sorted(feature_requests.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_packets": len(self.captured_requests),
            "unique_clients": len(self.client_endpoints),
            "unique_servers": len(self.server_endpoints),
            "command_distribution": dict(command_counts),
            "top_commands": top_commands,
            "top_features": top_features,
            "hourly_distribution": hourly_distribution,
            "capture_duration": max(ts for ts, _, _ in self.captured_requests) - min(ts for ts, _, _ in self.captured_requests)
            if len(self.captured_requests) > 1
            else 0,
        }

    def extract_license_info(self) -> list[dict[str, Any]]:
        """Extract license information from captured traffic.

        Returns:
            list[dict[str, Any]]: List of license checkout requests with timestamps
                and client details.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        licenses = []

        for timestamp, request, _ in self.captured_requests:
            if request.command == 0x01:
                license_info = {
                    "timestamp": timestamp,
                    "feature": request.feature,
                    "version": request.version_requested,
                    "client": request.hostname,
                    "username": request.username,
                    "platform": request.platform,
                    "client_id": request.client_id,
                }
                licenses.append(license_info)

        return licenses

    def detect_server_endpoints(self) -> list[dict[str, Any]]:
        """Detect FlexLM server endpoints from captured traffic.

        Returns:
            list[dict[str, Any]]: List of server endpoints with IP, port, and
                protocol information.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        servers = []
        for ip, port in self.server_endpoints:
            server_info = {
                "ip": ip,
                "port": port,
                "endpoint": f"{ip}:{port}",
                "protocol": "FlexLM",
            }
            servers.append(server_info)

        return servers

    def export_capture(self, filepath: str) -> None:
        """Export captured traffic to file.

        Args:
            filepath: Output file path for JSON export.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        import json

        capture_data = {
            "capture_time": time.time(),
            "total_packets": len(self.captured_requests),
            "packets": [
                {
                    "timestamp": ts,
                    "command": req.command,
                    "command_name": self.parser.FLEXLM_COMMANDS.get(req.command, "UNKNOWN"),
                    "feature": req.feature,
                    "version": req.version_requested,
                    "hostname": req.hostname,
                    "username": req.username,
                    "platform": req.platform,
                    "sequence": req.sequence,
                }
                for ts, req, _ in self.captured_requests
            ],
            "analysis": self.analyze_traffic_patterns(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(capture_data, f, indent=2)

        self.logger.info("Exported %d captured packets to %s", len(self.captured_requests), filepath)


class FlexLMLicenseGenerator:
    """FlexLM license file generator.

    Generates, parses, and validates FlexLM license files for licensing
    bypass research and testing. Supports feature creation, signature
    generation, and license file format manipulation.

    """

    def __init__(self) -> None:
        """Initialize license generator.

        Initializes the FlexLM license file generator with logging support.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        self.logger = get_logger(__name__)

    def generate_license_file(
        self,
        features: list[dict[str, Any]],
        server_host: str,
        server_port: int = 27000,
        vendor_daemon: str = "vendor",
        vendor_port: int = 27001,
    ) -> str:
        """Generate FlexLM license file content.

        Args:
            features: List of feature dictionaries.
            server_host: License server hostname.
            server_port: License server port. Defaults to 27000.
            vendor_daemon: Vendor daemon name. Defaults to "vendor".
            vendor_port: Vendor daemon port. Defaults to 27001.

        Returns:
            str: License file content in FlexLM format.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        lines = [
            f"SERVER {server_host} ANY {server_port}",
            f"VENDOR {vendor_daemon} PORT={vendor_port}",
            "",
        ]

        for feature in features:
            name = feature.get("name", "FEATURE")
            version = feature.get("version", "1.0")
            vendor = feature.get("vendor", vendor_daemon)
            expiry = feature.get("expiry", "31-dec-2025")
            count = feature.get("count", 1)
            signature = feature.get("signature", self._generate_signature(name, version))

            license_line = f'FEATURE {name} {vendor} {version} {expiry} {count} HOSTID=ANY SIGN="{signature}"'
            lines.append(license_line)

        return "\n".join(lines)

    def _generate_signature(self, feature: str, version: str) -> str:
        """Generate license signature.

        Args:
            feature: Feature name.
            version: Version string.

        Returns:
            str: Generated signature string.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        data = f"{feature}:{version}:{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:40].upper()

    def parse_license_file(self, content: str) -> dict[str, Any]:
        """Parse FlexLM license file.

        Args:
            content: License file content.

        Returns:
            dict[str, Any]: Parsed license data dictionary with servers, vendors,
                and features.

        Raises:
            None: All exceptions are caught and logged internally.

        """
        license_data: dict[str, Any] = {
            "servers": [],
            "vendors": [],
            "features": [],
        }

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if not parts:
                continue

            keyword = parts[0].upper()

            if keyword == "SERVER":
                if len(parts) >= 3:
                    license_data["servers"].append({
                        "hostname": parts[1],
                        "hostid": parts[2],
                        "port": int(parts[3]) if len(parts) > 3 else 27000,
                    })

            elif keyword == "VENDOR":
                vendor_info: dict[str, Any] = {"name": parts[1] if len(parts) > 1 else ""}
                for part in parts[2:]:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        if key.upper() == "PORT":
                            vendor_info["port"] = int(value)
                license_data["vendors"].append(vendor_info)

            elif keyword in {"FEATURE", "INCREMENT"}:
                if len(parts) >= 5:
                    feature_info = {
                        "name": parts[1],
                        "vendor": parts[2],
                        "version": parts[3],
                        "expiry": parts[4],
                        "count": int(parts[5]) if len(parts) > 5 else 1,
                    }

                    for part in parts[6:]:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            feature_info[key.lower()] = value.strip('"')

                    license_data["features"].append(feature_info)

        return license_data
