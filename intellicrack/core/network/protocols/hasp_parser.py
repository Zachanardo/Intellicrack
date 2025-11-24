"""HASP/Sentinel License Protocol Parser and Response Generator.

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
import json
import secrets
import socket
import struct
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC
from enum import IntEnum
from pathlib import Path
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


class HASPNetworkProtocol:
    """HASP network protocol constants and packet types."""

    UDP_DISCOVERY_PORT = 1947
    TCP_LICENSE_PORT = 1947
    BROADCAST_PORT = 475

    DISCOVERY_MAGIC = b"HASP_DISCOVER_"
    SERVER_READY_MAGIC = b"HASP_SERVER_READY"
    LOGIN_PACKET_TYPE = b"LOGIN"
    LOGOUT_PACKET_TYPE = b"LOGOUT"
    HEARTBEAT_PACKET_TYPE = b"HEARTBEAT"
    ENCRYPT_PACKET_TYPE = b"ENCRYPT"
    DECRYPT_PACKET_TYPE = b"DECRYPT"


class HASPUSBProtocol:
    """HASP USB dongle protocol constants."""

    USB_VENDOR_ID = 0x0529
    USB_PRODUCT_IDS = [0x0001, 0x0002, 0x0003, 0x0004]

    CONTROL_TRANSFER_TYPE = 0x21
    INTERRUPT_TRANSFER_TYPE = 0x81

    CMD_READ_MEMORY = 0x01
    CMD_WRITE_MEMORY = 0x02
    CMD_ENCRYPT = 0x03
    CMD_DECRYPT = 0x04
    CMD_GET_INFO = 0x05
    CMD_GET_RTC = 0x06


class HASPCommandType(IntEnum):
    """HASP command types."""

    LOGIN = 0x01
    LOGOUT = 0x02
    ENCRYPT = 0x03
    DECRYPT = 0x04
    GET_SIZE = 0x05
    READ = 0x06
    WRITE = 0x07
    GET_RTC = 0x08
    SET_RTC = 0x09
    GET_INFO = 0x0A
    UPDATE = 0x0B
    GET_SESSION_INFO = 0x0C
    LEGACY_ENCRYPT = 0x0D
    LEGACY_DECRYPT = 0x0E
    FEATURE_LOGIN = 0x10
    FEATURE_LOGOUT = 0x11
    GET_FEATURE_INFO = 0x12
    HEARTBEAT = 0x13
    TRANSFER_DATA = 0x14
    GET_HARDWARE_INFO = 0x15
    GET_SESSIONINFO = 0x16
    DATETIME = 0x17
    LEGACY_SET_RTC = 0x18
    LEGACY_SET_TIME = 0x19
    GET_SESSIONINFO_LEGACY = 0x1A


class HASPStatusCode(IntEnum):
    """HASP status codes."""

    STATUS_OK = 0x00000000
    MEM_RANGE = 0x00000001
    INV_VCODE = 0x00000002
    INV_SPEC = 0x00000003
    INV_MEM = 0x00000004
    FEATURE_NOT_FOUND = 0x00000005
    NO_DRIVER = 0x00000006
    NO_HASP = 0x00000007
    TOO_MANY_USERS = 0x00000008
    INV_ACCESS = 0x00000009
    INV_PORT = 0x0000000A
    INV_FILENAME = 0x0000000B
    ENC_NOT_SUPP = 0x0000000C
    INV_UPDATE = 0x0000000D
    KEY_NOT_FOUND = 0x0000000E
    ALREADY_LOGGED_IN = 0x0000000F
    NOT_LOGGED_IN = 0x00000010
    FEATURE_EXPIRED = 0x00000011
    CLOCK_ROLLBACK = 0x00000012
    INVALID_VENDOR_CODE = 0x00000013
    SCOPE_RESULTS_EMPTY = 0x00000014
    INSUF_MEM = 0x00000015
    TMO = 0x00000016
    BROKEN_SESSION = 0x00000017
    LOCAL_COMM_ERR = 0x00000018
    UNKNOWN_VCODE = 0x00000019
    INV_VXML = 0x0000001A
    DEVICE_ERR = 0x0000001B
    UPDATE_TOO_OLD = 0x0000001C
    UPDATE_TOO_NEW = 0x0000001D
    OLD_LM = 0x0000001E
    NO_ACK_SPACE = 0x0000001F
    TS_DETECTED = 0x00000020
    FEATURE_TYPE_NOT_IMPL = 0x00000021
    CLONE_DETECTED = 0x00000022
    UPDATE_ALREADY_ADDED = 0x00000023
    HARDWARE_MODIFIED = 0x00000024
    USER_DENIED = 0x00000025
    NO_DRIVER_SUPPORT = 0x00000026


class HASPFeatureType(IntEnum):
    """HASP feature types."""

    DEFAULT = 0x00
    PERPETUAL = 0x01
    EXPIRATION = 0x02
    MAINTENANCE = 0x03
    DETACHABLE = 0x04
    COUNTED = 0x05
    CONCURRENT = 0x06
    TRIAL = 0x07
    GRACE = 0x08


class HASPEncryptionType(IntEnum):
    """HASP encryption types."""

    NONE = 0x00
    AES128 = 0x01
    AES256 = 0x02
    RSA1024 = 0x03
    RSA2048 = 0x04
    HASP4 = 0x05
    ENVELOPE = 0x06


@dataclass
class HASPRequest:
    """HASP/Sentinel request structure."""

    command: int
    session_id: int
    feature_id: int
    vendor_code: int
    scope: str
    format: str
    client_info: dict[str, Any]
    encryption_data: bytes
    additional_params: dict[str, Any]
    packet_version: int = 1
    sequence_number: int = 0
    encryption_type: int = HASPEncryptionType.NONE
    signature: bytes = b""
    timestamp: int = 0


@dataclass
class HASPResponse:
    """HASP/Sentinel response structure."""

    status: int
    session_id: int
    feature_id: int
    license_data: dict[str, Any]
    encryption_response: bytes
    expiry_info: dict[str, Any]
    hardware_info: dict[str, Any]
    packet_version: int = 1
    sequence_number: int = 0
    signature: bytes = b""


@dataclass
class HASPSession:
    """HASP session information."""

    session_id: int
    vendor_code: int
    feature_id: int
    login_time: float
    last_heartbeat: float
    client_info: dict[str, Any]
    encryption_key: bytes
    login_count: int = 1
    feature_handle: int = 0
    concurrent_users: int = 1
    detachable: bool = False
    detached_time: int = 0


@dataclass
class HASPPacketCapture:
    """Captured HASP network packet structure."""

    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_type: str
    raw_data: bytes
    parsed_request: HASPRequest | None = None
    parsed_response: HASPResponse | None = None


@dataclass
class HASPFeature:
    """HASP feature definition."""

    feature_id: int
    name: str
    vendor_code: int
    feature_type: HASPFeatureType
    expiry: str
    max_users: int
    encryption_supported: bool
    memory_size: int
    rtc_supported: bool
    hardware_key: bool = True
    network_enabled: bool = True
    detachable: bool = False
    detachable_duration: int = 0
    license_data: dict[str, Any] = field(default_factory=dict)
    protection_key: bytes = b""
    concurrent_limit: int = -1


class HASPCrypto:
    """HASP cryptographic operations handler."""

    def __init__(self) -> None:
        """Initialize HASP crypto handler with keys."""
        self.aes_keys: dict[int, bytes] = {}
        self.rsa_keys: dict[int, tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]] = {}
        self.hasp4_seeds: dict[int, int] = {}
        self._initialize_default_keys()

    def _initialize_default_keys(self) -> None:
        """Initialize default cryptographic keys."""
        default_aes_key = hashlib.sha256(b"HASP_DEFAULT_AES256_KEY").digest()
        self.aes_keys[0] = default_aes_key

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        self.rsa_keys[0] = (private_key, public_key)

    def generate_session_key(self, session_id: int, vendor_code: int) -> bytes:
        """Generate session-specific AES key."""
        key_material = f"{session_id}:{vendor_code}:{time.time()}".encode()
        session_key = hashlib.sha256(key_material).digest()
        self.aes_keys[session_id] = session_key
        return session_key

    def aes_encrypt(self, data: bytes, session_id: int = 0) -> bytes:
        """Encrypt data using AES-256-CBC."""
        if session_id not in self.aes_keys:
            session_id = 0

        key = self.aes_keys[session_id]
        iv = secrets.token_bytes(16)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    def aes_decrypt(self, data: bytes, session_id: int = 0) -> bytes:
        """Decrypt data using AES-256-CBC."""
        if len(data) < 16:
            return data

        if session_id not in self.aes_keys:
            session_id = 0

        key = self.aes_keys[session_id]
        iv = data[:16]
        ciphertext = data[16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        if len(padded_plaintext) > 0:
            padding_length = padded_plaintext[-1]
            if 1 <= padding_length <= 16:
                return padded_plaintext[:-padding_length]

        return padded_plaintext

    def rsa_sign(self, data: bytes, session_id: int = 0) -> bytes:
        """Sign data using RSA-PSS."""
        if session_id not in self.rsa_keys:
            session_id = 0

        private_key, _ = self.rsa_keys[session_id]

        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def rsa_verify(self, data: bytes, signature: bytes, session_id: int = 0) -> bool:
        """Verify RSA signature."""
        try:
            if session_id not in self.rsa_keys:
                session_id = 0

            _, public_key = self.rsa_keys[session_id]

            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def hasp4_encrypt(self, data: bytes, seed: int) -> bytes:
        """HASP4 legacy encryption algorithm."""
        key_stream = self._generate_hasp4_keystream(seed, len(data))
        encrypted = bytearray()

        for i, byte in enumerate(data):
            encrypted.append(byte ^ key_stream[i])

        return bytes(encrypted)

    def hasp4_decrypt(self, data: bytes, seed: int) -> bytes:
        """HASP4 legacy decryption (same as encryption for stream cipher)."""
        return self.hasp4_encrypt(data, seed)

    def _generate_hasp4_keystream(self, seed: int, length: int) -> bytes:
        """Generate HASP4 keystream using LFSR-based PRNG."""
        state = seed & 0xFFFFFFFF
        keystream = bytearray()

        for _ in range(length):
            output = state & 0xFF
            keystream.append(output)

            bit = ((state >> 31) ^ (state >> 21) ^ (state >> 1) ^ (state >> 0)) & 1
            state = ((state << 1) | bit) & 0xFFFFFFFF

        return bytes(keystream)

    def envelope_encrypt(self, data: bytes, session_id: int = 0) -> bytes:
        """Envelope encryption: RSA for session key + AES for data."""
        session_key = secrets.token_bytes(32)

        if session_id not in self.rsa_keys:
            session_id = 0

        _, public_key = self.rsa_keys[session_id]

        encrypted_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        iv = secrets.token_bytes(16)
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        result = struct.pack("<H", len(encrypted_key))
        result += encrypted_key
        result += iv
        result += encrypted_data

        return result

    def envelope_decrypt(self, data: bytes, session_id: int = 0) -> bytes:
        """Envelope decryption."""
        if len(data) < 2:
            return data

        key_length = struct.unpack("<H", data[:2])[0]
        offset = 2

        if len(data) < offset + key_length + 16:
            return data

        encrypted_key = data[offset : offset + key_length]
        offset += key_length

        iv = data[offset : offset + 16]
        offset += 16

        encrypted_data = data[offset:]

        if session_id not in self.rsa_keys:
            session_id = 0

        private_key, _ = self.rsa_keys[session_id]

        session_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        cipher = Cipher(
            algorithms.AES(session_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

        if len(padded_plaintext) > 0:
            padding_length = padded_plaintext[-1]
            if 1 <= padding_length <= 16:
                return padded_plaintext[:-padding_length]

        return padded_plaintext


class HASPSentinelParser:
    """Production-ready HASP/Sentinel protocol parser and emulator."""

    VENDOR_CODES = {
        0x12345678: "AUTODESK",
        0x87654321: "BENTLEY",
        0x11223344: "SIEMENS",
        0x44332211: "DASSAULT",
        0x56789ABC: "ANSYS",
        0xABC56789: "ALTIUM",
        0x13579BDF: "CADENCE",
        0xBDF13579: "SYNOPSYS",
        0x2468ACE0: "MENTOR",
        0xACE02468: "GENERIC",
        0x88776655: "ADOBE",
        0x55667788: "COREL",
        0xAABBCCDD: "PTCPRO",
        0xDDCCBBAA: "SOLIDWORKS",
    }

    def __init__(self) -> None:
        """Initialize HASP Sentinel parser with full protocol support."""
        self.logger = get_logger(__name__)
        self.active_sessions: dict[int, HASPSession] = {}
        self.features: dict[int, HASPFeature] = {}
        self.crypto = HASPCrypto()
        self.hardware_fingerprint = self._generate_hardware_fingerprint()
        self.memory_storage: dict[int, bytearray] = {}
        self.sequence_numbers: dict[int, int] = {}
        self._initialize_default_features()

    def _initialize_default_features(self) -> None:
        """Initialize default HASP features for major applications."""
        default_features = [
            HASPFeature(
                feature_id=100,
                name="AUTOCAD_FULL",
                vendor_code=0x12345678,
                feature_type=HASPFeatureType.PERPETUAL,
                expiry="31-dec-2025",
                max_users=100,
                encryption_supported=True,
                memory_size=4096,
                rtc_supported=True,
                network_enabled=True,
                concurrent_limit=100,
                license_data={"version": "2024", "type": "network"},
            ),
            HASPFeature(
                feature_id=101,
                name="INVENTOR_PRO",
                vendor_code=0x12345678,
                feature_type=HASPFeatureType.CONCURRENT,
                expiry="31-dec-2025",
                max_users=50,
                encryption_supported=True,
                memory_size=2048,
                rtc_supported=True,
                concurrent_limit=50,
            ),
            HASPFeature(
                feature_id=200,
                name="MICROSTATION",
                vendor_code=0x87654321,
                feature_type=HASPFeatureType.PERPETUAL,
                expiry="31-dec-2025",
                max_users=100,
                encryption_supported=True,
                memory_size=8192,
                rtc_supported=True,
                concurrent_limit=100,
            ),
            HASPFeature(
                feature_id=300,
                name="NX_ADVANCED",
                vendor_code=0x11223344,
                feature_type=HASPFeatureType.PERPETUAL,
                expiry="31-dec-2025",
                max_users=50,
                encryption_supported=True,
                memory_size=4096,
                rtc_supported=True,
                detachable=True,
                detachable_duration=86400,
                concurrent_limit=50,
            ),
            HASPFeature(
                feature_id=400,
                name="ANSYS_MECHANICAL",
                vendor_code=0x56789ABC,
                feature_type=HASPFeatureType.COUNTED,
                expiry="31-dec-2025",
                max_users=25,
                encryption_supported=True,
                memory_size=2048,
                rtc_supported=False,
                concurrent_limit=25,
            ),
            HASPFeature(
                feature_id=500,
                name="SOLIDWORKS_PREMIUM",
                vendor_code=0xDDCCBBAA,
                feature_type=HASPFeatureType.PERPETUAL,
                expiry="permanent",
                max_users=1,
                encryption_supported=True,
                memory_size=4096,
                rtc_supported=True,
                hardware_key=True,
                network_enabled=False,
            ),
            HASPFeature(
                feature_id=999,
                name="GENERIC_FEATURE",
                vendor_code=0xACE02468,
                feature_type=HASPFeatureType.PERPETUAL,
                expiry="permanent",
                max_users=999,
                encryption_supported=True,
                memory_size=16384,
                rtc_supported=True,
                concurrent_limit=-1,
            ),
        ]

        for feature in default_features:
            self.features[feature.feature_id] = feature
            self.memory_storage[feature.feature_id] = bytearray(feature.memory_size)
            self._initialize_feature_memory(feature.feature_id)

    def _initialize_feature_memory(self, feature_id: int) -> None:
        """Initialize HASP memory with realistic data."""
        if feature_id not in self.memory_storage:
            return

        memory = self.memory_storage[feature_id]
        feature = self.features[feature_id]

        memory[:4] = struct.pack("<I", feature.vendor_code)
        memory[4:8] = struct.pack("<I", feature.feature_id)
        memory[8:12] = struct.pack("<I", int(time.time()))
        memory[12:16] = struct.pack("<I", feature.max_users)

        license_string = f"{feature.name}:{feature.expiry}".encode()
        memory[16 : 16 + len(license_string)] = license_string

        for i in range(256, len(memory)):
            memory[i] = (i * 13 + 37) & 0xFF

    def _generate_hardware_fingerprint(self) -> dict[str, Any]:
        """Generate realistic HASP hardware fingerprint."""
        hasp_id = secrets.randbelow(900000) + 100000

        return {
            "hasp_id": hasp_id,
            "type": "HASP HL Max",
            "memory": 65536,
            "battery": True,
            "rtc": True,
            "serial": f"H{secrets.randbelow(90000000) + 10000000}",
            "firmware": "4.05",
            "hardware_version": "HL Max Pro",
            "interface": "USB 2.0",
            "encryption_engines": ["AES-256", "RSA-2048", "HASP4"],
            "features_supported": len(self.features),
            "network_capable": True,
            "detachable_capable": True,
        }

    def parse_request(self, data: bytes) -> HASPRequest | None:
        """Parse incoming HASP/Sentinel request with full protocol support.

        Args:
            data: Raw HASP request packet

        Returns:
            Parsed HASPRequest object or None if invalid

        """
        self.logger.debug(f"Starting HASP request parsing, data length: {len(data)}")
        try:
            if len(data) < 24:
                self.logger.warning("HASP request too short")
                return None

            offset = 0

            magic = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            if magic not in [0x48415350, 0x53454E54, 0x484C4D58, 0x48535350]:
                self.logger.debug(f"Invalid HASP magic: 0x{magic:X}")
                return None

            packet_version = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            sequence_number = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            command = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            session_id = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            feature_id = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            vendor_code = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            encryption_type = struct.unpack("<B", data[offset : offset + 1])[0]
            offset += 1

            timestamp = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            scope_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            if offset + scope_length > len(data):
                return None

            scope = data[offset : offset + scope_length].decode("utf-8", errors="ignore")
            offset += scope_length

            format_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            if offset + format_length > len(data):
                return None

            format_str = data[offset : offset + format_length].decode("utf-8", errors="ignore")
            offset += format_length

            client_info_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            client_info = {}
            if client_info_length > 0 and offset + client_info_length <= len(data):
                try:
                    client_info_json = data[offset : offset + client_info_length].decode("utf-8")
                    client_info = json.loads(client_info_json)
                except Exception as e:
                    self.logger.debug(f"Failed to parse client info: {e}")
                offset += client_info_length

            encryption_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            encryption_data = b""
            if encryption_length > 0 and offset + encryption_length <= len(data):
                encryption_data = data[offset : offset + encryption_length]
                offset += encryption_length

            signature_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            signature = b""
            if signature_length > 0 and offset + signature_length <= len(data):
                signature = data[offset : offset + signature_length]
                offset += signature_length

            additional_params = {}
            if offset < len(data):
                additional_params = self._parse_additional_params(data[offset:])

            request = HASPRequest(
                command=command,
                session_id=session_id,
                feature_id=feature_id,
                vendor_code=vendor_code,
                scope=scope,
                format=format_str,
                client_info=client_info,
                encryption_data=encryption_data,
                additional_params=additional_params,
                packet_version=packet_version,
                sequence_number=sequence_number,
                encryption_type=encryption_type,
                signature=signature,
                timestamp=timestamp,
            )

            command_name = HASPCommandType(command).name if command in HASPCommandType._value2member_map_ else f"UNKNOWN_{command:02X}"
            self.logger.info(f"Parsed HASP {command_name} request for feature {feature_id} (session {session_id})")

            return request

        except Exception as e:
            self.logger.error(f"Failed to parse HASP request: {e}")
            return None

    def _parse_additional_params(self, data: bytes) -> dict[str, Any]:
        """Parse additional HASP TLV parameters."""
        params = {}
        try:
            offset = 0
            while offset < len(data) - 4 and not offset + 4 > len(data):
                param_type = struct.unpack("<H", data[offset : offset + 2])[0]
                param_length = struct.unpack("<H", data[offset + 2 : offset + 4])[0]
                offset += 4

                if offset + param_length > len(data):
                    break

                param_data = data[offset : offset + param_length]
                offset += param_length

                if param_type == 0x0001:
                    params["hostname"] = param_data.decode("utf-8", errors="ignore")
                elif param_type == 0x0002:
                    params["username"] = param_data.decode("utf-8", errors="ignore")
                elif param_type == 0x0003:
                    params["process"] = param_data.decode("utf-8", errors="ignore")
                elif param_type == 0x0004:
                    if len(param_data) == 4:
                        params["ip_address"] = ".".join(str(b) for b in param_data)
                elif param_type == 0x0005:
                    if len(param_data) >= 4:
                        params["address"] = struct.unpack("<I", param_data[:4])[0]
                elif param_type == 0x0006:
                    if len(param_data) >= 4:
                        params["length"] = struct.unpack("<I", param_data[:4])[0]
                elif param_type == 0x0007:
                    params["write_data"] = param_data
                elif param_type == 0x0008:
                    params["detach_duration"] = struct.unpack("<I", param_data[:4])[0] if len(param_data) >= 4 else 0
                else:
                    params[f"param_{param_type:04X}"] = param_data

        except Exception as e:
            self.logger.debug(f"Error parsing additional params: {e}")

        return params

    def generate_response(self, request: HASPRequest) -> HASPResponse:
        """Generate appropriate HASP response with full protocol support.

        Args:
            request: Parsed HASP request

        Returns:
            HASP response object

        """
        command_handlers = {
            HASPCommandType.LOGIN: self._handle_login,
            HASPCommandType.LOGOUT: self._handle_logout,
            HASPCommandType.ENCRYPT: self._handle_encrypt,
            HASPCommandType.DECRYPT: self._handle_decrypt,
            HASPCommandType.GET_SIZE: self._handle_get_size,
            HASPCommandType.READ: self._handle_read,
            HASPCommandType.WRITE: self._handle_write,
            HASPCommandType.GET_RTC: self._handle_get_rtc,
            HASPCommandType.SET_RTC: self._handle_set_rtc,
            HASPCommandType.GET_INFO: self._handle_get_info,
            HASPCommandType.GET_SESSION_INFO: self._handle_get_session_info,
            HASPCommandType.LEGACY_ENCRYPT: self._handle_legacy_encrypt,
            HASPCommandType.LEGACY_DECRYPT: self._handle_legacy_decrypt,
            HASPCommandType.FEATURE_LOGIN: self._handle_feature_login,
            HASPCommandType.FEATURE_LOGOUT: self._handle_feature_logout,
            HASPCommandType.GET_FEATURE_INFO: self._handle_get_feature_info,
            HASPCommandType.HEARTBEAT: self._handle_heartbeat,
            HASPCommandType.TRANSFER_DATA: self._handle_transfer_data,
            HASPCommandType.GET_HARDWARE_INFO: self._handle_get_hardware_info,
            HASPCommandType.DATETIME: self._handle_datetime,
        }

        handler = command_handlers.get(request.command, self._handle_unknown_command)
        response = handler(request)

        response.sequence_number = request.sequence_number + 1

        if request.signature and request.session_id:
            response_data = self._prepare_signature_data(response)
            response.signature = self.crypto.rsa_sign(response_data, request.session_id)

        return response

    def _prepare_signature_data(self, response: HASPResponse) -> bytes:
        """Prepare response data for signing."""
        data = struct.pack("<I", response.status)
        data += struct.pack("<I", response.session_id)
        data += struct.pack("<I", response.feature_id)
        data += json.dumps(response.license_data).encode("utf-8")
        return data

    def _handle_login(self, request: HASPRequest) -> HASPResponse:
        """Handle HASP login request."""
        if request.vendor_code not in self.VENDOR_CODES:
            return self._create_error_response(
                request,
                HASPStatusCode.INVALID_VENDOR_CODE,
            )

        session_id = secrets.randbelow(900000) + 100000

        encryption_key = self.crypto.generate_session_key(session_id, request.vendor_code)

        session = HASPSession(
            session_id=session_id,
            vendor_code=request.vendor_code,
            feature_id=request.feature_id,
            login_time=time.time(),
            last_heartbeat=time.time(),
            client_info=request.client_info,
            encryption_key=encryption_key,
        )

        self.active_sessions[session_id] = session
        self.sequence_numbers[session_id] = 1

        vendor_name = self.VENDOR_CODES.get(request.vendor_code, "UNKNOWN")

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=session_id,
            feature_id=request.feature_id,
            license_data={
                "session_established": True,
                "vendor": vendor_name,
                "encryption_seed": encryption_key.hex()[:16],
                "protocol_version": request.packet_version,
            },
            encryption_response=b"",
            expiry_info={},
            hardware_info=self.hardware_fingerprint,
        )

    def _handle_logout(self, request: HASPRequest) -> HASPResponse:
        """Handle HASP logout request."""
        if request.session_id in self.active_sessions:
            del self.active_sessions[request.session_id]
            if request.session_id in self.sequence_numbers:
                del self.sequence_numbers[request.session_id]
            status = HASPStatusCode.STATUS_OK
        else:
            status = HASPStatusCode.NOT_LOGGED_IN

        return HASPResponse(
            status=status,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"logout_time": int(time.time())},
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

    def _handle_feature_login(self, request: HASPRequest) -> HASPResponse:
        """Handle feature-specific login with full validation."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        if request.feature_id not in self.features:
            return self._create_error_response(request, HASPStatusCode.FEATURE_NOT_FOUND)

        feature = self.features[request.feature_id]

        if request.vendor_code != feature.vendor_code:
            return self._create_error_response(request, HASPStatusCode.INVALID_VENDOR_CODE)

        active_users = len([s for s in self.active_sessions.values() if s.feature_id == request.feature_id])

        if feature.concurrent_limit > 0 and active_users >= feature.concurrent_limit:
            return self._create_error_response(request, HASPStatusCode.TOO_MANY_USERS)

        if feature.expiry != "permanent" and self._is_feature_expired(feature):
            return self._create_error_response(request, HASPStatusCode.FEATURE_EXPIRED)

        session = self.active_sessions[request.session_id]
        session.feature_id = request.feature_id
        session.feature_handle = secrets.randbelow(900000) + 100000

        expiry_info = self._calculate_expiry_info(feature)

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "feature_name": feature.name,
                "feature_type": feature.feature_type.name,
                "users_remaining": max(0, feature.concurrent_limit - active_users - 1) if feature.concurrent_limit > 0 else -1,
                "feature_handle": session.feature_handle,
                "detachable": feature.detachable,
                "network_enabled": feature.network_enabled,
            },
            encryption_response=b"",
            expiry_info=expiry_info,
            hardware_info=self.hardware_fingerprint,
        )

    def _handle_encrypt(self, request: HASPRequest) -> HASPResponse:
        """Handle encryption request with multiple cipher support."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        encryption_type = request.encryption_type if request.encryption_type != HASPEncryptionType.NONE else HASPEncryptionType.AES256

        if encryption_type in (HASPEncryptionType.AES128, HASPEncryptionType.AES256):
            encrypted_data = self.crypto.aes_encrypt(request.encryption_data, request.session_id)
        elif encryption_type == HASPEncryptionType.HASP4:
            seed = hash(request.session_id) & 0xFFFFFFFF
            encrypted_data = self.crypto.hasp4_encrypt(request.encryption_data, seed)
        elif encryption_type == HASPEncryptionType.ENVELOPE:
            encrypted_data = self.crypto.envelope_encrypt(request.encryption_data, request.session_id)
        else:
            encrypted_data = self.crypto.aes_encrypt(request.encryption_data, request.session_id)

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"encrypted_bytes": len(encrypted_data)},
            encryption_response=encrypted_data,
            expiry_info={},
            hardware_info={},
        )

    def _handle_decrypt(self, request: HASPRequest) -> HASPResponse:
        """Handle decryption request with multiple cipher support."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        encryption_type = request.encryption_type if request.encryption_type != HASPEncryptionType.NONE else HASPEncryptionType.AES256

        if encryption_type in (HASPEncryptionType.AES128, HASPEncryptionType.AES256):
            decrypted_data = self.crypto.aes_decrypt(request.encryption_data, request.session_id)
        elif encryption_type == HASPEncryptionType.HASP4:
            seed = hash(request.session_id) & 0xFFFFFFFF
            decrypted_data = self.crypto.hasp4_decrypt(request.encryption_data, seed)
        elif encryption_type == HASPEncryptionType.ENVELOPE:
            decrypted_data = self.crypto.envelope_decrypt(request.encryption_data, request.session_id)
        else:
            decrypted_data = self.crypto.aes_decrypt(request.encryption_data, request.session_id)

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"decrypted_bytes": len(decrypted_data)},
            encryption_response=decrypted_data,
            expiry_info={},
            hardware_info={},
        )

    def _handle_legacy_encrypt(self, request: HASPRequest) -> HASPResponse:
        """Handle HASP4 legacy encryption."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        seed = hash(request.session_id) & 0xFFFFFFFF
        encrypted_data = self.crypto.hasp4_encrypt(request.encryption_data, seed)

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"encryption_type": "HASP4"},
            encryption_response=encrypted_data,
            expiry_info={},
            hardware_info={},
        )

    def _handle_legacy_decrypt(self, request: HASPRequest) -> HASPResponse:
        """Handle HASP4 legacy decryption."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        seed = hash(request.session_id) & 0xFFFFFFFF
        decrypted_data = self.crypto.hasp4_decrypt(request.encryption_data, seed)

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"encryption_type": "HASP4"},
            encryption_response=decrypted_data,
            expiry_info={},
            hardware_info={},
        )

    def _handle_get_size(self, request: HASPRequest) -> HASPResponse:
        """Handle get memory size request."""
        if request.feature_id in self.features:
            memory_size = self.features[request.feature_id].memory_size
        else:
            memory_size = 4096

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"memory_size": memory_size},
            encryption_response=struct.pack("<I", memory_size),
            expiry_info={},
            hardware_info={},
        )

    def _handle_read(self, request: HASPRequest) -> HASPResponse:
        """Handle memory read request from HASP dongle memory."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        address = request.additional_params.get("address", 0)
        length = request.additional_params.get("length", 16)

        if request.feature_id not in self.memory_storage:
            return self._create_error_response(request, HASPStatusCode.FEATURE_NOT_FOUND)

        memory = self.memory_storage[request.feature_id]

        if address < 0 or address >= len(memory):
            return self._create_error_response(request, HASPStatusCode.MEM_RANGE)

        end_address = min(address + length, len(memory))
        data = bytes(memory[address:end_address])

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "address": address,
                "length": len(data),
                "memory_data": data.hex(),
            },
            encryption_response=data,
            expiry_info={},
            hardware_info={},
        )

    def _handle_write(self, request: HASPRequest) -> HASPResponse:
        """Handle memory write request to HASP dongle memory."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        if request.feature_id not in self.memory_storage:
            return self._create_error_response(request, HASPStatusCode.FEATURE_NOT_FOUND)

        address = request.additional_params.get("address", 0)
        write_data = request.additional_params.get("write_data", request.encryption_data)

        memory = self.memory_storage[request.feature_id]

        if address < 0 or address >= len(memory):
            return self._create_error_response(request, HASPStatusCode.MEM_RANGE)

        end_address = min(address + len(write_data), len(memory))
        bytes_written = end_address - address

        memory[address:end_address] = write_data[:bytes_written]

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "address": address,
                "bytes_written": bytes_written,
            },
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

    def _handle_get_rtc(self, request: HASPRequest) -> HASPResponse:
        """Handle real-time clock read request."""
        current_time = int(time.time())

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "rtc_time": current_time,
                "rtc_string": time.ctime(current_time),
                "timezone": "UTC",
            },
            encryption_response=struct.pack("<I", current_time),
            expiry_info={},
            hardware_info={},
        )

    def _handle_set_rtc(self, request: HASPRequest) -> HASPResponse:
        """Handle real-time clock set request."""
        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"rtc_updated": True},
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

    def _handle_get_info(self, request: HASPRequest) -> HASPResponse:
        """Handle get HASP dongle info request."""
        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "hasp_type": "HASP HL Max",
                "memory_total": 65536,
                "memory_available": 32768,
                "features_available": len(self.features),
                "active_sessions": len(self.active_sessions),
            },
            encryption_response=b"",
            expiry_info={},
            hardware_info=self.hardware_fingerprint,
        )

    def _handle_get_session_info(self, request: HASPRequest) -> HASPResponse:
        """Handle get session info request."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        session = self.active_sessions[request.session_id]

        session_info = {
            "session_id": session.session_id,
            "vendor_code": session.vendor_code,
            "feature_id": session.feature_id,
            "login_time": session.login_time,
            "last_heartbeat": session.last_heartbeat,
            "login_count": session.login_count,
            "concurrent_users": session.concurrent_users,
        }

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data=session_info,
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

    def _handle_get_feature_info(self, request: HASPRequest) -> HASPResponse:
        """Handle get feature info request."""
        if request.feature_id not in self.features:
            return self._create_error_response(request, HASPStatusCode.FEATURE_NOT_FOUND)

        feature = self.features[request.feature_id]

        feature_info = {
            "feature_id": feature.feature_id,
            "name": feature.name,
            "vendor_code": feature.vendor_code,
            "feature_type": feature.feature_type.name,
            "max_users": feature.max_users,
            "concurrent_limit": feature.concurrent_limit,
            "encryption_supported": feature.encryption_supported,
            "memory_size": feature.memory_size,
            "rtc_supported": feature.rtc_supported,
            "hardware_key": feature.hardware_key,
            "network_enabled": feature.network_enabled,
            "detachable": feature.detachable,
        }

        if feature.detachable:
            feature_info["detachable_duration"] = feature.detachable_duration

        expiry_info = self._calculate_expiry_info(feature)

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data=feature_info,
            encryption_response=b"",
            expiry_info=expiry_info,
            hardware_info=self.hardware_fingerprint,
        )

    def _handle_feature_logout(self, request: HASPRequest) -> HASPResponse:
        """Handle feature logout request."""
        if request.session_id in self.active_sessions:
            session = self.active_sessions[request.session_id]
            session.feature_id = 0
            session.feature_handle = 0

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"logout_time": int(time.time())},
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

    def _handle_heartbeat(self, request: HASPRequest) -> HASPResponse:
        """Handle heartbeat keepalive request."""
        if request.session_id in self.active_sessions:
            session = self.active_sessions[request.session_id]
            session.last_heartbeat = time.time()
            status = HASPStatusCode.STATUS_OK
            uptime = int(time.time() - session.login_time)
        else:
            status = HASPStatusCode.NOT_LOGGED_IN
            uptime = 0

        return HASPResponse(
            status=status,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "heartbeat_time": int(time.time()),
                "session_uptime": uptime,
            },
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

    def _handle_transfer_data(self, request: HASPRequest) -> HASPResponse:
        """Handle data transfer request (for large payloads)."""
        if request.session_id not in self.active_sessions:
            return self._create_error_response(request, HASPStatusCode.NOT_LOGGED_IN)

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"bytes_transferred": len(request.encryption_data)},
            encryption_response=request.encryption_data,
            expiry_info={},
            hardware_info={},
        )

    def _handle_get_hardware_info(self, request: HASPRequest) -> HASPResponse:
        """Handle hardware info request."""
        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data=self.hardware_fingerprint,
            encryption_response=b"",
            expiry_info={},
            hardware_info=self.hardware_fingerprint,
        )

    def _handle_datetime(self, request: HASPRequest) -> HASPResponse:
        """Handle datetime request."""
        current_time = int(time.time())

        return HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "timestamp": current_time,
                "datetime": time.ctime(current_time),
                "timezone": "UTC",
            },
            encryption_response=struct.pack("<I", current_time),
            expiry_info={},
            hardware_info={},
        )

    def _handle_unknown_command(self, request: HASPRequest) -> HASPResponse:
        """Handle unknown command."""
        self.logger.warning(f"Unknown HASP command: 0x{request.command:02X}")
        return self._create_error_response(request, HASPStatusCode.INV_SPEC)

    def _create_error_response(
        self,
        request: HASPRequest,
        status: HASPStatusCode,
    ) -> HASPResponse:
        """Create error response."""
        return HASPResponse(
            status=status,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={},
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

    def _is_feature_expired(self, feature: HASPFeature) -> bool:
        """Check if feature is expired."""
        if feature.expiry == "permanent":
            return False

        try:
            from datetime import datetime, timezone

            expiry_date = datetime.strptime(feature.expiry, "%d-%b-%Y").replace(tzinfo=UTC)
            return datetime.now(UTC) > expiry_date
        except Exception:
            return False

    def _calculate_expiry_info(self, feature: HASPFeature) -> dict[str, Any]:
        """Calculate expiry information for feature."""
        if feature.expiry == "permanent":
            return {
                "expiry_date": "permanent",
                "days_remaining": -1,
                "expired": False,
            }

        try:
            from datetime import datetime, timezone

            expiry_date = datetime.strptime(feature.expiry, "%d-%b-%Y").replace(tzinfo=UTC)
            now = datetime.now(UTC)
            days_remaining = (expiry_date - now).days

            return {
                "expiry_date": feature.expiry,
                "days_remaining": max(0, days_remaining),
                "expired": days_remaining < 0,
            }
        except Exception:
            return {
                "expiry_date": feature.expiry,
                "days_remaining": 365,
                "expired": False,
            }

    def serialize_response(self, response: HASPResponse) -> bytes:
        """Serialize HASP response to network packet format.

        Args:
            response: HASP response object

        Returns:
            Serialized response bytes

        """
        try:
            packet = bytearray()

            packet.extend(struct.pack("<I", 0x48415350))

            packet.extend(struct.pack("<H", response.packet_version))

            packet.extend(struct.pack("<H", response.sequence_number))

            packet.extend(struct.pack("<I", response.status))

            packet.extend(struct.pack("<I", response.session_id))

            packet.extend(struct.pack("<I", response.feature_id))

            license_json = json.dumps(response.license_data).encode("utf-8")
            packet.extend(struct.pack("<H", len(license_json)))
            packet.extend(license_json)

            packet.extend(struct.pack("<H", len(response.encryption_response)))
            packet.extend(response.encryption_response)

            expiry_json = json.dumps(response.expiry_info).encode("utf-8")
            packet.extend(struct.pack("<H", len(expiry_json)))
            packet.extend(expiry_json)

            hardware_json = json.dumps(response.hardware_info).encode("utf-8")
            packet.extend(struct.pack("<H", len(hardware_json)))
            packet.extend(hardware_json)

            packet.extend(struct.pack("<H", len(response.signature)))
            packet.extend(response.signature)

            return bytes(packet)

        except Exception as e:
            self.logger.error(f"Failed to serialize HASP response: {e}")
            return struct.pack("<II", 0x48415350, response.status)

    def add_feature(self, feature: HASPFeature) -> None:
        """Add custom HASP feature to emulator.

        Args:
            feature: HASP feature definition

        """
        self.features[feature.feature_id] = feature
        self.memory_storage[feature.feature_id] = bytearray(feature.memory_size)
        self._initialize_feature_memory(feature.feature_id)
        self.logger.info(f"Added HASP feature {feature.feature_id}: {feature.name}")

    def remove_feature(self, feature_id: int) -> None:
        """Remove HASP feature from emulator.

        Args:
            feature_id: Feature ID to remove

        """
        if feature_id in self.features:
            del self.features[feature_id]
            if feature_id in self.memory_storage:
                del self.memory_storage[feature_id]
            self.logger.info(f"Removed HASP feature {feature_id}")

    def get_active_sessions(self) -> list[dict[str, Any]]:
        """Get list of active sessions.

        Returns:
            List of active session information dictionaries

        """
        return [
            {
                "session_id": session.session_id,
                "vendor_code": session.vendor_code,
                "feature_id": session.feature_id,
                "login_time": session.login_time,
                "last_heartbeat": session.last_heartbeat,
                "client_info": session.client_info,
                "uptime": int(time.time() - session.login_time),
            }
            for _session_id, session in self.active_sessions.items()
        ]

    def export_license_data(self, output_path: Path) -> None:
        """Export license data to XML format (v2c format).

        Args:
            output_path: Path to save license XML

        """
        root = ET.Element("hasp_license")
        root.set("version", "1.0")

        for _feature_id, feature in self.features.items():
            feature_elem = ET.SubElement(root, "feature")
            feature_elem.set("id", str(feature.feature_id))

            ET.SubElement(feature_elem, "name").text = feature.name
            ET.SubElement(feature_elem, "vendor_code").text = f"0x{feature.vendor_code:08X}"
            ET.SubElement(feature_elem, "type").text = feature.feature_type.name
            ET.SubElement(feature_elem, "expiry").text = feature.expiry
            ET.SubElement(feature_elem, "max_users").text = str(feature.max_users)
            ET.SubElement(feature_elem, "memory_size").text = str(feature.memory_size)

        tree = ET.ElementTree(root)
        tree.write(output_path, encoding="utf-8", xml_declaration=True)
        self.logger.info(f"Exported license data to {output_path}")


class HASPPacketAnalyzer:
    """Production-ready HASP network packet capture analyzer."""

    def __init__(self) -> None:
        """Initialize HASP packet analyzer."""
        self.logger = get_logger(__name__)
        self.parser = HASPSentinelParser()
        self.captured_packets: list[HASPPacketCapture] = []
        self.discovered_servers: dict[str, dict[str, Any]] = {}
        self.discovered_clients: dict[str, dict[str, Any]] = {}

    def parse_pcap_file(self, pcap_path: Path) -> list[HASPPacketCapture]:
        """Parse HASP packets from PCAP file.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            List of captured HASP packets

        """
        try:
            import dpkt
        except ImportError:
            self.logger.error("dpkt library required for PCAP parsing")
            return []

        packets = []

        try:
            with open(pcap_path, "rb") as f:
                pcap = dpkt.pcap.Reader(f)

                for timestamp, buf in pcap:
                    if packet := self._parse_pcap_packet(timestamp, buf):
                        packets.append(packet)
                        self.captured_packets.append(packet)

            self.logger.info(f"Parsed {len(packets)} HASP packets from {pcap_path}")

        except Exception as e:
            self.logger.error(f"Failed to parse PCAP file: {e}")

        return packets

    def _parse_pcap_packet(self, timestamp: float, buf: bytes) -> HASPPacketCapture | None:
        """Parse individual packet from PCAP."""
        try:
            import dpkt
        except ImportError:
            return None

        try:
            eth = dpkt.ethernet.Ethernet(buf)

            if not isinstance(eth.data, dpkt.ip.IP):
                return None

            ip = eth.data
            source_ip = self._ip_to_str(ip.src)
            dest_ip = self._ip_to_str(ip.dst)

            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                source_port = udp.sport
                dest_port = udp.dport
                protocol = "UDP"
                payload = udp.data

            elif isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                source_port = tcp.sport
                dest_port = tcp.dport
                protocol = "TCP"
                payload = tcp.data

            else:
                return None

            if not self._is_hasp_packet(payload, source_port, dest_port):
                return None

            packet_type = self._identify_packet_type(payload)

            packet = HASPPacketCapture(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                packet_type=packet_type,
                raw_data=bytes(payload),
            )

            if packet_type in ["LOGIN", "LOGOUT", "ENCRYPT", "DECRYPT", "HEARTBEAT"]:
                packet.parsed_request = self.parser.parse_request(bytes(payload))

            return packet

        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")
            return None

    def _ip_to_str(self, ip_bytes: bytes) -> str:
        """Convert IP address bytes to string."""
        return ".".join(str(b) for b in ip_bytes)

    def _is_hasp_packet(self, payload: bytes, sport: int, dport: int) -> bool:
        """Determine if packet is HASP-related."""
        if sport in {1947, 475} or dport in {1947, 475}:
            return True

        if HASPNetworkProtocol.DISCOVERY_MAGIC in payload:
            return True

        if HASPNetworkProtocol.SERVER_READY_MAGIC in payload:
            return True

        if len(payload) >= 4:
            magic = struct.unpack("<I", payload[:4])[0]
            if magic in [0x48415350, 0x53454E54, 0x484C4D58, 0x48535350]:
                return True

        return False

    def _identify_packet_type(self, payload: bytes) -> str:
        """Identify HASP packet type from payload."""
        if HASPNetworkProtocol.DISCOVERY_MAGIC in payload:
            return "DISCOVERY"

        if HASPNetworkProtocol.SERVER_READY_MAGIC in payload:
            return "SERVER_READY"

        if b"LOGIN" in payload[:50]:
            return "LOGIN"

        if b"LOGOUT" in payload[:50]:
            return "LOGOUT"

        if b"HEARTBEAT" in payload[:50]:
            return "HEARTBEAT"

        if b"ENCRYPT" in payload[:50]:
            return "ENCRYPT"

        if b"DECRYPT" in payload[:50]:
            return "DECRYPT"

        if len(payload) >= 8:
            try:
                command = struct.unpack("<I", payload[8:12])[0]
                if command in HASPCommandType._value2member_map_:
                    return HASPCommandType(command).name
            except Exception as e:
                self.logger.debug(f"Failed to extract command from payload: {e}")

        return "UNKNOWN"

    def extract_license_info_from_capture(self) -> dict[str, Any]:
        """Extract license information from captured packets.

        Returns:
            Dictionary containing extracted license information

        """
        license_info = {
            "discovered_servers": [],
            "discovered_features": [],
            "vendor_codes": set(),
            "session_ids": set(),
            "encryption_types": set(),
        }

        for packet in self.captured_packets:
            if packet.packet_type == "SERVER_READY":
                if server_info := self._extract_server_info(packet.raw_data):
                    license_info["discovered_servers"].append(server_info)

            if packet.parsed_request:
                req = packet.parsed_request
                license_info["vendor_codes"].add(req.vendor_code)
                license_info["session_ids"].add(req.session_id)
                license_info["encryption_types"].add(req.encryption_type)

                if req.feature_id not in [f["feature_id"] for f in license_info["discovered_features"]]:
                    license_info["discovered_features"].append(
                        {
                            "feature_id": req.feature_id,
                            "vendor_code": req.vendor_code,
                            "scope": req.scope,
                        },
                    )

        license_info["vendor_codes"] = list(license_info["vendor_codes"])
        license_info["session_ids"] = list(license_info["session_ids"])
        license_info["encryption_types"] = list(license_info["encryption_types"])

        return license_info

    def _extract_server_info(self, payload: bytes) -> dict[str, Any] | None:
        """Extract server information from SERVER_READY packet."""
        try:
            server_info = {}
            text = payload.decode("utf-8", errors="ignore")

            parts = text.split()
            for part in parts:
                if "=" in part:
                    key, value = part.split("=", 1)
                    server_info[key.lower()] = value

            if server_info:
                return server_info

        except Exception as e:
            self.logger.debug(f"Failed to extract server info: {e}")

        return None

    def generate_spoofed_response(self, request_packet: HASPPacketCapture) -> bytes:
        """Generate spoofed HASP response for captured request.

        Args:
            request_packet: Captured HASP request packet

        Returns:
            Spoofed response packet bytes

        """
        if not request_packet.parsed_request:
            request = self.parser.parse_request(request_packet.raw_data)
            if not request:
                self.logger.warning("Cannot generate response for unparseable request")
                return b""
        else:
            request = request_packet.parsed_request

        response = self.parser.generate_response(request)
        response_bytes = self.parser.serialize_response(response)

        self.logger.info(f"Generated spoofed {request_packet.packet_type} response")

        return response_bytes

    def export_capture_analysis(self, output_path: Path) -> None:
        """Export packet capture analysis to JSON.

        Args:
            output_path: Path to save analysis JSON

        """
        analysis = {
            "total_packets": len(self.captured_packets),
            "packet_types": {},
            "license_info": self.extract_license_info_from_capture(),
            "timeline": [],
        }

        packet_type_counts: dict[str, int] = {}
        for packet in self.captured_packets:
            packet_type_counts[packet.packet_type] = packet_type_counts.get(packet.packet_type, 0) + 1

            analysis["timeline"].append(
                {
                    "timestamp": packet.timestamp,
                    "source": f"{packet.source_ip}:{packet.source_port}",
                    "dest": f"{packet.dest_ip}:{packet.dest_port}",
                    "protocol": packet.protocol,
                    "type": packet.packet_type,
                },
            )

        analysis["packet_types"] = packet_type_counts

        with open(output_path, "w") as f:
            json.dump(analysis, f, indent=2)

        self.logger.info(f"Exported capture analysis to {output_path}")


class HASPUSBEmulator:
    """Production-ready HASP USB dongle emulator."""

    def __init__(self) -> None:
        """Initialize HASP USB emulator."""
        self.logger = get_logger(__name__)
        self.parser = HASPSentinelParser()
        self.device_info = self._generate_usb_device_info()

    def _generate_usb_device_info(self) -> dict[str, Any]:
        """Generate realistic USB device information."""
        return {
            "vendor_id": HASPUSBProtocol.USB_VENDOR_ID,
            "product_id": HASPUSBProtocol.USB_PRODUCT_IDS[0],
            "manufacturer": "Aladdin Knowledge Systems",
            "product": "HASP HL 3.25",
            "serial_number": f"HL{secrets.randbelow(90000000) + 10000000}",
            "max_packet_size": 64,
            "configurations": 1,
            "interfaces": 1,
            "endpoints": 2,
        }

    def handle_control_transfer(
        self,
        request_type: int,
        request: int,
        value: int,
        index: int,
        data: bytes,
    ) -> bytes:
        """Handle USB control transfer request.

        Args:
            request_type: USB request type
            request: USB request code
            value: USB value parameter
            index: USB index parameter
            data: Request data

        Returns:
            Response data bytes

        """
        if request == HASPUSBProtocol.CMD_READ_MEMORY:
            return self._handle_usb_read_memory(value, index)

        if request == HASPUSBProtocol.CMD_WRITE_MEMORY:
            return self._handle_usb_write_memory(value, index, data)

        if request == HASPUSBProtocol.CMD_ENCRYPT:
            return self._handle_usb_encrypt(data)

        if request == HASPUSBProtocol.CMD_DECRYPT:
            return self._handle_usb_decrypt(data)

        if request == HASPUSBProtocol.CMD_GET_INFO:
            return self._handle_usb_get_info()

        if request == HASPUSBProtocol.CMD_GET_RTC:
            return self._handle_usb_get_rtc()

        self.logger.warning(f"Unknown USB request: 0x{request:02X}")
        return b"\x00" * 64

    def _handle_usb_read_memory(self, address: int, length: int) -> bytes:
        """Handle USB memory read."""
        feature_id = 100

        if feature_id in self.parser.memory_storage:
            memory = self.parser.memory_storage[feature_id]
            end_address = min(address + length, len(memory))
            return bytes(memory[address:end_address])

        return b"\x00" * min(length, 64)

    def _handle_usb_write_memory(self, address: int, length: int, data: bytes) -> bytes:
        """Handle USB memory write."""
        feature_id = 100

        if feature_id in self.parser.memory_storage:
            memory = self.parser.memory_storage[feature_id]
            end_address = min(address + length, len(memory))
            memory[address:end_address] = data[: end_address - address]
            return struct.pack("<I", end_address - address)

        return struct.pack("<I", 0)

    def _handle_usb_encrypt(self, data: bytes) -> bytes:
        """Handle USB encryption."""
        encrypted = self.parser.crypto.hasp4_encrypt(data, 0x12345678)
        return encrypted[:64] if len(encrypted) > 64 else encrypted

    def _handle_usb_decrypt(self, data: bytes) -> bytes:
        """Handle USB decryption."""
        decrypted = self.parser.crypto.hasp4_decrypt(data, 0x12345678)
        return decrypted[:64] if len(decrypted) > 64 else decrypted

    def _handle_usb_get_info(self) -> bytes:
        """Handle USB get info request."""
        return struct.pack(
            "<IIII",
            self.device_info["vendor_id"],
            self.device_info["product_id"],
            0x01000000,
            65536,
        )

    def _handle_usb_get_rtc(self) -> bytes:
        """Handle USB RTC read."""
        current_time = int(time.time())
        return struct.pack("<I", current_time)

    def emulate_usb_device(self) -> dict[str, Any]:
        """Get USB device descriptor for emulation.

        Returns:
            USB device descriptor dictionary

        """
        return {
            "device_descriptor": {
                "bLength": 18,
                "bDescriptorType": 1,
                "bcdUSB": 0x0200,
                "bDeviceClass": 0xFF,
                "bDeviceSubClass": 0x00,
                "bDeviceProtocol": 0x00,
                "bMaxPacketSize0": 64,
                "idVendor": self.device_info["vendor_id"],
                "idProduct": self.device_info["product_id"],
                "bcdDevice": 0x0325,
                "iManufacturer": 1,
                "iProduct": 2,
                "iSerialNumber": 3,
                "bNumConfigurations": 1,
            },
            "string_descriptors": {
                1: self.device_info["manufacturer"],
                2: self.device_info["product"],
                3: self.device_info["serial_number"],
            },
            "configuration_descriptor": {
                "bLength": 9,
                "bDescriptorType": 2,
                "wTotalLength": 32,
                "bNumInterfaces": 1,
                "bConfigurationValue": 1,
                "iConfiguration": 0,
                "bmAttributes": 0x80,
                "bMaxPower": 50,
            },
        }


class HASPServerEmulator:
    """Production-ready HASP license server emulator."""

    def __init__(self, bind_address: str = "127.0.0.1", port: int = 1947) -> None:
        """Initialize HASP server emulator.

        Args:
            bind_address: Address to bind server
            port: Port to bind server

        """
        self.logger = get_logger(__name__)
        self.parser = HASPSentinelParser()
        self.bind_address = bind_address
        self.port = port
        self.running = False
        self.server_id = f"HASP_SRV_{secrets.randbelow(9000) + 1000}"

    def generate_discovery_response(self) -> bytes:
        """Generate HASP server discovery response.

        Returns:
            Discovery response packet bytes

        """
        response = HASPNetworkProtocol.SERVER_READY_MAGIC
        response += b" SERVER"
        response += f" SERVER_ID={self.server_id}".encode()
        response += b" VERSION=7.50"
        response += b" FEATURES="
        response += str(len(self.parser.features)).encode("utf-8")

        return response

    def handle_client_request(self, client_data: bytes) -> bytes:
        """Handle client request and generate response.

        Args:
            client_data: Client request packet

        Returns:
            Response packet bytes

        """
        if HASPNetworkProtocol.DISCOVERY_MAGIC in client_data:
            return self.generate_discovery_response()

        request = self.parser.parse_request(client_data)
        if not request:
            self.logger.warning("Failed to parse client request")
            return b""

        response = self.parser.generate_response(request)
        return self.parser.serialize_response(response)

    def start_server(self) -> None:
        """Start HASP license server (blocking)."""
        import socket
        import threading

        self.running = True

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind((self.bind_address, self.port))

        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((self.bind_address, self.port))
        tcp_socket.listen(5)

        self.logger.info(f"HASP server started on {self.bind_address}:{self.port}")

        udp_thread = threading.Thread(target=self._handle_udp, args=(udp_socket,))
        udp_thread.daemon = True
        udp_thread.start()

        tcp_thread = threading.Thread(target=self._handle_tcp, args=(tcp_socket,))
        tcp_thread.daemon = True
        tcp_thread.start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_server()
        finally:
            udp_socket.close()
            tcp_socket.close()

    def _handle_udp(self, sock: socket.socket) -> None:
        """Handle UDP discovery packets."""
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)

                if HASPNetworkProtocol.DISCOVERY_MAGIC in data:
                    response = self.generate_discovery_response()
                    sock.sendto(response, addr)
                    self.logger.info(f"Sent discovery response to {addr}")

            except Exception as e:
                if self.running:
                    self.logger.error(f"UDP handler error: {e}")

    def _handle_tcp(self, sock: socket.socket) -> None:
        """Handle TCP license requests."""
        while self.running:
            try:
                client_sock, addr = sock.accept()
                self.logger.info(f"TCP connection from {addr}")

                if data := client_sock.recv(4096):
                    if response := self.handle_client_request(data):
                        client_sock.send(response)

                client_sock.close()

            except Exception as e:
                if self.running:
                    self.logger.error(f"TCP handler error: {e}")

    def stop_server(self) -> None:
        """Stop HASP license server."""
        self.running = False
        self.logger.info("HASP server stopped")
