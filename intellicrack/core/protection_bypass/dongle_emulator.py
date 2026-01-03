"""Hardware Dongle Emulation Module.

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
import logging
import os
import platform
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import get_logger

from ...utils.core.import_checks import FRIDA_AVAILABLE, WINREG_AVAILABLE, winreg


logger = get_logger(__name__)


try:
    from Crypto.Cipher import AES, DES, DES3  # noqa: S413
    from Crypto.Hash import SHA256  # noqa: S413
    from Crypto.PublicKey import RSA  # noqa: S413
    from Crypto.Signature import PKCS1_v1_5  # noqa: S413

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class DongleType(IntEnum):
    """Dongle type enumeration."""

    HASP = 1
    SENTINEL = 2
    WIBUKEY = 3
    SAFENET = 4
    SUPERPRO = 5
    ROCKEY = 6
    DINKEY = 7


class HASPStatus(IntEnum):
    """HASP API status codes."""

    HASP_STATUS_OK = 0
    HASP_MEM_RANGE = 1
    HASP_TOO_SHORT = 2
    HASP_INV_HND = 3
    HASP_INV_FILEID = 4
    HASP_OLD_DRIVER = 5
    HASP_NO_DRIVER = 6
    HASP_KEYNOTFOUND = 7
    HASP_FEATURE_NOT_FOUND = 11
    HASP_ALREADY_LOGGED_IN = 12
    HASP_NO_API_DYLIB = 13


class SentinelStatus(IntEnum):
    """Sentinel API status codes."""

    SP_SUCCESS = 0
    SP_INVALID_FUNCTION_CODE = 1
    SP_UNIT_NOT_FOUND = 2
    SP_ACCESS_DENIED = 3
    SP_PORT_IS_BUSY = 4
    SP_WRITE_NOT_READY = 5
    SP_NO_PORT_FOUND = 6
    SP_ALREADY_OPEN = 7


@dataclass
class USBDescriptor:
    """USB device descriptor structure.

    Field names match USB 2.0 Specification §9.6.1 Table 9-8 exactly.
    mixedCase naming is required for USB specification compliance.
    """

    bLength: int = 18  # noqa: N815 - USB spec field name
    bDescriptorType: int = 1  # noqa: N815 - USB spec field name
    bcdUSB: int = 0x0200  # noqa: N815 - USB spec field name
    bDeviceClass: int = 0xFF  # noqa: N815 - USB spec field name
    bDeviceSubClass: int = 0xFF  # noqa: N815 - USB spec field name
    bDeviceProtocol: int = 0xFF  # noqa: N815 - USB spec field name
    bMaxPacketSize0: int = 64  # noqa: N815 - USB spec field name
    idVendor: int = 0x0529  # noqa: N815 - USB spec field name
    idProduct: int = 0x0001  # noqa: N815 - USB spec field name
    bcdDevice: int = 0x0100  # noqa: N815 - USB spec field name
    iManufacturer: int = 1  # noqa: N815 - USB spec field name
    iProduct: int = 2  # noqa: N815 - USB spec field name
    iSerialNumber: int = 3  # noqa: N815 - USB spec field name
    bNumConfigurations: int = 1  # noqa: N815 - USB spec field name

    def to_bytes(self) -> bytes:
        """Serialize descriptor to bytes.

        Converts the USB device descriptor fields into a binary format suitable
        for USB communication, using little-endian packing as per USB 2.0 spec.

        Returns:
            bytes: Serialized USB device descriptor bytes in little-endian format.

        """
        return struct.pack(
            "<BBHBBBBHHHBBBB",
            self.bLength,
            self.bDescriptorType,
            self.bcdUSB,
            self.bDeviceClass,
            self.bDeviceSubClass,
            self.bDeviceProtocol,
            self.bMaxPacketSize0,
            self.idVendor,
            self.idProduct,
            self.bcdDevice,
            self.iManufacturer,
            self.iProduct,
            self.iSerialNumber,
            self.bNumConfigurations,
        )


@dataclass
class DongleMemory:
    """Dongle memory region structure."""

    rom: bytearray = field(default_factory=lambda: bytearray(8192))
    ram: bytearray = field(default_factory=lambda: bytearray(4096))
    eeprom: bytearray = field(default_factory=lambda: bytearray(2048))
    protected_areas: list[tuple[int, int]] = field(default_factory=list)
    read_only_areas: list[tuple[int, int]] = field(default_factory=list)

    def read(self, region: str, offset: int, length: int) -> bytes:
        """Read from dongle memory region.

        Retrieves data from the specified memory region (ROM, RAM, or EEPROM)
        at the given offset for the specified length.

        Args:
            region (str): Memory region name (rom, ram, or eeprom) to read from.
            offset (int): Byte offset within the region where reading begins.
            length (int): Number of bytes to read from the region.

        Returns:
            bytes: The requested memory data as bytes.

        Raises:
            ValueError: If region is invalid or if read offset and length exceed memory bounds.

        """
        memory_map = {"rom": self.rom, "ram": self.ram, "eeprom": self.eeprom}
        if region not in memory_map:
            error_msg = f"Invalid memory region: {region}"
            logger.exception(error_msg)
            raise ValueError(error_msg)
        mem = memory_map[region]
        if offset + length > len(mem):
            error_msg = f"Read beyond memory bounds: {offset}+{length} > {len(mem)}"
            logger.exception(error_msg)
            raise ValueError(error_msg)
        return bytes(mem[offset : offset + length])

    def write(self, region: str, offset: int, data: bytes) -> None:
        """Write to dongle memory region.

        Writes the provided data to the specified memory region (ROM, RAM, or EEPROM)
        at the given offset. Enforces read-only area protection for ROM regions.

        Args:
            region (str): Memory region name (rom, ram, or eeprom) to write to.
            offset (int): Byte offset within the region where writing begins.
            data (bytes): Bytes to write to memory at the specified offset.

        Raises:
            ValueError: If region is invalid or if write offset and data length exceed memory bounds.
            PermissionError: If attempting to write to a protected read-only area in ROM.

        """
        memory_map = {"rom": self.rom, "ram": self.ram, "eeprom": self.eeprom}
        if region not in memory_map:
            error_msg = f"Invalid memory region: {region}"
            logger.exception(error_msg)
            raise ValueError(error_msg)
        if region == "rom":
            for start, end in self.read_only_areas:
                if offset >= start and offset < end:
                    error_msg = "Cannot write to read-only area"
                    logger.exception(error_msg)
                    raise PermissionError(error_msg)
        mem = memory_map[region]
        if offset + len(data) > len(mem):
            error_msg = f"Write beyond memory bounds: {offset}+{len(data)} > {len(mem)}"
            logger.exception(error_msg)
            raise ValueError(error_msg)
        mem[offset : offset + len(data)] = data

    def is_protected(self, offset: int, length: int) -> bool:
        """Check if memory range is protected.

        Determines whether a specified memory range falls within any of the
        protected areas defined for this dongle memory instance.

        Args:
            offset (int): Starting byte offset in memory to check.
            length (int): Number of bytes in the range to check for protection.

        Returns:
            bool: True if the entire memory range is protected, False otherwise.

        """
        return any(offset >= start and offset + length <= end for start, end in self.protected_areas)


@dataclass
class HASPDongle:
    """HASP dongle emulation data."""

    hasp_id: int = 0x12345678
    vendor_code: int = 0x1234
    feature_id: int = 1
    seed_code: bytes = field(default_factory=lambda: os.urandom(16))
    memory: DongleMemory = field(default_factory=DongleMemory)
    logged_in: bool = False
    session_handle: int = 0
    password: bytes = b"defaultpass\x00\x00\x00\x00\x00"
    aes_key: bytes = field(default_factory=lambda: os.urandom(32))
    des_key: bytes = field(default_factory=lambda: os.urandom(24))
    rsa_key: object = None
    license_data: bytearray = field(default_factory=lambda: bytearray(512))
    rtc_counter: int = 0
    feature_map: dict[int, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize RSA key and feature map for HASP dongle.

        Generates RSA-2048 key if cryptography is available, and initializes
        the feature map with default license feature settings.

        """
        if CRYPTO_AVAILABLE and self.rsa_key is None:
            self.rsa_key = RSA.generate(2048)
        self.feature_map[self.feature_id] = {
            "id": self.feature_id,
            "type": "license",
            "expiration": 0xFFFFFFFF,
            "max_users": 10,
            "current_users": 0,
        }


@dataclass
class SentinelDongle:
    """Sentinel dongle emulation data."""

    device_id: int = 0x87654321
    vendor_id: int = 0x0529
    product_id: int = 0x0001
    serial_number: str = "SN123456789ABCDEF"
    firmware_version: str = "8.0.0"
    memory: DongleMemory = field(default_factory=DongleMemory)
    algorithms: list[str] = field(default_factory=lambda: ["AES", "RSA", "DES", "HMAC"])
    developer_id: int = 1000
    query_buffer: bytearray = field(default_factory=lambda: bytearray(1024))
    response_buffer: bytearray = field(default_factory=lambda: bytearray(1024))
    aes_key: bytes = field(default_factory=lambda: os.urandom(32))
    des_key: bytes = field(default_factory=lambda: os.urandom(24))
    rsa_key: object = None
    cell_data: dict[int, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize crypto keys and cell data for Sentinel dongle.

        Generates RSA-2048 key if cryptography is available, and initializes
        cell data with random bytes for Sentinel memory emulation.

        """
        if CRYPTO_AVAILABLE and self.rsa_key is None:
            self.rsa_key = RSA.generate(2048)
        for i in range(8):
            self.cell_data[i] = os.urandom(64)


@dataclass
class WibuKeyDongle:
    """WibuKey/CodeMeter dongle emulation data."""

    firm_code: int = 101
    product_code: int = 1000
    feature_code: int = 1
    serial_number: int = 1000001
    version: str = "6.90"
    memory: DongleMemory = field(default_factory=DongleMemory)
    user_data: bytearray = field(default_factory=lambda: bytearray(4096))
    container_handle: int = 0x12345678
    license_entries: dict[int, dict[str, Any]] = field(default_factory=dict)
    aes_key: bytes = field(default_factory=lambda: os.urandom(32))
    challenge_response_key: bytes = field(default_factory=lambda: os.urandom(16))
    active_licenses: set[int] = field(default_factory=set)

    def __post_init__(self) -> None:
        """Initialize license entries for WibuKey dongle.

        Sets up default license entry with unlimited expiration and
        high quantity for CodeMeter/WibuKey emulation.

        """
        self.license_entries[1] = {
            "firm_code": self.firm_code,
            "product_code": self.product_code,
            "feature_code": self.feature_code,
            "quantity": 100,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
        }


class USBEmulator:
    """USB device emulation for dongles."""

    def __init__(self, descriptor: USBDescriptor) -> None:
        """Initialize USB emulator with device descriptor.

        Creates a USB device emulator instance with the provided descriptor and
        sets up control and bulk transfer handlers for protocol communication.

        Args:
            descriptor (USBDescriptor): USB device descriptor containing vendor ID, product ID, and other USB specification metadata.

        """
        self.descriptor = descriptor
        self.configuration = 1
        self.interface = 0
        self.alt_setting = 0
        self.endpoints: dict[int, dict[str, Any]] = {}
        self.setup_endpoints()
        self.control_transfer_handlers: dict[int, Callable[..., bytes]] = {}
        self.bulk_transfer_handlers: dict[int, Callable[..., bytes]] = {}

    def setup_endpoints(self) -> None:
        """Configure USB endpoints.

        Initializes control endpoint 0x00, bulk endpoints 0x81/0x02,
        and interrupt endpoint 0x83 with appropriate packet sizes and directions.

        """
        self.endpoints[0x00] = {"type": "control", "max_packet": 64, "direction": "both"}
        self.endpoints[0x81] = {"type": "bulk", "max_packet": 512, "direction": "in"}
        self.endpoints[0x02] = {"type": "bulk", "max_packet": 512, "direction": "out"}
        self.endpoints[0x83] = {"type": "interrupt", "max_packet": 64, "direction": "in"}

    def control_transfer(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle USB control transfer.

        Processes USB control transfers by routing requests to registered handlers
        or handling standard descriptor requests per USB 2.0 specification.

        Args:
            bmRequestType (int): Request type field indicating direction and type from USB control transfer.
            bRequest (int): Request field specifying the command code from USB control transfer.
            wValue (int): Value field containing request-specific parameter data.
            wIndex (int): Index field containing request-specific parameter data.
            data (bytes): Data payload bytes for the control transfer request.

        Returns:
            bytes: Response data as bytes from the handler or descriptor, or empty bytes if no handler or no response.

        """
        request_key = (bmRequestType << 8) | bRequest
        if request_key in self.control_transfer_handlers:
            handler = self.control_transfer_handlers[request_key]
            result = handler(wValue, wIndex, data)
            return result if isinstance(result, bytes) else b""

        if bRequest == 0x06:
            descriptor_type = (wValue >> 8) & 0xFF
            if descriptor_type == 1:
                return self.descriptor.to_bytes()
            elif descriptor_type == 2:
                return self.get_configuration_descriptor()
            elif descriptor_type == 3:
                return self.get_string_descriptor(wValue & 0xFF)

        return b""

    def get_configuration_descriptor(self) -> bytes:
        """Generate configuration descriptor.

        Creates a complete USB configuration descriptor including configuration,
        interface, and endpoint descriptor data per USB 2.0 specification.

        Returns:
            bytes: USB configuration descriptor bytes containing configuration, interface, and all endpoint descriptor data.

        """
        config = struct.pack(
            "<BBHBBBBB",
            9,
            2,
            32,
            1,
            1,
            0,
            0x80,
            100,
        )
        interface = struct.pack(
            "<BBBBBBBBB",
            9,
            4,
            0,
            0,
            3,
            0xFF,
            0xFF,
            0xFF,
            0,
        )
        endpoint1 = struct.pack("<BBBBH", 7, 5, 0x81, 2, 512)
        endpoint2 = struct.pack("<BBBBH", 7, 5, 0x02, 2, 512)
        endpoint3 = struct.pack("<BBBBH", 7, 5, 0x83, 3, 64)
        return config + interface + endpoint1 + endpoint2 + endpoint3

    def get_string_descriptor(self, index: int) -> bytes:
        """Get USB string descriptor.

        Retrieves a USB string descriptor by index, returning language ID descriptor
        or UTF-16 little-endian encoded string descriptors as per USB 2.0 spec.

        Args:
            index (int): String descriptor index to retrieve (0 for language ID, 1-3 for device strings).

        Returns:
            bytes: Encoded USB string descriptor bytes in UTF-16 little-endian format, or empty bytes if index not found.

        """
        strings: dict[int, bytes | str] = {
            0: b"\x04\x03\x09\x04",
            1: "SafeNet Inc.",
            2: "Sentinel Hardware Key",
            3: "0123456789ABCDEF",
        }
        if index in strings:
            string_val = strings[index]
            if isinstance(string_val, bytes):
                return string_val
            if isinstance(string_val, str):
                string_utf16 = string_val.encode("utf-16-le")
                descriptor = struct.pack("<BB", len(string_utf16) + 2, 3) + string_utf16
                return descriptor + string_val.encode("ascii")
        return b""

    def bulk_transfer(self, endpoint: int, data: bytes) -> bytes:
        """Handle USB bulk transfer.

        Routes bulk transfer requests to registered endpoint handlers that process
        the data and return responses for dongle protocol communication.

        Args:
            endpoint (int): Target endpoint address (0x81 for in, 0x02 for out).
            data (bytes): Data bytes to transfer on the specified endpoint.

        Returns:
            bytes: Response data bytes from the endpoint handler, or empty bytes if no handler is registered.

        """
        if endpoint in self.bulk_transfer_handlers:
            handler = self.bulk_transfer_handlers[endpoint]
            result = handler(data)
            return result if isinstance(result, bytes) else b""
        return b""

    def register_control_handler(self, bmRequestType: int, bRequest: int, handler: Callable[..., bytes]) -> None:
        """Register handler for control transfer.

        Associates a handler function with a specific control transfer request type
        for custom protocol processing when that request is received.

        Args:
            bmRequestType (int): Request type field value indicating direction and request class.
            bRequest (int): Request field value specifying the command code.
            handler (Callable[..., bytes]): Callable function that processes the control transfer and returns response bytes.

        """
        request_key = (bmRequestType << 8) | bRequest
        self.control_transfer_handlers[request_key] = handler

    def register_bulk_handler(self, endpoint: int, handler: Callable[..., bytes]) -> None:
        """Register handler for bulk transfer.

        Associates a handler function with a specific bulk endpoint for custom
        protocol processing when bulk transfers occur on that endpoint.

        Args:
            endpoint (int): Target endpoint address (0x81 for in, 0x02 for out).
            handler (Callable[..., bytes]): Callable function that processes the bulk transfer and returns response bytes.

        """
        self.bulk_transfer_handlers[endpoint] = handler


class CryptoEngine:
    """Cryptographic operations for dongle emulation."""

    def __init__(self) -> None:
        """Initialize crypto engine.

        Sets up logger for cryptographic operations on dongle emulation.

        """
        self.logger = logging.getLogger("IntellicrackLogger.DongleCrypto")

    def hasp_encrypt(self, data: bytes, key: bytes, algorithm: str = "AES") -> bytes:
        """Perform HASP encryption operation.

        Encrypts plaintext data using the specified symmetric cipher algorithm
        with proper padding. Falls back to XOR encryption if cryptography unavailable.

        Args:
            data (bytes): Plaintext bytes to encrypt using the specified algorithm.
            key (bytes): Encryption key bytes (32 bytes for AES, 8 for DES, 24 for DES3).
            algorithm (str): Cipher algorithm to use ("AES", "DES", "DES3"). Defaults to "AES".

        Returns:
            bytes: Encrypted data bytes padded to cipher block size, or XOR-encrypted fallback.

        """
        if not CRYPTO_AVAILABLE:
            self.logger.warning("Crypto not available, returning XOR encryption")
            return self._xor_encrypt(data, key)

        try:
            if algorithm == "AES":
                aes_cipher = AES.new(
                    key[:32], AES.MODE_ECB
                )  # lgtm[py/weak-cryptographic-algorithm] ECB required for HASP protocol compatibility
                padded_data = data + b"\x00" * (16 - len(data) % 16)
                encrypted_result: bytes = aes_cipher.encrypt(padded_data)
                return encrypted_result
            elif algorithm == "DES":
                des_cipher = DES.new(key[:8], DES.MODE_ECB)  # noqa: S304 lgtm[py/weak-cryptographic-algorithm] DES required for legacy HASP dongle protocol
                padded_data = data + b"\x00" * (8 - len(data) % 8)
                return des_cipher.encrypt(padded_data)
            elif algorithm == "DES3":
                des3_cipher = DES3.new(
                    key[:24], DES3.MODE_ECB
                )  # lgtm[py/weak-cryptographic-algorithm] DES3 required for legacy HASP dongle protocol
                padded_data = data + b"\x00" * (8 - len(data) % 8)
                return des3_cipher.encrypt(padded_data)
            else:
                return self._xor_encrypt(data, key)
        except Exception as e:
            self.logger.exception("Encryption error: %s", e)
            return self._xor_encrypt(data, key)

    def hasp_decrypt(self, data: bytes, key: bytes, algorithm: str = "AES") -> bytes:
        """Perform HASP decryption operation.

        Decrypts ciphertext data using the specified symmetric cipher algorithm
        with automatic padding removal. Falls back to XOR decryption if cryptography unavailable.

        Args:
            data (bytes): Ciphertext bytes to decrypt using the specified algorithm.
            key (bytes): Decryption key bytes (32 bytes for AES, 8 for DES, 24 for DES3).
            algorithm (str): Cipher algorithm to use ("AES", "DES", "DES3"). Defaults to "AES".

        Returns:
            bytes: Decrypted plaintext bytes with null-byte padding removed, or XOR-decrypted fallback.

        """
        if not CRYPTO_AVAILABLE:
            self.logger.warning("Crypto not available, returning XOR decryption")
            return self._xor_encrypt(data, key)

        try:
            if algorithm == "AES":
                aes_cipher = AES.new(
                    key[:32], AES.MODE_ECB
                )  # lgtm[py/weak-cryptographic-algorithm] ECB required for HASP protocol compatibility
                decrypted: bytes = aes_cipher.decrypt(data)
                return decrypted.rstrip(b"\x00")
            elif algorithm == "DES":
                des_cipher = DES.new(key[:8], DES.MODE_ECB)  # noqa: S304 lgtm[py/weak-cryptographic-algorithm] DES required for legacy HASP dongle protocol
                decrypted = des_cipher.decrypt(data)
                return decrypted.rstrip(b"\x00")
            elif algorithm == "DES3":
                des3_cipher = DES3.new(
                    key[:24], DES3.MODE_ECB
                )  # lgtm[py/weak-cryptographic-algorithm] DES3 required for legacy HASP dongle protocol
                decrypted = des3_cipher.decrypt(data)
                return decrypted.rstrip(b"\x00")
            else:
                return self._xor_encrypt(data, key)
        except Exception as e:
            self.logger.exception("Decryption error: %s", e)
            return self._xor_encrypt(data, key)

    def sentinel_challenge_response(self, challenge: bytes, key: bytes) -> bytes:
        """Calculate Sentinel challenge-response.

        Computes the challenge-response for Sentinel/SafeNet dongle authentication
        using HMAC-SHA256, truncated to 16 bytes for protocol compatibility.

        Args:
            challenge (bytes): Challenge bytes from Sentinel dongle authentication request.
            key (bytes): Key bytes for HMAC computation in Sentinel authentication protocol.

        Returns:
            bytes: Challenge response as 16-byte HMAC-SHA256 value, or SHA256 digest fallback.

        """
        if not CRYPTO_AVAILABLE:
            return hashlib.sha256(challenge + key).digest()

        h = hmac.new(key, challenge, hashlib.sha256)
        response = h.digest()
        return response[:16]

    def wibukey_challenge_response(self, challenge: bytes, key: bytes) -> bytes:
        """Calculate WibuKey challenge-response.

        Computes the challenge-response for WibuKey/CodeMeter dongle authentication
        using XOR with index-based modification, optionally encrypted with AES.

        Args:
            challenge (bytes): Challenge bytes from WibuKey dongle authentication request.
            key (bytes): Key bytes for challenge computation in WibuKey authentication protocol.

        Returns:
            bytes: Challenge response as 16-byte value with XOR transformation and optional AES encryption.

        """
        response = bytearray(16)
        for i in range(16):
            challenge_byte = challenge[i % len(challenge)]
            key_byte = key[i % len(key)]
            response[i] = (challenge_byte ^ key_byte ^ (i * 17)) & 0xFF

        if CRYPTO_AVAILABLE:
            cipher = AES.new(
                key[:16], AES.MODE_ECB
            )  # lgtm[py/weak-cryptographic-algorithm] ECB required for WibuKey protocol compatibility
            return cipher.encrypt(bytes(response))

        return bytes(response)

    def rsa_sign(self, data: bytes, private_key: object) -> bytes:
        """Sign data with RSA private key.

        Creates a cryptographic signature of the provided data using an RSA private key
        in PKCS#1 v1.5 format with SHA256 hashing. Returns SHA256 digest as fallback.

        Args:
            data (bytes): Data bytes to sign using RSA private key.
            private_key (object): RSA private key object for creating PKCS#1 v1.5 signature.

        Returns:
            bytes: Signature bytes in PKCS#1 v1.5 format, or SHA256 digest hash if signing fails or unavailable.

        """
        if not CRYPTO_AVAILABLE or private_key is None:
            return hashlib.sha256(data).digest()

        try:
            h = SHA256.new(data)
            signer = PKCS1_v1_5.new(private_key)
            signature: bytes = signer.sign(h)
            return signature
        except Exception as e:
            self.logger.exception("RSA signing error: %s", e)
            return hashlib.sha256(data).digest()

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Perform simple XOR encryption fallback.

        Encrypts or decrypts data using simple XOR operation with the provided key,
        repeating the key as necessary. Used as fallback when cryptography is unavailable.

        Args:
            data (bytes): Data bytes to XOR encrypt using repeating key pattern.
            key (bytes): Key bytes for XOR operation, repeated to match data length.

        Returns:
            bytes: XOR-encrypted bytes using the repeating key pattern.

        """
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % len(key)]
        return bytes(result)


class HardwareDongleEmulator:
    """Implements hardware dongle emulation for various protection systems."""

    def __init__(self, app: object | None = None) -> None:
        """Initialize the hardware dongle emulator.

        Sets up all data structures for emulating multiple dongle types including
        HASP, Sentinel/SafeNet, and CodeMeter/WibuKey protection devices.

        Args:
            app: Application instance that contains the binary_path attribute for binary patching.

        """
        self.app = app
        self.logger = logging.getLogger("IntellicrackLogger.DongleEmulator")
        self.hooks: list[dict[str, Any]] = []
        self.patches: list[dict[str, Any]] = []
        self.virtual_dongles: dict[str, dict[str, Any]] = {}
        self.crypto_engine = CryptoEngine()
        self.usb_emulators: dict[str, USBEmulator] = {}
        self.hasp_dongles: dict[int, HASPDongle] = {}
        self.sentinel_dongles: dict[int, SentinelDongle] = {}
        self.wibukey_dongles: dict[int, WibuKeyDongle] = {}
        self.lock = threading.Lock()

    def activate_dongle_emulation(self, dongle_types: list[str] | None = None) -> dict[str, Any]:
        """Activate hardware dongle emulation.

        Orchestrates dongle emulation through virtual device creation, USB device emulation,
        API hooking, binary patching, and registry spoofing to defeat licensing protection.

        Args:
            dongle_types: List of dongle type names to emulate (SafeNet, HASP, CodeMeter, etc.),
                or None to emulate all supported protection mechanisms.

        Returns:
            Dictionary with success status, list of emulated dongles, methods applied, and any error messages.

        """
        if dongle_types is None:
            dongle_types = [
                "SafeNet",
                "HASP",
                "CodeMeter",
                "Rainbow",
                "ROCKEY",
                "Dinkey",
                "SuperPro",
                "eToken",
            ]

        methods_applied: list[str] = []
        errors: list[str] = []

        results: dict[str, Any] = {
            "success": False,
            "emulated_dongles": [],
            "methods_applied": methods_applied,
            "errors": errors,
        }

        try:
            self._create_virtual_dongles(dongle_types)
            methods_applied.append("Virtual Dongle Creation")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in dongle_emulator: %s", e)
            errors.append(f"Virtual dongle creation failed: {e!s}")

        try:
            self._setup_usb_emulation(dongle_types)
            methods_applied.append("USB Device Emulation")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in dongle_emulator: %s", e)
            errors.append(f"USB emulation failed: {e!s}")

        try:
            self._hook_dongle_apis(dongle_types)
            methods_applied.append("API Hooking")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in dongle_emulator: %s", e)
            errors.append(f"API hooking failed: {e!s}")

        try:
            if self.app and hasattr(self.app, "binary_path") and self.app.binary_path:
                self._patch_dongle_checks()
                methods_applied.append("Binary Patching")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in dongle_emulator: %s", e)
            errors.append(f"Binary patching failed: {e!s}")

        try:
            self._spoof_dongle_registry()
            methods_applied.append("Registry Spoofing")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error in dongle_emulator: %s", e)
            errors.append(f"Registry spoofing failed: {e!s}")

        results["emulated_dongles"] = list(self.virtual_dongles.keys())
        results["success"] = len(methods_applied) > 0
        return results

    def _create_virtual_dongles(self, dongle_types: list[str]) -> None:
        """Create virtual dongle devices with full memory and crypto support.

        Instantiates HASP, Sentinel, and WibuKey dongle objects with preconfigured
        memory regions, protected areas, and cryptographic keys for protocol emulation.

        Args:
            dongle_types (list[str]): List of dongle type names (SafeNet, HASP, CodeMeter, etc.) to create.

        """
        with self.lock:
            for dongle_type in dongle_types:
                if dongle_type in {"SafeNet", "HASP"}:
                    hasp_id = len(self.hasp_dongles) + 1
                    hasp_dongle = HASPDongle(hasp_id=0x12345678 + hasp_id)
                    hasp_dongle.memory.protected_areas = [(0, 1024)]
                    hasp_dongle.memory.read_only_areas = [(0, 512)]

                    license_info = struct.pack("<IIII", hasp_dongle.feature_id, 0xFFFFFFFF, 10, 1)
                    hasp_dongle.license_data[: len(license_info)] = license_info

                    self.hasp_dongles[hasp_id] = hasp_dongle
                    self.virtual_dongles[f"HASP_{hasp_id}"] = {
                        "type": "HASP",
                        "hasp_id": hasp_dongle.hasp_id,
                        "vendor_code": hasp_dongle.vendor_code,
                        "feature_id": hasp_dongle.feature_id,
                        "instance": hasp_dongle,
                    }

                elif dongle_type in {"Sentinel", "SafeNet"}:
                    sentinel_id = len(self.sentinel_dongles) + 1
                    sentinel_dongle = SentinelDongle(device_id=0x87654321 + sentinel_id)
                    sentinel_dongle.memory.protected_areas = [(0, 2048)]
                    sentinel_dongle.memory.read_only_areas = [(0, 1024)]

                    self.sentinel_dongles[sentinel_id] = sentinel_dongle
                    self.virtual_dongles[f"Sentinel_{sentinel_id}"] = {
                        "type": "Sentinel",
                        "device_id": sentinel_dongle.device_id,
                        "serial_number": sentinel_dongle.serial_number,
                        "instance": sentinel_dongle,
                    }

                elif dongle_type == "CodeMeter":
                    wibu_id = len(self.wibukey_dongles) + 1
                    wibu_dongle = WibuKeyDongle(serial_number=1000000 + wibu_id)
                    wibu_dongle.memory.protected_areas = [(0, 4096)]

                    self.wibukey_dongles[wibu_id] = wibu_dongle
                    self.virtual_dongles[f"WibuKey_{wibu_id}"] = {
                        "type": "WibuKey",
                        "firm_code": wibu_dongle.firm_code,
                        "product_code": wibu_dongle.product_code,
                        "serial_number": wibu_dongle.serial_number,
                        "instance": wibu_dongle,
                    }

        self.logger.info("Created %d virtual dongles with full memory emulation", len(self.virtual_dongles))

    def _setup_usb_emulation(self, dongle_types: list[str]) -> None:
        """Set up USB device emulation for dongles.

        Configures USB device emulators with appropriate vendor/product IDs and
        registers handlers for control and bulk transfers specific to each dongle type.

        Args:
            dongle_types (list[str]): List of dongle type names (HASP, Sentinel, CodeMeter) to configure USB emulation for.

        """
        for dongle_type in dongle_types:
            if dongle_type == "HASP":
                descriptor = USBDescriptor(
                    idVendor=0x0529,
                    idProduct=0x0001,
                    bDeviceClass=0xFF,
                    bDeviceSubClass=0xFF,
                )
                usb = USBEmulator(descriptor)
                usb.register_control_handler(0x40, 0x01, self._hasp_control_handler)
                usb.register_bulk_handler(0x02, self._hasp_bulk_out_handler)
                usb.register_bulk_handler(0x81, self._hasp_bulk_in_handler)
                self.usb_emulators["HASP_USB"] = usb

            elif dongle_type in {"Sentinel", "SafeNet"}:
                descriptor = USBDescriptor(
                    idVendor=0x0529,
                    idProduct=0x0001,
                    bDeviceClass=0xFF,
                )
                usb = USBEmulator(descriptor)
                usb.register_control_handler(0x40, 0x02, self._sentinel_control_handler)
                usb.register_bulk_handler(0x02, self._sentinel_bulk_out_handler)
                usb.register_bulk_handler(0x81, self._sentinel_bulk_in_handler)
                self.usb_emulators["Sentinel_USB"] = usb

            elif dongle_type == "CodeMeter":
                descriptor = USBDescriptor(
                    idVendor=0x064F,
                    idProduct=0x0BD7,
                    bDeviceClass=0x00,
                )
                usb = USBEmulator(descriptor)
                usb.register_control_handler(0x40, 0x03, self._wibukey_control_handler)
                usb.register_bulk_handler(0x02, self._wibukey_bulk_out_handler)
                usb.register_bulk_handler(0x81, self._wibukey_bulk_in_handler)
                self.usb_emulators["WibuKey_USB"] = usb

        self.logger.info("Setup USB emulation for %d dongle types", len(self.usb_emulators))

    def _hasp_control_handler(self, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle HASP USB control transfers.

        Processes HASP-specific control transfer requests for dongle identification,
        returning HASP ID, vendor code, feature ID, and seed code based on request type.

        Args:
            wValue (int): USB transfer wValue field indicating which information to return.
            wIndex (int): USB transfer wIndex field containing additional request parameters.
            data (bytes): Control transfer data payload from the request.

        Returns:
            bytes: Response data bytes containing HASP device information or empty response.

        """
        if not self.hasp_dongles:
            return b"\x00" * 64

        dongle = next(iter(self.hasp_dongles.values()))

        if wValue == 1:
            return struct.pack("<I", dongle.hasp_id)
        elif wValue == 2:
            return struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        elif wValue == 3:
            return dongle.seed_code

        return b"\x00" * 64

    def _hasp_bulk_out_handler(self, data: bytes) -> bytes:
        """Handle HASP bulk OUT transfers.

        Processes outgoing bulk transfer commands from the host to the HASP dongle,
        dispatching to appropriate handlers for login, logout, encryption, and memory operations.

        Args:
            data (bytes): Bulk transfer payload containing command code and parameters.

        Returns:
            bytes: Response data bytes from the command handler, or empty bytes if command unrecognized.

        """
        if len(data) < 4:
            return b""

        command = struct.unpack("<I", data[:4])[0]

        if command == 1:
            return self._hasp_login(data[4:])
        elif command == 2:
            return self._hasp_logout(data[4:])
        elif command == 3:
            return self._hasp_encrypt_command(data[4:])
        elif command == 4:
            return self._hasp_decrypt_command(data[4:])
        elif command == 5:
            return self._hasp_read_memory(data[4:])
        elif command == 6:
            return self._hasp_write_memory(data[4:])

        return struct.pack("<I", HASPStatus.HASP_STATUS_OK)

    def _hasp_bulk_in_handler(self, data: bytes) -> bytes:
        """Handle HASP bulk IN transfers.

        Handles incoming bulk transfer requests from the host to retrieve dongle
        information including HASP ID, vendor code, feature ID, and RTC counter.

        Args:
            data (bytes): Bulk transfer request data containing query parameters.

        Returns:
            bytes: Response data bytes containing dongle information in structured format.

        """
        if not self.hasp_dongles:
            return b"\x00" * 512

        dongle = next(iter(self.hasp_dongles.values()))
        response = bytearray(512)

        info = struct.pack(
            "<IHHQ",
            dongle.hasp_id,
            dongle.vendor_code,
            dongle.feature_id,
            dongle.rtc_counter,
        )
        response[: len(info)] = info

        return bytes(response)

    def _hasp_login(self, data: bytes) -> bytes:
        """Handle HASP login operation.

        Authenticates a login request by verifying the vendor code against emulated
        dongles and returns a session handle for subsequent operations.

        Args:
            data (bytes): Login request data containing vendor code and feature ID bytes.

        Returns:
            bytes: Status code and session handle if successful, or error status code otherwise.

        """
        if len(data) < 4:
            return struct.pack("<I", HASPStatus.HASP_TOO_SHORT)

        vendor_code, _feature_id = struct.unpack("<HH", data[:4])

        for dongle in self.hasp_dongles.values():
            if dongle.vendor_code == vendor_code:
                dongle.logged_in = True
                dongle.session_handle = 0x12345678 + len(self.hasp_dongles)
                return struct.pack("<II", HASPStatus.HASP_STATUS_OK, dongle.session_handle)

        return struct.pack("<I", HASPStatus.HASP_KEYNOTFOUND)

    def _hasp_logout(self, data: bytes) -> bytes:
        """Handle HASP logout operation.

        Terminates a login session by invalidating the session handle and marking
        the dongle as logged out for security.

        Args:
            data (bytes): Logout request data containing the session handle to terminate.

        Returns:
            bytes: Status code indicating successful logout or error code if session handle invalid.

        """
        if len(data) < 4:
            return struct.pack("<I", HASPStatus.HASP_TOO_SHORT)

        session_handle = struct.unpack("<I", data[:4])[0]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle:
                dongle.logged_in = False
                return struct.pack("<I", HASPStatus.HASP_STATUS_OK)

        return struct.pack("<I", HASPStatus.HASP_INV_HND)

    def _hasp_encrypt_command(self, data: bytes) -> bytes:
        """Handle HASP encrypt command.

        Encrypts plaintext data using the emulated dongle's encryption key and
        algorithm, returning encrypted data in response to host encryption request.

        Args:
            data (bytes): Encryption request containing session handle, data length, and plaintext bytes.

        Returns:
            bytes: Status code and encrypted data bytes, or error status if request invalid.

        """
        if len(data) < 8:
            return struct.pack("<I", HASPStatus.HASP_TOO_SHORT)

        session_handle, data_length = struct.unpack("<II", data[:8])
        plaintext = data[8 : 8 + data_length]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                encrypted = self.crypto_engine.hasp_encrypt(plaintext, dongle.aes_key, "AES")
                response = struct.pack("<II", HASPStatus.HASP_STATUS_OK, len(encrypted))
                return response + encrypted

        return struct.pack("<I", HASPStatus.HASP_INV_HND)

    def _hasp_decrypt_command(self, data: bytes) -> bytes:
        """Handle HASP decrypt command.

        Decrypts ciphertext data using the emulated dongle's decryption key and
        algorithm, returning plaintext in response to host decryption request.

        Args:
            data (bytes): Decryption request containing session handle, data length, and ciphertext bytes.

        Returns:
            bytes: Status code and decrypted plaintext bytes, or error status if request invalid.

        """
        if len(data) < 20:
            return struct.pack("<I", HASPStatus.HASP_TOO_SHORT)

        session_handle, data_length = struct.unpack("<II", data[:8])
        ciphertext = data[8 : 8 + data_length]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                decrypted = self.crypto_engine.hasp_decrypt(ciphertext, dongle.aes_key, "AES")
                response = struct.pack("<II", HASPStatus.HASP_STATUS_OK, len(decrypted))
                return response + decrypted

        return struct.pack("<I", HASPStatus.HASP_INV_HND)

    def _hasp_read_memory(self, data: bytes) -> bytes:
        """Handle HASP memory read operation.

        Reads data from the emulated dongle's EEPROM memory at the specified offset
        and length, enforcing session authentication and memory bounds.

        Args:
            data (bytes): Read request containing session handle, memory offset, and byte length.

        Returns:
            bytes: Status code and memory data bytes if successful, or error status code otherwise.

        """
        if len(data) < 12:
            return struct.pack("<I", HASPStatus.HASP_TOO_SHORT)

        session_handle, offset, length = struct.unpack("<III", data[:12])

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                try:
                    mem_data = dongle.memory.read("eeprom", offset, length)
                    response = struct.pack("<II", HASPStatus.HASP_STATUS_OK, len(mem_data))
                    return response + mem_data
                except (ValueError, PermissionError):
                    return struct.pack("<I", HASPStatus.HASP_MEM_RANGE)

        return struct.pack("<I", HASPStatus.HASP_INV_HND)

    def _hasp_write_memory(self, data: bytes) -> bytes:
        """Handle HASP memory write operation.

        Writes data to the emulated dongle's EEPROM memory at the specified offset,
        enforcing session authentication and memory bounds checking.

        Args:
            data (bytes): Write request containing session handle, memory offset, length, and write data bytes.

        Returns:
            bytes: Status code indicating successful write or error code if request invalid or bounds exceeded.

        """
        if len(data) < 12:
            return struct.pack("<I", HASPStatus.HASP_TOO_SHORT)

        session_handle, offset, length = struct.unpack("<III", data[:12])
        write_data = data[12 : 12 + length]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                try:
                    dongle.memory.write("eeprom", offset, write_data)
                    return struct.pack("<I", HASPStatus.HASP_STATUS_OK)
                except (ValueError, PermissionError):
                    return struct.pack("<I", HASPStatus.HASP_MEM_RANGE)

        return struct.pack("<I", HASPStatus.HASP_INV_HND)

    def _sentinel_control_handler(self, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle Sentinel USB control transfers.

        Processes Sentinel/SafeNet control transfer requests for device identification,
        returning device ID, vendor ID, serial number, and firmware version based on request.

        Args:
            wValue (int): USB transfer wValue field indicating which information to return.
            wIndex (int): USB transfer wIndex field containing additional request parameters.
            data (bytes): Control transfer payload data from the request.

        Returns:
            bytes: Response bytes containing requested Sentinel device information or empty response.

        """
        if not self.sentinel_dongles:
            return b"\x00" * 64

        dongle = next(iter(self.sentinel_dongles.values()))

        if wValue == 1:
            return struct.pack("<I", dongle.device_id)
        elif wValue == 2:
            return dongle.serial_number.encode("ascii")[:16].ljust(16, b"\x00")
        elif wValue == 3:
            return dongle.firmware_version.encode("ascii")[:16].ljust(16, b"\x00")

        return b"\x00" * 64

    def _sentinel_bulk_out_handler(self, data: bytes) -> bytes:
        """Handle Sentinel bulk OUT transfers.

        Dispatches command packets to appropriate Sentinel operation handlers
        based on command type code in the data payload (query, read, write, encrypt).

        Args:
            data (bytes): Bulk transfer payload containing command code and operation parameters.

        Returns:
            bytes: Response bytes from the executed Sentinel operation handler or status code.

        """
        if len(data) < 4:
            return b""

        command = struct.unpack("<I", data[:4])[0]

        if command == 1:
            return self._sentinel_query(data[4:])
        elif command == 2:
            return self._sentinel_read(data[4:])
        elif command == 3:
            return self._sentinel_write(data[4:])
        elif command == 4:
            return self._sentinel_encrypt(data[4:])

        return struct.pack("<I", SentinelStatus.SP_SUCCESS)

    def _sentinel_bulk_in_handler(self, data: bytes) -> bytes:
        """Handle Sentinel bulk IN transfers.

        Retrieves previously buffered response data from emulated Sentinel dongle
        that was populated by earlier OUT transfer operations.

        Args:
            data (bytes): Bulk IN request data payload (typically unused for Sentinel protocol).

        Returns:
            bytes: Response buffer containing up to 512 bytes from dongle response buffer.

        """
        if not self.sentinel_dongles:
            return b"\x00" * 512

        dongle = next(iter(self.sentinel_dongles.values()))
        return bytes(dongle.response_buffer[:512])

    def _sentinel_query(self, data: bytes) -> bytes:
        """Handle Sentinel query operation.

        Responds to Sentinel device query requests by returning dongle identification
        and status information (device ID, serial number, firmware version, developer ID).

        Args:
            data (bytes): Query request data bytes (typically unused for basic query operation).

        Returns:
            bytes: Status code indicating success or device not found error.

        """
        if not self.sentinel_dongles:
            return struct.pack("<I", SentinelStatus.SP_UNIT_NOT_FOUND)

        dongle = next(iter(self.sentinel_dongles.values()))

        query_data = struct.pack(
            "<I16s16sI",
            dongle.device_id,
            dongle.serial_number.encode("ascii")[:16].ljust(16, b"\x00"),
            dongle.firmware_version.encode("ascii")[:16].ljust(16, b"\x00"),
            dongle.developer_id,
        )

        dongle.response_buffer[: len(query_data)] = query_data

        return struct.pack("<I", SentinelStatus.SP_SUCCESS)

    def _sentinel_read(self, data: bytes) -> bytes:
        """Handle Sentinel read operation.

        Reads data from specified cell in Sentinel dongle memory and buffers
        the result for subsequent IN transfer to the host.

        Args:
            data (bytes): Read request containing cell ID (4 bytes) and read length (4 bytes).

        Returns:
            bytes: Status code indicating success, invalid function code, or unit not found.

        """
        if len(data) < 8:
            return struct.pack("<I", SentinelStatus.SP_INVALID_FUNCTION_CODE)

        cell_id, length = struct.unpack("<II", data[:8])

        for dongle in self.sentinel_dongles.values():
            if cell_id in dongle.cell_data:
                cell_data = dongle.cell_data[cell_id][:length]
                dongle.response_buffer[: len(cell_data)] = cell_data
                return struct.pack("<I", SentinelStatus.SP_SUCCESS)

        return struct.pack("<I", SentinelStatus.SP_UNIT_NOT_FOUND)

    def _sentinel_write(self, data: bytes) -> bytes:
        """Handle Sentinel write operation.

        Writes data to specified cell in Sentinel dongle memory. Data is padded
        to 64 bytes with null bytes if needed for memory alignment.

        Args:
            data (bytes): Write request containing cell ID (4 bytes), data length (4 bytes),
                  and cell data bytes to write.

        Returns:
            bytes: Status code indicating success, invalid function code, or unit not found.

        """
        if len(data) < 8:
            return struct.pack("<I", SentinelStatus.SP_INVALID_FUNCTION_CODE)

        cell_id, length = struct.unpack("<II", data[:8])
        write_data = data[8 : 8 + length]

        for dongle in self.sentinel_dongles.values():
            if cell_id < 64:
                dongle.cell_data[cell_id] = write_data.ljust(64, b"\x00")
                return struct.pack("<I", SentinelStatus.SP_SUCCESS)

        return struct.pack("<I", SentinelStatus.SP_UNIT_NOT_FOUND)

    def _sentinel_encrypt(self, data: bytes) -> bytes:
        """Handle Sentinel encryption operation.

        Encrypts plaintext using AES encryption with the emulated Sentinel dongle's
        AES key and buffers the encrypted result for subsequent IN transfer.

        Args:
            data (bytes): Encryption request containing data length (4 bytes) and plaintext bytes.

        Returns:
            bytes: Status code indicating success, invalid function code, or unit not found.

        """
        if len(data) < 4:
            return struct.pack("<I", SentinelStatus.SP_INVALID_FUNCTION_CODE)

        data_length = struct.unpack("<I", data[:4])[0]
        plaintext = data[4 : 4 + data_length]

        for dongle in self.sentinel_dongles.values():
            encrypted = self.crypto_engine.hasp_encrypt(plaintext, dongle.aes_key, "AES")
            dongle.response_buffer[: len(encrypted)] = encrypted
            return struct.pack("<I", SentinelStatus.SP_SUCCESS)

        return struct.pack("<I", SentinelStatus.SP_UNIT_NOT_FOUND)

    def _wibukey_control_handler(self, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle WibuKey USB control transfers.

        Processes WibuKey/CodeMeter control transfer requests for device identification,
        returning firmware code, product code, serial number, and version based on request.

        Args:
            wValue (int): USB transfer wValue field indicating which information to return.
            wIndex (int): USB transfer wIndex field containing additional request parameters.
            data (bytes): Control transfer payload data from the request.

        Returns:
            bytes: Response bytes containing requested WibuKey device information or empty response.

        """
        if not self.wibukey_dongles:
            return b"\x00" * 64

        dongle = next(iter(self.wibukey_dongles.values()))

        if wValue == 1:
            return struct.pack(
                "<III",
                dongle.firm_code,
                dongle.product_code,
                dongle.serial_number,
            )
        elif wValue == 2:
            return dongle.version.encode("ascii")[:16].ljust(16, b"\x00")

        return b"\x00" * 64

    def _wibukey_bulk_out_handler(self, data: bytes) -> bytes:
        """Handle WibuKey bulk OUT transfers.

        Dispatches command packets to appropriate WibuKey operation handlers
        based on command type code (open, access, encrypt, challenge) in the payload.

        Args:
            data (bytes): Bulk transfer payload containing command code and operation parameters.

        Returns:
            bytes: Response bytes from the executed WibuKey operation handler or status code.

        """
        if len(data) < 4:
            return b""

        command = struct.unpack("<I", data[:4])[0]

        if command == 1:
            return self._wibukey_open(data[4:])
        elif command == 2:
            return self._wibukey_access(data[4:])
        elif command == 3:
            return self._wibukey_encrypt(data[4:])
        elif command == 4:
            return self._wibukey_challenge(data[4:])

        return struct.pack("<I", 0)

    def _wibukey_bulk_in_handler(self, data: bytes) -> bytes:
        """Handle WibuKey bulk IN transfers.

        Retrieves WibuKey dongle information including firmware code, product code,
        feature code, and serial number from the buffered response.

        Args:
            data (bytes): Bulk IN request data payload (typically unused for WibuKey protocol).

        Returns:
            bytes: Response buffer containing dongle identification and status information.

        """
        if not self.wibukey_dongles:
            return b"\x00" * 512

        dongle = next(iter(self.wibukey_dongles.values()))
        response = bytearray(512)

        info = struct.pack(
            "<IIII",
            dongle.firm_code,
            dongle.product_code,
            dongle.feature_code,
            dongle.serial_number,
        )
        response[: len(info)] = info

        return bytes(response)

    def _wibukey_open(self, data: bytes) -> bytes:
        """Handle WibuKey open operation.

        Opens a WibuKey/CodeMeter license container by verifying firmware and
        product codes, returning a container handle on success.

        Args:
            data (bytes): Open request containing firm code (4 bytes) and product code (4 bytes).

        Returns:
            bytes: Error code (0) and container handle on success, or error code (1) if request invalid or no matching dongle.

        """
        if len(data) < 8:
            return struct.pack("<I", 1)

        firm_code, product_code = struct.unpack("<II", data[:8])

        for dongle in self.wibukey_dongles.values():
            if dongle.firm_code == firm_code and dongle.product_code == product_code:
                return struct.pack("<II", 0, dongle.container_handle)

        return struct.pack("<I", 1)

    def _wibukey_access(self, data: bytes) -> bytes:
        """Handle WibuKey access operation.

        Validates access to a license feature in a WibuKey/CodeMeter container,
        marking the feature as active if enabled and available.

        Args:
            data (bytes): Access request containing container handle (4 bytes), feature code
                  (4 bytes), and access type (4 bytes) indicating access permission type.

        Returns:
            bytes: Error code (0) indicating success, or error code (1) if request invalid or feature unavailable.

        """
        if len(data) < 12:
            return struct.pack("<I", 1)

        container_handle, feature_code, _access_type = struct.unpack("<III", data[:12])

        for dongle in self.wibukey_dongles.values():
            if dongle.container_handle == container_handle and feature_code in dongle.license_entries:
                entry = dongle.license_entries[feature_code]
                if entry["enabled"]:
                    dongle.active_licenses.add(feature_code)
                    return struct.pack("<I", 0)

        return struct.pack("<I", 1)

    def _wibukey_encrypt(self, data: bytes) -> bytes:
        """Handle WibuKey encrypt operation.

        Encrypts plaintext using AES encryption with the WibuKey/CodeMeter dongle's
        AES key, returning error code and encrypted data on success.

        Args:
            data (bytes): Encryption request containing container handle (4 bytes), data length
                  (4 bytes), and plaintext bytes to encrypt.

        Returns:
            bytes: Error code (0) and encrypted data length on success, or error code (1) if request invalid or container not found.

        """
        if len(data) < 8:
            return struct.pack("<I", 1)

        container_handle, data_length = struct.unpack("<II", data[:8])
        plaintext = data[8 : 8 + data_length]

        for dongle in self.wibukey_dongles.values():
            if dongle.container_handle == container_handle:
                encrypted = self.crypto_engine.hasp_encrypt(plaintext, dongle.aes_key, "AES")
                response = struct.pack("<II", 0, len(encrypted))
                return response + encrypted

        return struct.pack("<I", 1)

    def _wibukey_challenge(self, data: bytes) -> bytes:
        """Handle WibuKey challenge-response operation.

        Computes a cryptographic challenge-response using WibuKey/CodeMeter's
        challenge-response algorithm with the dongle's challenge response key.

        Args:
            data (bytes): Challenge request containing container handle (4 bytes), challenge
                  length (4 bytes), and challenge bytes for authentication.

        Returns:
            bytes: Error code (0) and response data length on success, or error code (1) if request invalid or container not found.

        """
        if len(data) < 20:
            return struct.pack("<I", 1)

        container_handle, challenge_length = struct.unpack("<II", data[:8])
        challenge = data[8 : 8 + challenge_length]

        for dongle in self.wibukey_dongles.values():
            if dongle.container_handle == container_handle:
                response = self.crypto_engine.wibukey_challenge_response(
                    challenge,
                    dongle.challenge_response_key,
                )
                result = struct.pack("<II", 0, len(response))
                return result + response

        return struct.pack("<I", 1)

    def _hook_dongle_apis(self, dongle_types: list[str]) -> None:
        """Install comprehensive Frida hooks for dongle APIs.

        Generates and installs Frida instrumentation hooks for HASP, Sentinel,
        and CodeMeter/WibuKey API functions, redirecting calls to emulated handlers.

        Args:
            dongle_types (list[str]): List of dongle type names (HASP, Sentinel, CodeMeter) to install hooks for.

        """
        if not FRIDA_AVAILABLE:
            self.logger.warning("Frida not available - skipping dongle API hooking")
            return

        frida_script = f"""
        console.log("[Dongle Emulator] Starting comprehensive dongle API hooking...");

        if ({dongle_types!s}.includes("HASP")) {{
            var haspModule = Process.findModuleByName("hasp_windows_x64_demo.dll");
            if (!haspModule) {{ haspModule = Process.findModuleByName("aksusbd_x64.dll"); }}
            if (!haspModule) {{ haspModule = Process.findModuleByName("hasp_net_windows.dll"); }}

            if (haspModule) {{
                try {{
                    var haspLogin = Module.findExportByName(haspModule.name, "hasp_login");
                    if (haspLogin) {{
                        Interceptor.attach(haspLogin, {{
                            onEnter: function(args) {{
                                this.vendorCode = args[0].toInt32();
                                this.featureId = args[1].toInt32();
                                this.handlePtr = args[2];
                                console.log("[HASP] hasp_login called: vendor=" + this.vendorCode + " feature=" + this.featureId);
                            }},
                            onLeave: function(retval) {{
                                if (this.handlePtr) {{
                                    this.handlePtr.writeU32(0x12345678);
                                }}
                                retval.replace(0);
                                console.log("[HASP] hasp_login returning HASP_STATUS_OK with handle 0x12345678");
                            }}
                        }});
                    }}

                    var haspEncrypt = Module.findExportByName(haspModule.name, "hasp_encrypt");
                    if (haspEncrypt) {{
                        Interceptor.attach(haspEncrypt, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                this.dataPtr = args[1];
                                this.dataLen = args[2].toInt32();
                                console.log("[HASP] hasp_encrypt called: handle=0x" + this.handle.toString(16) + " len=" + this.dataLen);
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[HASP] hasp_encrypt returning HASP_STATUS_OK");
                            }}
                        }});
                    }}

                    var haspDecrypt = Module.findExportByName(haspModule.name, "hasp_decrypt");
                    if (haspDecrypt) {{
                        Interceptor.attach(haspDecrypt, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                console.log("[HASP] hasp_decrypt called: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[HASP] hasp_decrypt returning HASP_STATUS_OK");
                            }}
                        }});
                    }}

                    var haspRead = Module.findExportByName(haspModule.name, "hasp_read");
                    if (haspRead) {{
                        Interceptor.attach(haspRead, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                this.fileId = args[1].toInt32();
                                this.offset = args[2].toInt32();
                                this.length = args[3].toInt32();
                                this.buffer = args[4];
                                console.log("[HASP] hasp_read: file=" + this.fileId + " offset=" + this.offset + " len=" + this.length);
                            }},
                            onLeave: function(retval) {{
                                if (this.buffer && this.length > 0) {{
                                    var memoryData = new Uint8Array(this.length);
                                    var baseValue = (this.fileId * 17 + this.offset * 3) & 0xFF;
                                    for (var i = 0; i < this.length; i++) {{
                                        var value = (baseValue + i * 7 + (this.handle & 0xFF)) & 0xFF;
                                        memoryData[i] = value;
                                    }}
                                    this.buffer.writeByteArray(Array.from(memoryData));
                                }}
                                retval.replace(0);
                                console.log("[HASP] hasp_read returning HASP_STATUS_OK");
                            }}
                        }});
                    }}

                    var haspWrite = Module.findExportByName(haspModule.name, "hasp_write");
                    if (haspWrite) {{
                        Interceptor.attach(haspWrite, {{
                            onLeave: function(retval) {{
                                retval.replace(0);
                            }}
                        }});
                    }}

                    var haspGetSize = Module.findExportByName(haspModule.name, "hasp_get_size");
                    if (haspGetSize) {{
                        Interceptor.attach(haspGetSize, {{
                            onEnter: function(args) {{
                                this.sizePtr = args[3];
                            }},
                            onLeave: function(retval) {{
                                if (this.sizePtr) {{
                                    this.sizePtr.writeU32(4096);
                                }}
                                retval.replace(0);
                            }}
                        }});
                    }}

                    var haspLogout = Module.findExportByName(haspModule.name, "hasp_logout");
                    if (haspLogout) {{
                        Interceptor.attach(haspLogout, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                console.log("[HASP] hasp_logout called: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[HASP] hasp_logout returning HASP_STATUS_OK");
                            }}
                        }});
                    }}

                    var haspGetRtc = Module.findExportByName(haspModule.name, "hasp_get_rtc");
                    if (haspGetRtc) {{
                        Interceptor.attach(haspGetRtc, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                this.rtcPtr = args[1];
                                console.log("[HASP] hasp_get_rtc called: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                if (this.rtcPtr) {{
                                    var currentTime = Math.floor(Date.now() / 1000);
                                    this.rtcPtr.writeU32(currentTime);
                                }}
                                retval.replace(0);
                                console.log("[HASP] hasp_get_rtc returning HASP_STATUS_OK");
                            }}
                        }});
                    }}

                    var haspLegacyEncrypt = Module.findExportByName(haspModule.name, "hasp_legacy_encrypt");
                    if (haspLegacyEncrypt) {{
                        Interceptor.attach(haspLegacyEncrypt, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                console.log("[HASP] hasp_legacy_encrypt called: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[HASP] hasp_legacy_encrypt returning HASP_STATUS_OK");
                            }}
                        }});
                    }}

                    var haspGetInfo = Module.findExportByName(haspModule.name, "hasp_get_info");
                    if (haspGetInfo) {{
                        Interceptor.attach(haspGetInfo, {{
                            onEnter: function(args) {{
                                this.infoPtr = args[2];
                                console.log("[HASP] hasp_get_info called");
                            }},
                            onLeave: function(retval) {{
                                if (this.infoPtr) {{
                                    var infoXml = "<haspinfo><hasp id=\"12345678\"><feature id=\"1\"/></hasp></haspinfo>";
                                    var infoBytes = new Uint8Array(infoXml.length);
                                    for (var i = 0; i < infoXml.length; i++) {{
                                        infoBytes[i] = infoXml.charCodeAt(i);
                                    }}
                                    this.infoPtr.writeByteArray(Array.from(infoBytes));
                                }}
                                retval.replace(0);
                                console.log("[HASP] hasp_get_info returning HASP_STATUS_OK");
                            }}
                        }});
                    }}

                    console.log("[HASP] Comprehensive HASP API hooks installed");
                }} catch(e) {{
                    console.log("[HASP] Error installing hooks: " + e);
                }}
            }}
        }}

        if ({dongle_types!s}.includes("Sentinel") || {dongle_types!s}.includes("SafeNet")) {{
            var sentinelModule = Process.findModuleByName("sentinel.dll");
            if (!sentinelModule) {{ sentinelModule = Process.findModuleByName("sentinelkeyW.dll"); }}
            if (!sentinelModule) {{ sentinelModule = Process.findModuleByName("sx32w.dll"); }}

            if (sentinelModule) {{
                try {{
                    var sentinelFind = Module.findExportByName(sentinelModule.name, "RNBOsproFindFirstUnit");
                    if (sentinelFind) {{
                        Interceptor.attach(sentinelFind, {{
                            onEnter: function(args) {{
                                this.devIdPtr = args[0];
                                console.log("[Sentinel] RNBOsproFindFirstUnit called");
                            }},
                            onLeave: function(retval) {{
                                if (this.devIdPtr) {{
                                    this.devIdPtr.writeU32(0x87654321);
                                }}
                                retval.replace(0);
                                console.log("[Sentinel] RNBOsproFindFirstUnit returning SP_SUCCESS");
                            }}
                        }});
                    }}

                    var sentinelQuery = Module.findExportByName(sentinelModule.name, "RNBOsproQuery");
                    if (sentinelQuery) {{
                        Interceptor.attach(sentinelQuery, {{
                            onEnter: function(args) {{
                                this.queryBuf = args[1];
                                this.respBuf = args[2];
                                console.log("[Sentinel] RNBOsproQuery called");
                            }},
                            onLeave: function(retval) {{
                                if (this.respBuf) {{
                                    var response = new Uint8Array(64);
                                    response[0] = 0x87; response[1] = 0x65; response[2] = 0x43; response[3] = 0x21;
                                    var serial = "SN123456789ABCDEF";
                                    for (var i = 0; i < serial.length; i++) {{
                                        response[4 + i] = serial.charCodeAt(i);
                                    }}
                                    response[20] = 0x08; response[21] = 0x00; response[22] = 0x00;
                                    for (var j = 23; j < 64; j++) {{
                                        response[j] = (j * 13) & 0xFF;
                                    }}
                                    this.respBuf.writeByteArray(Array.from(response));
                                }}
                                retval.replace(0);
                                console.log("[Sentinel] RNBOsproQuery returning SP_SUCCESS");
                            }}
                        }});
                    }}

                    var sentinelRead = Module.findExportByName(sentinelModule.name, "RNBOsproRead");
                    if (sentinelRead) {{
                        Interceptor.attach(sentinelRead, {{
                            onEnter: function(args) {{
                                this.address = args[1].toInt32();
                                this.length = args[2].toInt32();
                                this.buffer = args[3];
                                console.log("[Sentinel] RNBOsproRead: addr=" + this.address + " len=" + this.length);
                            }},
                            onLeave: function(retval) {{
                                if (this.buffer && this.length > 0) {{
                                    var cellData = new Uint8Array(this.length);
                                    var seed = (this.address * 23 + 0x87654321) & 0xFFFFFFFF;
                                    for (var i = 0; i < this.length; i++) {{
                                        seed = ((seed * 1103515245) + 12345) & 0xFFFFFFFF;
                                        cellData[i] = (seed >> 16) & 0xFF;
                                    }}
                                    this.buffer.writeByteArray(Array.from(cellData));
                                }}
                                retval.replace(0);
                            }}
                        }});
                    }}

                    var sentinelWrite = Module.findExportByName(sentinelModule.name, "RNBOsproWrite");
                    if (sentinelWrite) {{
                        Interceptor.attach(sentinelWrite, {{
                            onEnter: function(args) {{
                                this.address = args[1].toInt32();
                                this.length = args[2].toInt32();
                                console.log("[Sentinel] RNBOsproWrite: addr=" + this.address + " len=" + this.length);
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[Sentinel] RNBOsproWrite returning SP_SUCCESS");
                            }}
                        }});
                    }}

                    var sentinelFindNext = Module.findExportByName(sentinelModule.name, "RNBOsproFindNextUnit");
                    if (sentinelFindNext) {{
                        Interceptor.attach(sentinelFindNext, {{
                            onEnter: function(args) {{
                                this.devIdPtr = args[0];
                                console.log("[Sentinel] RNBOsproFindNextUnit called");
                            }},
                            onLeave: function(retval) {{
                                retval.replace(2);
                                console.log("[Sentinel] RNBOsproFindNextUnit returning SP_UNIT_NOT_FOUND");
                            }}
                        }});
                    }}

                    var sentinelDecrement = Module.findExportByName(sentinelModule.name, "RNBOsproDecrement");
                    if (sentinelDecrement) {{
                        Interceptor.attach(sentinelDecrement, {{
                            onEnter: function(args) {{
                                this.address = args[1].toInt32();
                                console.log("[Sentinel] RNBOsproDecrement: addr=" + this.address);
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[Sentinel] RNBOsproDecrement returning SP_SUCCESS");
                            }}
                        }});
                    }}

                    var sentinelGetStatus = Module.findExportByName(sentinelModule.name, "RNBOsproGetFullStatus");
                    if (sentinelGetStatus) {{
                        Interceptor.attach(sentinelGetStatus, {{
                            onEnter: function(args) {{
                                this.statusPtr = args[1];
                                console.log("[Sentinel] RNBOsproGetFullStatus called");
                            }},
                            onLeave: function(retval) {{
                                if (this.statusPtr) {{
                                    var status = new Uint8Array(128);
                                    status[0] = 0x87; status[1] = 0x65; status[2] = 0x43; status[3] = 0x21;
                                    status[4] = 0x08; status[5] = 0x00;
                                    var serial = "SN123456789ABCDEF";
                                    for (var i = 0; i < serial.length; i++) {{
                                        status[8 + i] = serial.charCodeAt(i);
                                    }}
                                    for (var j = 32; j < 128; j++) {{
                                        status[j] = ((j * 11 + 0x87) ^ (j >> 1)) & 0xFF;
                                    }}
                                    this.statusPtr.writeByteArray(Array.from(status));
                                }}
                                retval.replace(0);
                                console.log("[Sentinel] RNBOsproGetFullStatus returning SP_SUCCESS");
                            }}
                        }});
                    }}

                    console.log("[Sentinel] Comprehensive Sentinel API hooks installed");
                }} catch(e) {{
                    console.log("[Sentinel] Error installing hooks: " + e);
                }}
            }}
        }}

        if ({dongle_types!s}.includes("CodeMeter")) {{
            var wibuModule = Process.findModuleByName("WibuCm64.dll");
            if (!wibuModule) {{ wibuModule = Process.findModuleByName("WibuKey64.dll"); }}

            if (wibuModule) {{
                try {{
                    var cmAccess = Module.findExportByName(wibuModule.name, "CmAccess");
                    if (cmAccess) {{
                        Interceptor.attach(cmAccess, {{
                            onEnter: function(args) {{
                                this.firmCode = args[0].toInt32();
                                this.productCode = args[1].toInt32();
                                this.handlePtr = args[2];
                                console.log("[CodeMeter] CmAccess: firm=" + this.firmCode + " product=" + this.productCode);
                            }},
                            onLeave: function(retval) {{
                                if (this.handlePtr) {{
                                    this.handlePtr.writeU32(0x12345678);
                                }}
                                retval.replace(0);
                                console.log("[CodeMeter] CmAccess returning success");
                            }}
                        }});
                    }}

                    var cmCrypt = Module.findExportByName(wibuModule.name, "CmCrypt");
                    if (cmCrypt) {{
                        Interceptor.attach(cmCrypt, {{
                            onLeave: function(retval) {{
                                retval.replace(0);
                            }}
                        }});
                    }}

                    var cmGetInfo = Module.findExportByName(wibuModule.name, "CmGetInfo");
                    if (cmGetInfo) {{
                        Interceptor.attach(cmGetInfo, {{
                            onEnter: function(args) {{
                                this.infoPtr = args[1];
                            }},
                            onLeave: function(retval) {{
                                if (this.infoPtr) {{
                                    var info = new Uint8Array(256);
                                    info[0] = 0x65; info[1] = 0x00; info[2] = 0xE8; info[3] = 0x03;
                                    info[4] = 0x01; info[5] = 0x00; info[6] = 0x00; info[7] = 0x00;
                                    info[8] = 0x40; info[9] = 0x42; info[10] = 0x0F; info[11] = 0x00;
                                    var versionStr = "6.90";
                                    for (var i = 0; i < versionStr.length; i++) {{
                                        info[12 + i] = versionStr.charCodeAt(i);
                                    }}
                                    for (var j = 16; j < 256; j++) {{
                                        info[j] = ((j * 19 + 0x42) ^ (j >> 2)) & 0xFF;
                                    }}
                                    this.infoPtr.writeByteArray(Array.from(info));
                                }}
                                retval.replace(0);
                            }}
                        }});
                    }}

                    var cmRelease = Module.findExportByName(wibuModule.name, "CmRelease");
                    if (cmRelease) {{
                        Interceptor.attach(cmRelease, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                console.log("[CodeMeter] CmRelease: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[CodeMeter] CmRelease returning success");
                            }}
                        }});
                    }}

                    var cmSetFeature = Module.findExportByName(wibuModule.name, "CmSetFeature");
                    if (cmSetFeature) {{
                        Interceptor.attach(cmSetFeature, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                this.featureCode = args[1].toInt32();
                                console.log("[CodeMeter] CmSetFeature: handle=0x" + this.handle.toString(16) + " feature=" + this.featureCode);
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[CodeMeter] CmSetFeature returning success");
                            }}
                        }});
                    }}

                    var cmBoxSequence = Module.findExportByName(wibuModule.name, "CmBoxSequence");
                    if (cmBoxSequence) {{
                        Interceptor.attach(cmBoxSequence, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                this.seqPtr = args[1];
                                console.log("[CodeMeter] CmBoxSequence: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                if (this.seqPtr) {{
                                    this.seqPtr.writeU32(1000001);
                                }}
                                retval.replace(0);
                                console.log("[CodeMeter] CmBoxSequence returning success");
                            }}
                        }});
                    }}

                    var cmCalculatePioCoreKey = Module.findExportByName(wibuModule.name, "CmCalculatePioCoreKey");
                    if (cmCalculatePioCoreKey) {{
                        Interceptor.attach(cmCalculatePioCoreKey, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                this.keyPtr = args[1];
                                console.log("[CodeMeter] CmCalculatePioCoreKey: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                if (this.keyPtr) {{
                                    var keyData = new Uint8Array(32);
                                    for (var i = 0; i < 32; i++) {{
                                        keyData[i] = ((i * 23 + 0x42) ^ (i << 2)) & 0xFF;
                                    }}
                                    this.keyPtr.writeByteArray(Array.from(keyData));
                                }}
                                retval.replace(0);
                                console.log("[CodeMeter] CmCalculatePioCoreKey returning success");
                            }}
                        }});
                    }}

                    console.log("[CodeMeter] Comprehensive CodeMeter API hooks installed");
                }} catch(e) {{
                    console.log("[CodeMeter] Error installing hooks: " + e);
                }}
            }}
        }}

        if ({dongle_types!s}.includes("WibuKey")) {{
            var wkbModule = Process.findModuleByName("WibuKey64.dll");
            if (!wkbModule) {{ wkbModule = Process.findModuleByName("wibucm.dll"); }}

            if (wkbModule) {{
                try {{
                    var wkbOpen2 = Module.findExportByName(wkbModule.name, "WkbOpen2");
                    if (wkbOpen2) {{
                        Interceptor.attach(wkbOpen2, {{
                            onEnter: function(args) {{
                                this.handlePtr = args[0];
                                console.log("[WibuKey] WkbOpen2 called");
                            }},
                            onLeave: function(retval) {{
                                if (this.handlePtr) {{
                                    this.handlePtr.writeU32(0x12345678);
                                }}
                                retval.replace(0);
                                console.log("[WibuKey] WkbOpen2 returning success");
                            }}
                        }});
                    }}

                    var wkbClose = Module.findExportByName(wkbModule.name, "WkbClose");
                    if (wkbClose) {{
                        Interceptor.attach(wkbClose, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                console.log("[WibuKey] WkbClose: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[WibuKey] WkbClose returning success");
                            }}
                        }});
                    }}

                    var wkbCrypt = Module.findExportByName(wkbModule.name, "WkbCrypt");
                    if (wkbCrypt) {{
                        Interceptor.attach(wkbCrypt, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                console.log("[WibuKey] WkbCrypt: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[WibuKey] WkbCrypt returning success");
                            }}
                        }});
                    }}

                    var wkbCrypt2 = Module.findExportByName(wkbModule.name, "WkbCrypt2");
                    if (wkbCrypt2) {{
                        Interceptor.attach(wkbCrypt2, {{
                            onLeave: function(retval) {{
                                retval.replace(0);
                            }}
                        }});
                    }}

                    var wkbGetEntry = Module.findExportByName(wkbModule.name, "WkbGetEntry");
                    if (wkbGetEntry) {{
                        Interceptor.attach(wkbGetEntry, {{
                            onEnter: function(args) {{
                                this.handle = args[0].toInt32();
                                this.entryPtr = args[1];
                                console.log("[WibuKey] WkbGetEntry: handle=0x" + this.handle.toString(16));
                            }},
                            onLeave: function(retval) {{
                                if (this.entryPtr) {{
                                    var entry = new Uint8Array(64);
                                    entry[0] = 0x65; entry[1] = 0x00;
                                    entry[2] = 0xE8; entry[3] = 0x03;
                                    entry[4] = 0x64; entry[5] = 0x00;
                                    for (var i = 6; i < 64; i++) {{
                                        entry[i] = ((i * 17 + 0x65) ^ (i >> 1)) & 0xFF;
                                    }}
                                    this.entryPtr.writeByteArray(Array.from(entry));
                                }}
                                retval.replace(0);
                                console.log("[WibuKey] WkbGetEntry returning success");
                            }}
                        }});
                    }}

                    var wkbCheckEntry = Module.findExportByName(wkbModule.name, "WkbCheckEntry");
                    if (wkbCheckEntry) {{
                        Interceptor.attach(wkbCheckEntry, {{
                            onLeave: function(retval) {{
                                retval.replace(0);
                            }}
                        }});
                    }}

                    console.log("[WibuKey] Comprehensive WibuKey API hooks installed");
                }} catch(e) {{
                    console.log("[WibuKey] Error installing hooks: " + e);
                }}
            }}
        }}

        if ({dongle_types!s}.includes("SafeNet")) {{
            var safenetModule = Process.findModuleByName("etoken.dll");
            if (!safenetModule) {{ safenetModule = Process.findModuleByName("eTSignC.dll"); }}

            if (safenetModule) {{
                try {{
                    var caOpenSession = Module.findExportByName(safenetModule.name, "CA_OpenSession");
                    if (caOpenSession) {{
                        Interceptor.attach(caOpenSession, {{
                            onEnter: function(args) {{
                                this.sessionPtr = args[1];
                                console.log("[SafeNet] CA_OpenSession called");
                            }},
                            onLeave: function(retval) {{
                                if (this.sessionPtr) {{
                                    this.sessionPtr.writeU32(0x12345678);
                                }}
                                retval.replace(0);
                                console.log("[SafeNet] CA_OpenSession returning success");
                            }}
                        }});
                    }}

                    var caCloseSession = Module.findExportByName(safenetModule.name, "CA_CloseSession");
                    if (caCloseSession) {{
                        Interceptor.attach(caCloseSession, {{
                            onEnter: function(args) {{
                                this.session = args[0].toInt32();
                                console.log("[SafeNet] CA_CloseSession: session=0x" + this.session.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[SafeNet] CA_CloseSession returning success");
                            }}
                        }});
                    }}

                    var caLogin = Module.findExportByName(safenetModule.name, "CA_Login");
                    if (caLogin) {{
                        Interceptor.attach(caLogin, {{
                            onEnter: function(args) {{
                                this.session = args[0].toInt32();
                                console.log("[SafeNet] CA_Login: session=0x" + this.session.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[SafeNet] CA_Login returning success");
                            }}
                        }});
                    }}

                    var caLogout = Module.findExportByName(safenetModule.name, "CA_Logout");
                    if (caLogout) {{
                        Interceptor.attach(caLogout, {{
                            onEnter: function(args) {{
                                this.session = args[0].toInt32();
                                console.log("[SafeNet] CA_Logout: session=0x" + this.session.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[SafeNet] CA_Logout returning success");
                            }}
                        }});
                    }}

                    var caCreateObject = Module.findExportByName(safenetModule.name, "CA_CreateObject");
                    if (caCreateObject) {{
                        Interceptor.attach(caCreateObject, {{
                            onEnter: function(args) {{
                                this.session = args[0].toInt32();
                                this.objectPtr = args[2];
                                console.log("[SafeNet] CA_CreateObject: session=0x" + this.session.toString(16));
                            }},
                            onLeave: function(retval) {{
                                if (this.objectPtr) {{
                                    this.objectPtr.writeU32(0x1000);
                                }}
                                retval.replace(0);
                                console.log("[SafeNet] CA_CreateObject returning success");
                            }}
                        }});
                    }}

                    var caDestroyObject = Module.findExportByName(safenetModule.name, "CA_DestroyObject");
                    if (caDestroyObject) {{
                        Interceptor.attach(caDestroyObject, {{
                            onEnter: function(args) {{
                                this.session = args[0].toInt32();
                                this.object = args[1].toInt32();
                                console.log("[SafeNet] CA_DestroyObject: session=0x" + this.session.toString(16) + " obj=0x" + this.object.toString(16));
                            }},
                            onLeave: function(retval) {{
                                retval.replace(0);
                                console.log("[SafeNet] CA_DestroyObject returning success");
                            }}
                        }});
                    }}

                    console.log("[SafeNet] Comprehensive SafeNet API hooks installed");
                }} catch(e) {{
                    console.log("[SafeNet] Error installing hooks: " + e);
                }}
            }}
        }}

        var kernel32 = Module.findModuleByName("kernel32.dll");
        if (kernel32) {{
            var deviceIoControl = Module.findExportByName("kernel32.dll", "DeviceIoControl");
            if (deviceIoControl) {{
                Interceptor.attach(deviceIoControl, {{
                    onEnter: function(args) {{
                        this.ioControlCode = args[1].toInt32();
                        this.outBuffer = args[4];
                        this.outBufferSize = args[5].toInt32();
                        this.bytesReturned = args[6];
                    }},
                    onLeave: function(retval) {{
                        var isDongleIoctl = (this.ioControlCode & 0xFFFF0000) === 0x00220000 ||
                                          (this.ioControlCode & 0xFFFF0000) === 0x00320000;

                        if (isDongleIoctl) {{
                            if (this.outBuffer && this.outBufferSize > 0) {{
                                var responseLen = Math.min(this.outBufferSize, 64);
                                var ioctlResponse = new Uint8Array(responseLen);
                                var ctrlType = (this.ioControlCode >> 8) & 0xFF;
                                ioctlResponse[0] = 0x01; ioctlResponse[1] = 0x00;
                                ioctlResponse[2] = ctrlType; ioctlResponse[3] = 0x00;
                                for (var k = 4; k < responseLen; k++) {{
                                    ioctlResponse[k] = ((k * 11 + this.ioControlCode) ^ (k << 3)) & 0xFF;
                                }}
                                this.outBuffer.writeByteArray(Array.from(ioctlResponse));
                            }}
                            if (this.bytesReturned) {{
                                this.bytesReturned.writeU32(Math.min(this.outBufferSize, 64));
                            }}
                            retval.replace(1);
                            console.log("[Dongle] DeviceIoControl for dongle IOCTL: 0x" + this.ioControlCode.toString(16));
                        }}
                    }}
                }});
            }}
        }}

        console.log("[Dongle Emulator] All comprehensive dongle API hooks installed!");
        """

        self.hooks.append({
            "type": "frida",
            "script": frida_script,
            "target": f"Dongle APIs: {', '.join(dongle_types)}",
        })
        self.logger.info("Comprehensive dongle API hooks installed for: %s", ", ".join(dongle_types))

    def _patch_dongle_checks(self) -> None:
        """Patch binary instructions that check for dongle presence.

        Identifies and records binary patches for common dongle presence checks,
        converting conditional jumps to unconditional jumps to bypass protection.
        Patches are not applied directly but stored for external patching tools.

        """
        if not self.app or not hasattr(self.app, "binary_path") or not self.app.binary_path:
            return

        try:
            binary_path = Path(self.app.binary_path)
            if not binary_path.exists():
                return

            with open(binary_path, "rb") as f:
                binary_data = f.read()

            dongle_check_patterns = [
                {
                    "pattern": b"\x85\xc0\x74",
                    "patch": b"\x85\xc0\xeb",
                    "desc": "TEST EAX, EAX; JZ -> JMP",
                },
                {
                    "pattern": b"\x85\xc0\x75",
                    "patch": b"\x85\xc0\xeb",
                    "desc": "TEST EAX, EAX; JNZ -> JMP",
                },
                {
                    "pattern": b"\x83\xf8\x00\x74",
                    "patch": b"\x83\xf8\x00\xeb",
                    "desc": "CMP EAX, 0; JZ -> JMP",
                },
                {
                    "pattern": b"\x83\xf8\x00\x75",
                    "patch": b"\x83\xf8\x00\xeb",
                    "desc": "CMP EAX, 0; JNZ -> JMP",
                },
                {
                    "pattern": b"\x3d\x00\x00\x00\x00\x74",
                    "patch": b"\x3d\x00\x00\x00\x00\xeb",
                    "desc": "CMP EAX, 0; JZ -> JMP",
                },
                {
                    "pattern": b"\x3d\x00\x00\x00\x00\x75",
                    "patch": b"\x3d\x00\x00\x00\x00\xeb",
                    "desc": "CMP EAX, 0; JNZ -> JMP",
                },
                {
                    "pattern": b"\x48\x85\xc0\x74",
                    "patch": b"\x48\x85\xc0\xeb",
                    "desc": "TEST RAX, RAX; JZ -> JMP (x64)",
                },
                {
                    "pattern": b"\x48\x85\xc0\x75",
                    "patch": b"\x48\x85\xc0\xeb",
                    "desc": "TEST RAX, RAX; JNZ -> JMP (x64)",
                },
            ]

            patches_applied = 0
            for pattern_info in dongle_check_patterns:
                pattern_val = pattern_info["pattern"]
                patch_val = pattern_info["patch"]
                desc_val = pattern_info["desc"]

                if not isinstance(pattern_val, bytes) or not isinstance(patch_val, bytes) or not isinstance(desc_val, str):
                    continue

                pattern = pattern_val
                patch = patch_val
                desc = desc_val

                offset = binary_data.find(pattern)
                while offset != -1:
                    self.patches.append({
                        "offset": offset,
                        "original": pattern,
                        "patch": patch,
                        "description": f"Dongle check bypass: {desc}",
                    })
                    patches_applied += 1
                    offset = binary_data.find(pattern, offset + 1)

            self.logger.info("Identified %d dongle check patterns to patch", patches_applied)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error patching dongle checks: %s", e)

    def _spoof_dongle_registry(self) -> None:
        """Manipulate Windows registry to establish dongle presence.

        Creates registry entries for SafeNet Sentinel, HASP, and CodeMeter/WibuKey
        dongles to establish installation and availability on the system.

        """
        try:
            if platform.system() != "Windows":
                self.logger.info("Not on Windows - skipping registry spoofing")
                return

            if not WINREG_AVAILABLE or winreg is None:
                self.logger.warning("winreg module not available - skipping registry spoofing")
                return

            dongle_registry_entries = [
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\SafeNet",
                    "InstallDir",
                    r"C:\Program Files\SafeNet",
                ),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SafeNet\Sentinel", "Version", "8.0.0"),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Sentinel",
                    "Start",
                    2,
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Aladdin Knowledge Systems",
                    "HASP",
                    "Installed",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Aladdin Knowledge Systems\HASP",
                    "Version",
                    "4.95",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WIBU-SYSTEMS",
                    "CodeMeter",
                    r"C:\Program Files\CodeMeter",
                ),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WIBU-SYSTEMS\CodeMeter", "Version", "6.90"),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\CodeMeter",
                    "Start",
                    2,
                ),
            ]

            for hkey, path, name, value in dongle_registry_entries:
                try:
                    key = winreg.CreateKey(hkey, path)
                    if isinstance(value, int):
                        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                    elif isinstance(value, str):
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                    winreg.CloseKey(key)
                    self.logger.debug("Set registry entry %s\\%s = %s", path, name, value)
                except OSError as e:
                    self.logger.warning("Could not set registry entry %s\\%s: %s", path, name, e)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Registry spoofing failed: %s", e)

    def process_hasp_challenge(self, challenge: bytes, dongle_id: int = 1) -> bytes:
        """Process HASP cryptographic challenge.

        Generates challenge-response using HMAC-SHA256 for challenges >= 16 bytes,
        or SHA256 hash of challenge concatenated with seed code for shorter challenges.

        Args:
            challenge: Challenge bytes from protected application.
            dongle_id: ID of specific HASP dongle to use. Defaults to 1.

        Returns:
            Challenge response bytes (16 bytes for HMAC, full hash for SHA256).

        """
        if dongle_id not in self.hasp_dongles:
            self.logger.exception("HASP dongle %s not found", dongle_id)
            return b""

        dongle = self.hasp_dongles[dongle_id]

        return (
            self.crypto_engine.sentinel_challenge_response(challenge, dongle.aes_key)
            if len(challenge) >= 16
            else hashlib.sha256(challenge + dongle.seed_code).digest()[:16]
        )

    def read_dongle_memory(self, dongle_type: str, dongle_id: int, region: str, offset: int, length: int) -> bytes:
        """Read from dongle memory.

        Reads memory data from specified dongle instance, supporting HASP, Sentinel,
        and WibuKey/CodeMeter protection dongles with rom, ram, and eeprom regions.

        Args:
            dongle_type: Type of dongle (HASP, Sentinel, WibuKey). Case-insensitive.
            dongle_id: ID of specific dongle instance to read from.
            region: Memory region name (rom, ram, or eeprom).
            offset: Byte offset within the region.
            length: Number of bytes to read.

        Returns:
            Memory data bytes from the requested region, or empty bytes on error.

        """
        try:
            if dongle_type.upper() == "HASP" and dongle_id in self.hasp_dongles:
                return self.hasp_dongles[dongle_id].memory.read(region, offset, length)
            elif dongle_type.upper() == "SENTINEL" and dongle_id in self.sentinel_dongles:
                return self.sentinel_dongles[dongle_id].memory.read(region, offset, length)
            elif dongle_type.upper() == "WIBUKEY" and dongle_id in self.wibukey_dongles:
                return self.wibukey_dongles[dongle_id].memory.read(region, offset, length)
            else:
                self.logger.exception("Dongle %s %s not found", dongle_type, dongle_id)
                return b""
        except (ValueError, PermissionError) as e:
            self.logger.exception("Memory read error: %s", e)
            return b""

    def write_dongle_memory(self, dongle_type: str, dongle_id: int, region: str, offset: int, data: bytes) -> bool:
        """Write to dongle memory.

        Writes memory data to specified dongle instance, supporting HASP, Sentinel,
        and WibuKey/CodeMeter protection dongles with rom, ram, and eeprom regions.

        Args:
            dongle_type: Type of dongle (HASP, Sentinel, WibuKey). Case-insensitive.
            dongle_id: ID of specific dongle instance to write to.
            region: Memory region name (rom, ram, or eeprom).
            offset: Byte offset within the region.
            data: Bytes to write to dongle memory.

        Returns:
            True if write succeeded, False if dongle not found or write error occurred.

        """
        try:
            if dongle_type.upper() == "HASP" and dongle_id in self.hasp_dongles:
                self.hasp_dongles[dongle_id].memory.write(region, offset, data)
                return True
            elif dongle_type.upper() == "SENTINEL" and dongle_id in self.sentinel_dongles:
                self.sentinel_dongles[dongle_id].memory.write(region, offset, data)
                return True
            elif dongle_type.upper() == "WIBUKEY" and dongle_id in self.wibukey_dongles:
                self.wibukey_dongles[dongle_id].memory.write(region, offset, data)
                return True
            else:
                self.logger.exception("Dongle %s %s not found", dongle_type, dongle_id)
                return False
        except (ValueError, PermissionError) as e:
            self.logger.exception("Memory write error: %s", e)
            return False

    def generate_emulation_script(self, dongle_types: list[str]) -> str:
        """Generate a Frida script for dongle emulation.

        Retrieves the Frida instrumentation script that was previously generated
        during emulation setup for the specified dongle types.

        Args:
            dongle_types: List of dongle types for which to retrieve the script.

        Returns:
            Frida JavaScript script string for dongle emulation, or empty string if not found.

        """
        return next((hook["script"] for hook in self.hooks if hook["type"] == "frida"), "")

    def get_emulation_status(self) -> dict[str, Any]:
        """Get the current status of dongle emulation.

        Provides comprehensive status on active hooks, patches, virtual dongles,
        and availability of backend support (Frida, WinReg, cryptography).

        Returns:
            Dictionary containing counts and identifiers for all active emulation components.

        """
        return {
            "hooks_installed": len(self.hooks),
            "patches_identified": len(self.patches),
            "virtual_dongles_active": list(self.virtual_dongles.keys()),
            "emulated_dongle_count": len(self.virtual_dongles),
            "usb_emulators": list(self.usb_emulators.keys()),
            "hasp_dongles": len(self.hasp_dongles),
            "sentinel_dongles": len(self.sentinel_dongles),
            "wibukey_dongles": len(self.wibukey_dongles),
            "frida_available": FRIDA_AVAILABLE,
            "winreg_available": WINREG_AVAILABLE,
            "crypto_available": CRYPTO_AVAILABLE,
        }

    def clear_emulation(self) -> None:
        """Clear all dongle emulation hooks and virtual devices.

        Safely clears all emulation state including Frida hooks, binary patches,
        and virtual dongle instances using thread-safe locking.

        """
        with self.lock:
            self.hooks.clear()
            self.patches.clear()
            self.virtual_dongles.clear()
            self.usb_emulators.clear()
            self.hasp_dongles.clear()
            self.sentinel_dongles.clear()
            self.wibukey_dongles.clear()
        self.logger.info("Cleared all dongle emulation hooks and virtual devices")

    def get_dongle_config(self, dongle_type: str) -> dict[str, Any] | None:
        """Get configuration for a specific dongle type.

        Args:
            dongle_type (str): Type of dongle to get configuration for.
                         Valid types: 'hasp', 'sentinel', 'wibukey', 'codemeter',
                         'safenet', 'superpro', 'rockey', 'dinkey'

        Returns:
            dict[str, Any] | None: Dictionary containing dongle configuration parameters, or None if not found.

        """
        dongle_type_lower = dongle_type.lower().strip()

        config_templates: dict[str, dict[str, Any]] = {
            "hasp": {
                "type": "HASP",
                "vendor_id": 0x0529,
                "product_id": 0x0001,
                "memory_size": 8192,
                "algorithms": ["AES", "DES", "DES3", "RSA"],
                "features": {
                    "encryption": True,
                    "decryption": True,
                    "memory_read": True,
                    "memory_write": True,
                    "rtc": True,
                    "feature_licensing": True,
                },
                "api_functions": [
                    "hasp_login",
                    "hasp_logout",
                    "hasp_encrypt",
                    "hasp_decrypt",
                    "hasp_read",
                    "hasp_write",
                    "hasp_get_size",
                    "hasp_get_rtc",
                    "hasp_legacy_get_info",
                ],
                "driver_names": ["aksusbd.sys", "hardlock.sys", "hasp_net.dll"],
                "emulation_ready": True,
            },
            "sentinel": {
                "type": "Sentinel",
                "vendor_id": 0x0529,
                "product_id": 0x0001,
                "memory_size": 4096,
                "algorithms": ["AES", "RSA", "DES", "HMAC"],
                "features": {
                    "query": True,
                    "read": True,
                    "write": True,
                    "encryption": True,
                    "challenge_response": True,
                },
                "api_functions": [
                    "RNBOsproFindFirstUnit",
                    "RNBOsproFindNextUnit",
                    "RNBOsproQuery",
                    "RNBOsproRead",
                    "RNBOsproWrite",
                    "RNBOsproDecrement",
                    "RNBOsproGetFullStatus",
                ],
                "driver_names": ["sentinel.sys", "sntnlusb.sys", "sx32w.dll"],
                "emulation_ready": True,
            },
            "safenet": {
                "type": "SafeNet",
                "vendor_id": 0x0529,
                "product_id": 0x0001,
                "memory_size": 4096,
                "algorithms": ["AES", "RSA", "ECC"],
                "features": {
                    "encryption": True,
                    "signing": True,
                    "key_storage": True,
                    "certificate_storage": True,
                },
                "api_functions": [
                    "CA_OpenSession",
                    "CA_CloseSession",
                    "CA_Login",
                    "CA_Logout",
                    "CA_CreateObject",
                    "CA_DestroyObject",
                ],
                "driver_names": ["etoken.dll", "eTSignC.dll"],
                "emulation_ready": True,
            },
            "wibukey": {
                "type": "WibuKey",
                "vendor_id": 0x064F,
                "product_id": 0x0BD7,
                "memory_size": 4096,
                "algorithms": ["AES", "Challenge-Response"],
                "features": {
                    "encryption": True,
                    "decryption": True,
                    "license_management": True,
                    "container_access": True,
                },
                "api_functions": [
                    "WkbOpen2",
                    "WkbClose",
                    "WkbCrypt",
                    "WkbCrypt2",
                    "WkbGetEntry",
                    "WkbProgramEntry",
                    "WkbCheckEntry",
                ],
                "driver_names": ["wibukey.sys", "wibucm.dll", "WibuKey64.dll"],
                "emulation_ready": True,
            },
            "codemeter": {
                "type": "CodeMeter",
                "vendor_id": 0x064F,
                "product_id": 0x0BD7,
                "memory_size": 16384,
                "algorithms": ["AES-256", "RSA-2048", "ECC"],
                "features": {
                    "encryption": True,
                    "decryption": True,
                    "license_borrowing": True,
                    "network_licensing": True,
                    "container_management": True,
                    "secure_update": True,
                },
                "api_functions": [
                    "CmAccess",
                    "CmRelease",
                    "CmCrypt",
                    "CmGetInfo",
                    "CmSetFeature",
                    "CmBoxSequence",
                    "CmCalculatePioCoreKey",
                ],
                "driver_names": ["CodeMeter.exe", "WibuCm64.dll", "CodeMeter64.dll"],
                "emulation_ready": True,
            },
            "superpro": {
                "type": "SuperPro",
                "vendor_id": 0x0529,
                "product_id": 0x0001,
                "memory_size": 2048,
                "algorithms": ["DES", "AES"],
                "features": {
                    "query": True,
                    "read": True,
                    "write": True,
                    "decrement": True,
                },
                "api_functions": [
                    "RNBOsproFindFirstUnit",
                    "RNBOsproQuery",
                    "RNBOsproRead",
                    "RNBOsproWrite",
                ],
                "driver_names": ["sprousb.sys", "sentinel.dll"],
                "emulation_ready": True,
            },
            "rockey": {
                "type": "ROCKEY",
                "vendor_id": 0x0471,
                "product_id": 0x485D,
                "memory_size": 1024,
                "algorithms": ["DES", "Custom"],
                "features": {
                    "read": True,
                    "write": True,
                    "run_user_code": True,
                    "hardware_id": True,
                },
                "api_functions": [
                    "Rockey_Find",
                    "Rockey_Open",
                    "Rockey_Close",
                    "Rockey_Read",
                    "Rockey_Write",
                    "Rockey_Encrypt",
                    "Rockey_Decrypt",
                ],
                "driver_names": ["rockey.sys", "rockey4.dll"],
                "emulation_ready": True,
            },
            "dinkey": {
                "type": "Dinkey",
                "vendor_id": 0x16D0,
                "product_id": 0x0543,
                "memory_size": 512,
                "algorithms": ["AES-128", "SHA-256"],
                "features": {
                    "encryption": True,
                    "license_count": True,
                    "expiry_date": True,
                    "feature_flags": True,
                },
                "api_functions": [
                    "DDProtCheck",
                    "DDProtGetInfo",
                    "DDProtGetData",
                    "DDProtSetData",
                    "DDProtDecrement",
                ],
                "driver_names": ["dinkey.sys", "ddprot32.dll", "ddprot64.dll"],
                "emulation_ready": True,
            },
        }

        if dongle_type_lower in config_templates:
            config = config_templates[dongle_type_lower].copy()

            with self.lock:
                if dongle_type_lower == "hasp" and self.hasp_dongles:
                    hasp_dongle = next(iter(self.hasp_dongles.values()))
                    config["active_instance"] = {
                        "hasp_id": hasp_dongle.hasp_id,
                        "vendor_code": hasp_dongle.vendor_code,
                        "feature_id": hasp_dongle.feature_id,
                        "logged_in": hasp_dongle.logged_in,
                        "session_handle": hasp_dongle.session_handle,
                    }
                elif dongle_type_lower == "sentinel" and self.sentinel_dongles:
                    sentinel_dongle = next(iter(self.sentinel_dongles.values()))
                    config["active_instance"] = {
                        "device_id": sentinel_dongle.device_id,
                        "serial_number": sentinel_dongle.serial_number,
                        "firmware_version": sentinel_dongle.firmware_version,
                        "developer_id": sentinel_dongle.developer_id,
                    }
                elif dongle_type_lower in {"wibukey", "codemeter"} and self.wibukey_dongles:
                    wibu_dongle = next(iter(self.wibukey_dongles.values()))
                    config["active_instance"] = {
                        "firm_code": wibu_dongle.firm_code,
                        "product_code": wibu_dongle.product_code,
                        "feature_code": wibu_dongle.feature_code,
                        "serial_number": wibu_dongle.serial_number,
                        "container_handle": wibu_dongle.container_handle,
                        "active_licenses": list(wibu_dongle.active_licenses),
                    }

            return config

        self.logger.warning("Unknown dongle type: %s", dongle_type)
        return None


def activate_hardware_dongle_emulation(app: object, dongle_types: list[str] | None = None) -> dict[str, object]:
    """Activate hardware dongle emulation.

    Convenience function that creates a HardwareDongleEmulator instance and
    activates emulation for specified dongle types or all supported types if none specified.

    Args:
        app: Application instance containing binary_path attribute for binary patching.
        dongle_types: List of dongle type names to emulate. If None, emulates all supported types.

    Returns:
        Results dictionary with success status, list of emulated dongles, and methods applied.

    """
    emulator = HardwareDongleEmulator(app)
    return emulator.activate_dongle_emulation(dongle_types)


__all__ = [
    "CryptoEngine",
    "DongleMemory",
    "DongleType",
    "HASPDongle",
    "HASPStatus",
    "HardwareDongleEmulator",
    "SentinelDongle",
    "SentinelStatus",
    "USBDescriptor",
    "USBEmulator",
    "WibuKeyDongle",
    "activate_hardware_dongle_emulation",
]
