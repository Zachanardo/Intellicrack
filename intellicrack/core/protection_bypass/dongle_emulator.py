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
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from ...utils.core.import_checks import FRIDA_AVAILABLE, WINREG_AVAILABLE, winreg


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
        """Serialize descriptor to bytes."""
        return struct.pack(
            '<BBHBBBBHHHBBBB',
            self.bLength, self.bDescriptorType, self.bcdUSB,
            self.bDeviceClass, self.bDeviceSubClass, self.bDeviceProtocol,
            self.bMaxPacketSize0, self.idVendor, self.idProduct,
            self.bcdDevice, self.iManufacturer, self.iProduct,
            self.iSerialNumber, self.bNumConfigurations,
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
        """Read from dongle memory region."""
        memory_map = {'rom': self.rom, 'ram': self.ram, 'eeprom': self.eeprom}
        if region not in memory_map:
            error_msg = f"Invalid memory region: {region}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        mem = memory_map[region]
        if offset + length > len(mem):
            error_msg = f"Read beyond memory bounds: {offset}+{length} > {len(mem)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        return bytes(mem[offset:offset + length])

    def write(self, region: str, offset: int, data: bytes) -> None:
        """Write to dongle memory region."""
        memory_map = {'rom': self.rom, 'ram': self.ram, 'eeprom': self.eeprom}
        if region not in memory_map:
            error_msg = f"Invalid memory region: {region}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        if region == 'rom':
            for start, end in self.read_only_areas:
                if offset >= start and offset < end:
                    error_msg = "Cannot write to read-only area"
                    logger.error(error_msg)
                    raise PermissionError(error_msg)
        mem = memory_map[region]
        if offset + len(data) > len(mem):
            error_msg = f"Write beyond memory bounds: {offset}+{len(data)} > {len(mem)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        mem[offset:offset + len(data)] = data

    def is_protected(self, offset: int, length: int) -> bool:
        """Check if memory range is protected."""
        for start, end in self.protected_areas:
            if offset >= start and offset + length <= end:
                return True
        return False


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
    rsa_key: Any = None
    license_data: bytearray = field(default_factory=lambda: bytearray(512))
    rtc_counter: int = 0
    feature_map: dict[int, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize RSA key if crypto available."""
        if CRYPTO_AVAILABLE and self.rsa_key is None:
            self.rsa_key = RSA.generate(2048)
        self.feature_map[self.feature_id] = {
            'id': self.feature_id,
            'type': 'license',
            'expiration': 0xFFFFFFFF,
            'max_users': 10,
            'current_users': 0,
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
    algorithms: list[str] = field(default_factory=lambda: ['AES', 'RSA', 'DES', 'HMAC'])
    developer_id: int = 1000
    query_buffer: bytearray = field(default_factory=lambda: bytearray(1024))
    response_buffer: bytearray = field(default_factory=lambda: bytearray(1024))
    aes_key: bytes = field(default_factory=lambda: os.urandom(32))
    des_key: bytes = field(default_factory=lambda: os.urandom(24))
    rsa_key: Any = None
    cell_data: dict[int, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize crypto keys."""
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
        """Initialize license entries."""
        self.license_entries[1] = {
            'firm_code': self.firm_code,
            'product_code': self.product_code,
            'feature_code': self.feature_code,
            'quantity': 100,
            'expiration': 0xFFFFFFFF,
            'enabled': True,
        }


class USBEmulator:
    """USB device emulation for dongles."""

    def __init__(self, descriptor: USBDescriptor) -> None:
        """Initialize USB emulator with device descriptor."""
        self.descriptor = descriptor
        self.configuration = 1
        self.interface = 0
        self.alt_setting = 0
        self.endpoints: dict[int, dict[str, Any]] = {}
        self.setup_endpoints()
        self.control_transfer_handlers: dict[int, Callable] = {}
        self.bulk_transfer_handlers: dict[int, Callable] = {}

    def setup_endpoints(self) -> None:
        """Configure USB endpoints."""
        self.endpoints[0x00] = {'type': 'control', 'max_packet': 64, 'direction': 'both'}
        self.endpoints[0x81] = {'type': 'bulk', 'max_packet': 512, 'direction': 'in'}
        self.endpoints[0x02] = {'type': 'bulk', 'max_packet': 512, 'direction': 'out'}
        self.endpoints[0x83] = {'type': 'interrupt', 'max_packet': 64, 'direction': 'in'}

    def control_transfer(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle USB control transfer."""
        request_key = (bmRequestType << 8) | bRequest
        if request_key in self.control_transfer_handlers:
            return self.control_transfer_handlers[request_key](wValue, wIndex, data)

        if bRequest == 0x06:
            descriptor_type = (wValue >> 8) & 0xFF
            if descriptor_type == 1:
                return self.descriptor.to_bytes()
            elif descriptor_type == 2:
                return self.get_configuration_descriptor()
            elif descriptor_type == 3:
                return self.get_string_descriptor(wValue & 0xFF)

        return b''

    def get_configuration_descriptor(self) -> bytes:
        """Generate configuration descriptor."""
        config = struct.pack('<BBHBBBBB',
            9, 2, 32, 1, 1, 0, 0x80, 100,
        )
        interface = struct.pack('<BBBBBBBBB',
            9, 4, 0, 0, 3, 0xFF, 0xFF, 0xFF, 0,
        )
        endpoint1 = struct.pack('<BBBBH', 7, 5, 0x81, 2, 512)
        endpoint2 = struct.pack('<BBBBH', 7, 5, 0x02, 2, 512)
        endpoint3 = struct.pack('<BBBBH', 7, 5, 0x83, 3, 64)
        return config + interface + endpoint1 + endpoint2 + endpoint3

    def get_string_descriptor(self, index: int) -> bytes:
        """Get USB string descriptor."""
        strings = {
            0: b'\x04\x03\x09\x04',
            1: "SafeNet Inc.",
            2: "Sentinel Hardware Key",
            3: "0123456789ABCDEF",
        }
        if index in strings:
            if index == 0:
                return strings[0]
            string = strings[index]
            string_utf16 = string.encode('utf-16-le')
            descriptor = struct.pack('<BB', len(string_utf16) + 2, 3) + string_utf16
            return descriptor + string.encode('ascii')
        return b''

    def bulk_transfer(self, endpoint: int, data: bytes) -> bytes:
        """Handle USB bulk transfer."""
        if endpoint in self.bulk_transfer_handlers:
            return self.bulk_transfer_handlers[endpoint](data)
        return b''

    def register_control_handler(self, bmRequestType: int, bRequest: int, handler: Callable) -> None:
        """Register handler for control transfer."""
        request_key = (bmRequestType << 8) | bRequest
        self.control_transfer_handlers[request_key] = handler

    def register_bulk_handler(self, endpoint: int, handler: Callable) -> None:
        """Register handler for bulk transfer."""
        self.bulk_transfer_handlers[endpoint] = handler


class CryptoEngine:
    """Cryptographic operations for dongle emulation."""

    def __init__(self) -> None:
        """Initialize crypto engine."""
        self.logger = logging.getLogger("IntellicrackLogger.DongleCrypto")

    def hasp_encrypt(self, data: bytes, key: bytes, algorithm: str = 'AES') -> bytes:
        """Perform HASP encryption operation."""
        if not CRYPTO_AVAILABLE:
            self.logger.warning("Crypto not available, returning XOR encryption")
            return self._xor_encrypt(data, key)

        try:
            if algorithm == 'AES':
                cipher = AES.new(key[:32], AES.MODE_ECB)
                padded_data = data + b'\x00' * (16 - len(data) % 16)
                return cipher.encrypt(padded_data)
            elif algorithm == 'DES':
                cipher = DES.new(key[:8], DES.MODE_ECB)  # noqa: S304 - Required for HASP dongle emulation
                padded_data = data + b'\x00' * (8 - len(data) % 8)
                return cipher.encrypt(padded_data)
            elif algorithm == 'DES3':
                cipher = DES3.new(key[:24], DES3.MODE_ECB)
                padded_data = data + b'\x00' * (8 - len(data) % 8)
                return cipher.encrypt(padded_data)
            else:
                return self._xor_encrypt(data, key)
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            return self._xor_encrypt(data, key)

    def hasp_decrypt(self, data: bytes, key: bytes, algorithm: str = 'AES') -> bytes:
        """Perform HASP decryption operation."""
        if not CRYPTO_AVAILABLE:
            self.logger.warning("Crypto not available, returning XOR decryption")
            return self._xor_encrypt(data, key)

        try:
            if algorithm == 'AES':
                cipher = AES.new(key[:32], AES.MODE_ECB)
                decrypted = cipher.decrypt(data)
                return decrypted.rstrip(b'\x00')
            elif algorithm == 'DES':
                cipher = DES.new(key[:8], DES.MODE_ECB)  # noqa: S304 - Required for HASP dongle emulation
                decrypted = cipher.decrypt(data)
                return decrypted.rstrip(b'\x00')
            elif algorithm == 'DES3':
                cipher = DES3.new(key[:24], DES3.MODE_ECB)
                decrypted = cipher.decrypt(data)
                return decrypted.rstrip(b'\x00')
            else:
                return self._xor_encrypt(data, key)
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            return self._xor_encrypt(data, key)

    def sentinel_challenge_response(self, challenge: bytes, key: bytes) -> bytes:
        """Calculate Sentinel challenge-response."""
        if not CRYPTO_AVAILABLE:
            return hashlib.sha256(challenge + key).digest()

        h = hmac.new(key, challenge, hashlib.sha256)
        response = h.digest()
        return response[:16]

    def wibukey_challenge_response(self, challenge: bytes, key: bytes) -> bytes:
        """Calculate WibuKey challenge-response."""
        response = bytearray(16)
        for i in range(16):
            challenge_byte = challenge[i % len(challenge)]
            key_byte = key[i % len(key)]
            response[i] = (challenge_byte ^ key_byte ^ (i * 17)) & 0xFF

        if CRYPTO_AVAILABLE:
            cipher = AES.new(key[:16], AES.MODE_ECB)
            return cipher.encrypt(bytes(response))

        return bytes(response)

    def rsa_sign(self, data: bytes, private_key: Any) -> bytes:
        """Sign data with RSA private key."""
        if not CRYPTO_AVAILABLE or private_key is None:
            return hashlib.sha256(data).digest()

        try:
            h = SHA256.new(data)
            signer = PKCS1_v1_5.new(private_key)
            signature = signer.sign(h)
            return signature
        except Exception as e:
            self.logger.error(f"RSA signing error: {e}")
            return hashlib.sha256(data).digest()

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Perform simple XOR encryption fallback."""
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % len(key)]
        return bytes(result)


class HardwareDongleEmulator:
    """Implements hardware dongle emulation for various protection systems."""

    def __init__(self, app: Any | None = None) -> None:
        """Initialize the hardware dongle emulator.

        Args:
            app: Application instance that contains the binary_path attribute

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

    def activate_dongle_emulation(self, dongle_types: list[str] = None) -> dict[str, Any]:
        """Activate hardware dongle emulation.

        Args:
            dongle_types: List of dongle types to emulate (None for all supported types)

        Returns:
            dict: Results of the emulation activation with success status and methods applied

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

        results = {
            "success": False,
            "emulated_dongles": [],
            "methods_applied": [],
            "errors": [],
        }

        try:
            self._create_virtual_dongles(dongle_types)
            results["methods_applied"].append("Virtual Dongle Creation")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"Virtual dongle creation failed: {e!s}")

        try:
            self._setup_usb_emulation(dongle_types)
            results["methods_applied"].append("USB Device Emulation")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"USB emulation failed: {e!s}")

        try:
            self._hook_dongle_apis(dongle_types)
            results["methods_applied"].append("API Hooking")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"API hooking failed: {e!s}")

        try:
            if self.app and hasattr(self.app, "binary_path") and self.app.binary_path:
                self._patch_dongle_checks()
                results["methods_applied"].append("Binary Patching")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"Binary patching failed: {e!s}")

        try:
            self._spoof_dongle_registry()
            results["methods_applied"].append("Registry Spoofing")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"Registry spoofing failed: {e!s}")

        results["emulated_dongles"] = list(self.virtual_dongles.keys())
        results["success"] = len(results["methods_applied"]) > 0
        return results

    def _create_virtual_dongles(self, dongle_types: list[str]) -> None:
        """Create virtual dongle devices with full memory and crypto support."""
        with self.lock:
            for dongle_type in dongle_types:
                if dongle_type in {"SafeNet", "HASP"}:
                    hasp_id = len(self.hasp_dongles) + 1
                    dongle = HASPDongle(hasp_id=0x12345678 + hasp_id)
                    dongle.memory.protected_areas = [(0, 1024)]
                    dongle.memory.read_only_areas = [(0, 512)]

                    license_info = struct.pack('<IIII', dongle.feature_id, 0xFFFFFFFF, 10, 1)
                    dongle.license_data[0:len(license_info)] = license_info

                    self.hasp_dongles[hasp_id] = dongle
                    self.virtual_dongles[f"HASP_{hasp_id}"] = {
                        "type": "HASP",
                        "hasp_id": dongle.hasp_id,
                        "vendor_code": dongle.vendor_code,
                        "feature_id": dongle.feature_id,
                        "instance": dongle,
                    }

                elif dongle_type in {"Sentinel", "SafeNet"}:
                    sentinel_id = len(self.sentinel_dongles) + 1
                    dongle = SentinelDongle(device_id=0x87654321 + sentinel_id)
                    dongle.memory.protected_areas = [(0, 2048)]
                    dongle.memory.read_only_areas = [(0, 1024)]

                    self.sentinel_dongles[sentinel_id] = dongle
                    self.virtual_dongles[f"Sentinel_{sentinel_id}"] = {
                        "type": "Sentinel",
                        "device_id": dongle.device_id,
                        "serial_number": dongle.serial_number,
                        "instance": dongle,
                    }

                elif dongle_type == "CodeMeter":
                    wibu_id = len(self.wibukey_dongles) + 1
                    dongle = WibuKeyDongle(serial_number=1000000 + wibu_id)
                    dongle.memory.protected_areas = [(0, 4096)]

                    self.wibukey_dongles[wibu_id] = dongle
                    self.virtual_dongles[f"WibuKey_{wibu_id}"] = {
                        "type": "WibuKey",
                        "firm_code": dongle.firm_code,
                        "product_code": dongle.product_code,
                        "serial_number": dongle.serial_number,
                        "instance": dongle,
                    }

        self.logger.info(f"Created {len(self.virtual_dongles)} virtual dongles with full memory emulation")

    def _setup_usb_emulation(self, dongle_types: list[str]) -> None:
        """Set up USB device emulation for dongles."""
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

        self.logger.info(f"Setup USB emulation for {len(self.usb_emulators)} dongle types")

    def _hasp_control_handler(self, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle HASP USB control transfers."""
        if not self.hasp_dongles:
            return b'\x00' * 64

        dongle = next(iter(self.hasp_dongles.values()))

        if wValue == 1:
            return struct.pack('<I', dongle.hasp_id)
        elif wValue == 2:
            return struct.pack('<HH', dongle.vendor_code, dongle.feature_id)
        elif wValue == 3:
            return dongle.seed_code

        return b'\x00' * 64

    def _hasp_bulk_out_handler(self, data: bytes) -> bytes:
        """Handle HASP bulk OUT transfers."""
        if len(data) < 4:
            return b''

        command = struct.unpack('<I', data[:4])[0]

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

        return struct.pack('<I', HASPStatus.HASP_STATUS_OK)

    def _hasp_bulk_in_handler(self, data: bytes) -> bytes:
        """Handle HASP bulk IN transfers."""
        if not self.hasp_dongles:
            return b'\x00' * 512

        dongle = next(iter(self.hasp_dongles.values()))
        response = bytearray(512)

        info = struct.pack('<IHHQ',
            dongle.hasp_id,
            dongle.vendor_code,
            dongle.feature_id,
            dongle.rtc_counter,
        )
        response[0:len(info)] = info

        return bytes(response)

    def _hasp_login(self, data: bytes) -> bytes:
        """Handle HASP login operation."""
        if len(data) < 4:
            return struct.pack('<I', HASPStatus.HASP_TOO_SHORT)

        vendor_code, _feature_id = struct.unpack('<HH', data[:4])

        for dongle in self.hasp_dongles.values():
            if dongle.vendor_code == vendor_code:
                dongle.logged_in = True
                dongle.session_handle = 0x12345678 + len(self.hasp_dongles)
                return struct.pack('<II', HASPStatus.HASP_STATUS_OK, dongle.session_handle)

        return struct.pack('<I', HASPStatus.HASP_KEYNOTFOUND)

    def _hasp_logout(self, data: bytes) -> bytes:
        """Handle HASP logout operation."""
        if len(data) < 4:
            return struct.pack('<I', HASPStatus.HASP_TOO_SHORT)

        session_handle = struct.unpack('<I', data[:4])[0]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle:
                dongle.logged_in = False
                return struct.pack('<I', HASPStatus.HASP_STATUS_OK)

        return struct.pack('<I', HASPStatus.HASP_INV_HND)

    def _hasp_encrypt_command(self, data: bytes) -> bytes:
        """Handle HASP encrypt command."""
        if len(data) < 8:
            return struct.pack('<I', HASPStatus.HASP_TOO_SHORT)

        session_handle, data_length = struct.unpack('<II', data[:8])
        plaintext = data[8:8+data_length]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                encrypted = self.crypto_engine.hasp_encrypt(plaintext, dongle.aes_key, 'AES')
                response = struct.pack('<II', HASPStatus.HASP_STATUS_OK, len(encrypted))
                return response + encrypted

        return struct.pack('<I', HASPStatus.HASP_INV_HND)

    def _hasp_decrypt_command(self, data: bytes) -> bytes:
        """Handle HASP decrypt command."""
        if len(data) < 20:
            return struct.pack('<I', HASPStatus.HASP_TOO_SHORT)

        session_handle, data_length = struct.unpack('<II', data[:8])
        ciphertext = data[8:8+data_length]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                decrypted = self.crypto_engine.hasp_decrypt(ciphertext, dongle.aes_key, 'AES')
                response = struct.pack('<II', HASPStatus.HASP_STATUS_OK, len(decrypted))
                return response + decrypted

        return struct.pack('<I', HASPStatus.HASP_INV_HND)

    def _hasp_read_memory(self, data: bytes) -> bytes:
        """Handle HASP memory read operation."""
        if len(data) < 12:
            return struct.pack('<I', HASPStatus.HASP_TOO_SHORT)

        session_handle, offset, length = struct.unpack('<III', data[:12])

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                try:
                    mem_data = dongle.memory.read('eeprom', offset, length)
                    response = struct.pack('<II', HASPStatus.HASP_STATUS_OK, len(mem_data))
                    return response + mem_data
                except (ValueError, PermissionError):
                    return struct.pack('<I', HASPStatus.HASP_MEM_RANGE)

        return struct.pack('<I', HASPStatus.HASP_INV_HND)

    def _hasp_write_memory(self, data: bytes) -> bytes:
        """Handle HASP memory write operation."""
        if len(data) < 12:
            return struct.pack('<I', HASPStatus.HASP_TOO_SHORT)

        session_handle, offset, length = struct.unpack('<III', data[:12])
        write_data = data[12:12+length]

        for dongle in self.hasp_dongles.values():
            if dongle.session_handle == session_handle and dongle.logged_in:
                try:
                    dongle.memory.write('eeprom', offset, write_data)
                    return struct.pack('<I', HASPStatus.HASP_STATUS_OK)
                except (ValueError, PermissionError):
                    return struct.pack('<I', HASPStatus.HASP_MEM_RANGE)

        return struct.pack('<I', HASPStatus.HASP_INV_HND)

    def _sentinel_control_handler(self, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle Sentinel USB control transfers."""
        if not self.sentinel_dongles:
            return b'\x00' * 64

        dongle = next(iter(self.sentinel_dongles.values()))

        if wValue == 1:
            return struct.pack('<I', dongle.device_id)
        elif wValue == 2:
            return dongle.serial_number.encode('ascii')[:16].ljust(16, b'\x00')
        elif wValue == 3:
            return dongle.firmware_version.encode('ascii')[:16].ljust(16, b'\x00')

        return b'\x00' * 64

    def _sentinel_bulk_out_handler(self, data: bytes) -> bytes:
        """Handle Sentinel bulk OUT transfers."""
        if len(data) < 4:
            return b''

        command = struct.unpack('<I', data[:4])[0]

        if command == 1:
            return self._sentinel_query(data[4:])
        elif command == 2:
            return self._sentinel_read(data[4:])
        elif command == 3:
            return self._sentinel_write(data[4:])
        elif command == 4:
            return self._sentinel_encrypt(data[4:])

        return struct.pack('<I', SentinelStatus.SP_SUCCESS)

    def _sentinel_bulk_in_handler(self, data: bytes) -> bytes:
        """Handle Sentinel bulk IN transfers."""
        if not self.sentinel_dongles:
            return b'\x00' * 512

        dongle = next(iter(self.sentinel_dongles.values()))
        return bytes(dongle.response_buffer[:512])

    def _sentinel_query(self, data: bytes) -> bytes:
        """Handle Sentinel query operation."""
        if not self.sentinel_dongles:
            return struct.pack('<I', SentinelStatus.SP_UNIT_NOT_FOUND)

        dongle = next(iter(self.sentinel_dongles.values()))

        query_data = struct.pack('<I16s16sI',
            dongle.device_id,
            dongle.serial_number.encode('ascii')[:16].ljust(16, b'\x00'),
            dongle.firmware_version.encode('ascii')[:16].ljust(16, b'\x00'),
            dongle.developer_id,
        )

        dongle.response_buffer[0:len(query_data)] = query_data

        return struct.pack('<I', SentinelStatus.SP_SUCCESS)

    def _sentinel_read(self, data: bytes) -> bytes:
        """Handle Sentinel read operation."""
        if len(data) < 8:
            return struct.pack('<I', SentinelStatus.SP_INVALID_FUNCTION_CODE)

        cell_id, length = struct.unpack('<II', data[:8])

        for dongle in self.sentinel_dongles.values():
            if cell_id in dongle.cell_data:
                cell_data = dongle.cell_data[cell_id][:length]
                dongle.response_buffer[0:len(cell_data)] = cell_data
                return struct.pack('<I', SentinelStatus.SP_SUCCESS)

        return struct.pack('<I', SentinelStatus.SP_UNIT_NOT_FOUND)

    def _sentinel_write(self, data: bytes) -> bytes:
        """Handle Sentinel write operation."""
        if len(data) < 8:
            return struct.pack('<I', SentinelStatus.SP_INVALID_FUNCTION_CODE)

        cell_id, length = struct.unpack('<II', data[:8])
        write_data = data[8:8+length]

        for dongle in self.sentinel_dongles.values():
            if cell_id < 64:
                dongle.cell_data[cell_id] = write_data.ljust(64, b'\x00')
                return struct.pack('<I', SentinelStatus.SP_SUCCESS)

        return struct.pack('<I', SentinelStatus.SP_UNIT_NOT_FOUND)

    def _sentinel_encrypt(self, data: bytes) -> bytes:
        """Handle Sentinel encryption operation."""
        if len(data) < 4:
            return struct.pack('<I', SentinelStatus.SP_INVALID_FUNCTION_CODE)

        data_length = struct.unpack('<I', data[:4])[0]
        plaintext = data[4:4+data_length]

        for dongle in self.sentinel_dongles.values():
            encrypted = self.crypto_engine.hasp_encrypt(plaintext, dongle.aes_key, 'AES')
            dongle.response_buffer[0:len(encrypted)] = encrypted
            return struct.pack('<I', SentinelStatus.SP_SUCCESS)

        return struct.pack('<I', SentinelStatus.SP_UNIT_NOT_FOUND)

    def _wibukey_control_handler(self, wValue: int, wIndex: int, data: bytes) -> bytes:
        """Handle WibuKey USB control transfers."""
        if not self.wibukey_dongles:
            return b'\x00' * 64

        dongle = next(iter(self.wibukey_dongles.values()))

        if wValue == 1:
            return struct.pack('<III',
                dongle.firm_code,
                dongle.product_code,
                dongle.serial_number,
            )
        elif wValue == 2:
            return dongle.version.encode('ascii')[:16].ljust(16, b'\x00')

        return b'\x00' * 64

    def _wibukey_bulk_out_handler(self, data: bytes) -> bytes:
        """Handle WibuKey bulk OUT transfers."""
        if len(data) < 4:
            return b''

        command = struct.unpack('<I', data[:4])[0]

        if command == 1:
            return self._wibukey_open(data[4:])
        elif command == 2:
            return self._wibukey_access(data[4:])
        elif command == 3:
            return self._wibukey_encrypt(data[4:])
        elif command == 4:
            return self._wibukey_challenge(data[4:])

        return struct.pack('<I', 0)

    def _wibukey_bulk_in_handler(self, data: bytes) -> bytes:
        """Handle WibuKey bulk IN transfers."""
        if not self.wibukey_dongles:
            return b'\x00' * 512

        dongle = next(iter(self.wibukey_dongles.values()))
        response = bytearray(512)

        info = struct.pack('<IIII',
            dongle.firm_code,
            dongle.product_code,
            dongle.feature_code,
            dongle.serial_number,
        )
        response[0:len(info)] = info

        return bytes(response)

    def _wibukey_open(self, data: bytes) -> bytes:
        """Handle WibuKey open operation."""
        if len(data) < 8:
            return struct.pack('<I', 1)

        firm_code, product_code = struct.unpack('<II', data[:8])

        for dongle in self.wibukey_dongles.values():
            if dongle.firm_code == firm_code and dongle.product_code == product_code:
                return struct.pack('<II', 0, dongle.container_handle)

        return struct.pack('<I', 1)

    def _wibukey_access(self, data: bytes) -> bytes:
        """Handle WibuKey access operation."""
        if len(data) < 12:
            return struct.pack('<I', 1)

        container_handle, feature_code, _access_type = struct.unpack('<III', data[:12])

        for dongle in self.wibukey_dongles.values():
            if dongle.container_handle == container_handle:
                if feature_code in dongle.license_entries:
                    entry = dongle.license_entries[feature_code]
                    if entry['enabled']:
                        dongle.active_licenses.add(feature_code)
                        return struct.pack('<I', 0)

        return struct.pack('<I', 1)

    def _wibukey_encrypt(self, data: bytes) -> bytes:
        """Handle WibuKey encrypt operation."""
        if len(data) < 8:
            return struct.pack('<I', 1)

        container_handle, data_length = struct.unpack('<II', data[:8])
        plaintext = data[8:8+data_length]

        for dongle in self.wibukey_dongles.values():
            if dongle.container_handle == container_handle:
                encrypted = self.crypto_engine.hasp_encrypt(plaintext, dongle.aes_key, 'AES')
                response = struct.pack('<II', 0, len(encrypted))
                return response + encrypted

        return struct.pack('<I', 1)

    def _wibukey_challenge(self, data: bytes) -> bytes:
        """Handle WibuKey challenge-response operation."""
        if len(data) < 20:
            return struct.pack('<I', 1)

        container_handle, challenge_length = struct.unpack('<II', data[:8])
        challenge = data[8:8+challenge_length]

        for dongle in self.wibukey_dongles.values():
            if dongle.container_handle == container_handle:
                response = self.crypto_engine.wibukey_challenge_response(
                    challenge,
                    dongle.challenge_response_key,
                )
                result = struct.pack('<II', 0, len(response))
                return result + response

        return struct.pack('<I', 1)

    def _hook_dongle_apis(self, dongle_types: list[str]) -> None:
        """Install comprehensive Frida hooks for dongle APIs."""
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

                    console.log("[CodeMeter] Comprehensive CodeMeter API hooks installed");
                }} catch(e) {{
                    console.log("[CodeMeter] Error installing hooks: " + e);
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
        self.logger.info(f"Comprehensive dongle API hooks installed for: {', '.join(dongle_types)}")

    def _patch_dongle_checks(self) -> None:
        """Patch binary instructions that check for dongle presence."""
        if not self.app or not hasattr(self.app, "binary_path") or not self.app.binary_path:
            return

        try:
            binary_path = Path(self.app.binary_path)
            if not binary_path.exists():
                return

            with open(binary_path, "rb") as f:
                binary_data = f.read()

            dongle_check_patterns = [
                {"pattern": b"\x85\xc0\x74", "patch": b"\x85\xc0\xeb", "desc": "TEST EAX, EAX; JZ -> JMP"},
                {"pattern": b"\x85\xc0\x75", "patch": b"\x85\xc0\xeb", "desc": "TEST EAX, EAX; JNZ -> JMP"},
                {"pattern": b"\x83\xf8\x00\x74", "patch": b"\x83\xf8\x00\xeb", "desc": "CMP EAX, 0; JZ -> JMP"},
                {"pattern": b"\x83\xf8\x00\x75", "patch": b"\x83\xf8\x00\xeb", "desc": "CMP EAX, 0; JNZ -> JMP"},
                {"pattern": b"\x3d\x00\x00\x00\x00\x74", "patch": b"\x3d\x00\x00\x00\x00\xeb", "desc": "CMP EAX, 0; JZ -> JMP"},
                {"pattern": b"\x3d\x00\x00\x00\x00\x75", "patch": b"\x3d\x00\x00\x00\x00\xeb", "desc": "CMP EAX, 0; JNZ -> JMP"},
                {"pattern": b"\x48\x85\xc0\x74", "patch": b"\x48\x85\xc0\xeb", "desc": "TEST RAX, RAX; JZ -> JMP (x64)"},
                {"pattern": b"\x48\x85\xc0\x75", "patch": b"\x48\x85\xc0\xeb", "desc": "TEST RAX, RAX; JNZ -> JMP (x64)"},
            ]

            patches_applied = 0
            for pattern_info in dongle_check_patterns:
                pattern = pattern_info["pattern"]
                patch = pattern_info["patch"]
                desc = pattern_info["desc"]

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

            self.logger.info(f"Identified {patches_applied} dongle check patterns to patch")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error patching dongle checks: {e!s}")

    def _spoof_dongle_registry(self) -> None:
        """Manipulate Windows registry to establish dongle presence."""
        try:
            if platform.system() != "Windows":
                self.logger.info("Not on Windows - skipping registry spoofing")
                return

            if not WINREG_AVAILABLE or winreg is None:
                self.logger.warning("winreg module not available - skipping registry spoofing")
                return

            dongle_registry_entries = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SafeNet", "InstallDir", r"C:\Program Files\SafeNet"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SafeNet\Sentinel", "Version", "8.0.0"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Sentinel", "Start", 2),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Aladdin Knowledge Systems", "HASP", "Installed"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Aladdin Knowledge Systems\HASP", "Version", "4.95"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WIBU-SYSTEMS", "CodeMeter", r"C:\Program Files\CodeMeter"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WIBU-SYSTEMS\CodeMeter", "Version", "6.90"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\CodeMeter", "Start", 2),
            ]

            for hkey, path, name, value in dongle_registry_entries:
                try:
                    key = winreg.CreateKey(hkey, path)
                    if isinstance(value, int):
                        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                    else:
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                    winreg.CloseKey(key)
                    self.logger.debug(f"Set registry entry {path}\\{name} = {value}")
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Could not set registry entry {path}\\{name}: {e!s}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Registry spoofing failed: {e!s}")

    def process_hasp_challenge(self, challenge: bytes, dongle_id: int = 1) -> bytes:
        """Process HASP cryptographic challenge.

        Args:
            challenge: Challenge data from protected application
            dongle_id: ID of HASP dongle to use

        Returns:
            bytes: Challenge response

        """
        if dongle_id not in self.hasp_dongles:
            self.logger.error(f"HASP dongle {dongle_id} not found")
            return b''

        dongle = self.hasp_dongles[dongle_id]

        if len(challenge) >= 16:
            response = self.crypto_engine.sentinel_challenge_response(challenge, dongle.aes_key)
        else:
            response = hashlib.sha256(challenge + dongle.seed_code).digest()[:16]

        return response

    def read_dongle_memory(self, dongle_type: str, dongle_id: int, region: str, offset: int, length: int) -> bytes:
        """Read from dongle memory.

        Args:
            dongle_type: Type of dongle (HASP, Sentinel, WibuKey)
            dongle_id: ID of specific dongle
            region: Memory region (rom, ram, eeprom)
            offset: Offset within region
            length: Number of bytes to read

        Returns:
            bytes: Memory data

        """
        try:
            if dongle_type.upper() == "HASP" and dongle_id in self.hasp_dongles:
                return self.hasp_dongles[dongle_id].memory.read(region, offset, length)
            elif dongle_type.upper() == "SENTINEL" and dongle_id in self.sentinel_dongles:
                return self.sentinel_dongles[dongle_id].memory.read(region, offset, length)
            elif dongle_type.upper() == "WIBUKEY" and dongle_id in self.wibukey_dongles:
                return self.wibukey_dongles[dongle_id].memory.read(region, offset, length)
            else:
                self.logger.error(f"Dongle {dongle_type} {dongle_id} not found")
                return b''
        except (ValueError, PermissionError) as e:
            self.logger.error(f"Memory read error: {e}")
            return b''

    def write_dongle_memory(self, dongle_type: str, dongle_id: int, region: str, offset: int, data: bytes) -> bool:
        """Write to dongle memory.

        Args:
            dongle_type: Type of dongle (HASP, Sentinel, WibuKey)
            dongle_id: ID of specific dongle
            region: Memory region (rom, ram, eeprom)
            offset: Offset within region
            data: Data to write

        Returns:
            bool: True if successful

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
                self.logger.error(f"Dongle {dongle_type} {dongle_id} not found")
                return False
        except (ValueError, PermissionError) as e:
            self.logger.error(f"Memory write error: {e}")
            return False

    def generate_emulation_script(self, dongle_types: list[str]) -> str:
        """Generate a Frida script for dongle emulation.

        Args:
            dongle_types: List of dongle types to emulate

        Returns:
            str: Complete Frida script for dongle emulation

        """
        base_script = ""
        for hook in self.hooks:
            if hook["type"] == "frida":
                base_script = hook["script"]
                break

        return base_script

    def get_emulation_status(self) -> dict[str, Any]:
        """Get the current status of dongle emulation.

        Returns:
            dict: Status information about emulated dongles and hooks

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
        """Clear all dongle emulation hooks and virtual devices."""
        with self.lock:
            self.hooks.clear()
            self.patches.clear()
            self.virtual_dongles.clear()
            self.usb_emulators.clear()
            self.hasp_dongles.clear()
            self.sentinel_dongles.clear()
            self.wibukey_dongles.clear()
        self.logger.info("Cleared all dongle emulation hooks and virtual devices")


def activate_hardware_dongle_emulation(app: Any, dongle_types: list[str] = None) -> dict[str, Any]:
    """Activate hardware dongle emulation.

    Args:
        app: Application instance with binary_path
        dongle_types: List of dongle types to emulate

    Returns:
        dict: Results of the emulation activation

    """
    emulator = HardwareDongleEmulator(app)
    return emulator.activate_dongle_emulation(dongle_types)


__all__ = [
    "HardwareDongleEmulator",
    "activate_hardware_dongle_emulation",
    "DongleType",
    "HASPStatus",
    "SentinelStatus",
    "USBDescriptor",
    "DongleMemory",
    "HASPDongle",
    "SentinelDongle",
    "WibuKeyDongle",
    "USBEmulator",
    "CryptoEngine",
]
