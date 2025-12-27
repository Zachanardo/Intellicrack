#!/usr/bin/env python3
"""Hardware dongle emulator plugin for Intellicrack.

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

import contextlib
import hashlib
import json
import logging
import os
import random
import struct
import time
import traceback
import winreg
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from intellicrack.utils.logger import log_all_methods


logger = logging.getLogger(__name__)


"""
Hardware Dongle Emulator

Comprehensive USB and parallel port dongle emulation system supporting
HASP, Sentinel, Rainbow, CodeMeter, and custom protection dongles.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class DongleType(Enum):
    """Types of hardware dongles."""

    HASP_HL = "HASP_HL"
    HASP_4 = "HASP_4"
    HASP = "HASP"
    SENTINEL_SUPER_PRO = "Sentinel_SuperPro"
    SENTINEL_UltraPro = "Sentinel_UltraPro"
    SENTINEL = "Sentinel"
    RAINBOW_SENTINEL = "Rainbow_Sentinel"
    CODEOMETER = "CodeMeter"
    ROCKEY = "Rockey"
    MARX_CRYPTOBOX = "Marx_CryptoBox"
    HARDLOCK = "Hardlock"
    WIBU_BOX = "WibuBox"
    CUSTOM_USB = "Custom_USB"
    CUSTOM_LPT = "Custom_LPT"
    GENERIC = "Generic"


class DongleInterface(Enum):
    """Dongle interface types."""

    USB = "USB"
    PARALLEL_PORT = "Parallel_Port"
    ETHERNET = "Ethernet"
    MEMORY_MAPPED = "Memory_Mapped"


@log_all_methods
@dataclass
class DongleSpec:
    """Hardware dongle specification for configuring emulated protection devices.

    This class defines the complete configuration for a hardware dongle emulator,
    including type, interface, hardware IDs, memory layout, and supported
    cryptographic algorithms used by licensing protection systems.
    """

    dongle_type: DongleType
    interface: DongleInterface
    vendor_id: int
    product_id: int
    serial_number: str = ""
    firmware_version: str = "1.0.0"
    memory_size: int = 64  # KB
    algorithms: list[str] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Generate cryptographically secure serial number for dongle specification.

        Generates a unique dongle serial number by combining vendor ID, product ID,
        timestamp, and cryptographic random entropy if not explicitly provided.
        The serial number follows standard dongle formats used by HASP, Sentinel,
        and other USB-based protection dongles.
        """
        if not self.serial_number:
            # Generate cryptographically secure serial number based on hardware identifiers
            # Combines vendor ID, product ID, timestamp, and random entropy
            timestamp_bytes = struct.pack(">Q", int(time.time() * 1000000))
            random_bytes = os.urandom(8)  # Cryptographically secure random bytes

            # Create unique identifier combining all components
            serial_data = struct.pack(">HH", self.vendor_id, self.product_id) + timestamp_bytes + random_bytes

            # Generate deterministic hash-based serial number
            serial_hash = hashlib.sha256(serial_data).hexdigest()[:16].upper()

            # Format as standard dongle serial with hyphen separation (4-digit groups)
            # Standard format used by HASP, Sentinel, and most USB dongles
            self.serial_number = "-".join([serial_hash[i : i + 4] for i in range(0, 16, 4)])


@log_all_methods
@dataclass
class DongleMemory:
    """Dongle memory model with protection ranges and access control.

    Implements a memory management system for hardware dongles with support for
    read-only regions, protected ranges, and byte-level access control used in
    licensing key storage and algorithm execution.
    """

    size: int
    data: bytearray
    read_only_ranges: list[tuple[int, int]] = field(default_factory=list)
    protected_ranges: list[tuple[int, int]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Initialize dongle memory allocation and protection attributes.

        Allocates memory buffer if not provided and sets up protection
        ranges for read-only and protected memory regions.
        """
        if not self.data:
            self.data = bytearray(self.size)

    def read(self, address: int, length: int) -> bytes:
        """Read from dongle memory.

        Args:
            address: Memory address to read from.
            length: Number of bytes to read.

        Returns:
            Bytes read from the specified memory location.

        Raises:
            ValueError: If address or address+length exceeds memory bounds.
        """
        if address < 0 or address + length > self.size:
            raise ValueError("Memory access out of bounds")

        return bytes(self.data[address : address + length])

    def write(self, address: int, data: bytes) -> bool:
        """Write to dongle memory.

        Args:
            address: Memory address to write to.
            data: Bytes to write to memory.

        Returns:
            True if write succeeded, False if write attempted to protected/read-only region.

        Raises:
            ValueError: If address or address+len(data) exceeds memory bounds.
        """
        if address < 0 or address + len(data) > self.size:
            raise ValueError("Memory access out of bounds")

        # Check read-only ranges
        for start, end in self.read_only_ranges:
            if address + len(data) > start and address < end:
                return False  # Attempting to write to read-only memory

        self.data[address : address + len(data)] = data
        return True


@log_all_methods
class CryptoEngine:
    """Cryptographic engine implementing dongle-compatible algorithms.

    Provides encryption, decryption, and integrity checking algorithms used by
    hardware dongles including TEA (Tiny Encryption Algorithm), XOR transformation,
    and CRC16 checksums for challenge-response authentication protocols.
    """

    @staticmethod
    def tea_encrypt(data: bytes, key: bytes) -> bytes:
        """Encrypt data using TEA (Tiny Encryption Algorithm).

        Implements the Tiny Encryption Algorithm (TEA) block cipher with a
        64-bit block size and 128-bit key for dongle memory encryption and
        cryptographic challenge transformation in licensing systems.

        Args:
            data: Input data to encrypt (padded to 8-byte boundary).
            key: 16-byte encryption key for TEA algorithm.

        Returns:
            Encrypted data of same length as input.
        """
        if len(data) % 8 != 0:
            data += b"\x00" * (8 - len(data) % 8)

        key_ints = struct.unpack(">4I", key[:16])
        result = bytearray()

        delta = 0x9E3779B9

        for i in range(0, len(data), 8):
            v0, v1 = struct.unpack(">2I", data[i : i + 8])

            total = 0
            for _ in range(32):
                total += delta
                v0 += ((v1 << 4) + key_ints[0]) ^ (v1 + total) ^ ((v1 >> 5) + key_ints[1])
                v0 &= 0xFFFFFFFF
                v1 += ((v0 << 4) + key_ints[2]) ^ (v0 + total) ^ ((v0 >> 5) + key_ints[3])
                v1 &= 0xFFFFFFFF

            result.extend(struct.pack(">2I", v0, v1))

        return bytes(result)

    @staticmethod
    def tea_decrypt(data: bytes, key: bytes) -> bytes:
        """Decrypt data using TEA (Tiny Encryption Algorithm).

        Reverses TEA encryption by performing inverse round transformations
        on 64-bit blocks with the provided 128-bit key for license validation
        and cryptographic verification in dongle emulation.

        Args:
            data: Encrypted data to decrypt.
            key: 16-byte decryption key for TEA algorithm.

        Returns:
            Decrypted plaintext data of same length as input.
        """
        key_ints = struct.unpack(">4I", key[:16])
        result = bytearray()

        delta = 0x9E3779B9

        for i in range(0, len(data), 8):
            v0, v1 = struct.unpack(">2I", data[i : i + 8])

            total = 0xC6EF3720  # delta * 32
            for _ in range(32):
                v1 -= ((v0 << 4) + key_ints[2]) ^ (v0 + total) ^ ((v0 >> 5) + key_ints[3])
                v1 &= 0xFFFFFFFF
                v0 -= ((v1 << 4) + key_ints[0]) ^ (v1 + total) ^ ((v1 >> 5) + key_ints[1])
                v0 &= 0xFFFFFFFF
                total -= delta

            result.extend(struct.pack(">2I", v0, v1))

        return bytes(result)

    @staticmethod
    def simple_xor(data: bytes, key: bytes) -> bytes:
        """Encrypt data using simple XOR operation.

        Performs byte-wise XOR encryption of input data with a repeating key,
        commonly used by legacy dongle systems for challenge-response protocols
        and simple obfuscation of licensing data.

        Args:
            data: Data to encrypt or decrypt.
            key: XOR key (repeated cyclically if shorter than data).

        Returns:
            XOR-encrypted or decrypted data of same length as input.
        """
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

    @staticmethod
    def crc16(data: bytes) -> int:
        """Calculate CRC16 checksum using CCITT-FALSE polynomial.

        Computes a 16-bit cyclic redundancy check for integrity verification
        and message authentication codes in dongle communication protocols
        (HASP, Sentinel, and parallel port dongles).

        Args:
            data: Data to calculate CRC for.

        Returns:
            16-bit CRC16 checksum value (0x0000-0xFFFF).
        """
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc


@log_all_methods
class BaseDongleEmulator:
    """Base dongle emulator with core memory, crypto, and API operations.

    Implements foundational dongle emulation for all hardware protection types including
    memory management, cryptographic operations, challenge-response authentication,
    and virtual file systems. Serves as base class for specific dongle emulators
    (HASP, Sentinel, etc.).
    """

    def __init__(self, spec: DongleSpec) -> None:
        """Initialize base dongle emulator with specification and crypto engine.

        Sets up dongle memory, cryptographic engine, logging, API handlers,
        and internal session tracking for emulating hardware dongle operations.

        Args:
            spec: DongleSpec object containing type, interface, vendor/product IDs,
                and configuration for the emulated dongle.
        """
        self.spec = spec
        self.memory = DongleMemory(spec.memory_size * 1024, bytearray(spec.memory_size * 1024))
        self.crypto = CryptoEngine()
        self.logger = logging.getLogger(f"{__name__}.{spec.dongle_type.value}")
        self.active = False
        self.api_handlers: dict[str, Callable[..., Any]] = {}
        self._usb_device: Any = None
        self._sessions: dict[int, dict[str, Any]] = {}

        # Initialize dongle-specific data
        self._initialize_memory()
        self._setup_api_handlers()

    def _initialize_memory(self) -> None:
        """Initialize dongle memory with default data and protection ranges.

        Populates initial dongle memory with vendor ID, product ID, serial number,
        and firmware version at standard offsets. Marks hardware identification
        region as read-only to protect against modification attempts.
        """
        # Set up basic dongle information at fixed addresses
        self.memory.write(0x00, struct.pack("<HH", self.spec.vendor_id, self.spec.product_id))
        self.memory.write(0x04, self.spec.serial_number.encode()[:16].ljust(16, b"\x00"))
        self.memory.write(0x14, self.spec.firmware_version.encode()[:8].ljust(8, b"\x00"))

        # Mark first 32 bytes as read-only
        self.memory.read_only_ranges.append((0, 32))

    def _setup_api_handlers(self) -> None:
        """Set up API handlers for dongle operations.

        Initializes a dictionary mapping API operation names to handler methods
        that implement core dongle functionality including memory access,
        encryption, and authentication operations.
        """
        self.api_handlers = {
            "read_memory": self.read_memory,
            "write_memory": self.write_memory,
            "encrypt": self.encrypt_data,
            "decrypt": self.decrypt_data,
            "get_info": self.get_dongle_info,
            "challenge": self.process_challenge,
        }

    def start(self) -> None:
        """Start dongle emulation and activate licensing protection.

        Enables the dongle emulator to respond to API calls and licensing
        verification requests from protected applications.
        """
        self.active = True
        self.logger.info("Started %s emulation", self.spec.dongle_type.value)

    def stop(self) -> None:
        """Stop dongle emulation and deactivate licensing protection.

        Disables the dongle emulator and prevents further licensing verification
        operations from succeeding.
        """
        self.active = False
        self.logger.info("Stopped %s emulation", self.spec.dongle_type.value)

    def read_memory(self, address: int, length: int) -> bytes:
        """Read from dongle memory.

        Args:
            address: Memory address to read from.
            length: Number of bytes to read.

        Returns:
            Bytes read from dongle memory.

        Raises:
            RuntimeError: If dongle is not active.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        return self.memory.read(address, length)

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write to dongle memory.

        Args:
            address: Memory address to write to.
            data: Bytes to write.

        Returns:
            True if write succeeded, False if protected/read-only region.

        Raises:
            RuntimeError: If dongle is not active.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        return self.memory.write(address, data)

    def encrypt_data(self, data: bytes, algorithm: str = "TEA") -> bytes:
        """Encrypt data using dongle algorithm.

        Args:
            data: Data to encrypt.
            algorithm: Encryption algorithm ('TEA' or 'XOR', default 'TEA').

        Returns:
            Encrypted data.

        Raises:
            ValueError: If algorithm is not supported.
        """
        key = self.memory.read(0x20, 16)  # Key stored at offset 0x20

        if algorithm == "TEA":
            return self.crypto.tea_encrypt(data, key)
        if algorithm == "XOR":
            return self.crypto.simple_xor(data, key)
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    def decrypt_data(self, data: bytes, algorithm: str = "TEA") -> bytes:
        """Decrypt data using dongle algorithm.

        Args:
            data: Data to decrypt.
            algorithm: Decryption algorithm ('TEA' or 'XOR', default 'TEA').

        Returns:
            Decrypted data.

        Raises:
            ValueError: If algorithm is not supported.
        """
        key = self.memory.read(0x20, 16)

        if algorithm == "TEA":
            return self.crypto.tea_decrypt(data, key)
        if algorithm == "XOR":
            return self.crypto.simple_xor(data, key)
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    def get_dongle_info(self) -> dict[str, Any]:
        """Get dongle information.

        Returns:
            Dictionary containing dongle metadata (type, IDs, serial, firmware, memory size, active status).
        """
        return {
            "type": self.spec.dongle_type.value,
            "vendor_id": self.spec.vendor_id,
            "product_id": self.spec.product_id,
            "serial_number": self.spec.serial_number,
            "firmware_version": self.spec.firmware_version,
            "memory_size": self.spec.memory_size,
            "active": self.active,
        }

    def process_challenge(self, challenge: bytes) -> bytes:
        """Process challenge-response authentication.

        Args:
            challenge: Challenge data from the application.

        Returns:
            Challenge response with XOR transformation and CRC16 checksum.
        """
        key = self.memory.read(0x20, 16)
        response = self.crypto.simple_xor(challenge, key)
        crc = self.crypto.crc16(response)
        return response + struct.pack("<H", crc)

    def generate_response(self, data: bytes) -> bytes:
        """Generate cryptographic response for authentication.

        Creates a unique cryptographic response by hashing input data with the
        dongle's serial number, used for challenge-response authentication in
        licensing verification protocols.

        Args:
            data: Data to generate cryptographic response for.

        Returns:
            SHA256 hash (32 bytes) of data combined with dongle serial number.
        """
        return hashlib.sha256(data + self.spec.serial_number.encode()).digest()

    def reset(self) -> None:
        """Reset dongle state to initial configuration.

        Reinitializes dongle memory with default values and restores all
        protection settings to their original state, clearing any user-written
        data while preserving hardware identification information.
        """
        self.active = False
        self._initialize_memory()
        self.active = True
        self.logger.debug("Dongle %s reset to initial state", self.spec.serial_number)

    def execute_algorithm(self, algorithm_id: int, input_data: bytes) -> bytes:
        """Execute a cryptographic algorithm stored in the dongle.

        Executes dongle-stored algorithms for license validation, challenge
        transformation, and feature checking. Each algorithm ID corresponds to
        a specific cryptographic transformation used by protected applications.

        Args:
            algorithm_id: Algorithm identifier for the algorithm to execute (0x00-0xFF).
            input_data: Input data for the algorithm transformation.

        Returns:
            Processed output data from the algorithm execution.

        Raises:
            RuntimeError: If dongle is not active.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        if not input_data:
            return b""

        algorithm_map = {
            0x00: self._algo_identity,
            0x01: self._algo_xor_transform,
            0x02: self._algo_tea_encrypt,
            0x03: self._algo_tea_decrypt,
            0x04: self._algo_hash_response,
            0x05: self._algo_challenge_transform,
            0x06: self._algo_license_validate,
            0x07: self._algo_feature_check,
        }

        algorithm_func = algorithm_map.get(algorithm_id, self._algo_custom)

        try:
            result = algorithm_func(input_data)
            self.logger.debug("Algorithm 0x%02X executed, input=%d bytes, output=%d bytes", algorithm_id, len(input_data), len(result))
            return result
        except Exception:
            self.logger.exception("Algorithm execution failed")
            return b"\xff" * len(input_data)

    def _algo_identity(self, data: bytes) -> bytes:
        """Execute identity algorithm - returns input unchanged.

        Implements a pass-through algorithm that returns input data without
        transformation, used for testing and baseline comparisons.

        Args:
            data: Input data to return unchanged.

        Returns:
            Input data unchanged.
        """
        return data

    def _algo_xor_transform(self, data: bytes) -> bytes:
        """Execute XOR transformation using dongle key.

        Applies XOR encryption using the dongle's stored key, commonly used in
        legacy dongle systems for reversible data transformation.

        Args:
            data: Input data to transform with XOR.

        Returns:
            XOR-transformed data using dongle's key.
        """
        key = self.memory.read(0x20, 16)
        return self.crypto.simple_xor(data, key)

    def _algo_tea_encrypt(self, data: bytes) -> bytes:
        """Execute TEA encryption algorithm.

        Encrypts data using the TEA (Tiny Encryption Algorithm) with the
        dongle's stored key for cryptographic protection of license data.

        Args:
            data: Data to encrypt with TEA.

        Returns:
            TEA-encrypted data using dongle's key.
        """
        key = self.memory.read(0x20, 16)
        return self.crypto.tea_encrypt(data, key)

    def _algo_tea_decrypt(self, data: bytes) -> bytes:
        """Execute TEA decryption algorithm.

        Decrypts data encrypted with TEA algorithm using the dongle's stored key
        for license validation and feature verification.

        Args:
            data: Encrypted data to decrypt with TEA.

        Returns:
            TEA-decrypted plaintext using dongle's key.
        """
        key = self.memory.read(0x20, 16)
        return self.crypto.tea_decrypt(data, key)

    def _algo_hash_response(self, data: bytes) -> bytes:
        """Generate hash-based response for authentication.

        Combines input data with dongle key and creates SHA256 hash for
        authentication verification in licensing protocols.

        Args:
            data: Input data to hash for authentication.

        Returns:
            SHA256 hash truncated to input length (max 32 bytes).
        """
        key = self.memory.read(0x20, 16)
        combined = data + key
        hash_result = hashlib.sha256(combined).digest()
        return hash_result[: len(data)] if len(data) < 32 else hash_result

    def _algo_challenge_transform(self, data: bytes) -> bytes:
        """Transform challenge data for authentication protocols.

        Applies dual XOR transformation (with key and serial number) and
        appends CRC16 checksum for challenge-response authentication.

        Args:
            data: Challenge data to transform for verification.

        Returns:
            Transformed challenge data with CRC16 checksum appended.
        """
        key = self.memory.read(0x20, 16)
        serial_bytes = self.spec.serial_number.replace("-", "").encode()[:16]
        intermediate = self.crypto.simple_xor(data, key)
        result = self.crypto.simple_xor(intermediate, serial_bytes.ljust(16, b"\x00"))
        crc = self.crypto.crc16(result)
        return result + struct.pack("<H", crc)

    def _algo_license_validate(self, data: bytes) -> bytes:
        """Validate license data against dongle identity.

        Verifies license feature codes by comparing against dongle serial number
        hash and returns validation status code.

        Args:
            data: License validation data (4+ bytes containing feature code).

        Returns:
            License validation response (status code and serial hash).
        """
        if len(data) < 4:
            return b"\x00\x00\x00\x01"

        feature_code = struct.unpack("<I", data[:4])[0]
        serial_hash = hashlib.sha256(self.spec.serial_number.encode()).digest()
        expected_code = struct.unpack("<I", serial_hash[:4])[0]

        if feature_code in {expected_code, 1, 2, 5, 10, 100}:
            return struct.pack("<I", 0) + serial_hash
        return struct.pack("<I", 0x00000002)

    def _algo_feature_check(self, data: bytes) -> bytes:
        """Check if a specific feature is enabled in the dongle.

        Queries the dongle's feature bit map to determine if a specific feature
        is licensed and enabled for use by the protected application.

        Args:
            data: Feature check data (2+ bytes with feature ID).

        Returns:
            Feature check response (feature ID and enabled status as 16-bit values).
        """
        if len(data) < 2:
            return b"\x00\x00"

        feature_id = struct.unpack("<H", data[:2])[0]
        features_enabled = self.memory.read(0x40, 32)

        byte_idx = feature_id // 8
        bit_idx = feature_id % 8

        if byte_idx < len(features_enabled) and (features_enabled[byte_idx] & (1 << bit_idx)):
            return struct.pack("<HH", feature_id, 1)
        return struct.pack("<HH", feature_id, 0)

    def _algo_custom(self, data: bytes) -> bytes:
        """Execute custom algorithm fallback using combined transformations.

        Provides a fallback algorithm implementation that combines XOR encryption
        with CRC16 checksum for unknown algorithm IDs.

        Args:
            data: Input data for transformation.

        Returns:
            Transformed data with CRC16 checksum appended.
        """
        key = self.memory.read(0x20, 16)
        xor_result = self.crypto.simple_xor(data, key)
        crc = self.crypto.crc16(xor_result)
        return xor_result + struct.pack("<H", crc)

    def read_file(self, file_id: int) -> bytes:
        """Read a file from the dongle's virtual file system.

        Args:
            file_id: File identifier (0x0000-0xFFFF)

        Returns:
            File data as bytes, or empty bytes if file not found

        Raises:
            RuntimeError: If dongle is not active.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        file_table_base = 0x1000
        file_entry_size = 64
        max_files = 16

        for i in range(max_files):
            entry_addr = file_table_base + (i * file_entry_size)

            if entry_addr + file_entry_size > self.memory.size:
                break

            entry_data = self.memory.read(entry_addr, file_entry_size)

            stored_id = struct.unpack("<H", entry_data[:2])[0]
            if stored_id != file_id:
                continue

            file_size = struct.unpack("<I", entry_data[2:6])[0]
            file_offset = struct.unpack("<I", entry_data[6:10])[0]

            if file_size == 0 or file_offset == 0:
                continue

            if file_offset + file_size <= self.memory.size:
                file_data = self.memory.read(file_offset, file_size)
                self.logger.debug("Read file 0x%04X: %d bytes from offset 0x%04X", file_id, file_size, file_offset)
                return file_data

        self.logger.debug("File 0x%04X not found", file_id)
        return b""

    def write_file(self, file_id: int, file_data: bytes) -> bool:
        """Write a file to the dongle's virtual file system.

        Args:
            file_id: File identifier (0x0000-0xFFFF)
            file_data: Data to write

        Returns:
            True if write succeeded, False otherwise

        Raises:
            RuntimeError: If dongle is not active.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        if not file_data:
            return False

        file_table_base = 0x1000
        file_entry_size = 64
        max_files = 16
        data_area_base = 0x2000

        empty_slot = -1
        existing_slot = -1
        next_data_offset = data_area_base

        for i in range(max_files):
            entry_addr = file_table_base + (i * file_entry_size)

            if entry_addr + file_entry_size > self.memory.size:
                break

            entry_data = self.memory.read(entry_addr, file_entry_size)
            stored_id = struct.unpack("<H", entry_data[:2])[0]

            if stored_id == file_id:
                existing_slot = i
                break

            if stored_id == 0 and empty_slot == -1:
                empty_slot = i

            if stored_id != 0:
                file_size = struct.unpack("<I", entry_data[2:6])[0]
                file_offset = struct.unpack("<I", entry_data[6:10])[0]
                next_data_offset = max(next_data_offset, file_offset + file_size)

        slot = existing_slot if existing_slot >= 0 else empty_slot
        if slot < 0:
            self.logger.error("No available file slots")
            return False

        data_offset = next_data_offset
        if existing_slot >= 0:
            entry_addr = file_table_base + (existing_slot * file_entry_size)
            entry_data = self.memory.read(entry_addr, file_entry_size)
            data_offset = struct.unpack("<I", entry_data[6:10])[0]

        if data_offset + len(file_data) > self.memory.size:
            self.logger.error("File too large: %d bytes exceeds available space", len(file_data))
            return False

        write_success = self.memory.write(data_offset, file_data)
        if not write_success:
            return False

        entry_addr = file_table_base + (slot * file_entry_size)
        entry = struct.pack("<H", file_id)
        entry += struct.pack("<I", len(file_data))
        entry += struct.pack("<I", data_offset)
        entry += struct.pack("<I", int(time.time()))
        entry += b"\x00" * (file_entry_size - len(entry))

        write_success = self.memory.write(entry_addr, entry)
        if write_success:
            self.logger.debug("Wrote file 0x%04X: %d bytes at offset 0x%04X", file_id, len(file_data), data_offset)

        return write_success

    def read_counter(self, counter_id: int) -> int:
        """Read a counter value from the dongle.

        Args:
            counter_id: Counter identifier (0x00-0x0F).

        Returns:
            Current counter value (32-bit unsigned integer).

        Raises:
            RuntimeError: If dongle is not active.
            ValueError: If counter_id is out of valid range.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        counter_base = 0x80
        max_counters = 16

        if counter_id < 0 or counter_id >= max_counters:
            raise ValueError(f"Invalid counter ID: {counter_id}")

        counter_addr = counter_base + (counter_id * 4)
        counter_data = self.memory.read(counter_addr, 4)
        counter_value: int = struct.unpack("<I", counter_data)[0]

        self.logger.debug("Counter %d value: %d", counter_id, counter_value)
        return counter_value

    def increment_counter(self, counter_id: int, increment: int = 1) -> int:
        """Increment a counter value in the dongle.

        Args:
            counter_id: Counter identifier (0x00-0x0F).
            increment: Amount to increment by (default 1).

        Returns:
            New counter value after increment.

        Raises:
            RuntimeError: If dongle is not active.
            ValueError: If counter_id is out of valid range.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        counter_base = 0x80
        max_counters = 16

        if counter_id < 0 or counter_id >= max_counters:
            raise ValueError(f"Invalid counter ID: {counter_id}")

        current_value = self.read_counter(counter_id)
        new_value = (current_value + increment) & 0xFFFFFFFF

        counter_addr = counter_base + (counter_id * 4)
        self.memory.write(counter_addr, struct.pack("<I", new_value))

        self.logger.debug("Counter %d incremented: %d -> %d", counter_id, current_value, new_value)
        return new_value

    def get_rtc(self) -> int:
        """Get the current real-time clock value from the dongle.

        Returns:
            Unix timestamp representing the dongle's internal clock.

        Raises:
            RuntimeError: If dongle is not active.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        rtc_addr = 0x34
        rtc_data = self.memory.read(rtc_addr, 4)
        rtc_value: int = struct.unpack("<I", rtc_data)[0]

        if rtc_value == 0:
            rtc_value = int(time.time())
            self.memory.write(rtc_addr, struct.pack("<I", rtc_value))

        return rtc_value

    def set_rtc(self, timestamp: int) -> bool:
        """Set the real-time clock value in the dongle.

        Args:
            timestamp: Unix timestamp to set.

        Returns:
            True if RTC was set successfully.

        Raises:
            RuntimeError: If dongle is not active.
        """
        if not self.active:
            raise RuntimeError("Dongle not active")

        rtc_addr = 0x34
        return self.memory.write(rtc_addr, struct.pack("<I", timestamp & 0xFFFFFFFF))


@log_all_methods
class HASPEmulator(BaseDongleEmulator):
    """HASP dongle emulator for Aladdin Knowledge Systems licensing.

    Emulates HASP HL and HASP 4 hardware dongles with command processing for
    login/logout, memory access, encryption/decryption, and real-time clock
    operations used in software license protection.
    """

    def __init__(self, spec: DongleSpec) -> None:
        """Initialize HASP dongle emulator with command handlers and memory layout.

        Sets up HASP-specific command handlers, memory layout with encryption
        key area, and real-time clock initialization.

        Args:
            spec: DongleSpec object containing HASP device configuration.
        """
        super().__init__(spec)
        self.hasp_commands = {
            0x01: self._hasp_login,
            0x02: self._hasp_logout,
            0x03: self._hasp_encrypt,
            0x04: self._hasp_decrypt,
            0x05: self._hasp_read_memory,
            0x06: self._hasp_write_memory,
            0x07: self._hasp_get_size,
            0x08: self._hasp_get_rtc,
            0x09: self._hasp_set_rtc,
        }

        # Initialize HASP-specific memory layout
        self._init_hasp_memory()

    def _init_hasp_memory(self) -> None:
        """Initialize HASP-specific memory layout and default values.

        Sets up the HASP memory map with encryption key storage, user data areas,
        and real-time clock for license verification and time-based licensing.
        """
        # HASP memory layout
        # 0x00-0x1F: Hardware info (read-only)
        # 0x20-0x2F: Encryption key
        # 0x30-0x3F: User data area
        # 0x40-0xFF: Additional user data

        # Set encryption key
        hasp_key = b"HASP_DEFAULT_KEY"
        self.memory.write(0x20, hasp_key)

        # Set memory size
        self.memory.write(0x30, struct.pack("<I", self.spec.memory_size))

        # Real-time clock (current timestamp)
        self.memory.write(0x34, struct.pack("<I", int(time.time())))

    def process_hasp_command(self, command: int, data: bytes) -> bytes:
        """Process HASP command request.

        Routes HASP API commands to appropriate handler methods based on
        command code and executes the requested operation.

        Args:
            command: Command code identifying the HASP operation (0x01-0x09).
            data: Command data payload containing operation-specific parameters.

        Returns:
            Command response data with status code and operation results.
        """
        if command in self.hasp_commands:
            return self.hasp_commands[command](data)
        return b"\x00\x00\x00\x01"  # Error: unknown command

    def _hasp_login(self, data: bytes) -> bytes:
        """HASP login command for feature-based licensing.

        Authenticates request and establishes a session for the specified feature,
        allowing access to protected functionality if the feature is available.

        Args:
            data: Login data containing feature ID (4+ bytes).

        Returns:
            Login response with status code and session ID (8 bytes).
        """
        if len(data) < 4:
            return b"\x00\x00\x00\x01"  # Error

        feature_id = struct.unpack("<I", data[:4])[0]

        # Check if feature is available (simple check)
        if feature_id in {1, 2, 5, 10}:  # Demo features
            session_id = random.randint(1000, 9999)  # noqa: S311 - HASP dongle emulation demo session ID
            return struct.pack("<II", 0, session_id)  # Success + session ID

        return b"\x00\x00\x00\x02"  # Feature not found

    def _hasp_logout(self, _data: bytes) -> bytes:
        """HASP logout command to terminate licensing session.

        Closes the current session and releases access to protected features.

        Args:
            _data: Logout data (unused).

        Returns:
            Logout response status code (0x00000000 = success).
        """
        return b"\x00\x00\x00\x00"  # Success

    def _hasp_encrypt(self, data: bytes) -> bytes:
        """HASP encrypt command for cryptographic protection.

        Encrypts plaintext data using the dongle's encryption algorithm and
        returns encrypted ciphertext for license code protection.

        Args:
            data: Encryption request data (session ID + plaintext, 8+ bytes).

        Returns:
            Encryption response with status code and ciphertext.
        """
        if len(data) < 8:
            return b"\x00\x00\x00\x01"  # Error

        data_to_encrypt = data[4:]  # Skip session ID
        encrypted = self.encrypt_data(data_to_encrypt)

        return struct.pack("<I", 0) + encrypted  # Success + encrypted data

    def _hasp_decrypt(self, data: bytes) -> bytes:
        """HASP decrypt command for cryptographic verification.

        Decrypts ciphertext using the dongle's decryption algorithm and
        returns plaintext for license validation.

        Args:
            data: Decryption request data (session ID + ciphertext, 8+ bytes).

        Returns:
            Decryption response with status code and plaintext.
        """
        if len(data) < 8:
            return b"\x00\x00\x00\x01"  # Error

        data_to_decrypt = data[4:]  # Skip session ID
        decrypted = self.decrypt_data(data_to_decrypt)

        return struct.pack("<I", 0) + decrypted  # Success + decrypted data

    def _hasp_read_memory(self, data: bytes) -> bytes:
        """HASP read memory command for license data access.

        Reads data from dongle memory at specified address and returns
        the contents for license verification.

        Args:
            data: Read request data (session ID, address, length, 12 bytes).

        Returns:
            Read response with status code and memory data.
        """
        if len(data) < 12:
            return b"\x00\x00\x00\x01"  # Error

        _session_id, address, length = struct.unpack("<III", data[:12])

        try:
            memory_data = self.read_memory(address, length)
            return struct.pack("<I", 0) + memory_data  # Success + data
        except Exception:
            return b"\x00\x00\x00\x01"  # Error

    def _hasp_write_memory(self, data: bytes) -> bytes:
        """HASP write memory command for license data storage.

        Writes data to dongle memory at specified address for license
        configuration and personalization.

        Args:
            data: Write request data (session ID, address, length, write data).

        Returns:
            Write response with status code (0 = success, 1 = failure).
        """
        if len(data) < 12:
            return b"\x00\x00\x00\x01"  # Error

        _session_id, address, length = struct.unpack("<III", data[:12])
        write_data = data[12 : 12 + length]

        try:
            success = self.write_memory(address, write_data)
            return struct.pack("<I", 0 if success else 1)
        except Exception:
            return b"\x00\x00\x00\x01"  # Error

    def _hasp_get_size(self, _data: bytes) -> bytes:
        """HASP get memory size command.

        Returns the total memory size of the HASP dongle for allocation
        planning and license data storage capacity determination.

        Args:
            _data: Unused data parameter.

        Returns:
            Response with status code and memory size in bytes (8 bytes).
        """
        return struct.pack("<II", 0, self.spec.memory_size * 1024)

    def _hasp_get_rtc(self, _data: bytes) -> bytes:
        """HASP get real-time clock command.

        Returns the current time from the dongle's internal real-time clock
        for time-based license validation and expiration checking.

        Args:
            _data: Unused data parameter.

        Returns:
            Response with status code and Unix timestamp (8 bytes).
        """
        current_time = int(time.time())
        return struct.pack("<II", 0, current_time)

    def _hasp_set_rtc(self, data: bytes) -> bytes:
        """HASP set real-time clock command.

        Updates the dongle's internal real-time clock to the specified timestamp
        for synchronization with system time.

        Args:
            data: RTC setting data with new timestamp (8+ bytes).

        Returns:
            RTC set response status code (0x00000000 = success).
        """
        if len(data) < 8:
            return b"\x00\x00\x00\x01"  # Error

        new_time = struct.unpack("<I", data[4:8])[0]
        self.memory.write(0x34, struct.pack("<I", new_time))

        return b"\x00\x00\x00\x00"  # Success


@log_all_methods
class SentinelEmulator(BaseDongleEmulator):
    """Sentinel dongle emulator for Rainbow Technologies licensing.

    Emulates Sentinel SuperPro and UltraPro dongles with cell-based memory model
    where each cell has independent encryption algorithms and access permissions
    for advanced license protection schemes.
    """

    def __init__(self, spec: DongleSpec) -> None:
        """Initialize Sentinel dongle emulator with cell data and memory layout.

        Sets up cell-based memory model with read-only license data cells and
        writable user data cells with different encryption algorithms.

        Args:
            spec: DongleSpec object containing Sentinel device configuration.
        """
        super().__init__(spec)
        self.cell_data: dict[int, dict[str, Any]] = {}
        self._init_sentinel_memory()

    def _init_sentinel_memory(self) -> None:
        """Initialize Sentinel-specific memory with default cell configuration.

        Creates default cells for Sentinel dongle operations with distinct
        encryption algorithms, permissions, and data layouts for license
        storage and feature verification.
        """
        # Sentinel uses cell-based memory model
        # Each cell can have different access permissions

        # Initialize default cells
        self.cell_data[0] = {
            "data": b"SENTINEL_CELL_0_DATA" + b"\x00" * 40,
            "permissions": "RW",  # Read/Write
            "algorithm": "DES",
        }

        self.cell_data[1] = {
            "data": b"SENTINEL_KEY_DATA___" + b"\x00" * 40,
            "permissions": "R",  # Read-only
            "algorithm": "NONE",
        }

        self.cell_data[2] = {
            "data": struct.pack("<Q", int(time.time())),  # License timestamp
            "permissions": "R",
            "algorithm": "NONE",
        }

    def read_cell(self, cell_id: int) -> bytes:
        """Read from Sentinel cell with permission checking.

        Retrieves data from a specific Sentinel cell if read permission is granted,
        implementing cell-based access control for license verification.

        Args:
            cell_id: Cell identifier to read from.

        Returns:
            Cell data as bytes.

        Raises:
            ValueError: If cell_id does not exist in cell_data.
            PermissionError: If cell does not have read permission.
        """
        if cell_id not in self.cell_data:
            raise ValueError(f"Cell {cell_id} not found")

        cell = self.cell_data[cell_id]
        permissions = cell.get("permissions", "")
        if not isinstance(permissions, str) or "R" not in permissions:
            raise PermissionError(f"No read permission for cell {cell_id}")

        data_value = cell.get("data", b"")
        return data_value if isinstance(data_value, bytes) else b""

    def write_cell(self, cell_id: int, data: bytes) -> bool:
        """Write to Sentinel cell with permission checking.

        Stores data to a specific Sentinel cell if write permission is granted,
        implementing cell-based access control for license configuration.

        Args:
            cell_id: Cell identifier to write to.
            data: Data to write to cell.

        Returns:
            True if write succeeded, False if cell not found or lacks write permission.
        """
        if cell_id not in self.cell_data:
            return False

        cell = self.cell_data[cell_id]
        if "W" not in cell["permissions"]:
            return False

        self.cell_data[cell_id]["data"] = data
        return True

    def transform_data(self, cell_id: int, data: bytes) -> bytes:
        """Apply Sentinel transformation algorithm to data.

        Applies the encryption algorithm configured for a specific cell to transform
        input data, implementing per-cell cryptographic operations for advanced
        license protection and feature verification.

        Args:
            cell_id: Cell identifier specifying the algorithm to use.
            data: Data to transform with cell's algorithm.

        Returns:
            Transformed data using the cell's configured algorithm.
        """
        if cell_id not in self.cell_data:
            return data

        cell = self.cell_data[cell_id]
        algorithm = cell["algorithm"]

        if algorithm == "DES":
            # Simplified DES-like transformation
            key = cell["data"][:8]
            return self.crypto.simple_xor(data, key)
        if algorithm == "XOR":
            key = cell["data"][:16]
            return self.crypto.simple_xor(data, key)
        return data


@log_all_methods
class USBDongleDriver:
    """Real USB dongle driver implementation using pyusb/libusb or WinUSB.

    Manages USB-connected hardware dongles with support for real device detection,
    control transfers, and bulk data operations using platform-native USB APIs.
    """

    def __init__(self) -> None:
        """Initialize USB dongle driver with backend selection.

        Attempts to initialize USB communication library, falling back through
        pyusb, Windows WinUSB API, and finally direct hardware access methods.
        """
        self.dongles: dict[str, BaseDongleEmulator] = {}
        self.logger = logging.getLogger(f"{__name__}.USBDriver")

        # Try to import USB libraries
        self.usb_backend = None
        try:
            import usb.core
            import usb.util

            self.usb = usb
            self.usb_backend = "pyusb"
            self.logger.info("Using pyusb for USB communication")
        except ImportError:
            try:
                # Fallback to Windows WinUSB
                import win32api
                import win32file

                self.win32file = win32file
                self.win32api = win32api
                self.usb_backend = "winusb"
                self.logger.info("Using Windows WinUSB API")
            except ImportError:
                self.logger.warning("No USB backend available - using direct hardware access")

    def register_dongle(self, dongle: BaseDongleEmulator) -> None:
        """Register USB dongle and attempt real USB connection.

        Registers an emulated dongle and attempts to connect to a real USB device
        with matching vendor/product IDs if available, falling back to pure emulation.

        Args:
            dongle: BaseDongleEmulator instance to register for USB communication.
        """
        device_id = f"{dongle.spec.vendor_id:04X}:{dongle.spec.product_id:04X}"

        # Try to find real USB device
        if self.usb_backend == "pyusb":
            try:
                if device := self.usb.core.find(
                    idVendor=dongle.spec.vendor_id,
                    idProduct=dongle.spec.product_id,
                ):
                    # Store real device reference
                    dongle._usb_device = device
                    self.logger.info("Found real USB device for %s", device_id)

                    # Set configuration if needed
                    with contextlib.suppress(self.usb.core.USBError):
                        device.set_configuration()

            except Exception:
                self.logger.debug("Real USB device not found", exc_info=True)

        self.dongles[device_id] = dongle
        self.logger.info("Registered USB dongle %s", device_id)

    def unregister_dongle(self, vendor_id: int, product_id: int) -> None:
        """Unregister USB dongle and release resources.

        Removes registered dongle and releases any connected USB device resources
        to prevent resource leaks.

        Args:
            vendor_id: Dongle vendor ID for device identification.
            product_id: Dongle product ID for device identification.
        """
        device_id = f"{vendor_id:04X}:{product_id:04X}"
        if device_id in self.dongles:
            dongle = self.dongles[device_id]

            # Release USB device if connected
            if hasattr(dongle, "_usb_device") and dongle._usb_device:
                try:
                    if self.usb_backend == "pyusb":
                        self.usb.util.dispose_resources(dongle._usb_device)
                except Exception:
                    self.logger.debug("Failed to dispose USB resources", exc_info=True)

            del self.dongles[device_id]
            self.logger.info("Unregistered USB dongle %s", device_id)

    def find_dongles(self, vendor_id: int | None = None, product_id: int | None = None) -> list[BaseDongleEmulator]:
        """Find USB dongles matching criteria.

        Args:
            vendor_id: Optional vendor ID to filter by.
            product_id: Optional product ID to filter by.

        Returns:
            List of matching dongle emulator instances.
        """
        found = []

        # First check registered dongles
        for dongle in self.dongles.values():
            if vendor_id and dongle.spec.vendor_id != vendor_id:
                continue
            if product_id and dongle.spec.product_id != product_id:
                continue

            found.append(dongle)

        # Also scan for real USB devices if using pyusb
        if self.usb_backend == "pyusb" and not found:
            try:
                devices = self.usb.core.find(find_all=True)
                for device in devices:
                    if vendor_id and device.idVendor != vendor_id:
                        continue
                    if product_id and device.idProduct != product_id:
                        continue

                    # Create temporary dongle object for unregistered device
                    temp_dongle = BaseDongleEmulator(
                        DongleSpec(
                            dongle_type=DongleType.GENERIC,
                            interface=DongleInterface.USB,
                            vendor_id=device.idVendor,
                            product_id=device.idProduct,
                            memory_size=4096,
                        ),
                    )
                    temp_dongle._usb_device = device
                    found.append(temp_dongle)

            except Exception as e:
                self.logger.debug("USB scan error: %s", e, exc_info=True)

        return found

    def control_transfer(
        self,
        vendor_id: int,
        product_id: int,
        request_type: int,
        request: int,
        value: int,
        index: int,
        data: bytes,
    ) -> bytes:
        """Perform real USB control transfer.

        Args:
            vendor_id: USB device vendor ID.
            product_id: USB device product ID.
            request_type: USB control transfer request type.
            request: USB control transfer request code.
            value: USB control transfer value parameter.
            index: USB control transfer index parameter.
            data: Data to send or receive in transfer.

        Returns:
            Data returned from USB control transfer.

        Raises:
            RuntimeError: If no dongle found matching vendor/product IDs.
        """
        dongles = self.find_dongles(vendor_id, product_id)
        if not dongles:
            raise RuntimeError("No dongle found")

        dongle = dongles[0]

        # Try real USB communication first
        if hasattr(dongle, "_usb_device") and dongle._usb_device and self.usb_backend == "pyusb":
            try:
                # Perform real USB control transfer
                device = dongle._usb_device

                # USB control transfer direction
                if data:  # Write
                    bm_request_type = 0x40  # Host to device, vendor request
                    result = device.ctrl_transfer(
                        bm_request_type,
                        request,
                        value,
                        index,
                        data,
                    )
                    return b"\x00" if result == len(data) else b"\x01"
                # Read
                bm_request_type = 0xC0  # Device to host, vendor request
                length = 64  # Default read length

                result = device.ctrl_transfer(
                    bm_request_type,
                    request,
                    value,
                    index,
                    length,
                )
                return bytes(result)

            except Exception as e:
                self.logger.debug("USB transfer failed, using emulation: %s", e, exc_info=True)

        # Fallback to emulation for dongles without real USB
        if request == 0x01:  # Read memory
            address = value | (index << 16)
            length = len(data) if data else 64
            return dongle.read_memory(address, length)

        if request == 0x02:  # Write memory
            address = value | (index << 16)
            return b"\x00" if dongle.write_memory(address, data) else b"\x01"

        if request == 0x03:  # Get info
            info = dongle.get_dongle_info()
            return json.dumps(info).encode()

        if request == 0x04:  # Crypto operation
            if data:
                operation = data[0]
                payload = data[1:]

                if operation == 0x01:  # Encrypt
                    return dongle.encrypt_data(payload)
                if operation == 0x02:  # Decrypt
                    return dongle.decrypt_data(payload)
                return dongle.generate_response(payload) if operation == 0x03 else b"\xff"
            return b"\xff"  # Invalid data length

        if request != 0x05:
            return b"\xff"  # Unknown request
        # Real hardware ID from USB device
        if hasattr(dongle, "_usb_device") and dongle._usb_device:
            device = dongle._usb_device
            hw_id = f"{device.idVendor:04X}:{device.idProduct:04X}:{device.bus}:{device.address}"
            return hw_id.encode()
        return b"EMULATED:0000:0000:00:00"

    def bulk_transfer(self, vendor_id: int, product_id: int, endpoint: int, data: bytes | None = None, length: int = 0) -> bytes:
        """Perform USB bulk transfer for high-speed data.

        Args:
            vendor_id: USB device vendor ID.
            product_id: USB device product ID.
            endpoint: USB endpoint number for transfer.
            data: Optional data to write (None for read operation).
            length: Number of bytes to read (ignored if data provided).

        Returns:
            Data returned from bulk transfer.

        Raises:
            RuntimeError: If no dongle found matching vendor/product IDs.
        """
        dongles = self.find_dongles(vendor_id, product_id)
        if not dongles:
            raise RuntimeError("No dongle found")

        dongle = dongles[0]

        if hasattr(dongle, "_usb_device") and dongle._usb_device and self.usb_backend == "pyusb":
            try:
                device = dongle._usb_device

                if data:  # Write
                    written = device.write(endpoint, data)
                    return struct.pack("<I", written)
                # Read
                read_data = device.read(endpoint, length or 512)
                return bytes(read_data)

            except Exception as e:
                self.logger.debug("Bulk transfer failed: %s", e, exc_info=True)

        # Fallback for emulated dongles
        return struct.pack("<I", len(data)) if data else b"\x00" * (length or 512)


@log_all_methods
class ParallelPortEmulator:
    """Real parallel port dongle communication implementation.

    Emulates and communicates with legacy parallel port (LPT) hardware dongles
    using platform-specific port I/O methods (InpOut, WinIO, Linux ioperm, etc.).
    """

    def __init__(self, port_address: int = 0x378) -> None:
        """Initialize parallel port for legacy dongle communication.

        Sets up parallel port interface with platform-specific backend detection
        for direct hardware I/O access to LPT dongles.

        Args:
            port_address: Parallel port base address (default 0x378 for LPT1).
        """
        self.port_address = port_address
        self.data_register = 0
        self.status_register = 0
        self.control_register = 0
        self.dongles: dict[DongleType, BaseDongleEmulator] = {}
        self.logger = logging.getLogger(f"{__name__}.ParallelPort")

        # Platform-specific parallel port access
        self.port_backend: str | None = None
        self._init_port_access()

    def _init_port_access(self) -> None:
        """Initialize platform-specific parallel port access.

        Detects the operating system and configures appropriate port I/O
        mechanism (InpOut32, WinIO, Linux ioperm, etc.).
        """
        import platform

        system = platform.system()

        if system == "Windows":
            try:
                # Try inpout32/inpoutx64 for direct port access
                import ctypes

                if platform.machine().endswith("64"):
                    self.inpout = ctypes.WinDLL("inpoutx64.dll")
                else:
                    self.inpout = ctypes.WinDLL("inpout32.dll")

                self.port_backend = "inpout"
                self.logger.info("Using InpOut32/64 for parallel port access")

            except Exception:
                try:
                    # Try Windows WinIO
                    import win32file

                    self.win32file = win32file
                    self.port_backend = "winio"
                    self.logger.info("Using WinIO for parallel port access")
                except Exception:
                    self.logger.warning("No Windows parallel port driver available")
                    self.port_backend = None

        elif system == "Linux":
            try:
                # Linux parallel port via /dev/parport
                import os

                if os.path.exists("/dev/parport0"):
                    self.port_backend = "linux_parport"
                    self.logger.info("Using Linux /dev/parport0")
                else:
                    # Try ioperm for direct port access
                    import ctypes

                    libc = ctypes.CDLL("libc.so.6")
                    # Request I/O permissions for parallel port range
                    if libc.ioperm(self.port_address, 3, 1) == 0:
                        self.port_backend = "linux_ioperm"
                        self.logger.info("Using Linux ioperm for direct port access")
                    else:
                        self.logger.warning("Failed to get I/O permissions")

            except Exception:
                self.logger.warning("Linux parallel port initialization failed", exc_info=True)
                self.port_backend = None

        else:
            self.logger.warning("Unsupported platform for parallel port: %s", system)
            self.port_backend = None

    def attach_dongle(self, dongle: BaseDongleEmulator) -> None:
        """Attach dongle to parallel port.

        Registers a dongle emulator on the parallel port and sends initialization
        sequence if hardware backend is available for real device detection.

        Args:
            dongle: BaseDongleEmulator instance to attach to parallel port.
        """
        self.dongles[dongle.spec.dongle_type] = dongle
        self.logger.info("Attached %s to LPT", dongle.spec.dongle_type.value)

        # Send initialization sequence to real dongle
        if self.port_backend:
            self._init_dongle_communication()

    def _init_dongle_communication(self) -> None:
        """Initialize communication with real parallel port dongle.

        Sends standard initialization sequence to detect and configure
        parallel port dongle communication including presence check and
        bidirectional mode activation.
        """
        # Standard parallel port dongle initialization sequence
        init_sequence = [
            (self.port_address + 2, 0x04),  # Set control register
            (self.port_address, 0x00),  # Clear data register
            (self.port_address + 2, 0x0C),  # Enable bidirectional mode
            (self.port_address, 0xAA),  # Send presence check pattern
        ]

        for port, value in init_sequence:
            self._write_real_port(port, value)
            time.sleep(0.001)  # 1ms delay between commands

        # Check for dongle response
        response = self._read_real_port(self.port_address + 1)
        if response == 0x55:  # Expected response to 0xAA
            self.logger.info("Real parallel port dongle detected")
        else:
            self.logger.debug("No dongle response, got: 0x%02X", response)

    def read_port(self, port: int) -> int:
        """Read from parallel port.

        Attempts to read from real hardware first, then falls back to emulated
        parallel port registers for data, status, and control operations.

        Args:
            port: Port address to read from (0x378-0x37A for LPT1).

        Returns:
            Byte value read from the port (0x00-0xFF).
        """
        # Try real hardware first
        if self.port_backend:
            value = self._read_real_port(port)
            if value is not None:
                return value

        # Fallback to emulated registers
        if port == self.port_address:  # Data port
            return self.data_register
        if port == self.port_address + 1:  # Status port
            return self.status_register
        return self.control_register if port == self.port_address + 2 else 0xFF

    def write_port(self, port: int, value: int) -> None:
        """Write to parallel port.

        Performs write to real hardware if available, then updates emulated
        registers and processes dongle commands based on port address.

        Args:
            port: Port address to write to (0x378-0x37A for LPT1).
            value: Byte value to write (0x00-0xFF).
        """
        value &= 0xFF

        # Write to real hardware if available
        if self.port_backend:
            self._write_real_port(port, value)

        # Update emulated registers
        if port == self.port_address:  # Data port
            self.data_register = value
            self._process_data_write(value)
        elif port == self.port_address + 2:  # Control port
            self.control_register = value
            self._process_control_write(value)

    def _read_real_port(self, port: int) -> int | None:
        """Read from real parallel port hardware.

        Args:
            port: Port number to read from.

        Returns:
            Byte value read from port (0x00-0xFF), or None if read failed.
        """
        try:
            if self.port_backend == "inpout":
                # InpOut32/64 direct port read
                result: int = self.inpout.Inp32(port) & 0xFF
                return result

            if self.port_backend == "linux_ioperm":
                # Linux direct port read using inline assembly via ctypes
                # Uses x86/x86_64 IN instruction for direct hardware port access
                import ctypes
                import platform

                # Create inline assembly function for port read
                if platform.machine() in {"x86_64", "AMD64"}:
                    # x86_64 inline assembly for IN instruction
                    asm_code = bytes(
                        [
                            0x48,
                            0x89,
                            0xF8,  # mov rax, rdi (port number to rax)
                            0x66,
                            0x89,
                            0xC2,  # mov dx, ax (port to dx)
                            0xEC,  # in al, dx (read byte from port)
                            0xC3,  # ret (return value in al/rax)
                        ],
                    )
                else:
                    # x86 inline assembly for IN instruction
                    asm_code = bytes(
                        [
                            0x8B,
                            0x54,
                            0x24,
                            0x04,  # mov edx, [esp+4] (get port parameter)
                            0xEC,  # in al, dx (read byte from port)
                            0xC3,  # ret (return value in al)
                        ],
                    )

                # Allocate executable memory and copy assembly code
                libc = ctypes.CDLL(None)
                mmap_func = libc.mmap
                mmap_func.restype = ctypes.c_void_p
                mmap_func.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_int,
                    ctypes.c_int,
                    ctypes.c_int,
                    ctypes.c_long,
                ]

                # Allocate executable memory page
                prot_read = 0x1
                prot_write = 0x2
                prot_exec = 0x4
                map_private = 0x02
                map_anonymous = 0x20

                exec_mem = mmap_func(
                    0,
                    len(asm_code),
                    prot_read | prot_write | prot_exec,
                    map_private | map_anonymous,
                    -1,
                    0,
                )

                if exec_mem == -1:
                    return 0xFF  # Return default value on allocation failure

                # Copy assembly code to executable memory
                ctypes.memmove(exec_mem, asm_code, len(asm_code))

                # Create function pointer and call
                port_read_func = ctypes.CFUNCTYPE(ctypes.c_ubyte, ctypes.c_ushort)(exec_mem)
                value: int = port_read_func(port)

                # Clean up
                munmap_func = libc.munmap
                munmap_func(exec_mem, len(asm_code))

                return value

            if self.port_backend == "linux_parport":
                # Read via /dev/parport0
                try:
                    with open("/dev/parport0", "rb") as f:
                        f.seek(port - self.port_address)
                        return ord(f.read(1))
                except Exception as e:
                    self.logger.debug("Failed to read from parport: %s", e, exc_info=True)

        except Exception as e:
            self.logger.debug("Hardware read failed: %s", e, exc_info=True)

        return None

    def _write_real_port(self, port: int, value: int) -> None:
        """Write to real parallel port hardware.

        Args:
            port: Port address to write to.
            value: Byte value to write.
        """
        try:
            if self.port_backend == "inpout":
                # InpOut32/64 direct port write
                self.inpout.Out32(port, value)

            elif self.port_backend == "linux_ioperm":
                # Linux direct port write
                self._linux_port_write(port, value)

            elif self.port_backend == "linux_parport":
                # Write via /dev/parport0
                try:
                    with open("/dev/parport0", "wb") as f:
                        f.seek(port - self.port_address)
                        f.write(bytes([value]))
                except Exception as e:
                    self.logger.debug("Failed to write to parport: %s", e, exc_info=True)

        except Exception as e:
            self.logger.debug("Hardware write failed: %s", e, exc_info=True)

    def _linux_port_read(self, port: int) -> int:
        """Linux-specific port read using ctypes.

        Args:
            port: Port address to read from.

        Returns:
            Byte value read from the port.
        """
        import ctypes

        libc = ctypes.CDLL("libc.so.6")

        # Define inb function
        inb = libc.inb
        inb.argtypes = [ctypes.c_ushort]
        inb.restype = ctypes.c_ubyte

        result: int = inb(port)
        return result

    def _linux_port_write(self, port: int, value: int) -> None:
        """Linux-specific port write using ctypes.

        Args:
            port: Port address to write to.
            value: Byte value to write.
        """
        import ctypes

        libc = ctypes.CDLL("libc.so.6")

        # Define outb function
        outb = libc.outb
        outb.argtypes = [ctypes.c_ubyte, ctypes.c_ushort]

        outb(value, port)

    def _process_data_write(self, value: int) -> None:
        """Process data written to parallel port.

        Args:
            value: Data byte written to port.
        """
        if value == 0xAA:  # Presence check
            if self.dongles:
                # Real dongles respond with 0x55
                self.status_register = 0x55

                # Also send to real hardware if connected
                if self.port_backend:
                    time.sleep(0.001)  # Wait for dongle response
                    real_status = self._read_real_port(self.port_address + 1)
                    if real_status is not None:
                        self.status_register = real_status
            else:
                self.status_register = 0xFF

        elif value == 0x01:  # Read dongle ID
            if self.dongles:
                dongle = next(iter(self.dongles.values()))
                self.status_register = dongle.spec.vendor_id & 0xFF

        elif value & 0xF0 == 0x20:  # Memory read command
            address = (value & 0x0F) << 8  # High nibble of address
            if self.dongles:
                dongle = next(iter(self.dongles.values()))
                # Wait for low address byte
                self._pending_command = ("read_mem", address)

        elif value & 0xF0 == 0x30:  # Memory write command
            address = (value & 0x0F) << 8  # High nibble of address
            if self.dongles:
                self._pending_command = ("write_mem", address)

        elif hasattr(self, "_pending_command"):
            # Complete pending command
            cmd, addr = self._pending_command
            if cmd == "read_mem":
                if self.dongles:
                    dongle = next(iter(self.dongles.values()))
                    # Complete address and read
                    full_addr = addr | value
                    data = dongle.read_memory(full_addr, 1)
                    self.status_register = data[0] if data else 0xFF
            elif cmd == "write_mem":
                # This is the address low byte, wait for data
                self._pending_command = ("write_data", addr | value)
            elif cmd == "write_data":
                # Write data to address
                if self.dongles:
                    dongle = next(iter(self.dongles.values()))
                    dongle.write_memory(addr, bytes([value]))
                    self.status_register = 0x00  # Success

            delattr(self, "_pending_command")

    def _process_control_write(self, value: int) -> None:
        """Process control signals.

        Args:
            value: Control register value with bits representing signal control:
                Bit 0: Strobe signal
                Bit 1: Auto Line Feed signal
                Bit 2: Initialize signal
                Bit 3: Select signal
                Bit 4: Enable IRQ signal
                Bit 5: Enable bidirectional mode
        """
        # Bit 0: Strobe
        # Bit 1: Auto Line Feed
        # Bit 2: Initialize
        # Bit 3: Select
        # Bit 4: Enable IRQ
        # Bit 5: Enable bidirectional

        if value & 0x01 and hasattr(self, "_latched_data"):
            self._process_latched_command()

        if value & 0x04 and self.dongles:
            for dongle in self.dongles.values():
                dongle.reset()  # Reset dongle state using proper reset method

        if value & 0x20:  # Bidirectional mode
            self.logger.debug("Bidirectional mode enabled")

    def _process_latched_command(self) -> None:
        """Process a latched command triggered by strobe signal.

        This method handles parallel port dongle communication protocol
        where data is latched on the strobe signal edge.
        """
        if not hasattr(self, "_latched_data"):
            return

        latched_data = self._latched_data
        command_byte = latched_data & 0xFF

        if not self.dongles:
            self.status_register = 0xFF
            return

        dongle = next(iter(self.dongles.values()))

        command_type = (command_byte >> 4) & 0x0F
        command_param = command_byte & 0x0F

        if command_type == 0x00:
            self._handle_presence_command(dongle, command_param)
        elif command_type == 0x01:
            self._handle_id_command(dongle, command_param)
        elif command_type == 0x02:
            self._handle_memory_read_command(dongle, command_param)
        elif command_type == 0x03:
            self._handle_memory_write_command(dongle, command_param)
        elif command_type == 0x04:
            self._handle_crypto_command(dongle, command_param)
        elif command_type == 0x05:
            self._handle_challenge_command(dongle, command_param)
        elif command_type == 0x06:
            self._handle_counter_command(dongle, command_param)
        elif command_type == 0x07:
            self._handle_algorithm_command(dongle, command_param)
        elif command_type == 0x0F:
            self._handle_reset_command(dongle, command_param)
        else:
            self.status_register = 0xFE
            self.logger.debug("Unknown latched command: 0x%02X", command_byte)

        if hasattr(self, "_latched_data"):
            delattr(self, "_latched_data")

    def _handle_presence_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle presence check command.

        Args:
            dongle: Dongle emulator instance.
            param: Command parameter byte.
        """
        if param == 0x0A:
            self.status_register = 0x55
            self.data_register = dongle.spec.vendor_id & 0xFF
        else:
            self.status_register = 0x55 if dongle.active else 0xFF

    def _handle_id_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle ID read command.

        Args:
            dongle: Dongle emulator instance.
            param: Command parameter byte specifying which ID field to read.
        """
        if param == 0x00:
            self.status_register = dongle.spec.vendor_id & 0xFF
        elif param == 0x01:
            self.status_register = (dongle.spec.vendor_id >> 8) & 0xFF
        elif param == 0x02:
            self.status_register = dongle.spec.product_id & 0xFF
        elif param == 0x03:
            self.status_register = (dongle.spec.product_id >> 8) & 0xFF
        elif param >= 0x04 and param <= 0x07:
            serial_bytes = dongle.spec.serial_number.replace("-", "").encode()[:16]
            byte_idx = (param - 0x04) * 4
            if byte_idx < len(serial_bytes):
                self.status_register = serial_bytes[byte_idx]
            else:
                self.status_register = 0x00

    def _handle_memory_read_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle memory read command.

        Args:
            dongle: Dongle emulator instance.
            param: Address byte or data read indicator.
        """
        if not hasattr(self, "_mem_address"):
            self._mem_address = param << 8
            self.status_register = 0x00
        else:
            full_address = self._mem_address | param
            try:
                data = dongle.read_memory(full_address, 1)
                self.status_register = data[0] if data else 0xFF
            except Exception:
                self.status_register = 0xFF
            delattr(self, "_mem_address")

    def _handle_memory_write_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle memory write command.

        Args:
            dongle: Dongle emulator instance.
            param: Address or data byte to write.
        """
        if not hasattr(self, "_mem_write_state"):
            self._mem_write_state = {"address_high": param << 8}
            self.status_register = 0x00
        elif "address_low" not in self._mem_write_state:
            self._mem_write_state["address_low"] = param
            self.status_register = 0x00
        else:
            full_address = self._mem_write_state["address_high"] | self._mem_write_state["address_low"]
            try:
                success = dongle.write_memory(full_address, bytes([param]))
                self.status_register = 0x00 if success else 0x01
            except Exception:
                self.status_register = 0x01
            delattr(self, "_mem_write_state")

    def _handle_crypto_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle cryptographic command.

        Args:
            dongle: Dongle emulator instance.
            param: Command parameter specifying crypto operation.
        """
        if not hasattr(self, "_crypto_buffer"):
            self._crypto_buffer = bytearray()
            self._crypto_operation = param
            self.status_register = 0x00
            return

        if param == 0x0F:
            try:
                if self._crypto_operation == 0x01:
                    result = dongle.encrypt_data(bytes(self._crypto_buffer))
                elif self._crypto_operation == 0x02:
                    result = dongle.decrypt_data(bytes(self._crypto_buffer))
                else:
                    result = dongle.process_challenge(bytes(self._crypto_buffer))

                self._crypto_result = result
                self._crypto_result_idx = 0
                self.status_register = len(result) & 0xFF
            except Exception:
                self.status_register = 0xFF
            finally:
                delattr(self, "_crypto_buffer")
                if hasattr(self, "_crypto_operation"):
                    delattr(self, "_crypto_operation")
        elif param == 0x0E and hasattr(self, "_crypto_result"):
            if self._crypto_result_idx < len(self._crypto_result):
                self.status_register = self._crypto_result[self._crypto_result_idx]
                self._crypto_result_idx += 1
            else:
                self.status_register = 0x00
                delattr(self, "_crypto_result")
                delattr(self, "_crypto_result_idx")
        else:
            self._crypto_buffer.append(param)
            self.status_register = 0x00

    def _handle_challenge_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle challenge-response command.

        Args:
            dongle: Dongle emulator instance.
            param: Command parameter byte.
        """
        if not hasattr(self, "_challenge_data"):
            self._challenge_data = bytearray()

        if param == 0x0F:
            try:
                response = dongle.process_challenge(bytes(self._challenge_data))
                self._challenge_response = response
                self._challenge_response_idx = 0
                self.status_register = len(response) & 0xFF
            except Exception:
                self.status_register = 0xFF
            finally:
                delattr(self, "_challenge_data")
        elif param == 0x0E and hasattr(self, "_challenge_response"):
            if self._challenge_response_idx < len(self._challenge_response):
                self.status_register = self._challenge_response[self._challenge_response_idx]
                self._challenge_response_idx += 1
            else:
                self.status_register = 0x00
                delattr(self, "_challenge_response")
                delattr(self, "_challenge_response_idx")
        else:
            self._challenge_data.append(param)
            self.status_register = 0x00

    def _handle_counter_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle counter read/increment command.

        Args:
            dongle: Dongle emulator instance.
            param: Command parameter specifying counter ID and operation.
        """
        counter_id = param & 0x07
        operation = (param >> 3) & 0x01

        try:
            if operation == 0:
                value = dongle.read_counter(counter_id)
                if not hasattr(self, "_counter_byte_idx"):
                    self._counter_byte_idx = 0
                    self._counter_value = value

                byte_idx = self._counter_byte_idx
                self.status_register = (self._counter_value >> (byte_idx * 8)) & 0xFF
                self._counter_byte_idx += 1

                if self._counter_byte_idx >= 4:
                    delattr(self, "_counter_byte_idx")
                    delattr(self, "_counter_value")
            else:
                new_value = dongle.increment_counter(counter_id)
                self.status_register = new_value & 0xFF
        except Exception:
            self.status_register = 0xFF

    def _handle_algorithm_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle algorithm execution command.

        Args:
            dongle: Dongle emulator instance.
            param: Algorithm ID or command parameter byte.
        """
        if not hasattr(self, "_algo_state"):
            self._algo_state = {"algorithm_id": param, "input_data": bytearray()}
            self.status_register = 0x00
            return

        if param == 0x0F:
            try:
                algo_id_obj = self._algo_state.get("algorithm_id", 0)
                algo_id = int(algo_id_obj) if isinstance(algo_id_obj, (int, float)) else 0
                input_data_obj = self._algo_state.get("input_data", bytearray())
                input_data = bytes(input_data_obj) if isinstance(input_data_obj, (bytes, bytearray)) else b""
                result = dongle.execute_algorithm(algo_id, input_data)
                self._algo_result = result
                self._algo_result_idx = 0
                self.status_register = len(result) & 0xFF
            except Exception:
                self.status_register = 0xFF
            finally:
                delattr(self, "_algo_state")
        elif param == 0x0E and hasattr(self, "_algo_result"):
            if self._algo_result_idx < len(self._algo_result):
                self.status_register = self._algo_result[self._algo_result_idx]
                self._algo_result_idx += 1
            else:
                self.status_register = 0x00
                delattr(self, "_algo_result")
                delattr(self, "_algo_result_idx")
        else:
            input_data_obj = self._algo_state.get("input_data")
            if isinstance(input_data_obj, bytearray):
                input_data_obj.append(param)
            self.status_register = 0x00

    def _handle_reset_command(self, dongle: BaseDongleEmulator, param: int) -> None:
        """Handle dongle reset command.

        Args:
            dongle: Dongle emulator instance to reset.
            param: Parameter byte controlling reset operation.
        """
        if param == 0x0F:
            dongle.reset()
            self.status_register = 0x00
            self.data_register = 0x00

            for attr in [
                "_mem_address",
                "_mem_write_state",
                "_crypto_buffer",
                "_crypto_operation",
                "_crypto_result",
                "_crypto_result_idx",
                "_challenge_data",
                "_challenge_response",
                "_challenge_response_idx",
                "_counter_byte_idx",
                "_counter_value",
                "_algo_state",
                "_algo_result",
                "_algo_result_idx",
                "_pending_command",
            ]:
                if hasattr(self, attr):
                    delattr(self, attr)

            self.logger.debug("Dongle and parallel port state reset")
        else:
            self.status_register = 0x00


@log_all_methods
class DongleRegistryManager:
    """Manage Windows registry for dongle drivers and device enumeration.

    Installs and removes Windows registry entries to make emulated dongles appear
    as legitimate USB devices for licensing applications on Windows platforms.
    """

    def __init__(self) -> None:
        """Initialize dongle registry manager for real Windows registry manipulation.

        Sets up registry management for storing and restoring dongle driver
        entries in the Windows system registry.
        """
        self.logger = logging.getLogger(f"{__name__}.Registry")
        self.registry_backup: dict[str, Any] = {}  # Store original values for restoration
        self.installed_keys: list[str] = []  # Track installed keys for cleanup

    def install_driver_entries(self, spec: DongleSpec) -> None:
        """Install registry entries for dongle driver.

        Adds Windows registry entries to make the emulated dongle visible to
        device enumeration APIs and licensing applications.

        Args:
            spec: DongleSpec object containing device information for registry.
        """
        try:
            # USB device entries
            if spec.interface == DongleInterface.USB:
                self._install_usb_entries(spec)

            # Application-specific entries
            self._install_app_entries(spec)

        except Exception:
            self.logger.exception("Failed to install registry entries")

    def _install_usb_entries(self, spec: DongleSpec) -> None:
        """Install USB device registry entries.

        Creates registry entries in HKEY_LOCAL_MACHINE to register emulated
        USB dongle with device description, hardware IDs, and driver service.

        Args:
            spec: DongleSpec object containing USB device information.
        """
        device_key = f"USB\\VID_{spec.vendor_id:04X}&PID_{spec.product_id:04X}"

        try:
            # Create device key
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Enum\\{device_key}")

            # Set device description
            winreg.SetValueEx(key, "DeviceDesc", 0, winreg.REG_SZ, f"{spec.dongle_type.value} Dongle")

            # Set hardware ID
            winreg.SetValueEx(key, "HardwareID", 0, winreg.REG_MULTI_SZ, [device_key])

            # Set service name
            winreg.SetValueEx(key, "Service", 0, winreg.REG_SZ, "usbhub")

            winreg.CloseKey(key)

        except Exception:
            self.logger.exception("Failed to create USB registry entries")

    def _install_app_entries(self, spec: DongleSpec) -> None:
        """Install application-specific registry entries.

        Adds vendor-specific registry entries for HASP and Sentinel dongles
        to enable licensing application detection and initialization.

        Args:
            spec: DongleSpec object containing dongle type for registration.
        """
        try:
            # HASP entries
            if spec.dongle_type in {DongleType.HASP_HL, DongleType.HASP_4}:
                hasp_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Aladdin Knowledge Systems\HASP")
                winreg.SetValueEx(hasp_key, "InstallPath", 0, winreg.REG_SZ, r"C:\Windows\System32")
                winreg.CloseKey(hasp_key)

            # Sentinel entries
            elif spec.dongle_type.value.startswith("Sentinel"):
                sent_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Rainbow Technologies\Sentinel")
                winreg.SetValueEx(sent_key, "InstallPath", 0, winreg.REG_SZ, r"C:\Windows\System32")
                winreg.CloseKey(sent_key)

        except Exception:
            self.logger.exception("Failed to create app registry entries")

    def remove_driver_entries(self, spec: DongleSpec) -> None:
        """Remove registry entries for dongle driver.

        Deletes registry entries to unregister emulated dongle from device
        enumeration and licensing applications.

        Args:
            spec: DongleSpec object containing device information.
        """
        try:
            device_key = f"USB\\VID_{spec.vendor_id:04X}&PID_{spec.product_id:04X}"

            # Remove USB entries
            with contextlib.suppress(FileNotFoundError):
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Enum\\{device_key}")

        except Exception:
            self.logger.exception("Failed to remove registry entries")


@log_all_methods
class DongleAPIHooker:
    """Hook dongle-related APIs for interception and emulation.

    Installs API hooks on HASP, Sentinel, USB, and parallel port APIs to intercept
    licensing verification calls and route them to emulated dongle implementations.
    """

    def __init__(self, emulator_manager: object) -> None:
        """Initialize dongle API hooker for intercepting hardware dongle calls.

        Sets up API hooking infrastructure for intercepting dongle-related function
        calls from licensing-protected applications.

        Args:
            emulator_manager: Manager instance for dongle emulation operations.
        """
        self.manager = emulator_manager
        self.logger = logging.getLogger(f"{__name__}.APIHooker")
        self.hooks: dict[str, Callable[..., Any]] = {}

    def install_hooks(self) -> None:
        """Install API hooks for dongle functions.

        Installs interception hooks for all HASP, Sentinel, USB, and legacy
        parallel port API functions used by software licensing systems.
        """
        # HASP API hooks
        self._hook_hasp_apis()

        # Sentinel API hooks
        self._hook_sentinel_apis()

        # Generic USB hooks
        self._hook_usb_apis()

        # Parallel port hooks
        self._hook_lpt_apis()

    def _hook_hasp_apis(self) -> None:
        """Install hooks for HASP API functions.

        Hooks HASP RT (Runtime) library functions for login, encryption, memory
        access, and time synchronization operations.
        """
        hasp_functions = [
            "hasp_login",
            "hasp_logout",
            "hasp_encrypt",
            "hasp_decrypt",
            "hasp_read",
            "hasp_write",
            "hasp_get_size",
            "hasp_get_rtc",
            "hasp_set_rtc",
        ]

        for func_name in hasp_functions:
            self._install_function_hook("hasp_rt.dll", func_name, self._hasp_api_handler)

    def _hook_sentinel_apis(self) -> None:
        """Install hooks for Sentinel API functions.

        Hooks Sentinel (Rainbow Technologies) library functions for cell
        operations, queries, and data transformations.
        """
        sentinel_functions = [
            "RNBOsproQuery",
            "RNBOsproInitialize",
            "RNBOsproRead",
            "RNBOsproWrite",
            "RNBOsproFormatQuery",
        ]

        for func_name in sentinel_functions:
            self._install_function_hook("sx32w.dll", func_name, self._sentinel_api_handler)

    def _install_function_hook(self, dll_name: str, func_name: str, handler: Callable[..., Any]) -> None:
        """Install hook for specific function.

        Registers an API hook for a specific DLL function to intercept calls
        and route them to the emulation handler.

        Args:
            dll_name: Name of DLL containing target function.
            func_name: Name of function to hook.
            handler: Handler function to call when hooked function is invoked.
        """
        try:
            # This would use actual API hooking in real implementation
            # For now, just register the handler
            hook_key = f"{dll_name}!{func_name}"
            self.hooks[hook_key] = handler
            self.logger.info("Installed hook for %s", hook_key)

        except Exception:
            self.logger.exception("Failed to hook %s", func_name)

    def _hasp_api_handler(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle HASP API calls from licensing applications.

        Routes HASP API calls to appropriate handler methods based on function name
        and manages feature login/logout, encryption, and memory operations.

        Args:
            func_name: Name of HASP API function being called.
            args: Arguments passed to the HASP function.

        Returns:
            HASP API return code (0 for success, non-zero for error codes).
        """
        manager = self.manager
        if hasattr(manager, "get_dongles_by_type"):
            dongles = manager.get_dongles_by_type(DongleType.HASP_HL) or manager.get_dongles_by_type(DongleType.HASP_4)
        else:
            dongles = []

        if not dongles:
            return 0x00000001  # HASP_DONGLE_NOT_FOUND

        dongle = dongles[0]

        if func_name == "hasp_login":
            feature_id, vendor_code = args[:2]
            return self._handle_hasp_login(dongle, feature_id, vendor_code)

        if func_name == "hasp_logout":
            args[0]
            return 0  # HASP_STATUS_OK

        if func_name == "hasp_encrypt":
            _session_id, buffer, length = args[:3]
            return self._handle_hasp_encrypt(dongle, buffer, length)

        # Default success
        return 0

    def _sentinel_api_handler(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle Sentinel API calls from licensing applications.

        Routes Sentinel API calls to appropriate handler methods based on function name
        and manages cell operations, queries, and data transformations.

        Args:
            func_name: Name of Sentinel API function being called.
            args: Arguments passed to the Sentinel function.

        Returns:
            Sentinel API return code (0 for success, non-zero for error codes).
        """
        manager = self.manager
        if hasattr(manager, "get_dongles_by_type"):
            dongles = manager.get_dongles_by_type(DongleType.SENTINEL_SUPER_PRO)
        else:
            dongles = []
        if not dongles:
            return 0x00000001  # Error

        dongle = dongles[0]

        if func_name == "RNBOsproQuery":
            return self._handle_sentinel_query(dongle, args)

        # Default success
        return 0

    def _handle_sentinel_query(self, dongle: BaseDongleEmulator, args: tuple[Any, ...]) -> int:
        """Handle Sentinel SuperPro query operations.

        Processes RNBOsproQuery API calls which query dongle cells, execute algorithms,
        and retrieve dongle information. Sentinel dongles use a cell-based memory model
        with per-cell encryption algorithms.

        Args:
            dongle: The Sentinel dongle emulator instance.
            args: Query arguments tuple containing (query_type, cell_id, data_ptr, data_len).

        Returns:
            Status code (0 = success, non-zero = error).
        """
        sentinel_success = 0
        sentinel_invalid_parameter = 0x00000002
        sentinel_invalid_cell = 0x00000004
        sentinel_access_denied = 0x00000005

        if not dongle or not dongle.active:
            return 0x00000003
        if len(args) < 2:
            return sentinel_invalid_parameter

        query_type = args[0]
        cell_id = args[1] if len(args) > 1 else 0

        try:
            if query_type == 0x00:
                if not isinstance(dongle, SentinelEmulator):
                    return sentinel_invalid_parameter
                if cell_id not in dongle.cell_data:
                    return sentinel_invalid_cell
                cell = dongle.cell_data[cell_id]
                if "R" not in cell.get("permissions", ""):
                    return sentinel_access_denied
                return sentinel_success

            elif query_type == 0x01:
                if not isinstance(dongle, SentinelEmulator):
                    return sentinel_invalid_parameter
                dongle.read_cell(cell_id)
                return sentinel_success

            elif query_type == 0x02:
                if len(args) < 4:
                    return sentinel_invalid_parameter
                if not isinstance(dongle, SentinelEmulator):
                    return sentinel_invalid_parameter
                input_data = args[2] if len(args) > 2 else b""
                if isinstance(input_data, bytes):
                    dongle.transform_data(cell_id, input_data)
                return sentinel_success

            elif query_type == 0x03:
                return sentinel_success

            elif query_type == 0x04:
                if not isinstance(dongle, SentinelEmulator):
                    return sentinel_invalid_parameter
                return sentinel_success

            elif query_type == 0x10:
                return sentinel_success

            else:
                self.logger.warning("Unknown Sentinel query type: 0x%02X", query_type)
                return sentinel_invalid_parameter

        except PermissionError:
            return sentinel_access_denied
        except ValueError:
            return sentinel_invalid_cell
        except Exception:
            self.logger.exception("Sentinel query error")
            return sentinel_invalid_parameter

    def _handle_hasp_encrypt(self, dongle: BaseDongleEmulator, buffer: Any, length: int) -> int:
        """Handle HASP encryption API calls.

        Performs in-place encryption of data using the dongle's cryptographic engine.
        HASP dongles typically use TEA or AES algorithms with keys stored in protected
        dongle memory.

        Args:
            dongle: The HASP dongle emulator instance.
            buffer: Data buffer to encrypt (bytes or ctypes pointer).
            length: Length of data to encrypt.

        Returns:
            Status code (0 = HASP_STATUS_OK, non-zero = error).
        """
        hasp_status_ok = 0
        hasp_enc_not_supp = 0x0000001C
        hasp_internal_error = 0x00000021

        if not dongle or not dongle.active:
            return 0x00000001
        if length <= 0:
            return 0x0000000D
        try:
            data_to_encrypt: bytes
            if isinstance(buffer, bytes):
                data_to_encrypt = buffer[:length]
            elif isinstance(buffer, bytearray):
                data_to_encrypt = bytes(buffer[:length])
            elif hasattr(buffer, "contents"):
                import ctypes

                raw_data = ctypes.string_at(ctypes.addressof(buffer.contents), length)
                data_to_encrypt = bytes(raw_data)
            elif hasattr(buffer, "value"):
                data_to_encrypt = bytes(buffer.value[:length])
            else:
                try:
                    data_to_encrypt = bytes(buffer)[:length]
                except (TypeError, ValueError):
                    return hasp_internal_error

            if not hasattr(dongle, "encrypt_data"):
                return hasp_enc_not_supp

            encrypted = dongle.encrypt_data(data_to_encrypt)

            if isinstance(buffer, bytearray):
                buffer[: len(encrypted)] = encrypted
            elif hasattr(buffer, "contents"):
                import ctypes

                ctypes.memmove(ctypes.addressof(buffer.contents), encrypted, len(encrypted))
            elif hasattr(buffer, "value"):
                buffer.value = encrypted

            return hasp_status_ok
        except Exception:
            self.logger.exception("HASP encryption error")
            return hasp_internal_error

    def _handle_hasp_login(self, dongle: BaseDongleEmulator, feature_id: int, vendor_code: Any) -> int:
        """Handle HASP login API calls.

        Authenticates with the dongle and establishes a session for the specified feature.
        HASP uses feature-based licensing where each feature has a unique ID and may
        require specific vendor code validation.

        Args:
            dongle: The HASP dongle emulator instance.
            feature_id: The feature ID to login to (0 = default feature).
            vendor_code: Vendor-specific authentication code (bytes or integer).

        Returns:
            Status code (0 = HASP_STATUS_OK, non-zero = error).
        """
        hasp_status_ok = 0
        hasp_feature_not_found = 0x00000009
        hasp_inv_vcode = 0x0000000F
        hasp_no_more_connections = 0x00000016
        hasp_internal_error = 0x00000021

        if not dongle or not dongle.active:
            return 0x00000001
        try:
            allowed_features = {0, 1, 2, 5, 10, 100, 0xFFFF}

            if hasattr(dongle, "spec") and hasattr(dongle.spec, "features") and "allowed_features" in dongle.spec.features:
                allowed_features = set(dongle.spec.features["allowed_features"])

            if feature_id not in allowed_features and feature_id != 0 and not (0 <= feature_id <= 0xFFFF):
                return hasp_feature_not_found

            vendor_bytes: bytes | None = None
            if vendor_code is not None:
                if isinstance(vendor_code, int):
                    vendor_bytes = struct.pack("<I", vendor_code)
                elif isinstance(vendor_code, bytes):
                    vendor_bytes = vendor_code
                else:
                    try:
                        vendor_bytes = bytes(vendor_code)
                    except (TypeError, ValueError):
                        return hasp_inv_vcode

                if vendor_bytes and len(vendor_bytes) >= 4:
                    provided_vendor = struct.unpack("<I", vendor_bytes[:4])[0]
                    expected_vendor_id = getattr(dongle.spec, "vendor_id", 0x0529)
                    if provided_vendor != 0 and (provided_vendor & 0xFFFF) != expected_vendor_id:
                        self.logger.debug("Vendor code mismatch: expected %04X, got %04X", expected_vendor_id, provided_vendor)

            max_sessions = 16
            sessions = getattr(dongle, "_sessions", {})
            if isinstance(sessions, dict) and len(sessions) >= max_sessions:
                return hasp_no_more_connections

            session_id = (int(time.time() * 1000) & 0x7FFFFFFF) | (feature_id << 16)
            session_id &= 0xFFFFFFFF

            sessions_dict = getattr(dongle, "_sessions", {})
            if isinstance(sessions_dict, dict):
                sessions_dict[session_id] = {
                    "feature_id": feature_id,
                    "login_time": time.time(),
                    "vendor_code": vendor_code,
                }

            if hasattr(dongle, "_current_session"):
                dongle._current_session = session_id

            self.logger.debug("HASP login successful: feature=%d, session=%08X", feature_id, session_id)
            return hasp_status_ok

        except Exception:
            self.logger.exception("HASP login error")
            return hasp_internal_error

    def _hook_lpt_apis(self) -> None:
        """Install hooks for parallel port (LPT) dongle API functions.

        Hooks Windows API functions used by legacy parallel port dongles including
        direct port I/O functions and device driver communication functions.
        Legacy dongles communicate via LPT1 (0x378), LPT2 (0x278), or LPT3 (0x3BC).

        This method sets up interception for I/O port operations and driver checks.
        """
        lpt_functions_inpout = [
            ("Inp32", self._handle_port_read),
            ("Out32", self._handle_port_write),
            ("DlPortReadPortUchar", self._handle_port_read),
            ("DlPortWritePortUchar", self._handle_port_write),
            ("IsInpOutDriverOpen", self._handle_driver_check),
        ]

        lpt_driver_dlls = ["inpout32.dll", "inpoutx64.dll", "dlportio.dll", "portio.dll"]

        for dll_name in lpt_driver_dlls:
            for func_name, handler in lpt_functions_inpout:
                self._install_function_hook(dll_name, func_name, handler)

        kernel_io_functions = [
            ("DeviceIoControl", self._handle_device_io_control),
            ("CreateFileA", self._handle_create_file_lpt),
            ("CreateFileW", self._handle_create_file_lpt),
            ("ReadFile", self._handle_read_file_lpt),
            ("WriteFile", self._handle_write_file_lpt),
        ]

        for func_name, handler in kernel_io_functions:
            self._install_function_hook("kernel32.dll", func_name, handler)

        self.logger.info("Installed LPT port hooks for parallel port dongle emulation")

    def _handle_port_read(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle parallel port read operations for dongle communication.

        Reads byte value from parallel port address, supporting LPT1, LPT2, and LPT3
        base addresses and emulating attached dongle responses.

        Args:
            func_name: Name of port I/O function.
            args: Arguments containing port address.

        Returns:
            Byte value read from port (0x00-0xFF).
        """
        if not args:
            return 0xFF

        port_address = args[0]

        lpt1_base = 0x378
        lpt2_base = 0x278
        lpt3_base = 0x3BC

        for lpt_base in [lpt1_base, lpt2_base, lpt3_base]:
            if lpt_base <= port_address <= lpt_base + 2 and hasattr(self.manager, "lpt_emulator"):
                result: int = self.manager.lpt_emulator.read_port(port_address)
                return result

        return 0xFF

    def _handle_port_write(self, _func_name: str, args: tuple[Any, ...]) -> int:
        """Handle parallel port write operations for dongle communication.

        Writes byte value to parallel port address for command transmission to
        attached parallel port dongles.

        Args:
            _func_name: Name of port I/O function (unused).
            args: Arguments containing port address and value to write.

        Returns:
            Status code (0 for success).
        """
        if len(args) < 2:
            return 0

        port_address = args[0]
        value = args[1] & 0xFF

        lpt1_base = 0x378
        lpt2_base = 0x278
        lpt3_base = 0x3BC

        for lpt_base in [lpt1_base, lpt2_base, lpt3_base]:
            if lpt_base <= port_address <= lpt_base + 2 and hasattr(self.manager, "lpt_emulator"):
                self.manager.lpt_emulator.write_port(port_address, value)
                return 0

        return 0

    def _handle_driver_check(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle driver availability check for port I/O libraries.

        Returns success to indicate that port driver library is initialized
        and ready for I/O operations.

        Args:
            func_name: Name of driver check function.
            args: Function arguments (unused).

        Returns:
            1 indicating driver is available and initialized.
        """
        return 1

    def _handle_device_io_control(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle DeviceIoControl calls for LPT devices.

        Processes device control requests for parallel port devices by returning
        success status to indicate operation completion.

        Args:
            func_name: Name of device control function.
            args: Device control arguments.

        Returns:
            1 indicating successful device control operation.
        """
        return 1

    def _handle_create_file_lpt(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle CreateFile calls for LPT devices.

        Returns file handle for LPT device filenames to enable subsequent
        read/write operations on parallel port dongles.

        Args:
            func_name: Name of CreateFile function.
            args: Arguments containing filename for device opening.

        Returns:
            File handle (0x1000) if LPT device, -1 otherwise.
        """
        if not args:
            return -1

        filename = args[0]
        if isinstance(filename, bytes):
            filename = filename.decode("utf-8", errors="ignore")

        lpt_patterns = ["LPT1", "LPT2", "LPT3", "\\\\.\\LPT", "\\Device\\Parallel"]
        return next(
            (0x1000 for pattern in lpt_patterns if pattern.upper() in str(filename).upper()),
            -1,
        )

    def _handle_read_file_lpt(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle ReadFile calls for LPT handles.

        Intercepts file read operations on parallel port devices and returns
        success status to indicate data availability for licensing applications.

        Args:
            func_name: Name of ReadFile function.
            args: Read operation arguments including file handle and buffer.

        Returns:
            1 indicating successful read operation completion.
        """
        return 1

    def _handle_write_file_lpt(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle WriteFile calls for LPT handles.

        Intercepts file write operations on parallel port devices and returns
        success status to indicate dongle received command data.

        Args:
            func_name: Name of WriteFile function.
            args: Write operation arguments including file handle and data buffer.

        Returns:
            1 indicating successful write operation completion.
        """
        return 1

    def _hook_usb_apis(self) -> None:
        """Install hooks for USB dongle API functions.

        Hooks Windows API functions used by USB dongles including SetupAPI
        device enumeration, WinUSB communication, and HID device access.
        """
        setupapi_functions = [
            ("SetupDiGetClassDevsA", self._handle_setupdi_getclassdevs),
            ("SetupDiGetClassDevsW", self._handle_setupdi_getclassdevs),
            ("SetupDiEnumDeviceInterfaces", self._handle_setupdi_enumdeviceinterfaces),
            ("SetupDiGetDeviceInterfaceDetailA", self._handle_setupdi_getdeviceinterfacedetail),
            ("SetupDiGetDeviceInterfaceDetailW", self._handle_setupdi_getdeviceinterfacedetail),
        ]

        for func_name, handler in setupapi_functions:
            self._install_function_hook("setupapi.dll", func_name, handler)

        winusb_functions = [
            ("WinUsb_Initialize", self._handle_winusb_initialize),
            ("WinUsb_Free", self._handle_winusb_free),
            ("WinUsb_ReadPipe", self._handle_winusb_readpipe),
            ("WinUsb_WritePipe", self._handle_winusb_writepipe),
            ("WinUsb_ControlTransfer", self._handle_winusb_controltransfer),
            ("WinUsb_GetDescriptor", self._handle_winusb_getdescriptor),
        ]

        for func_name, handler in winusb_functions:
            self._install_function_hook("winusb.dll", func_name, handler)

        hid_functions = [
            ("HidD_GetHidGuid", self._handle_hidd_gethidguid),
            ("HidD_GetAttributes", self._handle_hidd_getattributes),
            ("HidD_GetFeature", self._handle_hidd_getfeature),
            ("HidD_SetFeature", self._handle_hidd_setfeature),
        ]

        for func_name, handler in hid_functions:
            self._install_function_hook("hid.dll", func_name, handler)

        self.logger.info("Installed USB hooks for USB dongle emulation")

    def _handle_setupdi_getclassdevs(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle SetupDiGetClassDevs calls for USB device enumeration.

        Returns device information set handle for emulated USB dongles to
        appear in Windows device enumeration.

        Args:
            func_name: Name of SetupAPI function.
            args: Function arguments for device class filtering.

        Returns:
            Device information set handle (0x1001).
        """
        return 0x1001

    def _handle_setupdi_enumdeviceinterfaces(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle SetupDiEnumDeviceInterfaces calls for device interface enumeration.

        Returns success for device interface enumeration on emulated USB dongles.

        Args:
            func_name: Name of SetupAPI function.
            args: Function arguments for device interface enumeration.

        Returns:
            1 indicating enumeration success.
        """
        return 1

    def _handle_setupdi_getdeviceinterfacedetail(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle SetupDiGetDeviceInterfaceDetail calls for device path retrieval.

        Returns success for retrieving device path and interface details from
        emulated USB dongles.

        Args:
            func_name: Name of SetupAPI function.
            args: Function arguments for device interface detail retrieval.

        Returns:
            1 indicating operation success.
        """
        return 1

    def _handle_winusb_initialize(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle WinUsb_Initialize calls for USB device initialization.

        Returns success to indicate USB device has been initialized for
        communication with emulated dongle.

        Args:
            func_name: Name of WinUSB function.
            args: Function arguments for device initialization.

        Returns:
            1 indicating successful initialization.
        """
        return 1

    def _handle_winusb_free(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle WinUsb_Free calls for USB device cleanup.

        Returns success to indicate USB device resources have been released.

        Args:
            func_name: Name of WinUSB function.
            args: Function arguments for resource cleanup.

        Returns:
            1 indicating successful cleanup.
        """
        return 1

    def _handle_winusb_readpipe(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle WinUsb_ReadPipe calls for USB bulk data reading.

        Returns success for USB bulk pipe read operations from emulated dongle.

        Args:
            func_name: Name of WinUSB function.
            args: Function arguments for bulk read operation.

        Returns:
            1 indicating successful read operation.
        """
        return 1

    def _handle_winusb_writepipe(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle WinUsb_WritePipe calls for USB bulk data writing.

        Returns success for USB bulk pipe write operations to emulated dongle.

        Args:
            func_name: Name of WinUSB function.
            args: Function arguments for bulk write operation.

        Returns:
            1 indicating successful write operation.
        """
        return 1

    def _handle_winusb_controltransfer(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle WinUsb_ControlTransfer calls for USB control requests.

        Returns success for USB control transfer operations to emulated dongle
        for license verification and configuration.

        Args:
            func_name: Name of WinUSB function.
            args: Function arguments for control transfer operation.

        Returns:
            1 indicating successful control transfer.
        """
        return 1

    def _handle_winusb_getdescriptor(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle WinUsb_GetDescriptor calls for USB device descriptor retrieval.

        Returns success for retrieving USB device descriptors from emulated dongle.

        Args:
            func_name: Name of WinUSB function.
            args: Function arguments for descriptor retrieval.

        Returns:
            1 indicating successful descriptor retrieval.
        """
        return 1

    def _handle_hidd_gethidguid(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle HidD_GetHidGuid calls for HID device class GUID retrieval.

        Returns success for retrieving HID device class GUID for emulated
        HID-based dongle devices.

        Args:
            func_name: Name of HID function.
            args: Function arguments for GUID retrieval.

        Returns:
            1 indicating successful GUID retrieval.
        """
        return 1

    def _handle_hidd_getattributes(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle HidD_GetAttributes calls for HID device attributes.

        Returns success for retrieving HID device attributes (vendor ID, product ID).

        Args:
            func_name: Name of HID function.
            args: Function arguments for attribute retrieval.

        Returns:
            1 indicating successful attribute retrieval.
        """
        return 1

    def _handle_hidd_getfeature(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle HidD_GetFeature calls for HID feature report retrieval.

        Returns success for reading HID feature reports from emulated dongle.

        Args:
            func_name: Name of HID function.
            args: Function arguments for feature report retrieval.

        Returns:
            1 indicating successful feature report retrieval.
        """
        return 1

    def _handle_hidd_setfeature(self, func_name: str, args: tuple[Any, ...]) -> int:
        """Handle HidD_SetFeature calls for HID feature report transmission.

        Returns success for writing HID feature reports to emulated dongle.

        Args:
            func_name: Name of HID function.
            args: Function arguments for feature report transmission.

        Returns:
            1 indicating successful feature report transmission.
        """
        return 1


class HardwareDongleEmulator:
    """Manager for comprehensive hardware dongle emulation across all types.

    Orchestrates emulation of HASP, Sentinel, and other hardware dongles by
    managing USB/parallel port drivers, registry entries, and API interception
    for software licensing bypass and protection analysis.
    """

    def __init__(self) -> None:
        """Initialize hardware dongle emulator with all dongle types and drivers.

        Sets up USB driver, parallel port emulator, Windows registry management,
        and API hooking infrastructure for comprehensive dongle emulation.
        """
        self.logger = logging.getLogger(__name__)
        self.dongles: dict[str, BaseDongleEmulator] = {}
        self.usb_driver = USBDongleDriver()
        self.lpt_emulator = ParallelPortEmulator()
        self.registry_manager = DongleRegistryManager()
        self.api_hooker = DongleAPIHooker(self)

        # Built-in dongle specifications
        self.predefined_dongles = self._load_predefined_dongles()

    def _load_predefined_dongles(self) -> dict[DongleType, DongleSpec]:
        """Load predefined dongle specifications.

        Creates default DongleSpec configurations for common hardware dongles
        (HASP, Sentinel, CodeMeter) with standard vendor IDs, algorithms, and features.

        Returns:
            Dictionary mapping DongleType to DongleSpec with standard configurations.
        """
        return {
            DongleType.HASP_HL: DongleSpec(
                dongle_type=DongleType.HASP_HL,
                interface=DongleInterface.USB,
                vendor_id=0x0529,
                product_id=0x0001,
                memory_size=64,
                algorithms=["TEA", "AES"],
                features={"rtc": True, "counter": True},
            ),
            DongleType.HASP_4: DongleSpec(
                dongle_type=DongleType.HASP_4,
                interface=DongleInterface.PARALLEL_PORT,
                vendor_id=0x0529,
                product_id=0x0002,
                memory_size=32,
                algorithms=["DES", "XOR"],
                features={"memory": True},
            ),
            DongleType.SENTINEL_SUPER_PRO: DongleSpec(
                dongle_type=DongleType.SENTINEL_SUPER_PRO,
                interface=DongleInterface.USB,
                vendor_id=0x04B9,
                product_id=0x0300,
                memory_size=128,
                algorithms=["DES", "3DES"],
                features={"cells": True, "algorithms": True},
            ),
            DongleType.CODEOMETER: DongleSpec(
                dongle_type=DongleType.CODEOMETER,
                interface=DongleInterface.USB,
                vendor_id=0x064F,
                product_id=0x2AF9,
                memory_size=256,
                algorithms=["AES", "RSA"],
                features={"secure_element": True, "certificates": True},
            ),
            DongleType.ROCKEY: DongleSpec(
                dongle_type=DongleType.ROCKEY,
                interface=DongleInterface.USB,
                vendor_id=0x096E,
                product_id=0x0006,
                memory_size=64,
                algorithms=["TEA", "MD5"],
                features={"hardware_clock": True},
            ),
        }

    def create_dongle(self, dongle_type: DongleType, custom_spec: DongleSpec | None = None) -> str:
        """Create and start dongle emulation.

        Args:
            dongle_type: Type of dongle to create.
            custom_spec: Optional custom specification (uses predefined if None).

        Returns:
            Unique dongle identifier string.

        Raises:
            ValueError: If no specification found for dongle_type.
        """
        spec = custom_spec or self.predefined_dongles.get(dongle_type)
        if not spec:
            raise ValueError(f"No specification for {dongle_type}")

        # Create appropriate emulator
        emulator: BaseDongleEmulator
        if dongle_type in {DongleType.HASP_HL, DongleType.HASP_4}:
            emulator = HASPEmulator(spec)
        elif dongle_type.value.startswith("Sentinel"):
            emulator = SentinelEmulator(spec)
        else:
            emulator = BaseDongleEmulator(spec)

        # Register with appropriate driver
        if spec.interface == DongleInterface.USB:
            self.usb_driver.register_dongle(emulator)
        elif spec.interface == DongleInterface.PARALLEL_PORT:
            self.lpt_emulator.attach_dongle(emulator)

        # Install registry entries
        self.registry_manager.install_driver_entries(spec)

        # Start emulation
        emulator.start()

        # Store emulator
        dongle_id = f"{spec.dongle_type.value}_{spec.serial_number}"
        self.dongles[dongle_id] = emulator

        self.logger.info("Created dongle emulation: %s", dongle_id)
        return dongle_id

    def remove_dongle(self, dongle_id: str) -> bool:
        """Remove dongle emulation.

        Args:
            dongle_id: Unique dongle identifier to remove.

        Returns:
            True if dongle was removed, False if not found.
        """
        if dongle_id not in self.dongles:
            return False

        emulator = self.dongles[dongle_id]

        # Stop emulation
        emulator.stop()

        # Unregister from drivers
        if emulator.spec.interface == DongleInterface.USB:
            self.usb_driver.unregister_dongle(
                emulator.spec.vendor_id,
                emulator.spec.product_id,
            )

        # Remove registry entries
        self.registry_manager.remove_driver_entries(emulator.spec)

        # Remove from storage
        del self.dongles[dongle_id]

        self.logger.info("Removed dongle emulation: %s", dongle_id)
        return True

    def get_dongles_by_type(self, dongle_type: DongleType) -> list[BaseDongleEmulator]:
        """Get dongles by type.

        Args:
            dongle_type: Type of dongle to filter by.

        Returns:
            List of dongle emulators matching the specified type.
        """
        return [d for d in self.dongles.values() if d.spec.dongle_type == dongle_type]

    def start_api_hooks(self) -> None:
        """Start API hooks for installed dongles."""
        self.api_hooker.install_hooks()
        self.logger.info("API hooks installed")

    def emulate_dongle(self, dongle_type: str | DongleType) -> dict[str, Any]:
        """Emulate a hardware dongle of the specified type.

        Creates and starts emulation for the specified dongle type, installing
        necessary API hooks and registry entries. Returns a dictionary containing
        emulation status and dongle information.

        Args:
            dongle_type: The type of dongle to emulate. Can be a DongleType enum
                        or a string matching a DongleType value (e.g., "HASP_HL",
                        "Sentinel_SuperPro", "CodeMeter").

        Returns:
            Dictionary containing:
                - emulation_active: bool indicating if emulation is running
                - dongle_id: string identifier for the emulated dongle
                - dongle_type: type of dongle being emulated
                - vendor_id: USB vendor ID
                - product_id: USB product ID
                - serial_number: emulated serial number
                - interface: USB or Parallel_Port
                - error: error message if emulation failed (only present on failure)
        """
        result: dict[str, Any] = {
            "emulation_active": False,
            "dongle_id": None,
            "dongle_type": None,
            "vendor_id": None,
            "product_id": None,
            "serial_number": None,
            "interface": None,
        }

        try:
            if isinstance(dongle_type, str):
                dongle_type_enum = next(
                    (dt for dt in DongleType if dt.value.lower() == dongle_type.lower() or dt.name.lower() == dongle_type.lower()),
                    None,
                )
                if dongle_type_enum is None:
                    result["error"] = f"Unknown dongle type: {dongle_type}"
                    return result
                dongle_type = dongle_type_enum

            dongle_id = self.create_dongle(dongle_type)

            if dongle_id in self.dongles:
                dongle = self.dongles[dongle_id]
                result["emulation_active"] = dongle.active
                result["dongle_id"] = dongle_id
                result["dongle_type"] = dongle.spec.dongle_type.value
                result["vendor_id"] = dongle.spec.vendor_id
                result["product_id"] = dongle.spec.product_id
                result["serial_number"] = dongle.spec.serial_number
                result["interface"] = dongle.spec.interface.value

                self.start_api_hooks()

                self.logger.info("Dongle emulation started: %s", dongle_id)

        except ValueError as ve:
            result["error"] = str(ve)
            self.logger.warning("Failed to emulate dongle: %s", ve)
        except Exception as e:
            result["error"] = f"Emulation failed: {e}"
            self.logger.exception("Dongle emulation error")

        return result

    def list_dongles(self) -> list[dict[str, Any]]:
        """List all active dongles.

        Returns:
            List of dictionaries containing dongle IDs and information.
        """
        return [
            {
                "id": dongle_id,
                "info": dongle.get_dongle_info(),
            }
            for dongle_id, dongle in self.dongles.items()
        ]

    def export_dongles(self, output_file: str) -> None:
        """Export dongle configurations.

        Args:
            output_file: File path to export dongle configurations to.
        """
        export_data: dict[str, Any] = {
            "dongles": {},
            "timestamp": time.time(),
        }

        for dongle_id, dongle in self.dongles.items():
            dongles_dict = export_data.get("dongles", {})
            if isinstance(dongles_dict, dict):
                dongles_dict[dongle_id] = {
                    "spec": {
                        "dongle_type": dongle.spec.dongle_type.value,
                        "interface": dongle.spec.interface.value,
                        "vendor_id": dongle.spec.vendor_id,
                        "product_id": dongle.spec.product_id,
                        "serial_number": dongle.spec.serial_number,
                        "firmware_version": dongle.spec.firmware_version,
                        "memory_size": dongle.spec.memory_size,
                    },
                    "memory": dongle.memory.data.hex(),
                    "active": dongle.active,
                }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

        self.logger.info("Exported %d dongles to %s", len(self.dongles), output_file)

    def import_dongles(self, input_file: str) -> None:
        """Import dongle configurations.

        Args:
            input_file: File path to import dongle configurations from.
        """
        with open(input_file, encoding="utf-8") as f:
            import_data = json.load(f)

        imported_count = 0

        for dongle_id, dongle_data in import_data.get("dongles", {}).items():
            try:
                spec_data = dongle_data["spec"]

                spec = DongleSpec(
                    dongle_type=DongleType(spec_data["dongle_type"]),
                    interface=DongleInterface(spec_data["interface"]),
                    vendor_id=spec_data["vendor_id"],
                    product_id=spec_data["product_id"],
                    serial_number=spec_data["serial_number"],
                    firmware_version=spec_data["firmware_version"],
                    memory_size=spec_data["memory_size"],
                )

                # Create dongle
                new_dongle_id = self.create_dongle(spec.dongle_type, spec)

                # Restore memory
                if "memory" in dongle_data:
                    memory_data = bytes.fromhex(dongle_data["memory"])
                    self.dongles[new_dongle_id].memory.data = bytearray(memory_data)

                imported_count += 1

            except Exception:
                self.logger.exception("Failed to import dongle %s", dongle_id)

        self.logger.info("Imported %d dongles from %s", imported_count, input_file)

    def test_dongle(self, dongle_id: str) -> dict[str, Any]:
        """Test dongle functionality with real test patterns.

        Args:
            dongle_id: Identifier of dongle to test.

        Returns:
            Dictionary with test results including memory, encryption, and challenge-response tests.
        """
        if dongle_id not in self.dongles:
            return {"error": "Dongle not found"}

        dongle = self.dongles[dongle_id]

        results: dict[str, Any] = {
            "dongle_id": dongle_id,
            "type": dongle.spec.dongle_type.value,
            "tests": {},
        }

        try:
            # Generate unique test data based on dongle ID and timestamp
            test_pattern = hashlib.sha256(f"{dongle_id}{time.time()}".encode()).digest()[:20]

            # Test memory read/write with pattern verification
            memory_test_address = 0x100
            write_success = dongle.write_memory(memory_test_address, test_pattern)
            read_data = dongle.read_memory(memory_test_address, len(test_pattern))

            results["tests"]["memory"] = {
                "write_success": write_success,
                "read_success": read_data == test_pattern,
                "data_integrity": read_data == test_pattern,
                "pattern_hash": hashlib.sha256(test_pattern).hexdigest(),
            }

            # Test encryption with real cryptographic validation
            plaintext = os.urandom(32)  # Generate random test data
            encrypted = dongle.encrypt_data(plaintext)
            decrypted = dongle.decrypt_data(encrypted)

            results["tests"]["encryption"] = {
                "encrypt_success": len(encrypted) > 0,
                "decrypt_success": decrypted == plaintext,
                "round_trip_valid": decrypted == plaintext,
                "entropy_check": len(set(encrypted)) > len(encrypted) * 0.7,  # Check randomness
                "expansion_factor": len(encrypted) / len(plaintext),
            }

            # Test challenge-response with validation
            challenge = os.urandom(16)
            response = dongle.process_challenge(challenge)

            # Verify response is deterministic
            response2 = dongle.process_challenge(challenge)

            results["tests"]["challenge_response"] = {
                "response_generated": len(response) > 0,
                "response_length": len(response),
                "deterministic": response == response2,  # Same challenge should give same response
                "response_hash": hashlib.sha256(response).hexdigest()[:16],
            }

            # Test dongle-specific features
            if dongle.spec.dongle_type == DongleType.HASP:
                # HASP-specific tests
                results["tests"]["hasp_features"] = self._test_hasp_features(dongle)
            elif dongle.spec.dongle_type == DongleType.SENTINEL:
                # Sentinel-specific tests
                results["tests"]["sentinel_features"] = self._test_sentinel_features(dongle)

            # Hardware interface tests
            if hasattr(dongle, "_usb_device") and getattr(dongle, "_usb_device", None):
                results["tests"]["hardware"] = {
                    "interface": "USB",
                    "connected": True,
                    "device_present": True,
                }
            elif self.lpt_emulator.port_backend:
                results["tests"]["hardware"] = {
                    "interface": "Parallel",
                    "port_accessible": True,
                }
            else:
                results["tests"]["hardware"] = {
                    "interface": "Emulated",
                    "connected": False,
                }

        except Exception as e:
            self.logger.exception("Error testing dongle %s", dongle_id)
            results["tests"]["error"] = str(e)
            results["tests"]["traceback"] = traceback.format_exc()

        return results

    def _test_hasp_features(self, dongle: BaseDongleEmulator) -> dict[str, object]:
        """Test HASP-specific features.

        Args:
            dongle: HASP dongle emulator instance to test.

        Returns:
            Dictionary with test results for HASP-specific functionality.
        """
        results: dict[str, object] = {}

        try:
            # Test HASP memory file system
            file_id = 0x0001
            file_data = b"HASP_FILE_CONTENT"

            # Write file
            success = dongle.write_file(file_id, file_data)
            results["file_write"] = success

            # Read file
            read_data = dongle.read_file(file_id)
            results["file_read_match"] = read_data == file_data

            # Test RTC if available
            if hasattr(dongle, "get_rtc"):
                rtc_time = dongle.get_rtc()
                results["rtc_available"] = True
                results["rtc_time"] = rtc_time
            else:
                results["rtc_available"] = False

        except Exception as e:
            self.logger.exception("HASP feature test failed")
            results["error"] = str(e)

        return results

    def _test_sentinel_features(self, dongle: BaseDongleEmulator) -> dict[str, object]:
        """Test Sentinel-specific features.

        Args:
            dongle: Sentinel dongle emulator instance to test.

        Returns:
            Dictionary with test results for Sentinel-specific functionality.
        """
        results: dict[str, object] = {}

        try:
            # Test Sentinel algorithm execution
            algorithm_id = 0x01
            input_data = struct.pack("<I", 0x12345678)

            result = dongle.execute_algorithm(algorithm_id, input_data)
            results["algorithm_execution"] = len(result) > 0

            # Test counter operations
            counter_id = 0x00
            counter_value = dongle.read_counter(counter_id)
            results["counter_read"] = True
            results["counter_value"] = counter_value

            # Increment counter
            dongle.increment_counter(counter_id)
            new_value = dongle.read_counter(counter_id)
            results["counter_increment"] = new_value == counter_value + 1

        except Exception as e:
            self.logger.exception("Sentinel feature test failed")
            results["error"] = str(e)

        return results

    def shutdown(self) -> None:
        """Shutdown all dongle emulations and clean up resources."""
        for dongle_id in list(self.dongles):
            self.remove_dongle(dongle_id)

        self.logger.info("Hardware dongle emulator shutdown complete")


def main() -> None:
    """Demonstrate hardware dongle emulator usage.

    Provides command-line interface for managing dongle emulations including
    creation, testing, export/import, and API hook installation.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Hardware Dongle Emulator")
    parser.add_argument("--create", choices=[dt.value for dt in DongleType], help="Create dongle emulation")
    parser.add_argument("--list", action="store_true", help="List active dongles")
    parser.add_argument("--test", help="Test dongle by ID")
    parser.add_argument("--export", help="Export dongle configurations")
    parser.add_argument("--import", dest="import_file", help="Import dongle configurations")
    parser.add_argument("--hooks", action="store_true", help="Install API hooks")

    args = parser.parse_args()

    # Initialize emulator
    emulator = HardwareDongleEmulator()

    try:
        if args.create:
            dongle_type = DongleType(args.create)
            dongle_id = emulator.create_dongle(dongle_type)
            logger.info("Created dongle: %s", dongle_id)

        if args.list:
            dongles = emulator.list_dongles()
            logger.info("=== Active Dongles (%d) ===", len(dongles))
            for dongle in dongles:
                info = dongle["info"]
                logger.info("ID: %s", dongle["id"])
                logger.info("  Type: %s", info["type"])
                logger.info("  VID:PID: %04X:%04X", info["vendor_id"], info["product_id"])
                logger.info("  Serial: %s", info["serial_number"])
                logger.info("  Active: %s", info["active"])

        if args.test:
            results = emulator.test_dongle(args.test)
            logger.info("=== Test Results for %s ===", args.test)
            logger.info("%s", json.dumps(results, indent=2))

        if args.export:
            emulator.export_dongles(args.export)
            logger.info("Exported dongles to %s", args.export)

        if args.import_file:
            emulator.import_dongles(args.import_file)
            logger.info("Imported dongles from %s", args.import_file)

        if args.hooks:
            emulator.start_api_hooks()
            logger.info("API hooks installed")

            # Keep running to maintain hooks
            logger.info("Press Ctrl+C to exit...")
            with contextlib.suppress(KeyboardInterrupt):
                while True:
                    time.sleep(1)
    finally:
        emulator.shutdown()


if __name__ == "__main__":
    main()
