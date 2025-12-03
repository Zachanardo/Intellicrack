#!/usr/bin/env python3
"""Comprehensive tests for hardware dongle emulator.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import hashlib
import json
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
from hypothesis import assume, given, settings, strategies as st

from intellicrack.plugins.custom_modules.hardware_dongle_emulator import (
    BaseDongleEmulator,
    CryptoEngine,
    DongleInterface,
    DongleMemory,
    DongleSpec,
    DongleType,
    HardwareDongleEmulator,
    HASPEmulator,
    ParallelPortEmulator,
    SentinelEmulator,
    USBDongleDriver,
)


class TestDongleSpec:
    """Test DongleSpec dataclass and initialization."""

    def test_dongle_spec_initialization_with_serial(self) -> None:
        """DongleSpec initializes with provided serial number."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
            serial_number="1234-5678-ABCD-EF01",
        )

        assert spec.dongle_type == DongleType.HASP_HL
        assert spec.interface == DongleInterface.USB
        assert spec.vendor_id == 0x0529
        assert spec.product_id == 0x0001
        assert spec.serial_number == "1234-5678-ABCD-EF01"

    def test_dongle_spec_auto_generates_serial(self) -> None:
        """DongleSpec automatically generates cryptographically secure serial number."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )

        assert spec.serial_number != ""
        assert len(spec.serial_number) == 19
        assert spec.serial_number.count("-") == 3

        parts = spec.serial_number.split("-")
        assert len(parts) == 4
        assert all(len(part) == 4 for part in parts)
        assert all(c in "0123456789ABCDEF" for part in parts for c in part)

    def test_dongle_spec_serial_uniqueness(self) -> None:
        """Each DongleSpec generates unique serial numbers."""
        serials = set()
        for _ in range(100):
            spec = DongleSpec(
                dongle_type=DongleType.HASP_HL,
                interface=DongleInterface.USB,
                vendor_id=0x0529,
                product_id=0x0001,
            )
            serials.add(spec.serial_number)

        assert len(serials) == 100

    def test_dongle_spec_with_all_parameters(self) -> None:
        """DongleSpec accepts all configuration parameters."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
            serial_number="TEST-SERIAL-1234",
            firmware_version="2.5.0",
            memory_size=128,
            algorithms=["DES", "3DES", "AES"],
            features={"cells": True, "algorithms": True, "rtc": True},
        )

        assert spec.firmware_version == "2.5.0"
        assert spec.memory_size == 128
        assert "DES" in spec.algorithms
        assert "3DES" in spec.algorithms
        assert spec.features["cells"] is True
        assert spec.features["rtc"] is True


class TestDongleMemory:
    """Test DongleMemory read/write operations."""

    def test_dongle_memory_initialization(self) -> None:
        """DongleMemory initializes with correct size."""
        memory = DongleMemory(size=1024, data=bytearray(1024))

        assert memory.size == 1024
        assert len(memory.data) == 1024
        assert all(byte == 0 for byte in memory.data)

    def test_dongle_memory_auto_initializes_empty_data(self) -> None:
        """DongleMemory auto-initializes if no data provided."""
        memory = DongleMemory(size=2048, data=bytearray())

        assert memory.size == 2048
        assert len(memory.data) == 2048

    def test_dongle_memory_read_success(self) -> None:
        """Memory read returns correct data."""
        memory = DongleMemory(size=256, data=bytearray(256))
        test_data = b"TEST_DATA_PATTERN"
        memory.data[0x10 : 0x10 + len(test_data)] = test_data

        result = memory.read(0x10, len(test_data))

        assert result == test_data

    def test_dongle_memory_write_success(self) -> None:
        """Memory write stores data correctly."""
        memory = DongleMemory(size=256, data=bytearray(256))
        test_data = b"WRITE_TEST_DATA"

        success = memory.write(0x20, test_data)

        assert success is True
        assert memory.data[0x20 : 0x20 + len(test_data)] == test_data

    def test_dongle_memory_read_out_of_bounds_raises_error(self) -> None:
        """Reading beyond memory bounds raises ValueError."""
        memory = DongleMemory(size=256, data=bytearray(256))

        with pytest.raises(ValueError, match="Memory access out of bounds"):
            memory.read(250, 20)

    def test_dongle_memory_write_out_of_bounds_raises_error(self) -> None:
        """Writing beyond memory bounds raises ValueError."""
        memory = DongleMemory(size=256, data=bytearray(256))

        with pytest.raises(ValueError, match="Memory access out of bounds"):
            memory.write(250, b"OVERFLOW_DATA_PATTERN")

    def test_dongle_memory_read_only_protection(self) -> None:
        """Write to read-only range is rejected."""
        memory = DongleMemory(size=256, data=bytearray(256))
        memory.read_only_ranges.append((0x00, 0x20))

        success = memory.write(0x10, b"ATTEMPT_WRITE")

        assert success is False
        assert all(byte == 0 for byte in memory.data[0x10:0x20])

    def test_dongle_memory_write_allowed_outside_readonly(self) -> None:
        """Write succeeds outside read-only ranges."""
        memory = DongleMemory(size=256, data=bytearray(256))
        memory.read_only_ranges.append((0x00, 0x20))
        test_data = b"WRITABLE_AREA"

        success = memory.write(0x30, test_data)

        assert success is True
        assert memory.data[0x30 : 0x30 + len(test_data)] == test_data

    @given(
        address=st.integers(min_value=0, max_value=200),
        data=st.binary(min_size=1, max_size=50),
    )
    @settings(max_examples=50)
    def test_dongle_memory_round_trip(self, address: int, data: bytes) -> None:
        """Memory write followed by read returns same data."""
        memory = DongleMemory(size=256, data=bytearray(256))
        assume(address + len(data) <= 256)

        success = memory.write(address, data)
        result = memory.read(address, len(data))

        assert success is True
        assert result == data


class TestCryptoEngine:
    """Test CryptoEngine encryption algorithms."""

    def test_tea_encrypt_produces_output(self) -> None:
        """TEA encryption produces non-empty output."""
        engine = CryptoEngine()
        plaintext = b"SENSITIVE_DATA_TO_ENCRYPT_NOW"
        key = b"SIXTEEN_BYTE_KEY" * 1

        ciphertext = engine.tea_encrypt(plaintext, key)

        assert len(ciphertext) > 0
        assert ciphertext != plaintext

    def test_tea_decrypt_reverses_encryption(self) -> None:
        """TEA decryption correctly reverses encryption."""
        engine = CryptoEngine()
        plaintext = b"TEST_PLAINTEXT_MESSAGE_HERE!"
        key = b"VALID_CRYPTO_KEY"

        ciphertext = engine.tea_encrypt(plaintext, key)
        decrypted = engine.tea_decrypt(ciphertext, key)

        assert decrypted.rstrip(b"\x00") == plaintext

    def test_tea_encryption_deterministic(self) -> None:
        """TEA encryption is deterministic for same input."""
        engine = CryptoEngine()
        plaintext = b"DETERMINISTIC_TEST_DATA"
        key = b"CONSTANT_KEY_VAL"

        result1 = engine.tea_encrypt(plaintext, key)
        result2 = engine.tea_encrypt(plaintext, key)

        assert result1 == result2

    def test_tea_different_keys_produce_different_ciphertext(self) -> None:
        """TEA with different keys produces different ciphertext."""
        engine = CryptoEngine()
        plaintext = b"SAME_PLAINTEXT_DATA"
        key1 = b"FIRST_KEY_VALUE1"
        key2 = b"SECOND_KEY_VAL_2"

        cipher1 = engine.tea_encrypt(plaintext, key1)
        cipher2 = engine.tea_encrypt(plaintext, key2)

        assert cipher1 != cipher2

    def test_xor_encrypt_symmetric(self) -> None:
        """XOR encryption is symmetric (encrypt twice returns original)."""
        engine = CryptoEngine()
        plaintext = b"XOR_TEST_DATA_PATTERN"
        key = b"XOR_KEY"

        encrypted = engine.simple_xor(plaintext, key)
        decrypted = engine.simple_xor(encrypted, key)

        assert decrypted == plaintext

    def test_xor_changes_data(self) -> None:
        """XOR actually modifies the data."""
        engine = CryptoEngine()
        plaintext = b"ORIGINAL_DATA"
        key = b"KEY"

        encrypted = engine.simple_xor(plaintext, key)

        assert encrypted != plaintext

    def test_crc16_calculation(self) -> None:
        """CRC16 produces valid checksum."""
        engine = CryptoEngine()
        data = b"CHECKSUM_TEST_DATA"

        crc = engine.crc16(data)

        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_crc16_different_data_different_checksum(self) -> None:
        """CRC16 produces different checksums for different data."""
        engine = CryptoEngine()
        data1 = b"FIRST_DATA_BLOCK"
        data2 = b"SECOND_DATA_BLOCK"

        crc1 = engine.crc16(data1)
        crc2 = engine.crc16(data2)

        assert crc1 != crc2

    def test_crc16_deterministic(self) -> None:
        """CRC16 is deterministic."""
        engine = CryptoEngine()
        data = b"DETERMINISTIC_CRC_DATA"

        crc1 = engine.crc16(data)
        crc2 = engine.crc16(data)

        assert crc1 == crc2

    @given(plaintext=st.binary(min_size=8, max_size=128))
    @settings(max_examples=50)
    def test_tea_round_trip_property(self, plaintext: bytes) -> None:
        """TEA encryption/decryption round trip preserves data."""
        engine = CryptoEngine()
        key = b"PROPERTY_TEST_KY"

        ciphertext = engine.tea_encrypt(plaintext, key)
        decrypted = engine.tea_decrypt(ciphertext, key)

        assert decrypted.rstrip(b"\x00") == plaintext.rstrip(b"\x00")


class TestBaseDongleEmulator:
    """Test BaseDongleEmulator functionality."""

    def test_base_dongle_initialization(self) -> None:
        """BaseDongleEmulator initializes correctly."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )

        emulator = BaseDongleEmulator(spec)

        assert emulator.spec == spec
        assert emulator.memory is not None
        assert emulator.crypto is not None
        assert emulator.active is False

    def test_base_dongle_initializes_memory_with_hardware_info(self) -> None:
        """BaseDongleEmulator writes hardware info to memory."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
            serial_number="TEST-SERIAL-NUM",
        )

        emulator = BaseDongleEmulator(spec)

        vendor_product = struct.unpack("<HH", emulator.memory.read(0x00, 4))
        assert vendor_product[0] == 0x0529
        assert vendor_product[1] == 0x0001

        serial = emulator.memory.read(0x04, 16).rstrip(b"\x00")
        assert serial == b"TEST-SERIAL-NUM"

    def test_base_dongle_start_activates_emulation(self) -> None:
        """Starting dongle emulation sets active flag."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)

        emulator.start()

        assert emulator.active is True

    def test_base_dongle_stop_deactivates_emulation(self) -> None:
        """Stopping dongle emulation clears active flag."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        emulator.stop()

        assert emulator.active is False

    def test_base_dongle_read_memory_requires_active(self) -> None:
        """Reading memory requires dongle to be active."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)

        with pytest.raises(RuntimeError, match="Dongle not active"):
            emulator.read_memory(0x00, 16)

    def test_base_dongle_write_memory_requires_active(self) -> None:
        """Writing memory requires dongle to be active."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)

        with pytest.raises(RuntimeError, match="Dongle not active"):
            emulator.write_memory(0x30, b"TEST")

    def test_base_dongle_read_memory_when_active(self) -> None:
        """Reading memory works when dongle is active."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        data = emulator.read_memory(0x00, 4)

        assert len(data) == 4

    def test_base_dongle_write_memory_when_active(self) -> None:
        """Writing memory works when dongle is active."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        test_data = b"WRITABLE_TEST"

        success = emulator.write_memory(0x40, test_data)

        assert success is True
        assert emulator.memory.read(0x40, len(test_data)) == test_data

    def test_base_dongle_encrypt_data(self) -> None:
        """Dongle encryption produces ciphertext."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"ENCRYPTION_KEY16")
        plaintext = b"SENSITIVE_PLAINTEXT_DATA"

        ciphertext = emulator.encrypt_data(plaintext)

        assert ciphertext != plaintext
        assert len(ciphertext) > 0

    def test_base_dongle_decrypt_data(self) -> None:
        """Dongle decryption reverses encryption."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"ENCRYPTION_KEY16")
        plaintext = b"MESSAGE_TO_ENCRYPT_DECRYPT"

        ciphertext = emulator.encrypt_data(plaintext)
        decrypted = emulator.decrypt_data(ciphertext)

        assert decrypted.rstrip(b"\x00") == plaintext

    def test_base_dongle_get_info(self) -> None:
        """get_dongle_info returns complete information."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
            serial_number="INFO-TEST-SN",
            firmware_version="1.2.3",
            memory_size=64,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        info = emulator.get_dongle_info()

        assert info["type"] == "HASP_HL"
        assert info["vendor_id"] == 0x0529
        assert info["product_id"] == 0x0001
        assert info["serial_number"] == "INFO-TEST-SN"
        assert info["firmware_version"] == "1.2.3"
        assert info["memory_size"] == 64
        assert info["active"] is True

    def test_base_dongle_process_challenge(self) -> None:
        """process_challenge generates valid response."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"CHALLENGE_KEY_16")
        challenge = os.urandom(16)

        response = emulator.process_challenge(challenge)

        assert len(response) > len(challenge)
        crc_bytes = response[-2:]
        crc_value = struct.unpack("<H", crc_bytes)[0]
        assert 0 <= crc_value <= 0xFFFF

    def test_base_dongle_challenge_response_deterministic(self) -> None:
        """Same challenge produces same response."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"CHALLENGE_KEY_16")
        challenge = b"FIXED_CHALLENGE_DATA"

        response1 = emulator.process_challenge(challenge)
        response2 = emulator.process_challenge(challenge)

        assert response1 == response2


class TestHASPEmulator:
    """Test HASP-specific dongle emulation."""

    def test_hasp_emulator_initialization(self) -> None:
        """HASPEmulator initializes with HASP-specific features."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )

        emulator = HASPEmulator(spec)

        assert emulator.spec.dongle_type == DongleType.HASP_HL
        assert len(emulator.hasp_commands) > 0

    def test_hasp_memory_layout_initialized(self) -> None:
        """HASP memory layout is properly initialized."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        key = emulator.memory.read(0x20, 16)
        assert key == b"HASP_DEFAULT_KEY"

        memory_size = struct.unpack("<I", emulator.memory.read(0x30, 4))[0]
        assert memory_size == spec.memory_size

    def test_hasp_login_command_success(self) -> None:
        """HASP login command succeeds for valid feature."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        login_data = struct.pack("<I", 1)
        response = emulator.process_hasp_command(0x01, login_data)

        status, session_id = struct.unpack("<II", response)
        assert status == 0
        assert 1000 <= session_id <= 9999

    def test_hasp_login_invalid_feature(self) -> None:
        """HASP login fails for invalid feature."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        login_data = struct.pack("<I", 999)
        response = emulator.process_hasp_command(0x01, login_data)

        assert response == b"\x00\x00\x00\x02"

    def test_hasp_logout_command(self) -> None:
        """HASP logout command succeeds."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        response = emulator.process_hasp_command(0x02, b"\x00\x00\x00\x00")

        assert response == b"\x00\x00\x00\x00"

    def test_hasp_encrypt_command(self) -> None:
        """HASP encrypt command encrypts data."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        session_id = struct.pack("<I", 1234)
        plaintext = b"HASP_ENCRYPT_TEST_DATA_HERE"
        command_data = session_id + plaintext

        response = emulator.process_hasp_command(0x03, command_data)

        status = struct.unpack("<I", response[:4])[0]
        encrypted_data = response[4:]

        assert status == 0
        assert len(encrypted_data) > 0
        assert encrypted_data != plaintext

    def test_hasp_decrypt_command(self) -> None:
        """HASP decrypt command decrypts data."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        plaintext = b"HASP_DECRYPT_TEST_DATA_SAMPLE"
        session_id = struct.pack("<I", 1234)

        encrypt_response = emulator.process_hasp_command(0x03, session_id + plaintext)
        encrypted_data = encrypt_response[4:]

        decrypt_response = emulator.process_hasp_command(0x04, session_id + encrypted_data)

        status = struct.unpack("<I", decrypt_response[:4])[0]
        decrypted_data = decrypt_response[4:]

        assert status == 0
        assert decrypted_data.rstrip(b"\x00") == plaintext

    def test_hasp_read_memory_command(self) -> None:
        """HASP read memory command returns data."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        test_data = b"HASP_MEMORY_DATA"
        emulator.memory.write(0x50, test_data)

        command_data = struct.pack("<III", 1234, 0x50, len(test_data))
        response = emulator.process_hasp_command(0x05, command_data)

        status = struct.unpack("<I", response[:4])[0]
        read_data = response[4:]

        assert status == 0
        assert read_data == test_data

    def test_hasp_write_memory_command(self) -> None:
        """HASP write memory command stores data."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        write_data = b"HASP_WRITE_TEST"
        command_data = struct.pack("<III", 1234, 0x60, len(write_data)) + write_data
        response = emulator.process_hasp_command(0x06, command_data)

        status = struct.unpack("<I", response)[0]
        assert status == 0

        stored_data = emulator.memory.read(0x60, len(write_data))
        assert stored_data == write_data

    def test_hasp_get_size_command(self) -> None:
        """HASP get size command returns memory size."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
            memory_size=64,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        response = emulator.process_hasp_command(0x07, b"")

        status, size = struct.unpack("<II", response)
        assert status == 0
        assert size == 64 * 1024

    def test_hasp_get_rtc_command(self) -> None:
        """HASP get RTC command returns current time."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        before_time = int(time.time())
        response = emulator.process_hasp_command(0x08, b"")
        after_time = int(time.time())

        status, rtc_time = struct.unpack("<II", response)
        assert status == 0
        assert before_time <= rtc_time <= after_time

    def test_hasp_set_rtc_command(self) -> None:
        """HASP set RTC command updates time."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        new_time = 1234567890
        command_data = struct.pack("<II", 0, new_time)
        response = emulator.process_hasp_command(0x09, command_data)

        status = struct.unpack("<I", response)[0]
        assert status == 0

        stored_time = struct.unpack("<I", emulator.memory.read(0x34, 4))[0]
        assert stored_time == new_time


class TestSentinelEmulator:
    """Test Sentinel-specific dongle emulation."""

    def test_sentinel_emulator_initialization(self) -> None:
        """SentinelEmulator initializes with cell-based memory."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )

        emulator = SentinelEmulator(spec)

        assert emulator.spec.dongle_type == DongleType.SENTINEL_SUPER_PRO
        assert len(emulator.cell_data) > 0

    def test_sentinel_cell_initialization(self) -> None:
        """Sentinel cells are properly initialized."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)

        assert 0 in emulator.cell_data
        assert 1 in emulator.cell_data
        assert 2 in emulator.cell_data

        assert emulator.cell_data[0]["permissions"] == "RW"
        assert emulator.cell_data[1]["permissions"] == "R"

    def test_sentinel_read_cell_success(self) -> None:
        """Reading Sentinel cell returns data."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)
        emulator.start()

        data = emulator.read_cell(0)

        assert len(data) > 0
        assert b"SENTINEL_CELL_0_DATA" in data

    def test_sentinel_read_cell_permission_error(self) -> None:
        """Reading cell without read permission fails."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)
        emulator.start()

        emulator.cell_data[5] = {"data": b"NO_READ_ACCESS", "permissions": "W", "algorithm": "NONE"}

        with pytest.raises(PermissionError, match="No read permission"):
            emulator.read_cell(5)

    def test_sentinel_write_cell_success(self) -> None:
        """Writing to writable Sentinel cell succeeds."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)
        emulator.start()

        new_data = b"NEW_CELL_DATA_WRITTEN"
        success = emulator.write_cell(0, new_data)

        assert success is True
        assert emulator.cell_data[0]["data"] == new_data

    def test_sentinel_write_cell_permission_denied(self) -> None:
        """Writing to read-only Sentinel cell fails."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)
        emulator.start()

        original_data = emulator.cell_data[1]["data"]
        success = emulator.write_cell(1, b"ATTEMPT_WRITE")

        assert success is False
        assert emulator.cell_data[1]["data"] == original_data

    def test_sentinel_transform_data_des(self) -> None:
        """Sentinel DES transformation modifies data."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)
        emulator.start()

        input_data = b"TRANSFORM_THIS_DATA"
        transformed = emulator.transform_data(0, input_data)

        assert transformed != input_data
        assert len(transformed) == len(input_data)

    def test_sentinel_transform_data_xor(self) -> None:
        """Sentinel XOR transformation is symmetric."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)
        emulator.start()

        emulator.cell_data[3] = {
            "data": b"XOR_KEY_DATA_16B",
            "permissions": "RW",
            "algorithm": "XOR",
        }

        input_data = b"XOR_TRANSFORM_DATA"
        transformed = emulator.transform_data(3, input_data)
        restored = emulator.transform_data(3, transformed)

        assert transformed != input_data
        assert restored == input_data


class TestUSBDongleDriver:
    """Test USB dongle driver functionality."""

    def test_usb_driver_initialization(self) -> None:
        """USBDongleDriver initializes correctly."""
        driver = USBDongleDriver()

        assert driver.dongles == {}
        assert driver.logger is not None

    def test_usb_driver_register_dongle(self) -> None:
        """Registering dongle adds it to driver."""
        driver = USBDongleDriver()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)

        driver.register_dongle(emulator)

        device_id = "0529:0001"
        assert device_id in driver.dongles
        assert driver.dongles[device_id] == emulator

    def test_usb_driver_unregister_dongle(self) -> None:
        """Unregistering dongle removes it from driver."""
        driver = USBDongleDriver()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        driver.register_dongle(emulator)

        driver.unregister_dongle(0x0529, 0x0001)

        device_id = "0529:0001"
        assert device_id not in driver.dongles

    def test_usb_driver_find_dongles_by_vendor(self) -> None:
        """Finding dongles by vendor ID works."""
        driver = USBDongleDriver()
        spec1 = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        spec2 = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        driver.register_dongle(BaseDongleEmulator(spec1))
        driver.register_dongle(BaseDongleEmulator(spec2))

        found = driver.find_dongles(vendor_id=0x0529)

        assert len(found) == 1
        assert found[0].spec.vendor_id == 0x0529

    def test_usb_driver_find_dongles_by_product(self) -> None:
        """Finding dongles by product ID works."""
        driver = USBDongleDriver()
        spec1 = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        spec2 = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0002,
        )
        driver.register_dongle(BaseDongleEmulator(spec1))
        driver.register_dongle(BaseDongleEmulator(spec2))

        found = driver.find_dongles(product_id=0x0002)

        assert len(found) == 1
        assert found[0].spec.product_id == 0x0002

    def test_usb_driver_control_transfer_read_memory(self) -> None:
        """USB control transfer can read dongle memory."""
        driver = USBDongleDriver()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        test_data = b"USB_CONTROL_READ"
        emulator.memory.write(0x100, test_data)
        driver.register_dongle(emulator)

        result = driver.control_transfer(
            vendor_id=0x0529,
            product_id=0x0001,
            request_type=0xC0,
            request=0x01,
            value=0x100,
            index=0,
            data=b"",
        )

        assert len(result) >= len(test_data)
        assert result[: len(test_data)] == test_data

    def test_usb_driver_control_transfer_write_memory(self) -> None:
        """USB control transfer can write dongle memory."""
        driver = USBDongleDriver()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        driver.register_dongle(emulator)

        write_data = b"USB_WRITE_DATA"
        result = driver.control_transfer(
            vendor_id=0x0529,
            product_id=0x0001,
            request_type=0x40,
            request=0x02,
            value=0x200,
            index=0,
            data=write_data,
        )

        assert result == b"\x00"
        stored_data = emulator.memory.read(0x200, len(write_data))
        assert stored_data == write_data

    def test_usb_driver_control_transfer_encrypt(self) -> None:
        """USB control transfer can perform encryption."""
        driver = USBDongleDriver()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"USB_ENCRYPT_KEY1")
        driver.register_dongle(emulator)

        plaintext = b"USB_PLAINTEXT"
        data = b"\x01" + plaintext

        result = driver.control_transfer(
            vendor_id=0x0529,
            product_id=0x0001,
            request_type=0x40,
            request=0x04,
            value=0,
            index=0,
            data=data,
        )

        assert len(result) > 0
        assert result != plaintext

    def test_usb_driver_bulk_transfer_emulated(self) -> None:
        """USB bulk transfer works with emulated dongles."""
        driver = USBDongleDriver()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        driver.register_dongle(emulator)

        bulk_data = b"BULK_TRANSFER_DATA"
        result = driver.bulk_transfer(
            vendor_id=0x0529,
            product_id=0x0001,
            endpoint=0x01,
            data=bulk_data,
        )

        bytes_written = struct.unpack("<I", result)[0]
        assert bytes_written == len(bulk_data)


class TestParallelPortEmulator:
    """Test parallel port dongle emulation."""

    def test_parallel_port_initialization(self) -> None:
        """ParallelPortEmulator initializes with default port."""
        emulator = ParallelPortEmulator()

        assert emulator.port_address == 0x378
        assert emulator.data_register == 0
        assert emulator.status_register == 0
        assert emulator.control_register == 0

    def test_parallel_port_custom_address(self) -> None:
        """ParallelPortEmulator accepts custom port address."""
        emulator = ParallelPortEmulator(port_address=0x278)

        assert emulator.port_address == 0x278

    def test_parallel_port_attach_dongle(self) -> None:
        """Attaching dongle to parallel port works."""
        port = ParallelPortEmulator()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_4,
            interface=DongleInterface.PARALLEL_PORT,
            vendor_id=0x0529,
            product_id=0x0002,
        )
        emulator = BaseDongleEmulator(spec)

        port.attach_dongle(emulator)

        assert DongleType.HASP_4 in port.dongles

    def test_parallel_port_write_data_register(self) -> None:
        """Writing to parallel port data register updates state."""
        port = ParallelPortEmulator()

        port.write_port(0x378, 0xAA)

        assert port.data_register == 0xAA

    def test_parallel_port_read_data_register(self) -> None:
        """Reading parallel port data register returns current value."""
        port = ParallelPortEmulator()
        port.data_register = 0x55

        value = port.read_port(0x378)

        assert value == 0x55

    def test_parallel_port_write_control_register(self) -> None:
        """Writing to control register updates state."""
        port = ParallelPortEmulator()

        port.write_port(0x37A, 0x0C)

        assert port.control_register == 0x0C

    def test_parallel_port_presence_check(self) -> None:
        """Parallel port dongle presence check works."""
        port = ParallelPortEmulator()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_4,
            interface=DongleInterface.PARALLEL_PORT,
            vendor_id=0x0529,
            product_id=0x0002,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        port.attach_dongle(emulator)

        port.write_port(0x378, 0xAA)

        assert port.status_register == 0x55

    def test_parallel_port_read_dongle_id(self) -> None:
        """Reading dongle ID from parallel port works."""
        port = ParallelPortEmulator()
        spec = DongleSpec(
            dongle_type=DongleType.HASP_4,
            interface=DongleInterface.PARALLEL_PORT,
            vendor_id=0x0529,
            product_id=0x0002,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        port.attach_dongle(emulator)

        port.write_port(0x378, 0x01)

        assert port.status_register == 0x29


class TestHardwareDongleEmulator:
    """Test main HardwareDongleEmulator manager."""

    def test_hardware_emulator_initialization(self) -> None:
        """HardwareDongleEmulator initializes all components."""
        emulator = HardwareDongleEmulator()

        assert emulator.dongles == {}
        assert emulator.usb_driver is not None
        assert emulator.lpt_emulator is not None
        assert emulator.registry_manager is not None
        assert emulator.api_hooker is not None
        assert len(emulator.predefined_dongles) > 0

    def test_hardware_emulator_predefined_dongles_loaded(self) -> None:
        """Predefined dongle specifications are loaded."""
        emulator = HardwareDongleEmulator()

        assert DongleType.HASP_HL in emulator.predefined_dongles
        assert DongleType.HASP_4 in emulator.predefined_dongles
        assert DongleType.SENTINEL_SUPER_PRO in emulator.predefined_dongles
        assert DongleType.CODEOMETER in emulator.predefined_dongles

    def test_hardware_emulator_create_hasp_dongle(self) -> None:
        """Creating HASP dongle emulation works."""
        emulator = HardwareDongleEmulator()

        dongle_id = emulator.create_dongle(DongleType.HASP_HL)

        assert dongle_id in emulator.dongles
        assert emulator.dongles[dongle_id].spec.dongle_type == DongleType.HASP_HL
        assert emulator.dongles[dongle_id].active is True

    def test_hardware_emulator_create_sentinel_dongle(self) -> None:
        """Creating Sentinel dongle emulation works."""
        emulator = HardwareDongleEmulator()

        dongle_id = emulator.create_dongle(DongleType.SENTINEL_SUPER_PRO)

        assert dongle_id in emulator.dongles
        assert emulator.dongles[dongle_id].spec.dongle_type == DongleType.SENTINEL_SUPER_PRO

    def test_hardware_emulator_create_with_custom_spec(self) -> None:
        """Creating dongle with custom spec works."""
        emulator = HardwareDongleEmulator()
        custom_spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x9999,
            product_id=0x8888,
            serial_number="CUSTOM-SPEC-SN",
            memory_size=256,
        )

        dongle_id = emulator.create_dongle(DongleType.HASP_HL, custom_spec)

        created_dongle = emulator.dongles[dongle_id]
        assert created_dongle.spec.vendor_id == 0x9999
        assert created_dongle.spec.product_id == 0x8888
        assert created_dongle.spec.serial_number == "CUSTOM-SPEC-SN"

    def test_hardware_emulator_remove_dongle(self) -> None:
        """Removing dongle emulation works."""
        emulator = HardwareDongleEmulator()
        dongle_id = emulator.create_dongle(DongleType.HASP_HL)

        success = emulator.remove_dongle(dongle_id)

        assert success is True
        assert dongle_id not in emulator.dongles

    def test_hardware_emulator_remove_nonexistent_dongle(self) -> None:
        """Removing nonexistent dongle returns False."""
        emulator = HardwareDongleEmulator()

        success = emulator.remove_dongle("NONEXISTENT_ID")

        assert success is False

    def test_hardware_emulator_get_dongles_by_type(self) -> None:
        """Getting dongles by type returns correct dongles."""
        emulator = HardwareDongleEmulator()
        emulator.create_dongle(DongleType.HASP_HL)
        emulator.create_dongle(DongleType.HASP_HL)
        emulator.create_dongle(DongleType.SENTINEL_SUPER_PRO)

        hasp_dongles = emulator.get_dongles_by_type(DongleType.HASP_HL)
        sentinel_dongles = emulator.get_dongles_by_type(DongleType.SENTINEL_SUPER_PRO)

        assert len(hasp_dongles) == 2
        assert len(sentinel_dongles) == 1

    def test_hardware_emulator_list_dongles(self) -> None:
        """Listing dongles returns all active dongles."""
        emulator = HardwareDongleEmulator()
        emulator.create_dongle(DongleType.HASP_HL)
        emulator.create_dongle(DongleType.SENTINEL_SUPER_PRO)

        dongles_list = emulator.list_dongles()

        assert len(dongles_list) == 2
        assert all("id" in d for d in dongles_list)
        assert all("info" in d for d in dongles_list)

    def test_hardware_emulator_export_dongles(self) -> None:
        """Exporting dongle configurations creates valid JSON."""
        emulator = HardwareDongleEmulator()
        emulator.create_dongle(DongleType.HASP_HL)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            export_file = f.name

        try:
            emulator.export_dongles(export_file)

            assert Path(export_file).exists()

            with open(export_file) as f:
                export_data = json.load(f)

            assert "dongles" in export_data
            assert "timestamp" in export_data
            assert len(export_data["dongles"]) == 1
        finally:
            Path(export_file).unlink(missing_ok=True)

    def test_hardware_emulator_import_dongles(self) -> None:
        """Importing dongle configurations restores dongles."""
        emulator1 = HardwareDongleEmulator()
        emulator1.create_dongle(DongleType.HASP_HL)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            export_file = f.name

        try:
            emulator1.export_dongles(export_file)

            emulator2 = HardwareDongleEmulator()
            emulator2.import_dongles(export_file)

            assert len(emulator2.dongles) >= 1
        finally:
            Path(export_file).unlink(missing_ok=True)

    def test_hardware_emulator_test_dongle_memory(self) -> None:
        """Testing dongle validates memory operations."""
        emulator = HardwareDongleEmulator()
        dongle_id = emulator.create_dongle(DongleType.HASP_HL)

        results = emulator.test_dongle(dongle_id)

        assert "tests" in results
        assert "memory" in results["tests"]
        assert results["tests"]["memory"]["write_success"] is True
        assert results["tests"]["memory"]["read_success"] is True
        assert results["tests"]["memory"]["data_integrity"] is True

    def test_hardware_emulator_test_dongle_encryption(self) -> None:
        """Testing dongle validates encryption operations."""
        emulator = HardwareDongleEmulator()
        dongle_id = emulator.create_dongle(DongleType.HASP_HL)

        results = emulator.test_dongle(dongle_id)

        assert "encryption" in results["tests"]
        assert results["tests"]["encryption"]["encrypt_success"] is True
        assert results["tests"]["encryption"]["decrypt_success"] is True
        assert results["tests"]["encryption"]["round_trip_valid"] is True

    def test_hardware_emulator_test_dongle_challenge_response(self) -> None:
        """Testing dongle validates challenge-response mechanism."""
        emulator = HardwareDongleEmulator()
        dongle_id = emulator.create_dongle(DongleType.HASP_HL)

        results = emulator.test_dongle(dongle_id)

        assert "challenge_response" in results["tests"]
        assert results["tests"]["challenge_response"]["response_generated"] is True
        assert results["tests"]["challenge_response"]["deterministic"] is True

    def test_hardware_emulator_shutdown(self) -> None:
        """Shutdown removes all active dongles."""
        emulator = HardwareDongleEmulator()
        emulator.create_dongle(DongleType.HASP_HL)
        emulator.create_dongle(DongleType.SENTINEL_SUPER_PRO)

        emulator.shutdown()

        assert len(emulator.dongles) == 0


class TestDongleAntiEmulationDetection:
    """Test anti-emulation detection resistance."""

    def test_dongle_timing_attack_resistance(self) -> None:
        """Dongle operations have realistic timing characteristics."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        timings = []
        for _ in range(10):
            challenge = os.urandom(16)
            start = time.perf_counter()
            emulator.process_challenge(challenge)
            end = time.perf_counter()
            timings.append(end - start)

        avg_timing = sum(timings) / len(timings)
        assert avg_timing > 0
        assert all(t > 0 for t in timings)

    def test_dongle_serial_entropy(self) -> None:
        """Generated serial numbers have high entropy."""
        serials = []
        for _ in range(50):
            spec = DongleSpec(
                dongle_type=DongleType.HASP_HL,
                interface=DongleInterface.USB,
                vendor_id=0x0529,
                product_id=0x0001,
            )
            serials.append(spec.serial_number)

        unique_chars = set()
        for serial in serials:
            unique_chars.update(serial.replace("-", ""))

        assert len(unique_chars) >= 10

    def test_dongle_memory_pattern_validation(self) -> None:
        """Dongle memory contains realistic patterns."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        vendor_product = emulator.memory.read(0x00, 4)
        assert len(vendor_product) == 4
        assert any(b != 0 for b in vendor_product)

        key = emulator.memory.read(0x20, 16)
        assert len(key) == 16
        assert key != b"\x00" * 16

    def test_dongle_challenge_response_uniqueness(self) -> None:
        """Different challenges produce different responses."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"CHALLENGE_KEY_16")

        responses = set()
        for _ in range(20):
            challenge = os.urandom(16)
            response = emulator.process_challenge(challenge)
            responses.add(response)

        assert len(responses) == 20


class TestDongleRealWorldScenarios:
    """Test real-world dongle usage scenarios."""

    def test_commercial_software_license_validation_simulation(self) -> None:
        """Dongle emulates commercial software license validation."""
        emulator = HardwareDongleEmulator()
        dongle_id = emulator.create_dongle(DongleType.HASP_HL)
        dongle = emulator.dongles[dongle_id]

        dongle.memory.write(0x100, b"LICENSE_VALID_FLAG")
        dongle.memory.write(0x120, struct.pack("<I", int(time.time()) + 365 * 24 * 3600))

        license_flag = dongle.memory.read(0x100, 18)
        expiry_time = struct.unpack("<I", dongle.memory.read(0x120, 4))[0]

        assert license_flag == b"LICENSE_VALID_FLAG"
        assert expiry_time > int(time.time())

    def test_feature_bit_manipulation(self) -> None:
        """Dongle supports feature bit manipulation for license tiers."""
        emulator = HardwareDongleEmulator()
        dongle_id = emulator.create_dongle(DongleType.HASP_HL)
        dongle = emulator.dongles[dongle_id]

        feature_bits = 0b11010110
        dongle.memory.write(0x200, bytes([feature_bits]))

        stored_bits = dongle.memory.read(0x200, 1)[0]

        assert stored_bits == feature_bits
        assert stored_bits & 0b00000010 != 0
        assert stored_bits & 0b00100000 == 0

    def test_time_limited_license_emulation(self) -> None:
        """Dongle emulates time-limited license with expiry."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        rtc_response = emulator.process_hasp_command(0x08, b"")
        _status, current_time = struct.unpack("<II", rtc_response)

        expiry_time = current_time + 30 * 24 * 3600

        assert expiry_time > current_time
        assert expiry_time - current_time == 30 * 24 * 3600

    def test_multi_dongle_scenario(self) -> None:
        """Multiple dongles can coexist and be differentiated."""
        emulator = HardwareDongleEmulator()

        dongle_id1 = emulator.create_dongle(DongleType.HASP_HL)
        dongle_id2 = emulator.create_dongle(DongleType.SENTINEL_SUPER_PRO)
        dongle_id3 = emulator.create_dongle(DongleType.CODEOMETER)

        assert len(emulator.dongles) == 3
        assert all(
            emulator.dongles[did].active for did in [dongle_id1, dongle_id2, dongle_id3]
        )

        dongle1_serial = emulator.dongles[dongle_id1].spec.serial_number
        dongle2_serial = emulator.dongles[dongle_id2].spec.serial_number
        dongle3_serial = emulator.dongles[dongle_id3].spec.serial_number

        assert dongle1_serial != dongle2_serial
        assert dongle2_serial != dongle3_serial
        assert dongle1_serial != dongle3_serial

    def test_dongle_memory_persistence_across_operations(self) -> None:
        """Dongle memory persists across multiple operations."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        persistent_data = b"PERSISTENT_LICENSE_DATA"
        emulator.memory.write(0x150, persistent_data)

        for _ in range(10):
            _challenge_response = emulator.process_challenge(os.urandom(16))

        retrieved_data = emulator.memory.read(0x150, len(persistent_data))
        assert retrieved_data == persistent_data

    def test_dongle_cryptographic_operation_chaining(self) -> None:
        """Dongle supports chaining cryptographic operations."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"CRYPTO_CHAIN_KEY")

        original = b"ORIGINAL_PLAINTEXT_DATA"

        encrypted1 = emulator.encrypt_data(original)
        encrypted2 = emulator.encrypt_data(encrypted1)

        decrypted2 = emulator.decrypt_data(encrypted2)
        decrypted1 = emulator.decrypt_data(decrypted2)

        assert decrypted1.rstrip(b"\x00") == original


class TestDongleEdgeCases:
    """Test edge cases and error conditions."""

    def test_dongle_memory_boundary_read(self) -> None:
        """Reading at exact memory boundary works."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
            memory_size=1,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        data = emulator.memory.read(1024 - 16, 16)

        assert len(data) == 16

    def test_dongle_zero_length_read(self) -> None:
        """Zero-length memory read returns empty bytes."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        data = emulator.memory.read(0x00, 0)

        assert data == b""

    def test_dongle_invalid_algorithm(self) -> None:
        """Using invalid algorithm raises error."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        with pytest.raises(ValueError, match="Unsupported algorithm"):
            emulator.encrypt_data(b"DATA", algorithm="INVALID_ALGO")

    def test_hasp_command_insufficient_data(self) -> None:
        """HASP command with insufficient data returns error."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()

        response = emulator.process_hasp_command(0x01, b"\x00")

        assert response == b"\x00\x00\x00\x01"

    def test_sentinel_nonexistent_cell(self) -> None:
        """Reading nonexistent Sentinel cell raises error."""
        spec = DongleSpec(
            dongle_type=DongleType.SENTINEL_SUPER_PRO,
            interface=DongleInterface.USB,
            vendor_id=0x04B9,
            product_id=0x0300,
        )
        emulator = SentinelEmulator(spec)
        emulator.start()

        with pytest.raises(ValueError, match="Cell .* not found"):
            emulator.read_cell(999)

    def test_usb_driver_dongle_not_found(self) -> None:
        """USB control transfer with no dongle raises error."""
        driver = USBDongleDriver()

        with pytest.raises(RuntimeError, match="No dongle found"):
            driver.control_transfer(
                vendor_id=0xFFFF,
                product_id=0xFFFF,
                request_type=0xC0,
                request=0x01,
                value=0,
                index=0,
                data=b"",
            )

    def test_hardware_emulator_invalid_dongle_type(self) -> None:
        """Creating dongle with invalid type raises error."""
        emulator = HardwareDongleEmulator()

        with pytest.raises((ValueError, KeyError)):
            emulator.create_dongle(DongleType.CUSTOM_USB)


class TestDonglePerformance:
    """Test dongle performance characteristics."""

    def test_encryption_performance(self, benchmark: Any) -> None:
        """Encryption operation completes within acceptable time."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"PERFORMANCE_KEY1")
        data = b"PERFORMANCE_TEST_DATA" * 10

        result = benchmark(emulator.encrypt_data, data)

        assert len(result) > 0

    def test_memory_read_performance(self, benchmark: Any) -> None:
        """Memory read operation is fast."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()

        result = benchmark(emulator.memory.read, 0x00, 64)

        assert len(result) == 64

    def test_challenge_response_performance(self, benchmark: Any) -> None:
        """Challenge-response operation is efficient."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = BaseDongleEmulator(spec)
        emulator.start()
        emulator.memory.write(0x20, b"PERF_CHALLENGE16")
        challenge = os.urandom(16)

        result = benchmark(emulator.process_challenge, challenge)

        assert len(result) > 0

    def test_hasp_login_performance(self, benchmark: Any) -> None:
        """HASP login operation is fast."""
        spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0x0529,
            product_id=0x0001,
        )
        emulator = HASPEmulator(spec)
        emulator.start()
        login_data = struct.pack("<I", 1)

        result = benchmark(emulator.process_hasp_command, 0x01, login_data)

        assert len(result) == 8


class TestDongleExportImport:
    """Test dongle configuration export/import."""

    def test_export_preserves_memory_contents(self) -> None:
        """Exported dongle configuration includes memory data."""
        emulator = HardwareDongleEmulator()
        dongle_id = emulator.create_dongle(DongleType.HASP_HL)
        dongle = emulator.dongles[dongle_id]

        test_data = b"EXPORT_TEST_DATA_CONTENT"
        dongle.memory.write(0x180, test_data)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            export_file = f.name

        try:
            emulator.export_dongles(export_file)

            with open(export_file) as f:
                export_data = json.load(f)

            exported_dongle = list(export_data["dongles"].values())[0]
            memory_hex = exported_dongle["memory"]

            assert test_data.hex() in memory_hex
        finally:
            Path(export_file).unlink(missing_ok=True)

    def test_import_restores_memory_contents(self) -> None:
        """Imported dongle configuration restores memory data."""
        emulator1 = HardwareDongleEmulator()
        dongle_id = emulator1.create_dongle(DongleType.HASP_HL)
        dongle = emulator1.dongles[dongle_id]

        test_data = b"IMPORT_TEST_DATA_RESTORE"
        dongle.memory.write(0x190, test_data)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            export_file = f.name

        try:
            emulator1.export_dongles(export_file)

            emulator2 = HardwareDongleEmulator()
            emulator2.import_dongles(export_file)

            imported_dongle_id = list(emulator2.dongles.keys())[0]
            imported_dongle = emulator2.dongles[imported_dongle_id]

            restored_data = imported_dongle.memory.read(0x190, len(test_data))
            assert restored_data == test_data
        finally:
            Path(export_file).unlink(missing_ok=True)

    def test_export_includes_dongle_spec(self) -> None:
        """Export includes complete dongle specification."""
        emulator = HardwareDongleEmulator()
        custom_spec = DongleSpec(
            dongle_type=DongleType.HASP_HL,
            interface=DongleInterface.USB,
            vendor_id=0xABCD,
            product_id=0x1234,
            serial_number="EXPORT-SPEC-TEST",
            firmware_version="3.2.1",
            memory_size=128,
        )
        emulator.create_dongle(DongleType.HASP_HL, custom_spec)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            export_file = f.name

        try:
            emulator.export_dongles(export_file)

            with open(export_file) as f:
                export_data = json.load(f)

            exported_spec = list(export_data["dongles"].values())[0]["spec"]

            assert exported_spec["vendor_id"] == 0xABCD
            assert exported_spec["product_id"] == 0x1234
            assert exported_spec["serial_number"] == "EXPORT-SPEC-TEST"
            assert exported_spec["firmware_version"] == "3.2.1"
            assert exported_spec["memory_size"] == 128
        finally:
            Path(export_file).unlink(missing_ok=True)
