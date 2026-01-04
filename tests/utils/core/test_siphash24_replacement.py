"""Production tests for utils/core/siphash24_replacement.py.

This module validates SipHash-2-4 and SipHash-1-3 cryptographic hashing
implementations used for license key validation and hardware ID computation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct

import pytest

from intellicrack.utils.core.siphash24_replacement import (
    compute_hardware_id_hash,
    hash_license_key,
    siphash13,
    siphash24,
)


class TestSipHash24:
    """Test siphash24 core hashing function."""

    def test_siphash24_basic_hashing(self) -> None:
        """siphash24 produces 8-byte hash output."""
        key = b"0123456789ABCDEF"
        data = b"test data"

        result = siphash24(key, data)

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_deterministic(self) -> None:
        """siphash24 produces consistent output for same inputs."""
        key = b"0123456789ABCDEF"
        data = b"license key data"

        result1 = siphash24(key, data)
        result2 = siphash24(key, data)

        assert result1 == result2

    def test_siphash24_different_keys_different_output(self) -> None:
        """siphash24 produces different output with different keys."""
        data = b"same data"

        result1 = siphash24(b"key1" + b"\x00" * 12, data)
        result2 = siphash24(b"key2" + b"\x00" * 12, data)

        assert result1 != result2

    def test_siphash24_different_data_different_output(self) -> None:
        """siphash24 produces different output for different data."""
        key = b"0123456789ABCDEF"

        result1 = siphash24(key, b"data1")
        result2 = siphash24(key, b"data2")

        assert result1 != result2

    def test_siphash24_handles_empty_data(self) -> None:
        """siphash24 handles empty data input."""
        key = b"0123456789ABCDEF"
        result = siphash24(key, b"")

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_handles_large_data(self) -> None:
        """siphash24 handles large data inputs efficiently."""
        key = b"0123456789ABCDEF"
        large_data = b"A" * 10000

        result = siphash24(key, large_data)

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_key_padding(self) -> None:
        """siphash24 pads keys shorter than 16 bytes."""
        short_key = b"short"
        data = b"test"

        result = siphash24(short_key, data)

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_key_truncation(self) -> None:
        """siphash24 truncates keys longer than 16 bytes."""
        long_key = b"0123456789ABCDEF_EXTRA"
        data = b"test"

        result = siphash24(long_key, data)

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_accepts_string_key(self) -> None:
        """siphash24 accepts string keys and converts to bytes."""
        result = siphash24("string_key", b"data")

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_accepts_string_data(self) -> None:
        """siphash24 accepts string data and converts to bytes."""
        key = b"0123456789ABCDEF"
        result = siphash24(key, "string data")

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_binary_license_data(self) -> None:
        """siphash24 handles binary license data correctly."""
        key = b"LICENSEKEY123456"
        license_data = b"\x90\x50\x56\x53\x48ABC-DEF-GHI"

        result = siphash24(key, license_data)

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash24_avalanche_effect(self) -> None:
        """siphash24 shows avalanche effect (small input change -> large output change)."""
        key = b"0123456789ABCDEF"

        result1 = siphash24(key, b"test data")
        result2 = siphash24(key, b"test datb")

        hash1_int = struct.unpack("<Q", result1)[0]
        hash2_int = struct.unpack("<Q", result2)[0]

        bits_different = bin(hash1_int ^ hash2_int).count("1")
        assert bits_different > 20


class TestSipHash13:
    """Test siphash13 faster variant implementation."""

    def test_siphash13_basic_usage(self) -> None:
        """siphash13 produces 8-byte hash output."""
        hasher = siphash13()
        result = hasher(b"test data")

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash13_with_custom_key(self) -> None:
        """siphash13 accepts custom key."""
        key = b"CUSTOMKEY1234567"
        hasher = siphash13(key)
        result = hasher(b"data")

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash13_hashlib_style_update(self) -> None:
        """siphash13 supports hashlib-style update/digest interface."""
        hasher = siphash13()
        hasher.update(b"part1")
        hasher.update(b"part2")
        result = hasher.digest()

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash13_hexdigest(self) -> None:
        """siphash13 supports hexdigest method."""
        hasher = siphash13()
        hasher.update(b"test")
        hex_result = hasher.hexdigest()

        assert isinstance(hex_result, str)
        assert len(hex_result) == 16
        assert all(c in "0123456789abcdef" for c in hex_result)

    def test_siphash13_update_with_string(self) -> None:
        """siphash13 update accepts string input."""
        hasher = siphash13()
        hasher.update("string data")
        result = hasher.digest()

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash13_update_incremental(self) -> None:
        """siphash13 incremental updates produce consistent result."""
        hasher1 = siphash13()
        hasher1.update(b"data1")
        hasher1.update(b"data2")
        result1 = hasher1.digest()

        hasher2 = siphash13()
        hasher2.update(b"data1data2")
        result2 = hasher2.digest()

        assert result1 == result2

    def test_siphash13_callable_interface(self) -> None:
        """siphash13 callable interface works correctly."""
        hasher = siphash13()
        result = hasher(b"test data")

        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_siphash13_deterministic(self) -> None:
        """siphash13 produces consistent output for same inputs."""
        hasher1 = siphash13()
        hasher1.update(b"data")
        result1 = hasher1.digest()

        hasher2 = siphash13()
        hasher2.update(b"data")
        result2 = hasher2.digest()

        assert result1 == result2


class TestHashLicenseKey:
    """Test hash_license_key for license key hashing."""

    def test_hash_license_key_basic(self) -> None:
        """hash_license_key returns hash bytes and integer."""
        key_data = "ABC-DEF-GHI-JKL"

        hash_bytes, hash_int = hash_license_key(key_data)

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 8
        assert isinstance(hash_int, int)
        assert hash_int >= 0

    def test_hash_license_key_deterministic(self) -> None:
        """hash_license_key produces consistent output for same key."""
        key_data = "LICENSE-KEY-12345"

        result1 = hash_license_key(key_data)
        result2 = hash_license_key(key_data)

        assert result1 == result2

    def test_hash_license_key_different_keys(self) -> None:
        """hash_license_key produces different output for different keys."""
        result1 = hash_license_key("KEY-A")
        result2 = hash_license_key("KEY-B")

        assert result1 != result2

    def test_hash_license_key_accepts_bytes(self) -> None:
        """hash_license_key accepts bytes input."""
        key_data = b"LICENSE-KEY-BYTES"

        hash_bytes, hash_int = hash_license_key(key_data)

        assert isinstance(hash_bytes, bytes)
        assert isinstance(hash_int, int)

    def test_hash_license_key_default_salt(self) -> None:
        """hash_license_key uses default salt correctly."""
        key_data = "TEST-KEY"

        hash_bytes1, _ = hash_license_key(key_data)
        hash_bytes2, _ = hash_license_key(key_data, salt=b"LICENSEKEY123456")

        assert hash_bytes1 == hash_bytes2

    def test_hash_license_key_custom_salt(self) -> None:
        """hash_license_key respects custom salt."""
        key_data = "TEST-KEY"

        result1 = hash_license_key(key_data, salt=b"SALT1" + b"\x00" * 11)
        result2 = hash_license_key(key_data, salt=b"SALT2" + b"\x00" * 11)

        assert result1 != result2

    def test_hash_license_key_hash_int_matches_bytes(self) -> None:
        """hash_license_key integer matches bytes representation."""
        key_data = "VALIDATE-KEY"

        hash_bytes, hash_int = hash_license_key(key_data)

        unpacked = struct.unpack("<Q", hash_bytes)[0]
        assert unpacked == hash_int

    def test_hash_license_key_realistic_keys(self) -> None:
        """hash_license_key handles realistic license key formats."""
        realistic_keys = [
            "ABCD-EFGH-IJKL-MNOP",
            "12345-67890-ABCDE",
            "TRIAL-2025-12345",
            "PRO-LICENSE-XYZ123",
        ]

        for key in realistic_keys:
            hash_bytes, hash_int = hash_license_key(key)
            assert len(hash_bytes) == 8
            assert hash_int >= 0

    def test_hash_license_key_long_keys(self) -> None:
        """hash_license_key handles long license keys."""
        long_key = "A" * 1000

        hash_bytes, hash_int = hash_license_key(long_key)

        assert len(hash_bytes) == 8
        assert hash_int >= 0

    def test_hash_license_key_binary_safe(self) -> None:
        """hash_license_key handles binary data safely."""
        binary_key = b"\x00\x01\x02\x03\x90\x50\x56\x53"

        hash_bytes, hash_int = hash_license_key(binary_key)

        assert len(hash_bytes) == 8
        assert hash_int >= 0


class TestComputeHardwareIdHash:
    """Test compute_hardware_id_hash for hardware ID hashing."""

    def test_hardware_id_hash_basic(self) -> None:
        """compute_hardware_id_hash returns hash bytes and hex string."""
        components: list[bytes | str] = ["CPU-12345", "MAC-AABBCCDD", "DISK-XYZ"]

        hash_bytes, hex_str = compute_hardware_id_hash(components)

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 8
        assert isinstance(hex_str, str)
        assert len(hex_str) == 16

    def test_hardware_id_hash_deterministic(self) -> None:
        """compute_hardware_id_hash produces consistent output for same components."""
        components: list[bytes | str] = ["CPU-ID", "MAC-ADDR", "DISK-SN"]

        result1 = compute_hardware_id_hash(components)
        result2 = compute_hardware_id_hash(components)

        assert result1 == result2

    def test_hardware_id_hash_order_sensitive(self) -> None:
        """compute_hardware_id_hash is sensitive to component order."""
        list1: list[bytes | str] = ["A", "B", "C"]
        list2: list[bytes | str] = ["C", "B", "A"]
        result1 = compute_hardware_id_hash(list1)
        result2 = compute_hardware_id_hash(list2)

        assert result1 != result2

    def test_hardware_id_hash_accepts_bytes_components(self) -> None:
        """compute_hardware_id_hash accepts bytes components."""
        components: list[bytes | str] = [b"CPU-12345", b"MAC-AABBCC"]

        hash_bytes, hex_str = compute_hardware_id_hash(components)

        assert isinstance(hash_bytes, bytes)
        assert isinstance(hex_str, str)

    def test_hardware_id_hash_mixed_types(self) -> None:
        """compute_hardware_id_hash handles mixed string/bytes components."""
        components: list[bytes | str] = ["CPU-STRING", b"MAC-BYTES", "DISK-STRING"]

        hash_bytes, hex_str = compute_hardware_id_hash(components)

        assert len(hash_bytes) == 8
        assert len(hex_str) == 16

    def test_hardware_id_hash_hex_format(self) -> None:
        """compute_hardware_id_hash produces valid hex string."""
        components: list[bytes | str] = ["TEST1", "TEST2"]

        _, hex_str = compute_hardware_id_hash(components)

        assert all(c in "0123456789abcdef" for c in hex_str)

    def test_hardware_id_hash_matches_bytes(self) -> None:
        """compute_hardware_id_hash hex string matches bytes."""
        components: list[bytes | str] = ["CPU", "MAC"]

        hash_bytes, hex_str = compute_hardware_id_hash(components)

        assert hash_bytes.hex() == hex_str

    def test_hardware_id_hash_empty_components(self) -> None:
        """compute_hardware_id_hash handles empty component list."""
        hash_bytes, hex_str = compute_hardware_id_hash([])

        assert len(hash_bytes) == 8
        assert len(hex_str) == 16

    def test_hardware_id_hash_realistic_components(self) -> None:
        """compute_hardware_id_hash handles realistic hardware identifiers."""
        components: list[bytes | str] = [
            "CPU-Intel-Core-i7-12700K-Serial-12345",
            "MAC-00:1A:2B:3C:4D:5E",
            "DISK-SN-WD-WCC4E1234567",
            "BIOS-UUID-12345678-90AB-CDEF-1234-567890ABCDEF",
        ]

        hash_bytes, hex_str = compute_hardware_id_hash(components)

        assert len(hash_bytes) == 8
        assert len(hex_str) == 16

    def test_hardware_id_hash_single_component(self) -> None:
        """compute_hardware_id_hash works with single component."""
        components: list[bytes | str] = ["SINGLE-HWID"]

        hash_bytes, hex_str = compute_hardware_id_hash(components)

        assert len(hash_bytes) == 8
        assert len(hex_str) == 16

    def test_hardware_id_hash_many_components(self) -> None:
        """compute_hardware_id_hash handles many hardware components."""
        components: list[bytes | str] = [f"COMPONENT-{i}" for i in range(20)]

        hash_bytes, hex_str = compute_hardware_id_hash(components)

        assert len(hash_bytes) == 8
        assert len(hex_str) == 16


class TestSipHashIntegration:
    """Test SipHash functions in integrated scenarios."""

    def test_license_validation_workflow(self) -> None:
        """SipHash functions support license validation workflow."""
        license_key = "PREMIUM-2025-ABC123"

        hash1_bytes, hash1_int = hash_license_key(license_key)

        stored_hash = hash1_bytes
        hash2_bytes, _ = hash_license_key(license_key)

        assert hash2_bytes == stored_hash

    def test_hardware_locked_license_workflow(self) -> None:
        """SipHash functions support hardware-locked licensing."""
        license_key = "HWID-LICENSE-XYZ"
        hardware_components: list[bytes | str] = ["CPU-12345", "MAC-AABBCC"]

        license_hash_bytes, _ = hash_license_key(license_key)
        hwid_hash_bytes, hwid_hex = compute_hardware_id_hash(hardware_components)

        combined_data = license_hash_bytes + hwid_hash_bytes
        assert len(combined_data) == 16

    def test_different_hash_functions_produce_different_outputs(self) -> None:
        """Different SipHash variants produce different outputs."""
        data = b"test data"
        key = b"0123456789ABCDEF"

        hash24 = siphash24(key, data)

        hasher13 = siphash13(key)
        hash13 = hasher13(data)

        assert hash24 != hash13

    def test_license_key_collision_resistance(self) -> None:
        """hash_license_key shows collision resistance for similar keys."""
        keys = [
            "LICENSE-KEY-00001",
            "LICENSE-KEY-00002",
            "LICENSE-KEY-00003",
        ]

        hashes = [hash_license_key(key)[1] for key in keys]

        assert len(set(hashes)) == len(hashes)

    def test_hardware_id_uniqueness(self) -> None:
        """compute_hardware_id_hash produces unique IDs for different hardware."""
        hw_configs: list[list[bytes | str]] = [
            ["CPU-A", "MAC-1"],
            ["CPU-B", "MAC-1"],
            ["CPU-A", "MAC-2"],
        ]

        ids = [compute_hardware_id_hash(hw)[1] for hw in hw_configs]

        assert len(set(ids)) == len(ids)
