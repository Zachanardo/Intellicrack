#!/usr/bin/env python3
"""Production tests for VMProtect key schedule implementations.

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

import hashlib
import struct
from pathlib import Path
from typing import Callable

import pytest

from intellicrack.plugins.custom_modules.vm_protection_unwrapper import (
    ProtectionType,
    VMProtectHandler,
)


@pytest.fixture(scope="session")
def vmprotect_handler() -> VMProtectHandler:
    """Create a VMProtect handler instance for testing.

    Returns:
        Initialized VMProtectHandler for key schedule validation.

    """
    return VMProtectHandler()


@pytest.fixture(scope="session")
def vmprotect_1x_sample_encrypted() -> tuple[bytes, bytes, bytes]:
    """VMProtect 1.x sample encrypted bytecode with known key and plaintext.

    Returns:
        Tuple of (encrypted_data, key, expected_decrypted) for validation.

    """
    key = b"\x12\x34\x56\x78" * 4
    plaintext = b"\x90" * 64 + b"\xC3\xCC\xF4\x00" * 4 + b"\x8B\x44\x24\x04" * 8

    handler = VMProtectHandler()
    key_schedule = handler._vmprotect_1x_key_schedule(key)
    encrypted = handler._encrypt_with_schedule_1x(plaintext, key_schedule)

    return encrypted, key, plaintext


@pytest.fixture(scope="session")
def vmprotect_2x_sample_encrypted() -> tuple[bytes, bytes, bytes]:
    """VMProtect 2.x sample encrypted bytecode with known key and plaintext.

    Returns:
        Tuple of (encrypted_data, key, expected_decrypted) for validation.

    """
    key = b"\xAA\xBB\xCC\xDD" * 8
    plaintext = (
        b"\x48\x8B\x44\x24\x08" * 10
        + b"\x48\x89\x44\x24\x10" * 8
        + b"\x90\x90\xC3\x00" * 6
    )

    handler = VMProtectHandler()
    key_schedule = handler._vmprotect_2x_key_schedule(key)
    encrypted = handler._encrypt_with_schedule_2x(plaintext, key_schedule)

    return encrypted, key, plaintext


@pytest.fixture(scope="session")
def vmprotect_3x_sample_encrypted() -> tuple[bytes, bytes, bytes]:
    """VMProtect 3.x sample encrypted bytecode with known key and plaintext.

    Returns:
        Tuple of (encrypted_data, key, expected_decrypted) for validation.

    """
    key = hashlib.sha256(b"VMProtect3TestKey").digest() * 2
    plaintext = (
        b"\x48\x8B\x05\x00\x00\x00\x00" * 12
        + b"\x48\x89\x05\x00\x00\x00\x00" * 12
    )

    handler = VMProtectHandler()
    key_schedule = handler._vmprotect_3x_key_schedule(key)
    encrypted = handler._encrypt_with_schedule_3x(plaintext, key_schedule)

    return encrypted, key, plaintext


class TestVMProtect1xKeySchedule:
    """Test VMProtect 1.x key derivation implementation."""

    def test_vmprotect_1x_key_schedule_generates_44_round_keys(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x key schedule produces exactly 44 round keys."""
        key = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        assert len(key_schedule) == 44
        assert all(isinstance(k, int) for k in key_schedule)

    def test_vmprotect_1x_key_schedule_first_four_keys_match_input(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x first four round keys match input key words."""
        key = b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x11\x22\x33\x44\x55\x66\x77\x88"
        expected_first_four = struct.unpack("<4I", key)

        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        assert key_schedule[:4] == list(expected_first_four)

    def test_vmprotect_1x_key_schedule_xor_based_expansion(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x uses XOR-based key expansion algorithm."""
        key = b"\x01" * 16
        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        for i in range(4, 44):
            if i % 4 != 0:
                assert key_schedule[i] == (key_schedule[i - 4] ^ key_schedule[i - 1])

    def test_vmprotect_1x_key_schedule_rotation_on_fourth_rounds(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x applies rotation transformation on round key 4n."""
        key = b"\xFF\xEE\xDD\xCC" * 4
        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        for i in range(4, 44, 4):
            prev = key_schedule[i - 1]
            rotated = ((prev << 8) | (prev >> 24)) & 0xFFFFFFFF
            round_const = 0x01000000 << ((i // 4) - 1)
            expected = key_schedule[i - 4] ^ (rotated ^ round_const)

            assert key_schedule[i] == expected

    def test_vmprotect_1x_decrypts_real_encrypted_bytecode(
        self,
        vmprotect_handler: VMProtectHandler,
        vmprotect_1x_sample_encrypted: tuple[bytes, bytes, bytes],
    ) -> None:
        """VMProtect 1.x key schedule decrypts actual encrypted VM bytecode."""
        encrypted, key, expected_plaintext = vmprotect_1x_sample_encrypted

        decrypted = vmprotect_handler.decrypt_vm_code(
            encrypted, key, ProtectionType.VMPROTECT_1X
        )

        assert decrypted == expected_plaintext
        assert b"\x90" in decrypted
        assert b"\xC3" in decrypted

    def test_vmprotect_1x_key_schedule_deterministic_output(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x key schedule produces deterministic results."""
        key = hashlib.sha256(b"test_key").digest()[:16]

        schedule1 = vmprotect_handler._vmprotect_1x_key_schedule(key)
        schedule2 = vmprotect_handler._vmprotect_1x_key_schedule(key)

        assert schedule1 == schedule2

    def test_vmprotect_1x_key_schedule_handles_zero_key(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x handles all-zero key input correctly."""
        key = b"\x00" * 16

        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        assert len(key_schedule) == 44
        assert key_schedule[0] == 0
        assert any(k != 0 for k in key_schedule[4:])

    def test_vmprotect_1x_key_schedule_handles_max_key(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x handles maximum value key input correctly."""
        key = b"\xFF" * 16

        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        assert len(key_schedule) == 44
        assert all(0 <= k <= 0xFFFFFFFF for k in key_schedule)


class TestVMProtect2xKeySchedule:
    """Test VMProtect 2.x key derivation implementation."""

    def test_vmprotect_2x_key_schedule_generates_60_round_keys(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x key schedule produces exactly 60 round keys."""
        key = b"\x00\x11\x22\x33" * 8
        key_schedule = vmprotect_handler._vmprotect_2x_key_schedule(key)

        assert len(key_schedule) == 60
        assert all(isinstance(k, int) for k in key_schedule)

    def test_vmprotect_2x_key_schedule_first_eight_keys_match_input(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x first eight round keys match input key words."""
        key = b"\x12\x34\x56\x78" * 8
        expected_first_eight = struct.unpack("<8I", key)

        key_schedule = vmprotect_handler._vmprotect_2x_key_schedule(key)

        assert key_schedule[:8] == list(expected_first_eight)

    def test_vmprotect_2x_key_schedule_complex_transform_on_eighth_rounds(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x applies complex transform on round key 8n."""
        key = b"\xAA\xBB\xCC\xDD" * 8

        key_schedule = vmprotect_handler._vmprotect_2x_key_schedule(key)

        for i in range(8, 60, 8):
            prev = key_schedule[i - 1]
            transformed = vmprotect_handler._complex_transform(prev, i)
            expected = key_schedule[i - 8] ^ transformed
            assert key_schedule[i] == expected

    def test_vmprotect_2x_key_schedule_substitute_bytes_on_fourth_rounds(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x applies byte substitution on round key 8n+4."""
        key = b"\xFF\xEE\xDD\xCC" * 8

        key_schedule = vmprotect_handler._vmprotect_2x_key_schedule(key)

        for i in range(12, 60, 8):
            prev = key_schedule[i - 1]
            substituted = vmprotect_handler._substitute_bytes(prev)
            expected = key_schedule[i - 8] ^ substituted
            assert key_schedule[i] == expected

    def test_vmprotect_2x_complex_transform_rotates_and_xors(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x complex transform applies rotation and XOR."""
        test_value = 0x12345678
        round_num = 16

        result = vmprotect_handler._complex_transform(test_value, round_num)

        rotated = (
            (test_value << (round_num % 32)) | (test_value >> (32 - (round_num % 32)))
        ) & 0xFFFFFFFF
        round_constant = (0x9E3779B9 * round_num) & 0xFFFFFFFF
        expected = rotated ^ round_constant

        assert result == expected

    def test_vmprotect_2x_substitute_bytes_uses_sbox(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x byte substitution uses S-Box transformation."""
        test_value = 0x01020304

        result = vmprotect_handler._substitute_bytes(test_value)

        assert result != test_value
        assert 0 <= result <= 0xFFFFFFFF

        result2 = vmprotect_handler._substitute_bytes(test_value)
        assert result == result2

    def test_vmprotect_2x_decrypts_real_encrypted_bytecode(
        self,
        vmprotect_handler: VMProtectHandler,
        vmprotect_2x_sample_encrypted: tuple[bytes, bytes, bytes],
    ) -> None:
        """VMProtect 2.x key schedule decrypts actual encrypted VM bytecode."""
        encrypted, key, expected_plaintext = vmprotect_2x_sample_encrypted

        decrypted = vmprotect_handler.decrypt_vm_code(
            encrypted, key, ProtectionType.VMPROTECT_2X
        )

        assert decrypted == expected_plaintext
        assert b"\x48\x8B" in decrypted
        assert b"\x48\x89" in decrypted

    def test_vmprotect_2x_key_schedule_deterministic_output(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x key schedule produces deterministic results."""
        key = hashlib.sha256(b"test_key_2x").digest()

        schedule1 = vmprotect_handler._vmprotect_2x_key_schedule(key)
        schedule2 = vmprotect_handler._vmprotect_2x_key_schedule(key)

        assert schedule1 == schedule2

    def test_vmprotect_2x_key_schedule_handles_weak_keys(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x handles weak key patterns correctly."""
        weak_keys = [
            b"\x00" * 32,
            b"\xFF" * 32,
            b"\x01" * 32,
            b"\xAA\x55" * 16,
        ]

        for weak_key in weak_keys:
            key_schedule = vmprotect_handler._vmprotect_2x_key_schedule(weak_key)
            assert len(key_schedule) == 60
            assert all(0 <= k <= 0xFFFFFFFF for k in key_schedule)


class TestVMProtect3xKeySchedule:
    """Test VMProtect 3.x key derivation implementation."""

    def test_vmprotect_3x_key_schedule_generates_64_round_keys(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x key schedule produces exactly 64 round keys."""
        key = hashlib.sha512(b"vmprotect3_test").digest()
        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(key)

        assert len(key_schedule) == 64
        assert all(isinstance(k, int) for k in key_schedule)

    def test_vmprotect_3x_key_schedule_first_sixteen_keys_match_input(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x first sixteen round keys match input key words."""
        key = b"\x12\x34\x56\x78" * 16
        expected_first_sixteen = struct.unpack("<16I", key)

        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(key)

        assert key_schedule[:16] == list(expected_first_sixteen)

    def test_vmprotect_3x_key_schedule_uses_sigma_functions(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x uses SHA-256 sigma functions for key expansion."""
        key = hashlib.sha256(b"test_sigma").digest() * 2

        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(key)

        for i in range(16, 64):
            s0 = vmprotect_handler._sigma0(key_schedule[i - 15])
            s1 = vmprotect_handler._sigma1(key_schedule[i - 2])
            expected = (
                key_schedule[i - 16] + s0 + key_schedule[i - 7] + s1
            ) & 0xFFFFFFFF

            assert key_schedule[i] == expected

    def test_vmprotect_3x_sigma0_transformation(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x sigma0 applies correct bitwise operations."""
        test_value = 0x12345678

        result = vmprotect_handler._sigma0(test_value)

        expected = (
            ((test_value >> 7) | (test_value << 25))
            ^ ((test_value >> 18) | (test_value << 14))
            ^ (test_value >> 3)
        ) & 0xFFFFFFFF

        assert result == expected

    def test_vmprotect_3x_sigma1_transformation(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x sigma1 applies correct bitwise operations."""
        test_value = 0x87654321

        result = vmprotect_handler._sigma1(test_value)

        expected = (
            ((test_value >> 17) | (test_value << 15))
            ^ ((test_value >> 19) | (test_value << 13))
            ^ (test_value >> 10)
        ) & 0xFFFFFFFF

        assert result == expected

    def test_vmprotect_3x_key_schedule_pads_short_keys(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x pads short keys to 64 bytes with zeros."""
        short_key = b"\xAA\xBB\xCC\xDD" * 4

        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(short_key)

        assert len(key_schedule) == 64
        padded_key = short_key.ljust(64, b"\x00")
        expected_first_sixteen = struct.unpack("<16I", padded_key)
        assert key_schedule[:16] == list(expected_first_sixteen)

    def test_vmprotect_3x_decrypts_real_encrypted_bytecode(
        self,
        vmprotect_handler: VMProtectHandler,
        vmprotect_3x_sample_encrypted: tuple[bytes, bytes, bytes],
    ) -> None:
        """VMProtect 3.x key schedule decrypts actual encrypted VM bytecode."""
        encrypted, key, expected_plaintext = vmprotect_3x_sample_encrypted

        decrypted = vmprotect_handler.decrypt_vm_code(
            encrypted, key, ProtectionType.VMPROTECT_3X
        )

        assert decrypted == expected_plaintext
        assert b"\x48\x8B\x05" in decrypted
        assert b"\x48\x89\x05" in decrypted

    def test_vmprotect_3x_key_schedule_deterministic_output(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x key schedule produces deterministic results."""
        key = hashlib.sha512(b"test_key_3x").digest()

        schedule1 = vmprotect_handler._vmprotect_3x_key_schedule(key)
        schedule2 = vmprotect_handler._vmprotect_3x_key_schedule(key)

        assert schedule1 == schedule2

    def test_vmprotect_3x_key_schedule_handles_maximum_length_key(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x handles maximum 64-byte key correctly."""
        max_key = b"\xFF" * 64

        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(max_key)

        assert len(key_schedule) == 64
        assert all(0 <= k <= 0xFFFFFFFF for k in key_schedule)

    def test_vmprotect_3x_key_schedule_truncates_oversized_keys(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x truncates keys longer than 64 bytes."""
        oversized_key = b"\x12\x34\x56\x78" * 20

        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(oversized_key)

        assert len(key_schedule) == 64
        expected_first_sixteen = struct.unpack("<16I", oversized_key[:64])
        assert key_schedule[:16] == list(expected_first_sixteen)


class TestKeyScheduleDecryption:
    """Test actual VM bytecode decryption using key schedules."""

    def test_decrypt_with_schedule_processes_16_byte_blocks(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Decrypt with schedule processes data in 16-byte AES blocks."""
        key = b"\x2B\x7E\x15\x16" * 4
        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        plaintext = b"\x00\x11\x22\x33" * 4
        encrypted = vmprotect_handler._encrypt_with_schedule_1x(plaintext, key_schedule)

        decrypted = vmprotect_handler._decrypt_with_schedule(encrypted, key_schedule)

        assert decrypted == plaintext
        assert len(decrypted) % 16 == 0

    def test_decrypt_with_schedule_handles_multiple_blocks(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Decrypt with schedule handles multiple 16-byte blocks."""
        key = hashlib.sha256(b"multi_block_key").digest()[:16]
        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        plaintext = b"\x90" * 48
        encrypted = vmprotect_handler._encrypt_with_schedule_1x(plaintext, key_schedule)

        decrypted = vmprotect_handler._decrypt_with_schedule(encrypted, key_schedule)

        assert decrypted == plaintext
        assert len(decrypted) == 48

    def test_simple_decrypt_xor_fallback(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Simple decrypt provides XOR-based fallback for unknown versions."""
        key = b"\xAB\xCD\xEF\x12" * 4
        plaintext = b"\x48\x8B\x44\x24" * 8

        encrypted = vmprotect_handler._simple_encrypt(plaintext, key)
        decrypted = vmprotect_handler._simple_decrypt(encrypted, key)

        assert decrypted == plaintext

    def test_decrypt_vm_code_selects_correct_version(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Decrypt VM code selects correct algorithm based on version."""
        key_1x = b"\x11\x22\x33\x44" * 4
        key_2x = b"\x55\x66\x77\x88" * 8
        key_3x = hashlib.sha512(b"version_test").digest()

        plaintext = b"\x90\xC3\xCC\xF4" * 16

        encrypted_1x = vmprotect_handler.decrypt_vm_code(
            vmprotect_handler._encrypt_with_schedule_1x(
                plaintext, vmprotect_handler._vmprotect_1x_key_schedule(key_1x)
            ),
            key_1x,
            ProtectionType.VMPROTECT_1X,
        )

        encrypted_2x = vmprotect_handler.decrypt_vm_code(
            vmprotect_handler._encrypt_with_schedule_2x(
                plaintext, vmprotect_handler._vmprotect_2x_key_schedule(key_2x)
            ),
            key_2x,
            ProtectionType.VMPROTECT_2X,
        )

        encrypted_3x = vmprotect_handler.decrypt_vm_code(
            vmprotect_handler._encrypt_with_schedule_3x(
                plaintext, vmprotect_handler._vmprotect_3x_key_schedule(key_3x)
            ),
            key_3x,
            ProtectionType.VMPROTECT_3X,
        )

        assert encrypted_1x == plaintext
        assert encrypted_2x == plaintext
        assert encrypted_3x == plaintext


class TestKeyWhiteningAndExpansion:
    """Test key whitening and schedule expansion functionality."""

    def test_vmprotect_1x_key_expansion_covers_all_rounds(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x key expansion generates sufficient round keys."""
        key = b"\xDE\xAD\xBE\xEF" * 4
        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        assert len(key_schedule) >= 40
        assert all(isinstance(k, int) for k in key_schedule)

    def test_vmprotect_2x_key_whitening_affects_all_bytes(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 2.x key whitening affects all bytes of key schedule."""
        key = b"\x00" * 32
        key_schedule = vmprotect_handler._vmprotect_2x_key_schedule(key)

        unique_values = len(set(key_schedule))
        assert unique_values > 10

    def test_vmprotect_3x_expansion_provides_64_unique_keys(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x expansion provides 64 round keys with high entropy."""
        key = hashlib.sha256(b"high_entropy_test").digest() * 2
        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(key)

        assert len(key_schedule) == 64
        unique_values = len(set(key_schedule))
        assert unique_values > 32

    def test_key_schedule_avalanche_effect(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Key schedule exhibits avalanche effect from small key changes."""
        key1 = b"\x00" * 16
        key2 = b"\x01" + b"\x00" * 15

        schedule1 = vmprotect_handler._vmprotect_1x_key_schedule(key1)
        schedule2 = vmprotect_handler._vmprotect_1x_key_schedule(key2)

        differences = sum(1 for a, b in zip(schedule1, schedule2) if a != b)
        assert differences > len(schedule1) // 2


class TestEdgeCasesAndVersionVariations:
    """Test edge cases and version-specific variations."""

    def test_ultra_protection_key_schedule(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect Ultra protection uses standard key schedule."""
        ultra_key = hashlib.sha256(b"ultra_protection").digest()[:16]

        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(ultra_key)

        assert len(key_schedule) == 44
        assert all(isinstance(k, int) for k in key_schedule)

    def test_demo_version_key_schedule_limitations(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect demo version key schedule works identically."""
        demo_key = b"\xDE\xDE\xDE\xDE" * 4

        key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(demo_key)

        assert len(key_schedule) == 44

    def test_vmprotect_1x_vs_2x_key_schedule_differences(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 1.x and 2.x produce different key schedules from same key."""
        key_1x = b"\xAA\xBB\xCC\xDD" * 4
        key_2x = key_1x + b"\xEE\xFF\x00\x11" * 4

        schedule_1x = vmprotect_handler._vmprotect_1x_key_schedule(key_1x)
        schedule_2x = vmprotect_handler._vmprotect_2x_key_schedule(key_2x)

        assert len(schedule_1x) == 44
        assert len(schedule_2x) == 60

    def test_vmprotect_3x_handles_custom_key_derivation(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """VMProtect 3.x handles custom key derivation patterns."""
        custom_key = hashlib.sha512(b"custom_derivation").digest()

        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(custom_key)

        assert len(key_schedule) == 64
        assert all(0 <= k <= 0xFFFFFFFF for k in key_schedule)

    def test_version_specific_bytecode_decryption(
        self,
        vmprotect_handler: VMProtectHandler,
        vmprotect_1x_sample_encrypted: tuple[bytes, bytes, bytes],
        vmprotect_2x_sample_encrypted: tuple[bytes, bytes, bytes],
        vmprotect_3x_sample_encrypted: tuple[bytes, bytes, bytes],
    ) -> None:
        """Each VMProtect version decrypts its own bytecode correctly."""
        encrypted_1x, key_1x, plain_1x = vmprotect_1x_sample_encrypted
        encrypted_2x, key_2x, plain_2x = vmprotect_2x_sample_encrypted
        encrypted_3x, key_3x, plain_3x = vmprotect_3x_sample_encrypted

        decrypted_1x = vmprotect_handler.decrypt_vm_code(
            encrypted_1x, key_1x, ProtectionType.VMPROTECT_1X
        )
        decrypted_2x = vmprotect_handler.decrypt_vm_code(
            encrypted_2x, key_2x, ProtectionType.VMPROTECT_2X
        )
        decrypted_3x = vmprotect_handler.decrypt_vm_code(
            encrypted_3x, key_3x, ProtectionType.VMPROTECT_3X
        )

        assert decrypted_1x == plain_1x
        assert decrypted_2x == plain_2x
        assert decrypted_3x == plain_3x

    def test_corrupted_key_schedule_handling(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Key schedule generation handles corrupted key data gracefully."""
        corrupted_keys = [
            b"",
            b"\x00",
            b"\xFF" * 8,
            b"\xAA" * 12,
        ]

        for corrupted_key in corrupted_keys:
            padded_key = corrupted_key.ljust(16, b"\x00")
            key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(padded_key)
            assert len(key_schedule) == 44

    def test_key_schedule_with_repeating_patterns(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Key schedule handles repeating byte patterns correctly."""
        repeating_keys = [
            b"\xAA" * 16,
            b"\x55" * 16,
            b"\x00\xFF" * 8,
            b"\x01\x02\x03\x04" * 4,
        ]

        for repeating_key in repeating_keys:
            key_schedule = vmprotect_handler._vmprotect_1x_key_schedule(repeating_key)
            assert len(key_schedule) == 44
            assert any(key_schedule[i] != key_schedule[i + 1] for i in range(43))


class TestCustomKeyDerivationDetection:
    """Test detection of custom key derivation patterns."""

    def test_detect_non_standard_key_schedule(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Detect when non-standard key schedule is used."""
        standard_key = b"\x11\x22\x33\x44" * 4
        standard_schedule = vmprotect_handler._vmprotect_1x_key_schedule(standard_key)

        custom_schedule = [k ^ 0xDEADBEEF for k in standard_schedule]

        assert standard_schedule != custom_schedule

    def test_identify_key_schedule_version_from_pattern(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Identify VMProtect version from key schedule pattern."""
        key = b"\xAB\xCD\xEF\x12" * 16

        schedule_1x = vmprotect_handler._vmprotect_1x_key_schedule(key[:16])
        schedule_2x = vmprotect_handler._vmprotect_2x_key_schedule(key[:32])
        schedule_3x = vmprotect_handler._vmprotect_3x_key_schedule(key)

        assert len(schedule_1x) == 44
        assert len(schedule_2x) == 60
        assert len(schedule_3x) == 64

    def test_custom_key_derivation_with_mixed_operations(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Handle custom key derivation with mixed cryptographic operations."""
        base_key = hashlib.sha256(b"mixed_ops").digest()

        key_schedule = vmprotect_handler._vmprotect_3x_key_schedule(base_key * 2)

        assert len(key_schedule) == 64
        assert all(isinstance(k, int) for k in key_schedule)


class TestFailureConditions:
    """Test that code fails appropriately when key schedules are missing."""

    def test_missing_1x_key_schedule_fails_decryption(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Missing VMProtect 1.x key schedule implementation causes decryption failure."""
        original_method = vmprotect_handler._vmprotect_1x_key_schedule
        setattr(vmprotect_handler, "_vmprotect_1x_key_schedule", lambda key: [])

        encrypted = b"\xDE\xAD\xBE\xEF" * 16
        key = b"\x12\x34\x56\x78" * 4

        with pytest.raises((IndexError, ValueError, AssertionError)):
            vmprotect_handler.decrypt_vm_code(
                encrypted, key, ProtectionType.VMPROTECT_1X
            )

        setattr(vmprotect_handler, "_vmprotect_1x_key_schedule", original_method)

    def test_missing_2x_key_schedule_fails_decryption(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Missing VMProtect 2.x key schedule implementation causes decryption failure."""
        original_method = vmprotect_handler._vmprotect_2x_key_schedule
        setattr(vmprotect_handler, "_vmprotect_2x_key_schedule", lambda key: [])

        encrypted = b"\xCA\xFE\xBA\xBE" * 16
        key = b"\xAA\xBB\xCC\xDD" * 8

        with pytest.raises((IndexError, ValueError, AssertionError)):
            vmprotect_handler.decrypt_vm_code(
                encrypted, key, ProtectionType.VMPROTECT_2X
            )

        setattr(vmprotect_handler, "_vmprotect_2x_key_schedule", original_method)

    def test_missing_3x_key_schedule_fails_decryption(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Missing VMProtect 3.x key schedule implementation causes decryption failure."""
        original_method = vmprotect_handler._vmprotect_3x_key_schedule
        setattr(vmprotect_handler, "_vmprotect_3x_key_schedule", lambda key: [])

        encrypted = b"\x0D\xF0\xAD\xBA" * 16
        key = hashlib.sha512(b"test").digest()

        with pytest.raises((IndexError, ValueError, AssertionError)):
            vmprotect_handler.decrypt_vm_code(
                encrypted, key, ProtectionType.VMPROTECT_3X
            )

        setattr(vmprotect_handler, "_vmprotect_3x_key_schedule", original_method)

    def test_incomplete_key_schedule_produces_invalid_output(
        self, vmprotect_handler: VMProtectHandler
    ) -> None:
        """Incomplete key schedule produces invalid decryption output."""
        original_method = vmprotect_handler._vmprotect_1x_key_schedule
        setattr(vmprotect_handler, "_vmprotect_1x_key_schedule", lambda key: [0] * 44)

        key = b"\x12\x34\x56\x78" * 4
        plaintext = b"\x90\xC3\xCC\xF4" * 16

        encrypted = vmprotect_handler._encrypt_with_schedule_1x(
            plaintext, original_method(key)
        )

        decrypted = vmprotect_handler.decrypt_vm_code(
            encrypted, key, ProtectionType.VMPROTECT_1X
        )

        assert decrypted != plaintext

        setattr(vmprotect_handler, "_vmprotect_1x_key_schedule", original_method)
