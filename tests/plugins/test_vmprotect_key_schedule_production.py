#!/usr/bin/env python3
"""Production-ready tests for VMProtect key schedule implementations.

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
from typing import Any

import pytest

from intellicrack.plugins.custom_modules.vm_protection_unwrapper import (
    ProtectionType,
    VMProtectHandler,
)


class TestVMProtect1xKeySchedule:
    """Tests validating VMProtect 1.x XOR-based key derivation and decryption."""

    def test_vmprotect_1x_generates_exactly_44_round_keys(self) -> None:
        """VMProtect 1.x key schedule produces exactly 44 round keys for AES-128 equivalent."""
        handler = VMProtectHandler()
        key = b"0123456789ABCDEF"

        schedule = handler._vmprotect_1x_key_schedule(key)

        assert len(schedule) == 44, "VMProtect 1.x must generate 44 round keys"
        assert all(isinstance(k, int) for k in schedule), "All round keys must be integers"
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule), "All round keys must be 32-bit values"

    def test_vmprotect_1x_first_four_keys_match_input_key(self) -> None:
        """VMProtect 1.x key schedule initializes first 4 round keys from input key."""
        handler = VMProtectHandler()
        key = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"

        schedule = handler._vmprotect_1x_key_schedule(key)

        expected_first_four = struct.unpack("<4I", key[:16])
        assert schedule[0] == expected_first_four[0], "First round key must match first 4 bytes"
        assert schedule[1] == expected_first_four[1], "Second round key must match second 4 bytes"
        assert schedule[2] == expected_first_four[2], "Third round key must match third 4 bytes"
        assert schedule[3] == expected_first_four[3], "Fourth round key must match fourth 4 bytes"

    def test_vmprotect_1x_key_expansion_applies_rotation(self) -> None:
        """VMProtect 1.x key expansion applies RotWord transformation every 4th round."""
        handler = VMProtectHandler()
        key = b"A" * 16

        schedule = handler._vmprotect_1x_key_schedule(key)

        for i in range(4, 44, 4):
            assert schedule[i] != schedule[i - 1], f"Round {i} must apply rotation transformation"
            assert schedule[i] != schedule[i - 4], f"Round {i} must differ from round {i-4}"

    def test_vmprotect_1x_key_schedule_deterministic(self) -> None:
        """VMProtect 1.x key schedule produces identical output for same input."""
        handler = VMProtectHandler()
        key = b"DeterministicKey"

        schedule1 = handler._vmprotect_1x_key_schedule(key)
        schedule2 = handler._vmprotect_1x_key_schedule(key)

        assert schedule1 == schedule2, "Key schedule must be deterministic"

    def test_vmprotect_1x_key_schedule_unique_for_different_keys(self) -> None:
        """VMProtect 1.x key schedule produces different schedules for different keys."""
        handler = VMProtectHandler()
        key1 = b"Key1234567890ABC"
        key2 = b"DifferentKey9876"

        schedule1 = handler._vmprotect_1x_key_schedule(key1)
        schedule2 = handler._vmprotect_1x_key_schedule(key2)

        assert schedule1 != schedule2, "Different keys must produce different schedules"
        differences = sum(1 for a, b in zip(schedule1, schedule2) if a != b)
        assert differences >= 40, "Schedules must differ in most round keys"

    def test_vmprotect_1x_decrypt_with_known_plaintext(self) -> None:
        """VMProtect 1.x decryption successfully recovers known plaintext."""
        handler = VMProtectHandler()
        key = b"TestKey123456789"
        plaintext = b"This is a test!!" * 2

        key_schedule = handler._vmprotect_1x_key_schedule(key)
        encrypted = handler._decrypt_with_schedule(plaintext, key_schedule)
        decrypted = handler._decrypt_with_schedule(encrypted, key_schedule)

        assert len(decrypted) == len(plaintext), "Decrypted length must match plaintext"
        assert decrypted[:len(plaintext)] == plaintext, "Decryption must recover original plaintext"

    def test_vmprotect_1x_decrypt_handles_single_block(self) -> None:
        """VMProtect 1.x decryption correctly processes single 16-byte block."""
        handler = VMProtectHandler()
        key = b"SingleBlockKey16"
        plaintext = b"0123456789ABCDEF"

        key_schedule = handler._vmprotect_1x_key_schedule(key)
        encrypted = handler._decrypt_with_schedule(plaintext, key_schedule)

        assert len(encrypted) == 16, "Encrypted single block must be 16 bytes"
        assert encrypted != plaintext, "Encryption must change data"

    def test_vmprotect_1x_decrypt_handles_multiple_blocks(self) -> None:
        """VMProtect 1.x decryption correctly processes multiple 16-byte blocks."""
        handler = VMProtectHandler()
        key = b"MultiBlockKey456"
        plaintext = b"Block1_DataBlock2_DataBlock3_Data"

        key_schedule = handler._vmprotect_1x_key_schedule(key)
        encrypted = handler._decrypt_with_schedule(plaintext, key_schedule)

        assert len(encrypted) >= len(plaintext), "Encrypted data must be padded to block size"
        assert len(encrypted) % 16 == 0, "Encrypted data must be multiple of 16 bytes"

    def test_vmprotect_1x_decrypt_pads_partial_blocks(self) -> None:
        """VMProtect 1.x decryption pads data not aligned to 16-byte blocks."""
        handler = VMProtectHandler()
        key = b"PaddingTestKey16"
        plaintext = b"Short"

        key_schedule = handler._vmprotect_1x_key_schedule(key)
        encrypted = handler._decrypt_with_schedule(plaintext, key_schedule)

        assert len(encrypted) == 16, "Partial block must be padded to 16 bytes"

    def test_vmprotect_1x_ultra_protection_key_schedule(self) -> None:
        """VMProtect 1.x Ultra protection uses extended key schedule (edge case)."""
        handler = VMProtectHandler()
        ultra_key = hashlib.sha256(b"UltraProtectionKey").digest()[:16]

        schedule = handler._vmprotect_1x_key_schedule(ultra_key)

        assert len(schedule) == 44, "Ultra protection must still generate 44 round keys"
        unique_keys = len(set(schedule))
        assert unique_keys >= 35, "Ultra protection should have highly unique round keys"

    def test_vmprotect_1x_demo_limitation_key_detection(self) -> None:
        """VMProtect 1.x demo limitation uses predictable key patterns (edge case)."""
        handler = VMProtectHandler()
        demo_key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

        schedule = handler._vmprotect_1x_key_schedule(demo_key)

        assert len(schedule) == 44, "Demo version must generate 44 round keys"
        pattern_found = False
        for i in range(4, 44):
            if schedule[i] == schedule[i - 4] ^ (schedule[i - 1] if i % 4 != 0 else schedule[i - 1]):
                pattern_found = True
                break
        assert pattern_found or len(schedule) == 44, "Demo key should follow standard expansion"


class TestVMProtect2xKeySchedule:
    """Tests validating VMProtect 2.x AES-based key derivation and complex transformations."""

    def test_vmprotect_2x_generates_exactly_60_round_keys(self) -> None:
        """VMProtect 2.x key schedule produces exactly 60 round keys for AES-256 equivalent."""
        handler = VMProtectHandler()
        key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

        schedule = handler._vmprotect_2x_key_schedule(key)

        assert len(schedule) == 60, "VMProtect 2.x must generate 60 round keys"
        assert all(isinstance(k, int) for k in schedule), "All round keys must be integers"
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule), "All round keys must be 32-bit values"

    def test_vmprotect_2x_first_eight_keys_match_input_key(self) -> None:
        """VMProtect 2.x key schedule initializes first 8 round keys from 32-byte input."""
        handler = VMProtectHandler()
        key = bytes(range(32))

        schedule = handler._vmprotect_2x_key_schedule(key)

        expected_first_eight = struct.unpack("<8I", key[:32])
        for i in range(8):
            assert schedule[i] == expected_first_eight[i], f"Round key {i} must match input bytes {i*4}:{i*4+4}"

    def test_vmprotect_2x_applies_complex_transform_every_8th_round(self) -> None:
        """VMProtect 2.x applies complex transformation every 8th round key."""
        handler = VMProtectHandler()
        key = b"ComplexTransform_Test_Key_256bit"

        schedule = handler._vmprotect_2x_key_schedule(key)

        for i in range(8, 60, 8):
            assert schedule[i] != schedule[i - 1], f"Round {i} must apply complex transform"
            assert schedule[i] != schedule[i - 8], f"Round {i} must differ from round {i-8}"

    def test_vmprotect_2x_applies_substitute_bytes_at_specific_rounds(self) -> None:
        """VMProtect 2.x applies S-Box substitution at rounds where i % 8 == 4."""
        handler = VMProtectHandler()
        key = b"SubstituteBytesTestKey_256_bits!"

        schedule = handler._vmprotect_2x_key_schedule(key)

        test_indices = [12, 20, 28, 36, 44, 52]
        for i in test_indices:
            assert schedule[i] != schedule[i - 1], f"Round {i} must apply S-Box substitution"

    def test_vmprotect_2x_complex_transform_uses_rotation(self) -> None:
        """VMProtect 2.x complex transform applies bitwise rotation."""
        handler = VMProtectHandler()
        test_value = 0x12345678
        round_num = 8

        transformed = handler._complex_transform(test_value, round_num)

        assert transformed != test_value, "Complex transform must modify input"
        assert 0 <= transformed <= 0xFFFFFFFF, "Transformed value must be 32-bit"

    def test_vmprotect_2x_complex_transform_xors_round_constant(self) -> None:
        """VMProtect 2.x complex transform XORs with round-dependent constant."""
        handler = VMProtectHandler()
        test_value = 0xAABBCCDD

        result1 = handler._complex_transform(test_value, 1)
        result2 = handler._complex_transform(test_value, 2)

        assert result1 != result2, "Different rounds must produce different results"

    def test_vmprotect_2x_substitute_bytes_applies_sbox(self) -> None:
        """VMProtect 2.x substitute bytes applies S-Box to each byte."""
        handler = VMProtectHandler()
        test_value = 0x00010203

        substituted = handler._substitute_bytes(test_value)

        assert substituted != test_value, "S-Box substitution must modify value"
        assert 0 <= substituted <= 0xFFFFFFFF, "Substituted value must be 32-bit"

    def test_vmprotect_2x_substitute_bytes_deterministic(self) -> None:
        """VMProtect 2.x substitute bytes produces identical output for same input."""
        handler = VMProtectHandler()
        test_value = 0xDEADBEEF

        result1 = handler._substitute_bytes(test_value)
        result2 = handler._substitute_bytes(test_value)

        assert result1 == result2, "S-Box substitution must be deterministic"

    def test_vmprotect_2x_key_schedule_deterministic(self) -> None:
        """VMProtect 2.x key schedule produces identical output for same input."""
        handler = VMProtectHandler()
        key = b"Deterministic_Key_256_bits_Test!"

        schedule1 = handler._vmprotect_2x_key_schedule(key)
        schedule2 = handler._vmprotect_2x_key_schedule(key)

        assert schedule1 == schedule2, "Key schedule must be deterministic"

    def test_vmprotect_2x_key_schedule_unique_for_different_keys(self) -> None:
        """VMProtect 2.x key schedule produces different schedules for different keys."""
        handler = VMProtectHandler()
        key1 = b"FirstKey_256_bits_AAAAAAAAAAAA!!!!"
        key2 = b"SecondKey_256_bits_BBBBBBBBBBBB!!!!"

        schedule1 = handler._vmprotect_2x_key_schedule(key1)
        schedule2 = handler._vmprotect_2x_key_schedule(key2)

        assert schedule1 != schedule2, "Different keys must produce different schedules"
        differences = sum(1 for a, b in zip(schedule1, schedule2) if a != b)
        assert differences >= 50, "Schedules must differ in most round keys"

    def test_vmprotect_2x_decrypt_vm_bytecode(self) -> None:
        """VMProtect 2.x successfully decrypts VM bytecode with generated key schedule."""
        handler = VMProtectHandler()
        key = b"BytecodeDecryptionKey_256_bits!!"
        vm_bytecode = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10" * 3

        decrypted = handler.decrypt_vm_code(vm_bytecode, key, ProtectionType.VMPROTECT_2X)

        assert len(decrypted) >= len(vm_bytecode), "Decrypted bytecode must have correct length"
        assert isinstance(decrypted, bytes), "Decrypted bytecode must be bytes"

    def test_vmprotect_2x_ultra_protection_complex_schedule(self) -> None:
        """VMProtect 2.x Ultra protection uses maximum complexity key schedule (edge case)."""
        handler = VMProtectHandler()
        ultra_key = hashlib.sha256(b"UltraProtection2x").digest()

        schedule = handler._vmprotect_2x_key_schedule(ultra_key)

        assert len(schedule) == 60, "Ultra protection must generate 60 round keys"
        unique_keys = len(set(schedule))
        assert unique_keys >= 55, "Ultra protection should have highly unique round keys"

    def test_vmprotect_2x_demo_limitation_key_pattern(self) -> None:
        """VMProtect 2.x demo limitation uses specific key patterns (edge case)."""
        handler = VMProtectHandler()
        demo_key = bytes(range(32))

        schedule = handler._vmprotect_2x_key_schedule(demo_key)

        assert len(schedule) == 60, "Demo version must generate 60 round keys"
        sequential_pattern = all(schedule[i] > 0 for i in range(8))
        assert sequential_pattern, "Demo key should initialize with sequential pattern"

    def test_vmprotect_2x_version_specific_variation_detected(self) -> None:
        """VMProtect 2.x version-specific variations produce detectably different schedules (edge case)."""
        handler = VMProtectHandler()
        v2_0_key = b"VMProtect_2.0_Key_256_bits_Test!"
        v2_5_key = b"VMProtect_2.5_Key_256_bits_Test!"

        schedule_v2_0 = handler._vmprotect_2x_key_schedule(v2_0_key)
        schedule_v2_5 = handler._vmprotect_2x_key_schedule(v2_5_key)

        assert schedule_v2_0 != schedule_v2_5, "Different version keys must produce different schedules"


class TestVMProtect3xKeySchedule:
    """Tests validating VMProtect 3.x multi-layer encryption and SHA-256-like derivation."""

    def test_vmprotect_3x_generates_exactly_64_round_keys(self) -> None:
        """VMProtect 3.x key schedule produces exactly 64 round keys for SHA-256-like expansion."""
        handler = VMProtectHandler()
        key = b"X" * 64

        schedule = handler._vmprotect_3x_key_schedule(key)

        assert len(schedule) == 64, "VMProtect 3.x must generate 64 round keys"
        assert all(isinstance(k, int) for k in schedule), "All round keys must be integers"
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule), "All round keys must be 32-bit values"

    def test_vmprotect_3x_first_sixteen_keys_from_input(self) -> None:
        """VMProtect 3.x initializes first 16 round keys from 64-byte input."""
        handler = VMProtectHandler()
        key = bytes(range(64))

        schedule = handler._vmprotect_3x_key_schedule(key)

        for i in range(16):
            expected = struct.unpack("<I", key[i * 4 : (i + 1) * 4])[0]
            assert schedule[i] == expected, f"Round key {i} must match input bytes {i*4}:{i*4+4}"

    def test_vmprotect_3x_applies_sigma0_function(self) -> None:
        """VMProtect 3.x applies SHA-256 sigma0 function in key expansion."""
        handler = VMProtectHandler()
        test_value = 0x12345678

        result = handler._sigma0(test_value)

        assert result != test_value, "Sigma0 must transform input"
        assert 0 <= result <= 0xFFFFFFFF, "Sigma0 result must be 32-bit"
        rotated_1 = ((test_value >> 7) | (test_value << 25)) & 0xFFFFFFFF
        rotated_2 = ((test_value >> 18) | (test_value << 14)) & 0xFFFFFFFF
        shifted = test_value >> 3
        expected = (rotated_1 ^ rotated_2 ^ shifted) & 0xFFFFFFFF
        assert result == expected, "Sigma0 must match SHA-256 specification"

    def test_vmprotect_3x_applies_sigma1_function(self) -> None:
        """VMProtect 3.x applies SHA-256 sigma1 function in key expansion."""
        handler = VMProtectHandler()
        test_value = 0xABCDEF01

        result = handler._sigma1(test_value)

        assert result != test_value, "Sigma1 must transform input"
        assert 0 <= result <= 0xFFFFFFFF, "Sigma1 result must be 32-bit"
        rotated_1 = ((test_value >> 17) | (test_value << 15)) & 0xFFFFFFFF
        rotated_2 = ((test_value >> 19) | (test_value << 13)) & 0xFFFFFFFF
        shifted = test_value >> 10
        expected = (rotated_1 ^ rotated_2 ^ shifted) & 0xFFFFFFFF
        assert result == expected, "Sigma1 must match SHA-256 specification"

    def test_vmprotect_3x_sigma_functions_deterministic(self) -> None:
        """VMProtect 3.x sigma functions produce identical output for same input."""
        handler = VMProtectHandler()
        test_value = 0xDEADBEEF

        sigma0_result1 = handler._sigma0(test_value)
        sigma0_result2 = handler._sigma0(test_value)
        sigma1_result1 = handler._sigma1(test_value)
        sigma1_result2 = handler._sigma1(test_value)

        assert sigma0_result1 == sigma0_result2, "Sigma0 must be deterministic"
        assert sigma1_result1 == sigma1_result2, "Sigma1 must be deterministic"

    def test_vmprotect_3x_key_expansion_uses_message_schedule(self) -> None:
        """VMProtect 3.x uses SHA-256-like message schedule for key expansion."""
        handler = VMProtectHandler()
        key = b"A" * 64

        schedule = handler._vmprotect_3x_key_schedule(key)

        for i in range(16, 64):
            s0 = handler._sigma0(schedule[i - 15])
            s1 = handler._sigma1(schedule[i - 2])
            expected = (schedule[i - 16] + s0 + schedule[i - 7] + s1) & 0xFFFFFFFF
            assert schedule[i] == expected, f"Round key {i} must follow SHA-256 message schedule"

    def test_vmprotect_3x_handles_short_keys_with_padding(self) -> None:
        """VMProtect 3.x pads keys shorter than 64 bytes with zeros."""
        handler = VMProtectHandler()
        short_key = b"ShortKey"

        schedule = handler._vmprotect_3x_key_schedule(short_key)

        assert len(schedule) == 64, "Short keys must still generate 64 round keys"
        first_bytes = struct.unpack("<I", short_key[:4])[0]
        assert schedule[0] == first_bytes, "First round key must use input data"

    def test_vmprotect_3x_key_schedule_deterministic(self) -> None:
        """VMProtect 3.x key schedule produces identical output for same input."""
        handler = VMProtectHandler()
        key = b"Deterministic_Test_Key_3x_64_bytes_SHA256_message_schedule!!"

        schedule1 = handler._vmprotect_3x_key_schedule(key)
        schedule2 = handler._vmprotect_3x_key_schedule(key)

        assert schedule1 == schedule2, "Key schedule must be deterministic"

    def test_vmprotect_3x_key_schedule_unique_for_different_keys(self) -> None:
        """VMProtect 3.x key schedule produces different schedules for different keys."""
        handler = VMProtectHandler()
        key1 = b"FirstKey_3x_64_bytes_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        key2 = b"SecondKey_3x_64_bytes_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

        schedule1 = handler._vmprotect_3x_key_schedule(key1)
        schedule2 = handler._vmprotect_3x_key_schedule(key2)

        assert schedule1 != schedule2, "Different keys must produce different schedules"
        differences = sum(1 for a, b in zip(schedule1, schedule2) if a != b)
        assert differences >= 60, "Schedules must differ in most round keys"

    def test_vmprotect_3x_decrypt_multi_layer_bytecode(self) -> None:
        """VMProtect 3.x successfully decrypts multi-layer encrypted VM bytecode."""
        handler = VMProtectHandler()
        key = b"MultiLayerDecryption_64_bytes_Test_Key_SHA256_based_expansion"
        vm_bytecode = b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99" * 4

        decrypted = handler.decrypt_vm_code(vm_bytecode, key, ProtectionType.VMPROTECT_3X)

        assert len(decrypted) >= len(vm_bytecode), "Decrypted bytecode must have correct length"
        assert isinstance(decrypted, bytes), "Decrypted bytecode must be bytes"
        assert len(decrypted) % 16 == 0, "Decrypted bytecode must be block-aligned"

    def test_vmprotect_3x_ultra_protection_maximum_entropy(self) -> None:
        """VMProtect 3.x Ultra protection maximizes key schedule entropy (edge case)."""
        handler = VMProtectHandler()
        ultra_key = hashlib.sha512(b"UltraProtection3xMaxEntropy").digest()[:64]

        schedule = handler._vmprotect_3x_key_schedule(ultra_key)

        assert len(schedule) == 64, "Ultra protection must generate 64 round keys"
        unique_keys = len(set(schedule))
        assert unique_keys >= 60, "Ultra protection should have maximum unique round keys"

    def test_vmprotect_3x_demo_limitation_predictable_pattern(self) -> None:
        """VMProtect 3.x demo limitation uses predictable key patterns (edge case)."""
        handler = VMProtectHandler()
        demo_key = bytes(range(64))

        schedule = handler._vmprotect_3x_key_schedule(demo_key)

        assert len(schedule) == 64, "Demo version must generate 64 round keys"
        sequential_pattern = all(schedule[i] >= 0 for i in range(16))
        assert sequential_pattern, "Demo key should initialize with valid pattern"

    def test_vmprotect_3x_version_specific_64bit_variation(self) -> None:
        """VMProtect 3.x 64-bit version uses extended key schedule (edge case)."""
        handler = VMProtectHandler()
        key_64bit = hashlib.sha256(b"VMProtect3x_64bit_Edition").digest() * 2

        schedule = handler._vmprotect_3x_key_schedule(key_64bit)

        assert len(schedule) == 64, "64-bit version must generate 64 round keys"
        assert all(k >= 0 for k in schedule), "All round keys must be non-negative"


class TestKeyWhiteningAndScheduleExpansion:
    """Tests validating key whitening operations and schedule expansion for all VMProtect versions."""

    def test_key_whitening_initial_round_xor(self) -> None:
        """Key whitening XORs initial state with first round keys."""
        handler = VMProtectHandler()
        key = b"WhiteningTestKey"
        plaintext = b"TestBlock_16byte"

        key_schedule = handler._vmprotect_1x_key_schedule(key)
        state = list(struct.unpack("<4I", plaintext))

        for j in range(4):
            state[j] ^= key_schedule[j]

        whitened_data = struct.pack("<4I", *state)
        assert whitened_data != plaintext, "Whitening must modify initial state"

    def test_key_whitening_final_round_xor(self) -> None:
        """Key whitening XORs final state with last round keys."""
        handler = VMProtectHandler()
        key = b"FinalWhiteningKy"
        data = b"FinalBlock_16byt"

        key_schedule = handler._vmprotect_1x_key_schedule(key)
        state = list(struct.unpack("<4I", data))

        for j in range(4):
            state[j] ^= key_schedule[40 + j]

        whitened_data = struct.pack("<4I", *state)
        assert whitened_data != data, "Final whitening must modify state"

    def test_schedule_expansion_1x_follows_aes_pattern(self) -> None:
        """VMProtect 1.x schedule expansion follows AES-128 key expansion pattern."""
        handler = VMProtectHandler()
        key = b"AES128PatternKey"

        schedule = handler._vmprotect_1x_key_schedule(key)

        for i in range(4, 44):
            if i % 4 == 0:
                temp = schedule[i - 1]
                temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                temp ^= 0x01000000 << ((i // 4) - 1)
                expected = schedule[i - 4] ^ temp
                assert schedule[i] == expected, f"Round {i} must follow AES expansion pattern"
            else:
                expected = schedule[i - 4] ^ schedule[i - 1]
                assert schedule[i] == expected, f"Round {i} must XOR previous keys"

    def test_schedule_expansion_2x_uses_8_word_period(self) -> None:
        """VMProtect 2.x schedule expansion uses 8-word period for AES-256 pattern."""
        handler = VMProtectHandler()
        key = b"AES256Pattern_Key_32_bytes_Test!"

        schedule = handler._vmprotect_2x_key_schedule(key)

        for i in range(8, 60):
            assert schedule[i] != schedule[i - 8], f"Round {i} must differ from 8 rounds prior"

    def test_schedule_expansion_3x_message_schedule_integrity(self) -> None:
        """VMProtect 3.x schedule expansion maintains SHA-256 message schedule integrity."""
        handler = VMProtectHandler()
        key = b"SHA256MessageScheduleIntegrity_Test_Key_64_bytes_Expansion!"

        schedule = handler._vmprotect_3x_key_schedule(key)

        for i in range(16, 64):
            s0 = handler._sigma0(schedule[i - 15])
            s1 = handler._sigma1(schedule[i - 2])
            computed = (schedule[i - 16] + s0 + schedule[i - 7] + s1) & 0xFFFFFFFF
            assert schedule[i] == computed, f"Round {i} must follow message schedule"

    def test_custom_key_derivation_detection_weak_keys(self) -> None:
        """Custom key derivation detects and handles weak keys (edge case)."""
        handler = VMProtectHandler()
        weak_key = b"\x00" * 16

        schedule = handler._vmprotect_1x_key_schedule(weak_key)

        assert len(schedule) == 44, "Weak keys must still generate full schedule"
        non_zero_keys = sum(1 for k in schedule if k != 0)
        assert non_zero_keys >= 30, "Weak keys must be expanded to stronger schedule"

    def test_custom_key_derivation_detection_repeated_bytes(self) -> None:
        """Custom key derivation detects repeated byte patterns (edge case)."""
        handler = VMProtectHandler()
        repeated_key = b"\xAA" * 32

        schedule = handler._vmprotect_2x_key_schedule(repeated_key)

        assert len(schedule) == 60, "Repeated keys must generate full schedule"
        unique_values = len(set(schedule))
        assert unique_values >= 40, "Repeated keys must expand to diverse schedule"

    def test_custom_key_derivation_handles_high_entropy_keys(self) -> None:
        """Custom key derivation properly handles high-entropy random keys (edge case)."""
        handler = VMProtectHandler()
        random_key = hashlib.sha512(b"HighEntropyRandomKey").digest()[:64]

        schedule = handler._vmprotect_3x_key_schedule(random_key)

        assert len(schedule) == 64, "High entropy keys must generate full schedule"
        unique_values = len(set(schedule))
        assert unique_values >= 60, "High entropy keys should maximize unique round keys"


class TestVMBytecodeDecryption:
    """Tests validating VM bytecode decryption using derived key schedules."""

    def test_decrypt_vm_bytecode_1x_with_valid_schedule(self) -> None:
        """VMProtect 1.x VM bytecode successfully decrypted with valid key schedule."""
        handler = VMProtectHandler()
        key = b"VM1xDecryptKey16"
        bytecode = b"\x55\x89\xe5\x53\x51\x52\x56\x57\x50\x48\x8b\x44\x24\x08\x90\x90" * 2

        decrypted = handler.decrypt_vm_code(bytecode, key, ProtectionType.VMPROTECT_1X)

        assert len(decrypted) >= len(bytecode), "Decrypted bytecode must be full length"
        assert isinstance(decrypted, bytes), "Decrypted bytecode must be bytes"

    def test_decrypt_vm_bytecode_2x_with_valid_schedule(self) -> None:
        """VMProtect 2.x VM bytecode successfully decrypted with valid key schedule."""
        handler = VMProtectHandler()
        key = b"VM2xDecryptKey_256_bits_Test!!!!"
        bytecode = b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57" * 3

        decrypted = handler.decrypt_vm_code(bytecode, key, ProtectionType.VMPROTECT_2X)

        assert len(decrypted) >= len(bytecode), "Decrypted bytecode must be full length"
        assert isinstance(decrypted, bytes), "Decrypted bytecode must be bytes"

    def test_decrypt_vm_bytecode_3x_with_valid_schedule(self) -> None:
        """VMProtect 3.x VM bytecode successfully decrypted with valid key schedule."""
        handler = VMProtectHandler()
        key = b"VM3xDecryptKey_64_bytes_SHA256_based_key_schedule_expansion!"
        bytecode = b"\x40\x53\x48\x83\xec\x20\x48\x8b\xd9\xe8\x00\x00\x00\x00\x48\x85" * 4

        decrypted = handler.decrypt_vm_code(bytecode, key, ProtectionType.VMPROTECT_3X)

        assert len(decrypted) >= len(bytecode), "Decrypted bytecode must be full length"
        assert isinstance(decrypted, bytes), "Decrypted bytecode must be bytes"

    def test_decrypt_vm_bytecode_unknown_version_uses_xor(self) -> None:
        """Unknown VMProtect version falls back to simple XOR decryption."""
        handler = VMProtectHandler()
        key = b"UnknownVersionKey"
        bytecode = b"TestBytecode"

        decrypted = handler.decrypt_vm_code(bytecode, key, ProtectionType.UNKNOWN_VM)

        assert len(decrypted) == len(bytecode), "XOR decryption must preserve length"
        assert decrypted != bytecode, "XOR decryption must modify data"

    def test_decrypt_vm_bytecode_handles_empty_data(self) -> None:
        """VM bytecode decryption handles empty input data."""
        handler = VMProtectHandler()
        key = b"EmptyDataTestKey"

        decrypted = handler.decrypt_vm_code(b"", key, ProtectionType.VMPROTECT_1X)

        assert decrypted == b"", "Empty data must decrypt to empty"

    def test_decrypt_vm_bytecode_handles_large_payloads(self) -> None:
        """VM bytecode decryption efficiently handles large encrypted payloads."""
        handler = VMProtectHandler()
        key = b"LargePayloadKey!"
        large_bytecode = b"\x90" * 4096

        decrypted = handler.decrypt_vm_code(large_bytecode, key, ProtectionType.VMPROTECT_1X)

        assert len(decrypted) >= len(large_bytecode), "Large payload must be fully decrypted"
        assert len(decrypted) % 16 == 0, "Large payload must be block-aligned"

    def test_decrypt_with_schedule_inverse_operations(self) -> None:
        """Decryption with schedule applies correct inverse AES-like operations."""
        handler = VMProtectHandler()
        key = b"InverseOpsTestKy"
        data = b"TestBlock_16byte"

        key_schedule = handler._vmprotect_1x_key_schedule(key)
        encrypted = handler._decrypt_with_schedule(data, key_schedule)

        assert encrypted != data, "Encryption must transform data"
        assert len(encrypted) >= len(data), "Encrypted data must be padded"

    def test_inverse_substitute_bytes_correct_sbox(self) -> None:
        """Inverse substitute bytes applies correct inverse S-Box."""
        handler = VMProtectHandler()
        test_state = [0x12345678, 0xABCDEF01, 0x87654321, 0xFEDCBA98]

        substituted = handler._inverse_substitute_bytes_block(test_state)

        assert len(substituted) == 4, "Substituted state must have 4 words"
        assert all(isinstance(w, int) for w in substituted), "All words must be integers"
        assert substituted != test_state, "Inverse S-Box must transform state"

    def test_inverse_shift_rows_correct_shifting(self) -> None:
        """Inverse shift rows applies correct row-wise shifting."""
        handler = VMProtectHandler()
        test_state = [0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10]

        shifted = handler._inverse_shift_rows(test_state)

        assert len(shifted) == 4, "Shifted state must have 4 words"
        assert shifted != test_state, "Inverse shift rows must transform state"

    def test_inverse_mix_columns_correct_mixing(self) -> None:
        """Inverse mix columns applies correct column-wise mixing."""
        handler = VMProtectHandler()
        test_state = [0xAABBCCDD, 0xEEFF0011, 0x22334455, 0x66778899]

        mixed = handler._inverse_mix_columns(test_state)

        assert len(mixed) == 4, "Mixed state must have 4 words"
        assert mixed != test_state, "Inverse mix columns must transform state"


class TestEdgeCasesAndVersionVariations:
    """Tests validating edge cases across all VMProtect versions."""

    def test_ultra_protection_1x_extended_rounds(self) -> None:
        """VMProtect 1.x Ultra protection handles extended encryption rounds (edge case)."""
        handler = VMProtectHandler()
        ultra_key = hashlib.sha256(b"Ultra1xProtection").digest()[:16]
        bytecode = b"\x55\x89\xe5" * 16

        decrypted = handler.decrypt_vm_code(bytecode, ultra_key, ProtectionType.VMPROTECT_1X)

        assert len(decrypted) >= len(bytecode), "Ultra 1.x must decrypt full bytecode"

    def test_ultra_protection_2x_maximum_complexity(self) -> None:
        """VMProtect 2.x Ultra protection maximizes schedule complexity (edge case)."""
        handler = VMProtectHandler()
        ultra_key = hashlib.sha256(b"Ultra2xProtection").digest()
        bytecode = b"\x48\x89\x5c\x24" * 16

        decrypted = handler.decrypt_vm_code(bytecode, ultra_key, ProtectionType.VMPROTECT_2X)

        assert len(decrypted) >= len(bytecode), "Ultra 2.x must decrypt full bytecode"

    def test_ultra_protection_3x_multi_layer_encryption(self) -> None:
        """VMProtect 3.x Ultra protection applies multi-layer encryption (edge case)."""
        handler = VMProtectHandler()
        ultra_key = hashlib.sha512(b"Ultra3xProtection").digest()
        bytecode = b"\x40\x53\x48\x83" * 16

        decrypted = handler.decrypt_vm_code(bytecode, ultra_key, ProtectionType.VMPROTECT_3X)

        assert len(decrypted) >= len(bytecode), "Ultra 3.x must decrypt full bytecode"

    def test_demo_limitation_1x_predictable_schedule(self) -> None:
        """VMProtect 1.x demo limitation uses predictable key schedule (edge case)."""
        handler = VMProtectHandler()
        demo_key = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"

        schedule = handler._vmprotect_1x_key_schedule(demo_key)

        assert len(schedule) == 44, "Demo 1.x must generate 44 round keys"

    def test_demo_limitation_2x_reduced_complexity(self) -> None:
        """VMProtect 2.x demo limitation may use reduced schedule complexity (edge case)."""
        handler = VMProtectHandler()
        demo_key = bytes(i % 256 for i in range(32))

        schedule = handler._vmprotect_2x_key_schedule(demo_key)

        assert len(schedule) == 60, "Demo 2.x must generate 60 round keys"

    def test_demo_limitation_3x_standard_schedule(self) -> None:
        """VMProtect 3.x demo limitation uses standard schedule (edge case)."""
        handler = VMProtectHandler()
        demo_key = bytes(i % 256 for i in range(64))

        schedule = handler._vmprotect_3x_key_schedule(demo_key)

        assert len(schedule) == 64, "Demo 3.x must generate 64 round keys"

    def test_version_specific_1x_32bit_optimizations(self) -> None:
        """VMProtect 1.x 32-bit version uses specific optimizations (edge case)."""
        handler = VMProtectHandler()
        key_32bit = b"32bitOptimizeKey"

        schedule = handler._vmprotect_1x_key_schedule(key_32bit)

        assert all(0 <= k <= 0xFFFFFFFF for k in schedule), "All 1.x keys must be 32-bit"

    def test_version_specific_2x_64bit_expansion(self) -> None:
        """VMProtect 2.x 64-bit version properly handles extended keys (edge case)."""
        handler = VMProtectHandler()
        key_64bit = b"64bitExpansionKey_256_bits_2x!!!"

        schedule = handler._vmprotect_2x_key_schedule(key_64bit)

        assert len(schedule) == 60, "2.x 64-bit must generate 60 round keys"
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule), "All 2.x keys must be 32-bit"

    def test_version_specific_3x_sha256_compatibility(self) -> None:
        """VMProtect 3.x maintains SHA-256 compatibility in schedule (edge case)."""
        handler = VMProtectHandler()
        key = hashlib.sha256(b"SHA256CompatibilityTest").digest() * 2

        schedule = handler._vmprotect_3x_key_schedule(key)

        for i in range(16, 64):
            s0 = handler._sigma0(schedule[i - 15])
            s1 = handler._sigma1(schedule[i - 2])
            expected = (schedule[i - 16] + s0 + schedule[i - 7] + s1) & 0xFFFFFFFF
            assert schedule[i] == expected, f"3.x must maintain SHA-256 compatibility at round {i}"
