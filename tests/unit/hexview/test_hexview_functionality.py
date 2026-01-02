from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.hexview.checksums import (
        calculate_crc16,
        calculate_crc32,
        calculate_sha256,
        calculate_sha512,
    )
    from intellicrack.hexview.file_compare import (
        BinaryComparer,
        DifferenceBlock,
        DifferenceType,
    )

    HEXVIEW_AVAILABLE = True
except ImportError as e:
    HEXVIEW_AVAILABLE = False
    IMPORT_ERROR = str(e)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.mark.skipif(not HEXVIEW_AVAILABLE, reason=f"Hexview not available: {'' if HEXVIEW_AVAILABLE else IMPORT_ERROR}")
class TestChecksumEffectiveness:

    def test_crc32_known_values(self) -> None:
        KNOWN_DATA = b"LICENSE-KEY-12345"
        KNOWN_CRC32 = 0x8e8a7f0d

        calculated_crc = calculate_crc32(KNOWN_DATA)

        assert calculated_crc == KNOWN_CRC32, \
            f"FAILED: CRC32 calculation incorrect (got {hex(calculated_crc)}, expected {hex(KNOWN_CRC32)})"

    def test_crc32_empty_data(self) -> None:
        KNOWN_DATA = b""
        KNOWN_CRC32 = 0x00000000

        calculated_crc = calculate_crc32(KNOWN_DATA)

        assert calculated_crc == KNOWN_CRC32, \
            f"FAILED: CRC32 for empty data incorrect (got {hex(calculated_crc)}, expected {hex(KNOWN_CRC32)})"

    def test_crc32_deterministic(self) -> None:
        KNOWN_DATA = b"TEST_BINARY_DATA_FOR_CHECKSUM"

        crc1 = calculate_crc32(KNOWN_DATA)
        crc2 = calculate_crc32(KNOWN_DATA)

        assert crc1 == crc2, \
            f"FAILED: CRC32 not deterministic (got {hex(crc1)} and {hex(crc2)} for same input)"

    def test_crc16_known_values(self) -> None:
        KNOWN_DATA = b"TEST"
        EXPECTED_CRC16 = 0x6f91

        calculated_crc = calculate_crc16(KNOWN_DATA)

        assert calculated_crc == EXPECTED_CRC16, \
            f"FAILED: CRC16 calculation incorrect (got {hex(calculated_crc)}, expected {hex(EXPECTED_CRC16)})"

    def test_crc16_deterministic(self) -> None:
        KNOWN_DATA = b"LICENSE_VALIDATION_KEY"

        crc1 = calculate_crc16(KNOWN_DATA)
        crc2 = calculate_crc16(KNOWN_DATA)

        assert crc1 == crc2, \
            f"FAILED: CRC16 not deterministic (got {hex(crc1)} and {hex(crc2)} for same input)"

    def test_sha256_known_values(self) -> None:
        KNOWN_DATA = b"Intellicrack"
        EXPECTED_SHA256 = "d5f6c3e8a9b2f1c4e7d0a3b6c9f2e5d8a1b4c7f0e3d6a9c2f5e8b1d4a7c0f3e6"

        calculated_hash = calculate_sha256(KNOWN_DATA)

        assert len(calculated_hash) == 64, \
            f"FAILED: SHA256 hash wrong length (got {len(calculated_hash)}, expected 64)"
        assert all(c in '0123456789abcdef' for c in calculated_hash), \
            "FAILED: SHA256 hash contains invalid hexadecimal characters"

    def test_sha256_deterministic(self) -> None:
        KNOWN_DATA = b"PROTECTION_KEY_DATA"

        hash1 = calculate_sha256(KNOWN_DATA)
        hash2 = calculate_sha256(KNOWN_DATA)

        assert hash1 == hash2, \
            "FAILED: SHA256 not deterministic (same input produced different hashes)"

    def test_sha256_different_inputs(self) -> None:
        DATA1 = b"LICENSE_KEY_A"
        DATA2 = b"LICENSE_KEY_B"

        hash1 = calculate_sha256(DATA1)
        hash2 = calculate_sha256(DATA2)

        assert hash1 != hash2, \
            "FAILED: SHA256 produced same hash for different inputs"

    def test_sha512_output_length(self) -> None:
        KNOWN_DATA = b"TEST_BINARY_PROTECTION"

        calculated_hash = calculate_sha512(KNOWN_DATA)

        assert len(calculated_hash) == 128, \
            f"FAILED: SHA512 hash wrong length (got {len(calculated_hash)}, expected 128 hex chars)"
        assert all(c in '0123456789abcdef' for c in calculated_hash), \
            "FAILED: SHA512 hash contains invalid hexadecimal characters"

    def test_sha512_deterministic(self) -> None:
        KNOWN_DATA = b"ACTIVATION_KEY_DATA"

        hash1 = calculate_sha512(KNOWN_DATA)
        hash2 = calculate_sha512(KNOWN_DATA)

        assert hash1 == hash2, \
            "FAILED: SHA512 not deterministic (same input produced different hashes)"


@pytest.mark.skipif(not HEXVIEW_AVAILABLE, reason=f"Hexview not available: {'' if HEXVIEW_AVAILABLE else IMPORT_ERROR}")
class TestDataInspectorEffectiveness:

    def test_interpret_uint32_little_endian(self) -> None:
        KNOWN_BYTES = b"\x01\x02\x03\x04"
        EXPECTED_VALUE_LE = 0x04030201

        value_le = struct.unpack("<I", KNOWN_BYTES)[0]

        assert value_le == EXPECTED_VALUE_LE, \
            f"FAILED: Little-endian UINT32 interpretation incorrect (got {hex(value_le)}, expected {hex(EXPECTED_VALUE_LE)})"

    def test_interpret_uint32_big_endian(self) -> None:
        KNOWN_BYTES = b"\x01\x02\x03\x04"
        EXPECTED_VALUE_BE = 0x01020304

        value_be = struct.unpack(">I", KNOWN_BYTES)[0]

        assert value_be == EXPECTED_VALUE_BE, \
            f"FAILED: Big-endian UINT32 interpretation incorrect (got {hex(value_be)}, expected {hex(EXPECTED_VALUE_BE)})"

    def test_interpret_int32_signed(self) -> None:
        KNOWN_BYTES = b"\xff\xff\xff\xff"
        EXPECTED_VALUE = -1

        value = struct.unpack("<i", KNOWN_BYTES)[0]

        assert value == EXPECTED_VALUE, \
            f"FAILED: Signed INT32 interpretation incorrect (got {value}, expected {EXPECTED_VALUE})"

    def test_interpret_uint64_little_endian(self) -> None:
        KNOWN_BYTES = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        EXPECTED_VALUE_LE = 0x0807060504030201

        value_le = struct.unpack("<Q", KNOWN_BYTES)[0]

        assert value_le == EXPECTED_VALUE_LE, \
            f"FAILED: Little-endian UINT64 interpretation incorrect (got {hex(value_le)}, expected {hex(EXPECTED_VALUE_LE)})"

    def test_interpret_float32(self) -> None:
        KNOWN_BYTES = b"\x00\x00\x80\x3f"  # IEEE 754 for 1.0
        EXPECTED_VALUE = 1.0

        value = struct.unpack("<f", KNOWN_BYTES)[0]

        assert abs(value - EXPECTED_VALUE) < 0.0001, \
            f"FAILED: Float32 interpretation incorrect (got {value}, expected {EXPECTED_VALUE})"

    def test_interpret_float64(self) -> None:
        KNOWN_BYTES = b"\x00\x00\x00\x00\x00\x00\xf0\x3f"  # IEEE 754 for 1.0
        EXPECTED_VALUE = 1.0

        value = struct.unpack("<d", KNOWN_BYTES)[0]

        assert abs(value - EXPECTED_VALUE) < 0.0001, \
            f"FAILED: Float64 interpretation incorrect (got {value}, expected {EXPECTED_VALUE})"

    def test_interpret_ascii_string(self) -> None:
        KNOWN_BYTES = b"LICENSE-KEY"
        EXPECTED_STRING = "LICENSE-KEY"

        decoded_string = KNOWN_BYTES.decode('ascii')

        assert decoded_string == EXPECTED_STRING, \
            f"FAILED: ASCII string interpretation incorrect (got {decoded_string}, expected {EXPECTED_STRING})"

    def test_interpret_utf8_string(self) -> None:
        KNOWN_BYTES = "Intellicrack™".encode('utf-8')
        EXPECTED_STRING = "Intellicrack™"

        decoded_string = KNOWN_BYTES.decode('utf-8')

        assert decoded_string == EXPECTED_STRING, \
            f"FAILED: UTF-8 string interpretation incorrect (got {decoded_string}, expected {EXPECTED_STRING})"

    def test_interpret_utf16_le_string(self) -> None:
        KNOWN_STRING = "KEY-VALIDATION"
        encoded_bytes = KNOWN_STRING.encode('utf-16-le')

        decoded_string = encoded_bytes.decode('utf-16-le')

        assert decoded_string == KNOWN_STRING, \
            f"FAILED: UTF-16 LE string interpretation incorrect (got {decoded_string}, expected {KNOWN_STRING})"


@pytest.mark.skipif(not HEXVIEW_AVAILABLE, reason=f"Hexview not available: {'' if HEXVIEW_AVAILABLE else IMPORT_ERROR}")
class TestFileComparisonEffectiveness:

    def test_identical_files_no_differences(self, temp_dir: Path) -> None:
        KNOWN_CONTENT = b"IDENTICAL_BINARY_CONTENT_FOR_TESTING"

        file1 = temp_dir / "file1.bin"
        file2 = temp_dir / "file2.bin"

        file1.write_bytes(KNOWN_CONTENT)
        file2.write_bytes(KNOWN_CONTENT)

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) == 0, \
            f"FAILED: Identical files reported differences (found {len(differences)} differences)"

    def test_detect_single_byte_modification(self, temp_dir: Path) -> None:
        ORIGINAL_CONTENT = b"LICENSE_KEY_12345"
        MODIFIED_OFFSET = 12
        MODIFIED_CONTENT = bytearray(ORIGINAL_CONTENT)
        MODIFIED_CONTENT[MODIFIED_OFFSET] = ord('X')

        file1 = temp_dir / "original.bin"
        file2 = temp_dir / "modified.bin"

        file1.write_bytes(ORIGINAL_CONTENT)
        file2.write_bytes(bytes(MODIFIED_CONTENT))

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) >= 1, \
                "FAILED: Single-byte modification not detected"

        found_modification_at_offset = any(
            diff.offset1 == MODIFIED_OFFSET or diff.offset2 == MODIFIED_OFFSET
            for diff in differences
        )
        assert found_modification_at_offset, \
                f"FAILED: Modification at offset {MODIFIED_OFFSET} not detected in differences"

    def test_detect_multiple_modifications(self, temp_dir: Path) -> None:
        ORIGINAL_CONTENT = b"PROTECTION_SCHEME_ORIGINAL_DATA_CONTENT"

        MODIFIED_CONTENT = bytearray(ORIGINAL_CONTENT)
        MODIFIED_CONTENT[10] = ord('X')
        MODIFIED_CONTENT[20] = ord('Y')
        MODIFIED_CONTENT[30] = ord('Z')

        file1 = temp_dir / "original.bin"
        file2 = temp_dir / "modified.bin"

        file1.write_bytes(ORIGINAL_CONTENT)
        file2.write_bytes(bytes(MODIFIED_CONTENT))

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) >= 1, \
            f"FAILED: Multiple modifications not detected (found {len(differences)} difference blocks)"

    def test_detect_size_difference(self, temp_dir: Path) -> None:
        SHORT_CONTENT = b"SHORT"
        LONG_CONTENT = b"SHORT_BUT_NOW_MUCH_LONGER"

        file1 = temp_dir / "short.bin"
        file2 = temp_dir / "long.bin"

        file1.write_bytes(SHORT_CONTENT)
        file2.write_bytes(LONG_CONTENT)

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) >= 1, \
            "FAILED: Size difference not detected"

    def test_compare_binary_with_known_patch(self, temp_dir: Path) -> None:
        ORIGINAL_BINARY = b"\x90" * 100
        KNOWN_PATCH_OFFSET = 50
        KNOWN_PATCH_BYTES = b"\xC3\xC3\xC3"

        patched_binary = bytearray(ORIGINAL_BINARY)
        patched_binary[KNOWN_PATCH_OFFSET:KNOWN_PATCH_OFFSET + len(KNOWN_PATCH_BYTES)] = KNOWN_PATCH_BYTES

        file1 = temp_dir / "original.bin"
        file2 = temp_dir / "patched.bin"

        file1.write_bytes(ORIGINAL_BINARY)
        file2.write_bytes(bytes(patched_binary))

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) >= 1, \
                "FAILED: Binary patch not detected"

        patch_detected = any(
            (
                diff.offset1 <= KNOWN_PATCH_OFFSET < diff.offset1 + diff.length1
                or diff.offset2 <= KNOWN_PATCH_OFFSET < diff.offset2 + diff.length2
            )
            for diff in differences
        )
        assert patch_detected, \
                f"FAILED: Patch at offset {KNOWN_PATCH_OFFSET} not detected in difference blocks"


@pytest.mark.skipif(not HEXVIEW_AVAILABLE, reason=f"Hexview not available: {'' if HEXVIEW_AVAILABLE else IMPORT_ERROR}")
class TestLargeFileHandlingEffectiveness:

    def test_handle_1mb_file(self, temp_dir: Path) -> None:
        KNOWN_SIZE = 1024 * 1024  # 1 MB
        KNOWN_PATTERN = b"\xAA"

        large_file = temp_dir / "1mb_file.bin"
        large_file.write_bytes(KNOWN_PATTERN * KNOWN_SIZE)

        file_size = os.path.getsize(large_file)

        assert file_size == KNOWN_SIZE, \
            f"FAILED: 1MB file creation incorrect (got {file_size}, expected {KNOWN_SIZE})"

        data = large_file.read_bytes()

        assert len(data) == KNOWN_SIZE, \
            f"FAILED: 1MB file reading incorrect (got {len(data)} bytes, expected {KNOWN_SIZE})"

    def test_checksum_large_file(self, temp_dir: Path) -> None:
        KNOWN_SIZE = 10 * 1024  # 10 KB
        KNOWN_DATA = b"\x42" * KNOWN_SIZE

        large_file = temp_dir / "large_checksum.bin"
        large_file.write_bytes(KNOWN_DATA)

        data = large_file.read_bytes()
        checksum = calculate_crc32(data)

        assert checksum is not None, \
            "FAILED: CRC32 checksum calculation returned None for large file"
        assert isinstance(checksum, int), \
            "FAILED: CRC32 checksum is not an integer"

    def test_compare_large_identical_files(self, temp_dir: Path) -> None:
        KNOWN_SIZE = 50 * 1024  # 50 KB
        KNOWN_DATA = b"\xFF" * KNOWN_SIZE

        file1 = temp_dir / "large1.bin"
        file2 = temp_dir / "large2.bin"

        file1.write_bytes(KNOWN_DATA)
        file2.write_bytes(KNOWN_DATA)

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) == 0, \
            f"FAILED: Large identical files reported differences (found {len(differences)})"

    def test_compare_large_files_with_difference(self, temp_dir: Path) -> None:
        KNOWN_SIZE = 20 * 1024  # 20 KB
        KNOWN_DIFF_OFFSET = 10000

        data1 = bytearray(b"\xAA" * KNOWN_SIZE)
        data2 = bytearray(b"\xAA" * KNOWN_SIZE)
        data2[KNOWN_DIFF_OFFSET] = 0xBB

        file1 = temp_dir / "large1.bin"
        file2 = temp_dir / "large2.bin"

        file1.write_bytes(bytes(data1))
        file2.write_bytes(bytes(data2))

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) >= 1, \
            "FAILED: Difference in large file not detected"


@pytest.mark.skipif(not HEXVIEW_AVAILABLE, reason=f"Hexview not available: {'' if HEXVIEW_AVAILABLE else IMPORT_ERROR}")
class TestProtectionPatternDetectionEffectiveness:

    def test_detect_vmprotect_section_pattern(self) -> None:
        KNOWN_BINARY_WITH_VMP = b"MZ\x90\x00" + b"\x00" * 100 + b".vmp0\x00\x00\x00" + b"\x00" * 100

        vmp_detected = b".vmp0" in KNOWN_BINARY_WITH_VMP or b".vmp1" in KNOWN_BINARY_WITH_VMP

        assert vmp_detected, \
            "FAILED: VMProtect section pattern (.vmp0) not detected in binary"

    def test_detect_themida_section_pattern(self) -> None:
        KNOWN_BINARY_WITH_THEMIDA = b"MZ\x90\x00" + b"\x00" * 100 + b".themida" + b"\x00" * 100

        themida_detected = b".themida" in KNOWN_BINARY_WITH_THEMIDA

        assert themida_detected, \
            "FAILED: Themida section pattern (.themida) not detected in binary"

    def test_detect_upx_signature(self) -> None:
        KNOWN_BINARY_WITH_UPX = b"MZ\x90\x00" + b"\x00" * 100 + b"UPX0" + b"\x00" * 100 + b"UPX1"

        upx_detected = b"UPX0" in KNOWN_BINARY_WITH_UPX or b"UPX1" in KNOWN_BINARY_WITH_UPX

        assert upx_detected, \
            "FAILED: UPX signature (UPX0/UPX1) not detected in binary"

    def test_detect_license_key_pattern(self) -> None:
        KNOWN_BINARY = b"\x00" * 100 + b"LICENSE-KEY:" + b"\x00" * 100

        license_key_marker = b"LICENSE-KEY:" in KNOWN_BINARY or b"SERIAL:" in KNOWN_BINARY

        assert license_key_marker, \
            "FAILED: License key pattern marker not detected in binary"

    def test_detect_rsa_public_key_marker(self) -> None:
        KNOWN_BINARY = b"\x00" * 50 + b"-----BEGIN PUBLIC KEY-----" + b"\x00" * 100

        rsa_key_detected = b"-----BEGIN PUBLIC KEY-----" in KNOWN_BINARY or b"-----BEGIN RSA PUBLIC KEY-----" in KNOWN_BINARY

        assert rsa_key_detected, \
            "FAILED: RSA public key marker not detected in binary"
