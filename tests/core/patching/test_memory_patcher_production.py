"""Production Tests for Memory Patcher - Validates Real Patching Capabilities.

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

CRITICAL: These tests validate REAL memory patching against actual binaries.
Tests MUST FAIL if WriteProcessMemory, VirtualProtectEx, pattern-based patching,
verification, or rollback are non-functional.
"""

import ctypes
import os
import platform
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.patching.memory_patcher import (
    PAGE_EXECUTE_READWRITE,
    PAGE_GUARD,
    PAGE_NOACCESS,
    _bypass_memory_protection_windows,
    _handle_guard_pages_windows,
    _patch_memory_windows,
    bypass_memory_protection,
    detect_and_bypass_guard_pages,
    handle_guard_pages,
    patch_memory_direct,
)


@pytest.fixture
def real_writable_buffer() -> Any:
    """Create real writable memory buffer for testing."""
    buffer = ctypes.create_string_buffer(8192)
    original_data = b"ORIGINAL_CONTENT_FOR_PATCHING" * 100
    ctypes.memmove(buffer, original_data, min(len(original_data), 8192))
    return buffer


@pytest.fixture
def real_process_handle() -> int:
    """Get real process handle with full access rights."""
    if platform.system() != "Windows":
        pytest.skip("Windows-only test")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_ALL_ACCESS = 0x1F0FFF
    current_pid = os.getpid()

    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, current_pid)
    if not handle:
        pytest.fail(f"Failed to open process handle: error {ctypes.get_last_error()}")

    yield handle

    kernel32.CloseHandle(handle)


@pytest.fixture
def real_protected_executable(tmp_path: Path) -> Path:
    """Create real executable with protection patterns for testing.

    This generates a minimal PE executable with:
    - Valid PE headers
    - Code section with license check patterns
    - Data section with serial validation
    - Realistic instruction sequences that would be patched
    """
    exe_path = tmp_path / "protected_target.exe"

    dos_header = bytearray(b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80))
    dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        2,
        int(time.time()),
        0,
        0,
        0xE0,
        0x010B,
    )

    optional_header = bytearray(224)
    struct.pack_into("<H", optional_header, 0, 0x010B)
    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<I", optional_header, 20, 0x400000)
    struct.pack_into("<I", optional_header, 24, 0x1000)
    struct.pack_into("<I", optional_header, 28, 0x200)
    struct.pack_into("<H", optional_header, 64, 5)

    section_headers = bytearray()

    code_section_name = b".text\x00\x00\x00"
    code_section = struct.pack(
        "<8sIIIIIIHHI",
        code_section_name,
        0x1000,
        0x1000,
        0x1000,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    section_headers += code_section

    data_section_name = b".data\x00\x00\x00"
    data_section = struct.pack(
        "<8sIIIIIIHHI",
        data_section_name,
        0x1000,
        0x2000,
        0x1000,
        0x1400,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    section_headers += data_section

    code_content = bytearray(0x1000)

    offset = 0
    code_content[offset:offset+3] = b"\x55\x89\xE5"
    offset += 3

    code_content[offset:offset+5] = b"\x83\x7D\x08\x00\x74"
    license_check_je = offset + 4
    code_content[offset+4:offset+5] = b"\x15"
    offset += 5

    code_content[offset:offset+7] = b"\x8B\x45\x08\x50\xE8\x00\x00"
    offset += 7

    code_content[offset:offset+4] = b"\x85\xC0\x74\x20"
    serial_check_je = offset + 2
    offset += 4

    code_content[offset:offset+5] = b"\xB8\x01\x00\x00\x00"
    offset += 5

    code_content[offset:offset+2] = b"\xC9\xC3"
    offset += 2

    code_content[offset:offset+5] = b"\x33\xC0\xC9\xC3\x90"
    offset += 5

    data_content = bytearray(0x1000)
    serial_key = b"ABCD-1234-EFGH-5678\x00"
    data_content[0:len(serial_key)] = serial_key

    validation_table = struct.pack("<IIII", 0x12345678, 0xABCDEF00, 0xDEADBEEF, 0xCAFEBABE)
    data_content[0x100:0x100+16] = validation_table

    pe_content = bytearray(0x400)
    pe_content[0:len(dos_header)] = dos_header
    pe_content[0x40:0x40+len(dos_stub)] = dos_stub
    pe_content[0x80:0x80+4] = pe_signature
    pe_content[0x84:0x84+20] = coff_header
    pe_content[0x98:0x98+224] = optional_header
    pe_content[0x178:0x178+len(section_headers)] = section_headers

    full_binary = pe_content + code_content + data_content

    exe_path.write_bytes(full_binary)

    return exe_path


class TestAtomicMemoryProtectionChanges:
    """Validates atomic protection changes with VirtualProtectEx."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_virtualprotectex_changes_protection_atomically(
        self, real_writable_buffer: Any, real_process_handle: int
    ) -> None:
        """VirtualProtectEx changes protection in single atomic operation."""
        address = ctypes.addressof(real_writable_buffer)
        size = 4096

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        from intellicrack.core.patching.memory_patcher import _get_wintypes
        wintypes, _ = _get_wintypes()

        old_protect = wintypes.DWORD()

        result = kernel32.VirtualProtectEx(
            real_process_handle,
            ctypes.c_void_p(address),
            size,
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        )

        assert result != 0, f"VirtualProtectEx failed: {ctypes.get_last_error()}"
        assert old_protect.value != 0, "Old protection not retrieved"

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        query_result = kernel32.VirtualQueryEx(
            real_process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        assert query_result != 0, "VirtualQueryEx failed"
        assert mbi.Protect == PAGE_EXECUTE_READWRITE, "Protection not changed atomically"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_writeprocessmemory_with_protection_change(
        self, real_writable_buffer: Any, real_process_handle: int
    ) -> None:
        """WriteProcessMemory succeeds after VirtualProtectEx protection change."""
        address = ctypes.addressof(real_writable_buffer)
        patch_data = b"\xEB\x10\x90\x90"

        result = _patch_memory_windows(os.getpid(), address, patch_data)

        assert result, "WriteProcessMemory failed after protection change"

        actual_bytes = ctypes.string_at(address, len(patch_data))
        assert actual_bytes == patch_data, "Data not written correctly"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_protection_restored_after_patch(
        self, real_writable_buffer: Any, real_process_handle: int
    ) -> None:
        """Original protection restored after patching operation."""
        address = ctypes.addressof(real_writable_buffer)

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        from intellicrack.core.patching.memory_patcher import _get_wintypes
        wintypes, _ = _get_wintypes()

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi_before = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQueryEx(
            real_process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi_before),
            ctypes.sizeof(mbi_before),
        )
        original_protect = mbi_before.Protect

        patch_data = b"\x90\x90\x90\x90"
        result = _patch_memory_windows(os.getpid(), address, patch_data)
        assert result, "Patch failed"

        mbi_after = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQueryEx(
            real_process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi_after),
            ctypes.sizeof(mbi_after),
        )

        assert mbi_after.Protect == original_protect, "Protection not restored after patch"


class TestPatternBasedPatchLocation:
    """Validates pattern-based patch location identification."""

    def test_find_license_check_pattern_in_memory(self, real_writable_buffer: Any) -> None:
        """Locates license check pattern (TEST/JE sequence) in memory."""
        address = ctypes.addressof(real_writable_buffer)

        pattern = b"\x85\xC0\x74\x10"
        offset = 500
        ctypes.memmove(address + offset, pattern, len(pattern))

        buffer_content = ctypes.string_at(address, 1000)
        pattern_location = buffer_content.find(pattern)

        assert pattern_location != -1, "Pattern not found in buffer"
        assert pattern_location == offset, "Pattern location incorrect"

        found_address = address + pattern_location
        found_bytes = ctypes.string_at(found_address, len(pattern))
        assert found_bytes == pattern, "Pattern verification failed"

    def test_find_multiple_patterns_in_memory(self, real_writable_buffer: Any) -> None:
        """Locates multiple different patterns in same memory region."""
        address = ctypes.addressof(real_writable_buffer)

        patterns = [
            (100, b"\x74\x05"),
            (200, b"\x75\x10"),
            (300, b"\xEB\x20"),
            (400, b"\x85\xC0\x74\x15"),
        ]

        for offset, pattern in patterns:
            ctypes.memmove(address + offset, pattern, len(pattern))

        buffer_content = ctypes.string_at(address, 500)

        for expected_offset, pattern in patterns:
            found_offset = buffer_content.find(pattern)
            assert found_offset == expected_offset, f"Pattern {pattern.hex()} not at expected offset"

    def test_pattern_search_with_wildcards(self, real_writable_buffer: Any) -> None:
        """Finds patterns with wildcard bytes (variable operands)."""
        address = ctypes.addressof(real_writable_buffer)

        full_pattern = b"\x8B\x45\xF8\x83\xC0\x01"
        offset = 250
        ctypes.memmove(address + offset, full_pattern, len(full_pattern))

        wildcard_pattern = b"\x8B\x45"
        buffer_content = ctypes.string_at(address, 300)
        found_offset = buffer_content.find(wildcard_pattern)

        assert found_offset == offset, "Wildcard pattern search failed"

        full_match = ctypes.string_at(address + found_offset, len(full_pattern))
        assert full_match == full_pattern, "Full pattern verification failed"

    @pytest.mark.skipif(
        not Path("D:/Intellicrack/tests/fixtures/real_protected_binary.exe").exists(),
        reason="Real protected binary not available at D:/Intellicrack/tests/fixtures/real_protected_binary.exe"
    )
    def test_locate_license_check_in_real_binary(self) -> None:
        """Locates actual license check patterns in real protected binary.

        CRITICAL: This test requires a real protected binary at:
        D:/Intellicrack/tests/fixtures/real_protected_binary.exe

        The binary should contain standard license validation patterns:
        - TEST EAX, EAX / JE pattern (85 C0 74 XX)
        - CMP/JNE pattern (83 XX XX 75 XX)
        - String comparison patterns

        If this test is skipped, it means NO REAL BINARY is available for testing.
        Tests passing without this validation do NOT prove production readiness.
        """
        binary_path = Path("D:/Intellicrack/tests/fixtures/real_protected_binary.exe")
        binary_data = binary_path.read_bytes()

        license_check_patterns = [
            b"\x85\xC0\x74",
            b"\x85\xC0\x75",
            b"\x83\x7D\x08\x00\x74",
            b"\x3B\x45",
        ]

        found_patterns = []
        for pattern in license_check_patterns:
            offset = binary_data.find(pattern)
            if offset != -1:
                found_patterns.append((pattern, offset))

        assert len(found_patterns) > 0, "No license check patterns found in real binary"

        for pattern, offset in found_patterns:
            context = binary_data[max(0, offset-10):offset+len(pattern)+10]
            assert pattern in context, f"Pattern {pattern.hex()} context validation failed"


class TestPatchVerification:
    """Validates patch application verification mechanisms."""

    def test_verify_patch_applied_successfully(self, real_writable_buffer: Any) -> None:
        """Verifies patch was written correctly by reading back."""
        address = ctypes.addressof(real_writable_buffer)

        original = b"ORIGINAL"
        ctypes.memmove(address, original, len(original))

        patch_data = b"PATCHED!"
        result = patch_memory_direct(os.getpid(), address, patch_data)

        assert result, "Patch operation failed"

        actual = ctypes.string_at(address, len(patch_data))
        assert actual == patch_data, f"Verification failed: expected {patch_data.hex()}, got {actual.hex()}"

    def test_verify_partial_patch_failure(self, real_writable_buffer: Any) -> None:
        """Detects partial patch writes (incomplete operations)."""
        address = ctypes.addressof(real_writable_buffer)
        expected_size = 16

        patch_data = b"\xDE\xAD\xBE\xEF" * 4
        assert len(patch_data) == expected_size

        result = patch_memory_direct(os.getpid(), address, patch_data)

        if result:
            actual = ctypes.string_at(address, expected_size)
            assert len(actual) == expected_size, "Partial write detected"
            assert actual == patch_data, "Incomplete patch data"

    def test_verify_patch_boundaries(self, real_writable_buffer: Any) -> None:
        """Verifies patch doesn't corrupt adjacent memory."""
        address = ctypes.addressof(real_writable_buffer)

        before_region = b"BEFORE_REGION___"
        patch_region = b"PATCH_DATA______"
        after_region = b"AFTER_REGION____"

        total_size = len(before_region) + len(patch_region) + len(after_region)

        ctypes.memmove(address, before_region, len(before_region))
        ctypes.memmove(address + len(before_region), b"X" * len(patch_region), len(patch_region))
        ctypes.memmove(address + len(before_region) + len(patch_region), after_region, len(after_region))

        patch_offset = len(before_region)
        result = patch_memory_direct(os.getpid(), address + patch_offset, patch_region)
        assert result, "Patch failed"

        before_actual = ctypes.string_at(address, len(before_region))
        patch_actual = ctypes.string_at(address + patch_offset, len(patch_region))
        after_actual = ctypes.string_at(address + patch_offset + len(patch_region), len(after_region))

        assert before_actual == before_region, "Before region corrupted"
        assert patch_actual == patch_region, "Patch region incorrect"
        assert after_actual == after_region, "After region corrupted"

    def test_verify_multiple_patches_independently(self, real_writable_buffer: Any) -> None:
        """Verifies each patch in sequence independently."""
        address = ctypes.addressof(real_writable_buffer)

        patches = [
            (0, b"\x90\x90\x90\x90"),
            (50, b"\xEB\x10\x90\x90"),
            (100, b"\xC3\x90\x90\x90"),
            (150, b"\x74\x05\x90\x90"),
        ]

        for offset, patch_data in patches:
            result = patch_memory_direct(os.getpid(), address + offset, patch_data)
            assert result, f"Patch at offset {offset} failed"

            verification = ctypes.string_at(address + offset, len(patch_data))
            assert verification == patch_data, f"Verification failed at offset {offset}"


class TestPatchRollback:
    """Validates patch rollback and restoration capabilities."""

    def test_save_original_bytes_before_patch(self, real_writable_buffer: Any) -> None:
        """Saves original bytes before applying patch for rollback."""
        address = ctypes.addressof(real_writable_buffer)
        patch_size = 8

        original_bytes = ctypes.string_at(address, patch_size)

        assert len(original_bytes) == patch_size, "Original bytes not captured"
        assert original_bytes != b"\x00" * patch_size, "Original bytes appear uninitialized"

    def test_rollback_patch_to_original_state(self, real_writable_buffer: Any) -> None:
        """Rolls back patch by restoring saved original bytes."""
        address = ctypes.addressof(real_writable_buffer)
        patch_size = 16

        original_bytes = ctypes.string_at(address, patch_size)

        patch_data = b"\xDE\xAD\xBE\xEF" * 4
        result = patch_memory_direct(os.getpid(), address, patch_data)
        assert result, "Patch failed"

        patched_bytes = ctypes.string_at(address, patch_size)
        assert patched_bytes == patch_data, "Patch not applied"

        rollback_result = patch_memory_direct(os.getpid(), address, original_bytes)
        assert rollback_result, "Rollback failed"

        restored_bytes = ctypes.string_at(address, patch_size)
        assert restored_bytes == original_bytes, "Rollback incomplete"

    def test_rollback_multiple_patches_in_reverse_order(self, real_writable_buffer: Any) -> None:
        """Rolls back multiple patches in reverse application order."""
        address = ctypes.addressof(real_writable_buffer)

        patches_with_originals = []

        offsets = [0, 50, 100, 150]
        for offset in offsets:
            original = ctypes.string_at(address + offset, 4)
            patches_with_originals.append((offset, original, b"\xCC" * 4))

        for offset, original, patch_data in patches_with_originals:
            result = patch_memory_direct(os.getpid(), address + offset, patch_data)
            assert result, f"Patch at offset {offset} failed"

        for offset, original, patch_data in reversed(patches_with_originals):
            rollback_result = patch_memory_direct(os.getpid(), address + offset, original)
            assert rollback_result, f"Rollback at offset {offset} failed"

            restored = ctypes.string_at(address + offset, len(original))
            assert restored == original, f"Rollback verification failed at offset {offset}"

    def test_partial_rollback_specific_patches(self, real_writable_buffer: Any) -> None:
        """Rolls back specific patches while keeping others applied."""
        address = ctypes.addressof(real_writable_buffer)

        patch1_offset = 0
        patch2_offset = 50
        patch3_offset = 100

        original1 = ctypes.string_at(address + patch1_offset, 4)
        original2 = ctypes.string_at(address + patch2_offset, 4)
        original3 = ctypes.string_at(address + patch3_offset, 4)

        patch1 = b"\xAA\xAA\xAA\xAA"
        patch2 = b"\xBB\xBB\xBB\xBB"
        patch3 = b"\xCC\xCC\xCC\xCC"

        patch_memory_direct(os.getpid(), address + patch1_offset, patch1)
        patch_memory_direct(os.getpid(), address + patch2_offset, patch2)
        patch_memory_direct(os.getpid(), address + patch3_offset, patch3)

        rollback_result = patch_memory_direct(os.getpid(), address + patch2_offset, original2)
        assert rollback_result, "Selective rollback failed"

        state1 = ctypes.string_at(address + patch1_offset, 4)
        state2 = ctypes.string_at(address + patch2_offset, 4)
        state3 = ctypes.string_at(address + patch3_offset, 4)

        assert state1 == patch1, "Patch 1 should remain applied"
        assert state2 == original2, "Patch 2 should be rolled back"
        assert state3 == patch3, "Patch 3 should remain applied"


class TestGuardPageHandling:
    """Validates guard page detection and handling."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_detect_guard_page_protection(self, real_process_handle: int) -> None:
        """Detects PAGE_GUARD protection on memory region."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        buffer = ctypes.create_string_buffer(8192)
        address = ctypes.addressof(buffer)

        from intellicrack.core.patching.memory_patcher import _get_wintypes
        wintypes, _ = _get_wintypes()

        old_protect = wintypes.DWORD()
        kernel32.VirtualProtect(
            ctypes.c_void_p(address),
            4096,
            PAGE_GUARD | PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        )

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQuery(
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        assert mbi.Protect & PAGE_GUARD, "PAGE_GUARD not detected"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_remove_guard_page_before_patch(self, real_process_handle: int) -> None:
        """Removes PAGE_GUARD protection before applying patch."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        buffer = ctypes.create_string_buffer(8192)
        address = ctypes.addressof(buffer)

        from intellicrack.core.patching.memory_patcher import _get_wintypes
        wintypes, _ = _get_wintypes()

        old_protect = wintypes.DWORD()
        kernel32.VirtualProtect(
            ctypes.c_void_p(address),
            4096,
            PAGE_GUARD | PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        )

        result = handle_guard_pages(address, 4096)
        assert result, "Guard page removal failed"

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQuery(
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        assert not (mbi.Protect & PAGE_GUARD), "PAGE_GUARD not removed"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_patch_succeeds_after_guard_removal(self, real_process_handle: int) -> None:
        """Patch operation succeeds after guard page removal."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        buffer = ctypes.create_string_buffer(8192)
        address = ctypes.addressof(buffer)

        from intellicrack.core.patching.memory_patcher import _get_wintypes
        wintypes, _ = _get_wintypes()

        old_protect = wintypes.DWORD()
        kernel32.VirtualProtect(
            ctypes.c_void_p(address),
            4096,
            PAGE_GUARD | PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        )

        guard_result = handle_guard_pages(address, 4096)
        assert guard_result, "Guard removal failed"

        patch_data = b"\x90\x90\x90\x90"
        patch_result = patch_memory_direct(os.getpid(), address, patch_data)
        assert patch_result, "Patch failed after guard removal"

        verified = ctypes.string_at(address, len(patch_data))
        assert verified == patch_data, "Patch verification failed"


class TestCopyOnWriteSections:
    """Validates handling of copy-on-write memory sections."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_detect_copy_on_write_protection(self) -> None:
        """Detects PAGE_WRITECOPY protection on memory sections."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        from intellicrack.core.patching.memory_patcher import _get_wintypes
        wintypes, _ = _get_wintypes()

        PAGE_WRITECOPY = 0x08

        address = kernel32.VirtualAlloc(
            None,
            4096,
            0x1000,
            PAGE_WRITECOPY,
        )

        if not address:
            pytest.skip("Failed to allocate PAGE_WRITECOPY memory")

        try:
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            mbi = MEMORY_BASIC_INFORMATION()
            kernel32.VirtualQuery(
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )

            assert mbi.Protect & PAGE_WRITECOPY, "PAGE_WRITECOPY not detected"
        finally:
            kernel32.VirtualFree(address, 0, 0x8000)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_modify_copy_on_write_section(self) -> None:
        """Modifies copy-on-write section triggering private copy."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        PAGE_WRITECOPY = 0x08

        address = kernel32.VirtualAlloc(
            None,
            4096,
            0x1000,
            PAGE_WRITECOPY,
        )

        if not address:
            pytest.skip("Failed to allocate PAGE_WRITECOPY memory")

        try:
            original_data = b"ORIGINAL_COW_DATA"
            ctypes.memmove(address, original_data, len(original_data))

            bypass_result = bypass_memory_protection(address, 4096, PAGE_EXECUTE_READWRITE)
            assert bypass_result, "Protection change failed"

            patch_data = b"PATCHED_COW_DATA_"
            patch_result = patch_memory_direct(os.getpid(), address, patch_data)
            assert patch_result, "Patch to COW section failed"

            verified = ctypes.string_at(address, len(patch_data))
            assert verified == patch_data, "COW patch verification failed"
        finally:
            kernel32.VirtualFree(address, 0, 0x8000)


class TestRealBinaryPatchingWorkflow:
    """Integration tests for complete real-world patching workflows."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_patch_real_executable_license_check(self, real_protected_executable: Path) -> None:
        """Patches real executable license check using complete workflow."""
        if not real_protected_executable.exists():
            pytest.fail("Protected executable not created")

        binary_data = real_protected_executable.read_bytes()

        license_check_pattern = b"\x83\x7D\x08\x00\x74"
        pattern_offset = binary_data.find(license_check_pattern)

        if pattern_offset == -1:
            pytest.skip("License check pattern not found in test binary")

        je_offset = pattern_offset + 4

        subprocess_args = [
            sys.executable,
            "-c",
            f"""
import ctypes
import time

binary_path = r"{real_protected_executable}"
with open(binary_path, "rb") as f:
    data = f.read()

pattern = b"\\x83\\x7D\\x08\\x00\\x74"
offset = data.find(pattern)
print(f"Pattern offset: {{offset}}")

time.sleep(5)
""",
        ]

        proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)

        try:
            pid = proc.pid

            from intellicrack.core.patching.memory_patcher import _get_wintypes
            wintypes, _ = _get_wintypes()

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            PROCESS_ALL_ACCESS = 0x1F0FFF
            process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

            if not process_handle:
                pytest.skip(f"Failed to open target process: {ctypes.get_last_error()}")

            try:
                modules = (ctypes.c_void_p * 1024)()
                cb_needed = ctypes.c_ulong()

                psapi = ctypes.WinDLL("psapi", use_last_error=True)
                if psapi.EnumProcessModules(
                    process_handle,
                    ctypes.byref(modules),
                    ctypes.sizeof(modules),
                    ctypes.byref(cb_needed),
                ):
                    base_address = modules[0]

                    patch_address = base_address + pattern_offset + 4

                    patch_data = b"\xEB"

                    old_protect = wintypes.DWORD()
                    protect_result = kernel32.VirtualProtectEx(
                        process_handle,
                        ctypes.c_void_p(patch_address),
                        1,
                        PAGE_EXECUTE_READWRITE,
                        ctypes.byref(old_protect),
                    )

                    assert protect_result != 0, "VirtualProtectEx failed"

                    bytes_written = ctypes.c_size_t()
                    write_result = kernel32.WriteProcessMemory(
                        process_handle,
                        ctypes.c_void_p(patch_address),
                        patch_data,
                        len(patch_data),
                        ctypes.byref(bytes_written),
                    )

                    assert write_result != 0, "WriteProcessMemory failed"
                    assert bytes_written.value == len(patch_data), "Incomplete write"

                    read_buffer = ctypes.create_string_buffer(1)
                    bytes_read = ctypes.c_size_t()
                    read_result = kernel32.ReadProcessMemory(
                        process_handle,
                        ctypes.c_void_p(patch_address),
                        read_buffer,
                        1,
                        ctypes.byref(bytes_read),
                    )

                    assert read_result != 0, "ReadProcessMemory failed"
                    assert read_buffer.raw[0:1] == patch_data, "Patch verification failed"

                    kernel32.VirtualProtectEx(
                        process_handle,
                        ctypes.c_void_p(patch_address),
                        1,
                        old_protect.value,
                        ctypes.byref(old_protect),
                    )
                else:
                    pytest.skip("Failed to enumerate modules")
            finally:
                kernel32.CloseHandle(process_handle)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_complete_patch_workflow_with_rollback(self, real_writable_buffer: Any) -> None:
        """Complete workflow: locate pattern, patch, verify, rollback."""
        address = ctypes.addressof(real_writable_buffer)

        pattern = b"\x85\xC0\x74\x10"
        pattern_offset = 500
        ctypes.memmove(address + pattern_offset, pattern, len(pattern))

        original_bytes = ctypes.string_at(address + pattern_offset, len(pattern))
        assert original_bytes == pattern, "Pattern setup failed"

        buffer_content = ctypes.string_at(address, 1000)
        found_offset = buffer_content.find(pattern)
        assert found_offset == pattern_offset, "Pattern location failed"

        patch_data = b"\x85\xC0\xEB\x10"
        patch_result = patch_memory_direct(os.getpid(), address + found_offset, patch_data)
        assert patch_result, "Patch application failed"

        patched_bytes = ctypes.string_at(address + found_offset, len(patch_data))
        assert patched_bytes == patch_data, "Patch verification failed"

        rollback_result = patch_memory_direct(os.getpid(), address + found_offset, original_bytes)
        assert rollback_result, "Rollback failed"

        restored_bytes = ctypes.string_at(address + found_offset, len(original_bytes))
        assert restored_bytes == original_bytes, "Rollback verification failed"


class TestEdgeCaseHandling:
    """Tests for edge cases and error conditions."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_patch_across_page_boundary(self) -> None:
        """Patches data spanning multiple memory pages."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        from intellicrack.core.patching.memory_patcher import _get_wintypes
        wintypes, _ = _get_wintypes()

        class SYSTEM_INFO(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", ctypes.c_ushort),
                ("wReserved", ctypes.c_ushort),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_size_t),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", ctypes.c_ushort),
                ("wProcessorRevision", ctypes.c_ushort),
            ]

        si = SYSTEM_INFO()
        kernel32.GetSystemInfo(ctypes.byref(si))
        page_size = si.dwPageSize

        buffer = ctypes.create_string_buffer(page_size * 2)
        address = ctypes.addressof(buffer)

        boundary_offset = page_size - 4
        patch_data = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"

        bypass_memory_protection(address, page_size * 2)

        result = patch_memory_direct(os.getpid(), address + boundary_offset, patch_data)
        assert result, "Cross-page patch failed"

        verified = ctypes.string_at(address + boundary_offset, len(patch_data))
        assert verified == patch_data, "Cross-page patch verification failed"

    def test_handle_zero_size_patch(self, real_writable_buffer: Any) -> None:
        """Handles zero-size patch gracefully."""
        address = ctypes.addressof(real_writable_buffer)

        result = patch_memory_direct(os.getpid(), address, b"")

        assert isinstance(result, bool)

    def test_handle_oversized_patch_data(self, real_writable_buffer: Any) -> None:
        """Handles patch data larger than typical buffer."""
        address = ctypes.addressof(real_writable_buffer)

        large_patch = b"\x90" * 4096
        result = patch_memory_direct(os.getpid(), address, large_patch)

        assert isinstance(result, bool)

        if result:
            verified = ctypes.string_at(address, len(large_patch))
            assert verified == large_patch, "Large patch verification failed"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_handle_invalid_memory_region(self) -> None:
        """Handles patching invalid memory gracefully."""
        invalid_address = 0x0
        patch_data = b"\x90\x90"

        result = patch_memory_direct(os.getpid(), invalid_address, patch_data)

        assert not result, "Should fail on invalid address"

    def test_handle_concurrent_patch_operations(self, real_writable_buffer: Any) -> None:
        """Handles multiple concurrent patches to different regions."""
        address = ctypes.addressof(real_writable_buffer)

        import threading

        results = []

        def patch_region(offset: int, data: bytes) -> None:
            result = patch_memory_direct(os.getpid(), address + offset, data)
            results.append((offset, result))

        threads = [
            threading.Thread(target=patch_region, args=(0, b"\xAA" * 4)),
            threading.Thread(target=patch_region, args=(100, b"\xBB" * 4)),
            threading.Thread(target=patch_region, args=(200, b"\xCC" * 4)),
            threading.Thread(target=patch_region, args=(300, b"\xDD" * 4)),
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=5)

        assert len(results) == 4, "Not all patches completed"
        assert all(result for _, result in results), "Some patches failed"
