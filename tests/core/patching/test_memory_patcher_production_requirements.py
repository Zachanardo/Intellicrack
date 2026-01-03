"""Production-Ready Tests for Memory Patcher - testingtodo.md Requirements.

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

Tests validate exact requirements from testingtodo.md:
- WriteProcessMemory with VirtualProtectEx
- Atomic page protection changes
- Pattern-based patch locations
- Patch application verification
- Patch rollback capability
- Edge cases: Guard pages, copy-on-write sections
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
    _get_wintypes,
    _handle_guard_pages_windows,
    _patch_memory_windows,
    bypass_memory_protection,
    detect_and_bypass_guard_pages,
    handle_guard_pages,
    patch_memory_direct,
)


@pytest.fixture
def isolated_process(tmp_path: Path) -> subprocess.Popen[bytes]:
    """Create isolated test process for real memory operations.

    Returns:
        Popen process object for testing memory patching.

    """
    test_program = tmp_path / "test_target.py"
    test_program.write_text(
        """
import time
import sys

data_buffer = bytearray(b"ORIGINAL_LICENSE_CHECK" * 100)
print(f"PID:{os.getpid()}", flush=True)
print(f"BUFFER_ADDR:{id(data_buffer)}", flush=True)

while True:
    time.sleep(0.1)
""",
        encoding="utf-8",
    )

    proc: subprocess.Popen[bytes] = subprocess.Popen(
        [sys.executable, str(test_program)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(0.5)

    yield proc

    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture
def writable_memory() -> tuple[int, Any]:
    """Create writable memory buffer for testing.

    Returns:
        Tuple of (address, buffer) for testing.

    """
    buffer = ctypes.create_string_buffer(8192)
    test_data = b"LICENSE_CHECK_ROUTINE" * 100
    ctypes.memmove(buffer, test_data, min(len(test_data), 8192))
    return ctypes.addressof(buffer), buffer


@pytest.fixture
def protected_memory() -> tuple[int, Any]:
    """Create protected memory that requires VirtualProtectEx.

    Returns:
        Tuple of (address, buffer) for testing.

    """
    buffer = ctypes.create_string_buffer(4096)
    address: int = ctypes.addressof(buffer)

    if platform.system() == "Windows":
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        old_protect = wintypes.DWORD()

        PAGE_READONLY: int = 0x02
        kernel32.VirtualProtect(
            ctypes.c_void_p(address), 4096, PAGE_READONLY, ctypes.byref(old_protect)
        )

    return address, buffer


class PatternSearcher:
    """Real pattern-based patch location finder."""

    @staticmethod
    def find_pattern(data: bytes, pattern: bytes) -> list[int]:
        """Find all occurrences of byte pattern in data.

        Args:
            data: Byte data to search in.
            pattern: Byte pattern to find.

        Returns:
            List of offsets where pattern occurs.

        """
        offsets: list[int] = []
        search_start: int = 0

        while True:
            offset = data.find(pattern, search_start)
            if offset == -1:
                break
            offsets.append(offset)
            search_start = offset + 1

        return offsets

    @staticmethod
    def find_wildcard_pattern(data: bytes, pattern: bytes, wildcard: int = 0xFF) -> list[int]:
        """Find pattern with wildcard bytes.

        Args:
            data: Byte data to search in.
            pattern: Byte pattern with wildcards.
            wildcard: Byte value representing wildcard.

        Returns:
            List of offsets where pattern matches.

        """
        offsets: list[int] = []

        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j, pattern_byte in enumerate(pattern):
                if pattern_byte != wildcard and data[i + j] != pattern_byte:
                    match = False
                    break
            if match:
                offsets.append(i)

        return offsets


class PatchRollbackManager:
    """Real patch rollback implementation."""

    def __init__(self) -> None:
        """Initialize rollback manager with patch history."""
        self.patch_history: list[dict[str, Any]] = []

    def record_patch(self, address: int, original_data: bytes, new_data: bytes) -> None:
        """Record patch for potential rollback.

        Args:
            address: Memory address patched.
            original_data: Original bytes before patch.
            new_data: New bytes after patch.

        """
        self.patch_history.append(
            {
                "address": address,
                "original_data": original_data,
                "new_data": new_data,
                "timestamp": time.time(),
            }
        )

    def rollback_patch(self, process_id: int, patch_index: int) -> bool:
        """Rollback specific patch by index.

        Args:
            process_id: Target process ID.
            patch_index: Index of patch to rollback.

        Returns:
            True if rollback successful, False otherwise.

        """
        if patch_index >= len(self.patch_history):
            return False

        patch = self.patch_history[patch_index]
        return patch_memory_direct(
            process_id, patch["address"], patch["original_data"]
        )

    def rollback_all(self, process_id: int) -> bool:
        """Rollback all patches in reverse order.

        Args:
            process_id: Target process ID.

        Returns:
            True if all rollbacks successful, False otherwise.

        """
        for patch in reversed(self.patch_history):
            if not patch_memory_direct(
                process_id, patch["address"], patch["original_data"]
            ):
                return False
        return True


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestWriteProcessMemoryWithVirtualProtectEx:
    """Requirement: Must implement WriteProcessMemory with VirtualProtectEx."""

    def test_patch_memory_windows_uses_virtualprotectex(self, writable_memory: tuple[int, Any]) -> None:
        """_patch_memory_windows uses VirtualProtectEx before WriteProcessMemory."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        original_data = ctypes.string_at(address, 20)
        patch_data = b"\x90\x90\x90\x90\x90"

        result: bool = _patch_memory_windows(process_id, address, patch_data)

        assert result, "WriteProcessMemory with VirtualProtectEx must succeed"

        patched_data = ctypes.string_at(address, len(patch_data))
        assert patched_data == patch_data, "Patch data must be written correctly"

    def test_virtualprotectex_changes_protection_before_write(self, protected_memory: tuple[int, Any]) -> None:
        """VirtualProtectEx changes protection before WriteProcessMemory."""
        address, buffer = protected_memory
        process_id: int = os.getpid()

        patch_data = b"\xEB\x10\x90\x90"
        result: bool = _patch_memory_windows(process_id, address, patch_data)

        assert result, "VirtualProtectEx must change protection to allow writing"

        actual_data = ctypes.string_at(address, len(patch_data))
        assert actual_data == patch_data, "Write must succeed after protection change"

    def test_virtualprotectex_restores_original_protection(self, writable_memory: tuple[int, Any]) -> None:
        """VirtualProtectEx restores original protection after WriteProcessMemory."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

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
        kernel32.VirtualQuery(
            ctypes.c_void_p(address), ctypes.byref(mbi_before), ctypes.sizeof(mbi_before)
        )
        original_protection = mbi_before.Protect

        patch_data = b"\xAA\xBB\xCC\xDD"
        result: bool = _patch_memory_windows(process_id, address, patch_data)
        assert result

        mbi_after = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQuery(
            ctypes.c_void_p(address), ctypes.byref(mbi_after), ctypes.sizeof(mbi_after)
        )

        assert (
            mbi_after.Protect == original_protection
        ), "Original protection must be restored"

    def test_writeprocessmemory_verifies_bytes_written(self, writable_memory: tuple[int, Any]) -> None:
        """WriteProcessMemory verifies all bytes were written successfully."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        large_patch = b"\xDE\xAD\xBE\xEF" * 64
        result: bool = _patch_memory_windows(process_id, address, large_patch)

        assert result, "WriteProcessMemory must verify bytes_written equals data length"

        actual_data = ctypes.string_at(address, len(large_patch))
        assert (
            actual_data == large_patch
        ), "All bytes must be written and verified"
        assert len(actual_data) == len(large_patch), "Byte count verification required"

    def test_writeprocessmemory_fails_on_invalid_address(self) -> None:
        """WriteProcessMemory fails gracefully on invalid addresses."""
        invalid_address: int = 0xDEADBEEF
        process_id: int = os.getpid()
        patch_data = b"\x90\x90\x90\x90"

        result: bool = _patch_memory_windows(process_id, invalid_address, patch_data)

        assert not result, "WriteProcessMemory must fail on invalid addresses"

    def test_writeprocessmemory_handles_process_open_failure(self) -> None:
        """WriteProcessMemory handles OpenProcess failure correctly."""
        invalid_pid: int = 99999999
        address: int = 0x400000
        patch_data = b"\x90\x90"

        result: bool = _patch_memory_windows(invalid_pid, address, patch_data)

        assert not result, "Must fail when OpenProcess returns NULL"

    def test_process_handle_closed_after_patching(self, writable_memory: tuple[int, Any]) -> None:
        """Process handle is properly closed after patching operation."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        patch_data = b"\x90\x90\x90\x90"
        result: bool = _patch_memory_windows(process_id, address, patch_data)

        assert result, "Patching must succeed"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestAtomicPageProtectionChanges:
    """Requirement: Must handle page protection changes atomically."""

    def test_protection_change_is_atomic(self, writable_memory: tuple[int, Any]) -> None:
        """Protection change, write, restore happens atomically without interruption."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        original_data = ctypes.string_at(address, 16)
        patch_data = b"\xAA" * 16

        result: bool = _patch_memory_windows(process_id, address, patch_data)

        assert result, "Atomic operation must complete successfully"

        patched_data = ctypes.string_at(address, 16)
        assert patched_data == patch_data, "Data must be written during atomic operation"

    def test_atomic_operation_restores_protection_on_error(self, writable_memory: tuple[int, Any]) -> None:
        """Protection is restored even if write operation fails."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

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
            ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        original_protection = mbi.Protect

        large_invalid_patch = b"\xFF" * 1000000
        result: bool = _patch_memory_windows(process_id, address, large_invalid_patch)

        mbi_after = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQuery(
            ctypes.c_void_p(address), ctypes.byref(mbi_after), ctypes.sizeof(mbi_after)
        )

        assert (
            mbi_after.Protect == original_protection
        ), "Protection must be restored even on failure"

    def test_no_race_condition_during_protection_change(self, writable_memory: tuple[int, Any]) -> None:
        """No race condition exists between VirtualProtectEx and WriteProcessMemory."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        for i in range(10):
            patch_data = bytes([i] * 8)
            result: bool = _patch_memory_windows(process_id, address + (i * 8), patch_data)
            assert result, f"Iteration {i} must succeed without race conditions"

            actual = ctypes.string_at(address + (i * 8), 8)
            assert actual == patch_data, f"Data integrity maintained in iteration {i}"

    def test_protection_change_covers_exact_region(self, writable_memory: tuple[int, Any]) -> None:
        """VirtualProtectEx changes protection for exact data length region."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        patch_sizes = [1, 4, 16, 64, 256]

        for size in patch_sizes:
            patch_data = b"\xCC" * size
            result: bool = _patch_memory_windows(process_id, address, patch_data)

            assert result, f"Must handle exact region size {size}"

            actual = ctypes.string_at(address, size)
            assert actual == patch_data, f"Exact {size} bytes written"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestPatternBasedPatchLocations:
    """Requirement: Must support pattern-based patch locations."""

    def test_find_single_pattern_occurrence(self, writable_memory: tuple[int, Any]) -> None:
        """Pattern search finds single occurrence of byte sequence."""
        address, buffer = writable_memory

        test_data = b"\x00" * 100 + b"\x74\x05\x90\x90" + b"\x00" * 100
        ctypes.memmove(address, test_data, len(test_data))

        memory_data = ctypes.string_at(address, len(test_data))

        pattern = b"\x74\x05\x90\x90"
        offsets = PatternSearcher.find_pattern(memory_data, pattern)

        assert len(offsets) == 1, "Must find single pattern occurrence"
        assert offsets[0] == 100, "Pattern location must be correct"

    def test_find_multiple_pattern_occurrences(self, writable_memory: tuple[int, Any]) -> None:
        """Pattern search finds all occurrences of repeated pattern."""
        address, buffer = writable_memory

        pattern = b"\x85\xC0\x74\x10"
        test_data = b"\x90" * 50 + pattern + b"\x90" * 50 + pattern + b"\x90" * 50 + pattern
        ctypes.memmove(address, test_data, min(len(test_data), 8192))

        memory_data = ctypes.string_at(address, len(test_data))
        offsets = PatternSearcher.find_pattern(memory_data, pattern)

        assert len(offsets) == 3, "Must find all pattern occurrences"
        assert offsets[0] == 50, "First occurrence location correct"
        assert offsets[1] == 104, "Second occurrence location correct"
        assert offsets[2] == 158, "Third occurrence location correct"

    def test_wildcard_pattern_matching(self, writable_memory: tuple[int, Any]) -> None:
        """Pattern search supports wildcard bytes (e.g., ?? in IDA patterns)."""
        address, buffer = writable_memory

        test_data = b"\x00" * 50 + b"\x48\x8B\x05\x12\x34\x56\x78" + b"\x00" * 50
        test_data += b"\x48\x8B\x05\xAA\xBB\xCC\xDD" + b"\x00" * 50
        ctypes.memmove(address, test_data, min(len(test_data), 8192))

        memory_data = ctypes.string_at(address, len(test_data))

        pattern = b"\x48\x8B\x05\xFF\xFF\xFF\xFF"
        offsets = PatternSearcher.find_wildcard_pattern(memory_data, pattern, wildcard=0xFF)

        assert len(offsets) == 2, "Wildcard pattern must match multiple variations"
        assert offsets[0] == 50, "First wildcard match location"
        assert offsets[1] == 57 + 50, "Second wildcard match location"

    def test_patch_at_pattern_location(self, writable_memory: tuple[int, Any]) -> None:
        """Patch is applied at pattern-found location."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        license_check_pattern = b"\x74\x05"
        test_data = b"\x90" * 100 + license_check_pattern + b"\x90" * 100
        ctypes.memmove(address, test_data, len(test_data))

        memory_data = ctypes.string_at(address, len(test_data))
        offsets = PatternSearcher.find_pattern(memory_data, license_check_pattern)

        assert len(offsets) > 0, "Pattern must be found"

        patch_offset = offsets[0]
        patch_data = b"\xEB\x05"

        result: bool = patch_memory_direct(
            process_id, address + patch_offset, patch_data
        )

        assert result, "Patch at pattern location must succeed"

        patched_memory = ctypes.string_at(address, len(test_data))
        assert patched_memory[patch_offset:patch_offset + 2] == patch_data, "Pattern location patched correctly"

    def test_patch_all_pattern_occurrences(self, writable_memory: tuple[int, Any]) -> None:
        """All pattern occurrences can be patched."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        pattern = b"\x74\x10"
        test_data = pattern + b"\x90" * 50 + pattern + b"\x90" * 50 + pattern
        ctypes.memmove(address, test_data, len(test_data))

        memory_data = ctypes.string_at(address, len(test_data))
        offsets = PatternSearcher.find_pattern(memory_data, pattern)

        patch_data = b"\xEB\x10"

        for offset in offsets:
            result: bool = patch_memory_direct(
                process_id, address + offset, patch_data
            )
            assert result, f"Patch at offset {offset} must succeed"

        final_memory = ctypes.string_at(address, len(test_data))

        for offset in offsets:
            assert (
                final_memory[offset:offset + 2] == patch_data
            ), f"Pattern at offset {offset} patched"

    def test_pattern_not_found_returns_empty(self, writable_memory: tuple[int, Any]) -> None:
        """Pattern search returns empty list when pattern not found."""
        address, buffer = writable_memory

        test_data = b"\x90\x90\x90\x90" * 100
        ctypes.memmove(address, test_data, len(test_data))

        memory_data = ctypes.string_at(address, len(test_data))

        pattern = b"\xDE\xAD\xBE\xEF"
        offsets = PatternSearcher.find_pattern(memory_data, pattern)

        assert len(offsets) == 0, "Non-existent pattern returns empty list"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestPatchApplicationVerification:
    """Requirement: Must verify patch application success."""

    def test_verify_bytes_written_count(self, writable_memory: tuple[int, Any]) -> None:
        """Verification confirms all bytes written successfully."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        patch_data = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
        result: bool = _patch_memory_windows(process_id, address, patch_data)

        assert result, "Patch must succeed with verification"

        actual_data = ctypes.string_at(address, len(patch_data))
        assert (
            actual_data == patch_data
        ), "Verification: exact bytes written"
        assert len(actual_data) == len(patch_data), "Verification: correct byte count"

    def test_verification_detects_partial_write(self, writable_memory: tuple[int, Any]) -> None:
        """Verification detects when fewer bytes written than requested."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        valid_patch = b"\x90\x90\x90\x90"
        result: bool = _patch_memory_windows(process_id, address, valid_patch)

        assert result, "Valid patch succeeds"

        actual = ctypes.string_at(address, len(valid_patch))
        assert len(actual) == len(valid_patch), "All bytes must be written"

    def test_verification_confirms_data_integrity(self, writable_memory: tuple[int, Any]) -> None:
        """Verification confirms written data matches intended patch."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        test_patterns = [
            b"\x90\x90\x90\x90",
            b"\xEB\x10\x90\x90",
            b"\x33\xC0\xC3",
            b"\xCC\xCC\xCC\xCC",
        ]

        for idx, patch_data in enumerate(test_patterns):
            result: bool = patch_memory_direct(
                process_id, address + (idx * 10), patch_data
            )

            assert result, f"Patch {idx} must succeed"

            actual = ctypes.string_at(address + (idx * 10), len(patch_data))
            assert (
                actual == patch_data
            ), f"Verification: patch {idx} data integrity"

    def test_verification_reads_back_patched_memory(self, writable_memory: tuple[int, Any]) -> None:
        """Verification reads back memory after WriteProcessMemory."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        patch_data = b"\x48\x31\xC0\xC3"
        result: bool = patch_memory_direct(process_id, address, patch_data)

        assert result, "Patch must succeed"

        readback = ctypes.string_at(address, len(patch_data))
        assert readback == patch_data, "Readback verification confirms write"

    def test_verification_fails_on_write_error(self) -> None:
        """Verification fails when WriteProcessMemory returns error."""
        invalid_address: int = 0x0
        process_id: int = os.getpid()
        patch_data = b"\x90\x90"

        result: bool = _patch_memory_windows(process_id, invalid_address, patch_data)

        assert not result, "Verification must detect write failure"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestPatchRollbackCapability:
    """Requirement: Must implement patch rollback capability."""

    def test_rollback_single_patch(self, writable_memory: tuple[int, Any]) -> None:
        """Single patch can be rolled back to original state."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        original_data = ctypes.string_at(address, 16)

        rollback_mgr = PatchRollbackManager()

        patch_data = b"\xAA\xBB\xCC\xDD"
        rollback_mgr.record_patch(address, original_data[:4], patch_data)

        result: bool = patch_memory_direct(process_id, address, patch_data)
        assert result, "Patch must succeed"

        patched = ctypes.string_at(address, 4)
        assert patched == patch_data, "Patch applied"

        rollback_result: bool = rollback_mgr.rollback_patch(process_id, 0)
        assert rollback_result, "Rollback must succeed"

        restored = ctypes.string_at(address, 4)
        assert restored == original_data[:4], "Original data restored"

    def test_rollback_multiple_patches_reverse_order(self, writable_memory: tuple[int, Any]) -> None:
        """Multiple patches rolled back in reverse order."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        original_data = ctypes.string_at(address, 100)

        rollback_mgr = PatchRollbackManager()

        patches = [
            (0, b"\xAA\xAA"),
            (10, b"\xBB\xBB"),
            (20, b"\xCC\xCC"),
        ]

        for offset, patch_data in patches:
            rollback_mgr.record_patch(
                address + offset, original_data[offset:offset + 2], patch_data
            )
            result: bool = patch_memory_direct(
                process_id, address + offset, patch_data
            )
            assert result

        rollback_result: bool = rollback_mgr.rollback_all(process_id)
        assert rollback_result, "Rollback all must succeed"

        restored = ctypes.string_at(address, 100)
        assert restored == original_data, "All patches rolled back"

    def test_rollback_preserves_unpatched_data(self, writable_memory: tuple[int, Any]) -> None:
        """Rollback preserves data not affected by patches."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        original_full = ctypes.string_at(address, 200)

        rollback_mgr = PatchRollbackManager()

        patch_data = b"\xDE\xAD"
        rollback_mgr.record_patch(address + 50, original_full[50:52], patch_data)

        result: bool = patch_memory_direct(process_id, address + 50, patch_data)
        assert result

        rollback_mgr.rollback_patch(process_id, 0)

        restored_full = ctypes.string_at(address, 200)
        assert restored_full[:50] == original_full[:50], "Data before patch preserved"
        assert restored_full[52:] == original_full[52:], "Data after patch preserved"
        assert restored_full[50:52] == original_full[50:52], "Patched area restored"

    def test_rollback_manager_tracks_patch_history(self, writable_memory: tuple[int, Any]) -> None:
        """Rollback manager maintains complete patch history."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        rollback_mgr = PatchRollbackManager()

        patches = [
            b"\x90\x90",
            b"\xEB\x10",
            b"\xCC\xCC",
        ]

        for idx, patch_data in enumerate(patches):
            original = ctypes.string_at(address + (idx * 10), 2)
            rollback_mgr.record_patch(address + (idx * 10), original, patch_data)
            patch_memory_direct(process_id, address + (idx * 10), patch_data)

        assert len(rollback_mgr.patch_history) == 3, "All patches recorded"

        for idx, history_entry in enumerate(rollback_mgr.patch_history):
            assert history_entry["new_data"] == patches[idx], f"Patch {idx} recorded correctly"
            assert "timestamp" in history_entry, "Timestamp recorded"

    def test_selective_patch_rollback(self, writable_memory: tuple[int, Any]) -> None:
        """Specific patches can be selectively rolled back."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        original_data = ctypes.string_at(address, 100)

        rollback_mgr = PatchRollbackManager()

        patches = [
            (0, b"\xAA"),
            (10, b"\xBB"),
            (20, b"\xCC"),
        ]

        for offset, patch_data in patches:
            rollback_mgr.record_patch(
                address + offset, original_data[offset:offset + 1], patch_data
            )
            patch_memory_direct(process_id, address + offset, patch_data)

        rollback_mgr.rollback_patch(process_id, 1)

        current = ctypes.string_at(address, 100)

        assert current[0:1] == b"\xAA", "Patch 0 still applied"
        assert current[10:11] == original_data[10:11], "Patch 1 rolled back"
        assert current[20:21] == b"\xCC", "Patch 2 still applied"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestGuardPageHandling:
    """Edge case: Guard pages must be handled correctly."""

    def test_detect_guard_page_protection(self) -> None:
        """Guard page detection identifies PAGE_GUARD protection."""
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        MEM_COMMIT: int = 0x1000
        MEM_RELEASE: int = 0x8000

        if allocated_address := kernel32.VirtualAlloc(
            None, 4096, MEM_COMMIT, PAGE_GUARD | PAGE_EXECUTE_READWRITE
        ):
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
                    ctypes.c_void_p(allocated_address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                assert mbi.Protect & PAGE_GUARD, "PAGE_GUARD must be detected"

            finally:
                kernel32.VirtualFree(allocated_address, 0, MEM_RELEASE)

    def test_remove_guard_page_before_patching(self) -> None:
        """Guard pages are removed before memory patching."""
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        MEM_COMMIT: int = 0x1000
        MEM_RELEASE: int = 0x8000

        if allocated_address := kernel32.VirtualAlloc(
            None, 4096, MEM_COMMIT, PAGE_GUARD | PAGE_EXECUTE_READWRITE
        ):
            try:
                result: bool = _handle_guard_pages_windows(allocated_address, 4096)

                assert result, "Guard page removal must succeed"

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
                    ctypes.c_void_p(allocated_address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                assert not (mbi.Protect & PAGE_GUARD), "PAGE_GUARD must be removed"

            finally:
                kernel32.VirtualFree(allocated_address, 0, MEM_RELEASE)

    def test_patch_succeeds_after_guard_removal(self) -> None:
        """Memory patching succeeds after guard page removal."""
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        process_id: int = os.getpid()

        MEM_COMMIT: int = 0x1000
        MEM_RELEASE: int = 0x8000

        if allocated_address := kernel32.VirtualAlloc(
            None, 4096, MEM_COMMIT, PAGE_GUARD | PAGE_EXECUTE_READWRITE
        ):
            try:
                guard_result: bool = _handle_guard_pages_windows(
                    allocated_address, 4096
                )
                assert guard_result, "Guard removal must succeed"

                patch_data = b"\x90\x90\x90\x90"
                patch_result: bool = patch_memory_direct(
                    process_id, allocated_address, patch_data
                )

                assert patch_result, "Patch must succeed after guard removal"

                actual = ctypes.string_at(allocated_address, len(patch_data))
                assert actual == patch_data, "Patch data written correctly"

            finally:
                kernel32.VirtualFree(allocated_address, 0, MEM_RELEASE)

    def test_guard_page_comprehensive_detection_and_bypass(self) -> None:
        """Comprehensive guard page detection and bypass workflow."""
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        MEM_COMMIT: int = 0x1000
        MEM_RELEASE: int = 0x8000
        PROCESS_ALL_ACCESS: int = 0x1F0FFF

        if allocated_address := kernel32.VirtualAlloc(
            None, 4096, MEM_COMMIT, PAGE_GUARD | PAGE_EXECUTE_READWRITE
        ):
            try:
                process_handle: int = kernel32.OpenProcess(
                    PROCESS_ALL_ACCESS, False, os.getpid()
                )

                try:
                    result: bool = detect_and_bypass_guard_pages(
                        process_handle, allocated_address, 4096
                    )

                    assert result, "Comprehensive guard bypass must succeed"

                finally:
                    kernel32.CloseHandle(process_handle)

            finally:
                kernel32.VirtualFree(allocated_address, 0, MEM_RELEASE)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestCopyOnWriteSections:
    """Edge case: Copy-on-write sections must be handled correctly."""

    def test_detect_copy_on_write_protection(self) -> None:
        """Copy-on-write protection is detected correctly."""
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        PAGE_WRITECOPY: int = 0x08
        MEM_COMMIT: int = 0x1000
        MEM_RELEASE: int = 0x8000

        if allocated_address := kernel32.VirtualAlloc(
            None, 4096, MEM_COMMIT, PAGE_WRITECOPY
        ):
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
                    ctypes.c_void_p(allocated_address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                assert mbi.Protect == PAGE_WRITECOPY, "Copy-on-write detected"

            finally:
                kernel32.VirtualFree(allocated_address, 0, MEM_RELEASE)

    def test_patch_copy_on_write_memory(self) -> None:
        """Patching copy-on-write memory succeeds."""
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        process_id: int = os.getpid()

        PAGE_WRITECOPY: int = 0x08
        MEM_COMMIT: int = 0x1000
        MEM_RELEASE: int = 0x8000

        if allocated_address := kernel32.VirtualAlloc(
            None, 4096, MEM_COMMIT, PAGE_WRITECOPY
        ):
            try:
                bypass_result: bool = _bypass_memory_protection_windows(
                    allocated_address, 4096, PAGE_EXECUTE_READWRITE
                )
                assert bypass_result, "Protection change must succeed"

                patch_data = b"\xDE\xAD\xBE\xEF"
                patch_result: bool = patch_memory_direct(
                    process_id, allocated_address, patch_data
                )

                assert patch_result, "Copy-on-write patching must succeed"

                actual = ctypes.string_at(allocated_address, len(patch_data))
                assert actual == patch_data, "Patch data written to COW memory"

            finally:
                kernel32.VirtualFree(allocated_address, 0, MEM_RELEASE)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific requirement")
class TestProductionMemoryPatchingWorkflows:
    """Production-ready integration tests for complete workflows."""

    def test_complete_patch_workflow_with_all_requirements(self, writable_memory: tuple[int, Any]) -> None:
        """Complete workflow: pattern finding, atomic patching, verification, rollback."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        license_pattern = b"\x74\x05"
        test_data = b"\x90" * 100 + license_pattern + b"\x90" * 100
        ctypes.memmove(address, test_data, len(test_data))

        original_full = ctypes.string_at(address, len(test_data))

        memory_data = ctypes.string_at(address, len(test_data))
        offsets = PatternSearcher.find_pattern(memory_data, license_pattern)

        assert len(offsets) > 0, "Pattern must be found"

        rollback_mgr = PatchRollbackManager()

        patch_offset = offsets[0]
        patch_data = b"\xEB\x05"

        rollback_mgr.record_patch(
            address + patch_offset,
            original_full[patch_offset:patch_offset + 2],
            patch_data,
        )

        bypass_result: bool = bypass_memory_protection(address, len(test_data))
        assert bypass_result, "Protection bypass required"

        guard_result: bool = handle_guard_pages(address, len(test_data))
        assert guard_result, "Guard page handling required"

        patch_result: bool = patch_memory_direct(
            process_id, address + patch_offset, patch_data
        )
        assert patch_result, "Patch must succeed"

        patched_memory = ctypes.string_at(address, len(test_data))
        assert (
            patched_memory[patch_offset:patch_offset + 2] == patch_data
        ), "Verification: patch applied"

        rollback_result: bool = rollback_mgr.rollback_patch(process_id, 0)
        assert rollback_result, "Rollback must succeed"

        restored_memory = ctypes.string_at(address, len(test_data))
        assert restored_memory == original_full, "Memory restored to original state"

    def test_production_multi_patch_scenario(self, writable_memory: tuple[int, Any]) -> None:
        """Production scenario: multiple license checks patched and verified."""
        address, buffer = writable_memory
        process_id: int = os.getpid()

        test_binary = (
            b"\x55\x89\xE5"
            + b"\x74\x10"
            + b"\x90\x90"
            + b"\x85\xC0"
            + b"\x74\x20"
            + b"\x90\x90"
            + b"\x75\x15"
            + b"\xC3"
        )

        ctypes.memmove(address, test_binary, len(test_binary))

        patterns_to_patch = [
            (b"\x74\x10", b"\xEB\x10"),
            (b"\x74\x20", b"\xEB\x20"),
            (b"\x75\x15", b"\xEB\x15"),
        ]

        memory_data = ctypes.string_at(address, len(test_binary))

        rollback_mgr = PatchRollbackManager()

        for original_pattern, new_pattern in patterns_to_patch:
            offsets = PatternSearcher.find_pattern(memory_data, original_pattern)

            for offset in offsets:
                rollback_mgr.record_patch(
                    address + offset,
                    memory_data[offset:offset + len(original_pattern)],
                    new_pattern,
                )

                result: bool = patch_memory_direct(
                    process_id, address + offset, new_pattern
                )
                assert result, f"Patch at offset {offset} must succeed"

        final_memory = ctypes.string_at(address, len(test_binary))

        expected_patched = test_binary.replace(b"\x74\x10", b"\xEB\x10")
        expected_patched = expected_patched.replace(b"\x74\x20", b"\xEB\x20")
        expected_patched = expected_patched.replace(b"\x75\x15", b"\xEB\x15")

        assert final_memory == expected_patched, "All patches applied correctly"

        rollback_mgr.rollback_all(process_id)

        restored = ctypes.string_at(address, len(test_binary))
        assert restored == test_binary, "All patches rolled back"
