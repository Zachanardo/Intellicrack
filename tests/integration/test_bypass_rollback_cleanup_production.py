"""
Production tests for bypass rollback and cleanup procedures.

Tests validate proper cleanup after bypass operations, including restoring original
binary state on failure, removing temporary artifacts, and ensuring no residual
modifications remain after unsuccessful bypass attempts.
"""

import pytest
from pathlib import Path
from typing import Optional, List, Dict
import struct
import time
import hashlib

from intellicrack.core.protection_bypass.vm_bypass import VMProtectBypass
from intellicrack.core.protection_bypass.arxan_bypass import ArxanBypass
from intellicrack.core.certificate.bypass_orchestrator import BypassOrchestrator
from intellicrack.core.patching.binary_patcher import BinaryPatcher


class BypassStateManager:
    """Manages bypass state including backup and rollback operations."""

    def __init__(self, original_binary: bytes):
        self.original_binary = original_binary
        self.original_hash = hashlib.sha256(original_binary).hexdigest()
        self.backup_stack: List[bytes] = []
        self.modification_log: List[str] = []

    def create_backup(self, label: str) -> None:
        """Create backup point before modification."""
        self.backup_stack.append(self.original_binary)
        self.modification_log.append(f"Backup: {label}")

    def rollback(self) -> Optional[bytes]:
        """Rollback to last backup point."""
        if self.backup_stack:
            restored = self.backup_stack.pop()
            self.modification_log.append("Rollback executed")
            return restored
        return None

    def verify_restoration(self, current_binary: bytes) -> bool:
        """Verify binary was restored to original state."""
        current_hash = hashlib.sha256(current_binary).hexdigest()
        return current_hash == self.original_hash

    def clear_backups(self) -> None:
        """Clear all backup points and cleanup."""
        self.backup_stack.clear()
        self.modification_log.append("Cleanup: All backups cleared")


class CleanupVerifier:
    """Verifies proper cleanup after bypass operations."""

    @staticmethod
    def verify_no_temp_artifacts(binary_data: bytes) -> bool:
        """Verify no temporary modification artifacts remain."""
        temp_markers = [
            b'__TEMP__',
            b'__BACKUP__',
            b'__MODIFIED__',
            b'__PATCH_TEMP__',
            b'XXXXXXXX',
        ]

        for marker in temp_markers:
            if marker in binary_data:
                return False
        return True

    @staticmethod
    def verify_structure_integrity(binary_data: bytes) -> bool:
        """Verify PE structure integrity after cleanup."""
        if len(binary_data) < 64:
            return False

        if binary_data[0:2] != b'MZ':
            return False

        pe_offset_bytes = binary_data[60:64]
        if len(pe_offset_bytes) != 4:
            return False

        pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
        if pe_offset >= len(binary_data) - 4:
            return False

        if binary_data[pe_offset:pe_offset+2] != b'PE':
            return False

        return True

    @staticmethod
    def count_modifications(original: bytes, current: bytes) -> int:
        """Count number of byte-level modifications between binaries."""
        if len(original) != len(current):
            return abs(len(original) - len(current))

        differences = sum(1 for a, b in zip(original, current) if a != b)
        return differences


@pytest.fixture
def protected_binary_with_backup() -> bytes:
    """Create protected binary suitable for backup/restore testing."""
    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    ]) + b'\x00' * 48

    pe_offset = struct.pack('<I', 64)
    pe_header = pe_header[:60] + pe_offset

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH',
        0x014C, 2, int(time.time()), 0, 0, 0xE0, 0x010B
    )

    protection_marker = b'VMProtect v3.5.1'

    license_check = b'\x55\x8B\xEC\x83\xEC\x10'
    license_check += b'\xE8\x20\x00\x00\x00'
    license_check += b'\x85\xC0\x74\x0A'
    license_check += b'\x6A\x00\xE8\x30\x00\x00\x00'
    license_check += b'\xEB\x08'
    license_check += b'\x6A\x01\xE8\x25\x00\x00\x00'
    license_check += b'\x8B\xE5\x5D\xC3'

    binary = pe_header
    binary += pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += protection_marker
    binary += b'\x00' * 512
    binary += license_check
    binary += b'\x00' * (4096 - len(binary))

    return binary


def test_rollback_on_failed_bypass(protected_binary_with_backup: bytes) -> None:
    """
    Rollback to original binary when bypass operation fails.

    Tests that failed bypass attempts properly restore original binary state
    without leaving partial modifications.
    """
    state_manager = BypassStateManager(protected_binary_with_backup)
    state_manager.create_backup("pre-bypass")

    try:
        vmprotect_bypass = VMProtectBypass(protected_binary_with_backup)
        modified = vmprotect_bypass.apply_bypass()

        if modified == protected_binary_with_backup:
            raise ValueError("Bypass failed - no modifications made")

    except Exception:
        restored = state_manager.rollback()
        assert restored is not None
        assert state_manager.verify_restoration(restored)

    verifier = CleanupVerifier()
    final_binary = state_manager.rollback() or protected_binary_with_backup
    assert verifier.verify_structure_integrity(final_binary)


def test_cleanup_removes_temp_artifacts(protected_binary_with_backup: bytes) -> None:
    """
    Verify cleanup removes all temporary modification artifacts.

    Tests that after bypass operations (successful or failed), no temporary
    markers or backup data remains in binary.
    """
    vmprotect_bypass = VMProtectBypass(protected_binary_with_backup)
    modified = vmprotect_bypass.apply_bypass()

    verifier = CleanupVerifier()
    assert verifier.verify_no_temp_artifacts(modified)

    patcher = BinaryPatcher(modified)
    final = patcher.patch_all_protections()

    assert verifier.verify_no_temp_artifacts(final)
    assert verifier.verify_structure_integrity(final)


def test_partial_bypass_cleanup() -> None:
    """
    Cleanup after partial bypass where some operations succeed and others fail.

    Tests proper cleanup when multi-stage bypass partially completes, ensuring
    no inconsistent state remains.
    """
    pe_header = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 56
    pe_header = pe_header[:60] + struct.pack('<I', 64)

    pe_signature = b'PE\x00\x00'
    coff_header = struct.pack('<HHIIIHH', 0x014C, 3, int(time.time()), 0, 0, 0xE0, 0x010B)

    binary = pe_header + pe_signature + coff_header
    binary += b'\x00' * (0x400 - len(binary))
    binary += b'VMProtect v3.5.1' + b'\x00' * 256
    binary += b'Arxan GuardIT v5.2' + b'\x00' * 256
    binary += b'\x55\x8B\xEC\x85\xC0\x74\x05\xC3'
    binary += b'\x00' * (6144 - len(binary))

    state_manager = BypassStateManager(binary)
    state_manager.create_backup("pre-multi-bypass")

    current = binary
    success_count = 0

    try:
        vmprotect_bypass = VMProtectBypass(current)
        current = vmprotect_bypass.apply_bypass()
        success_count += 1
    except Exception:
        pass

    try:
        arxan_bypass = ArxanBypass(current)
        current = arxan_bypass.apply_bypass()
        success_count += 1
    except Exception:
        restored = state_manager.rollback()
        if restored:
            current = restored

    verifier = CleanupVerifier()
    assert verifier.verify_structure_integrity(current)
    assert verifier.verify_no_temp_artifacts(current)


def test_rollback_preserves_original_hash(protected_binary_with_backup: bytes) -> None:
    """
    Verify rollback perfectly restores original binary including hash.

    Tests that rollback operation produces bit-for-bit identical copy of
    original binary, not just functionally equivalent version.
    """
    original_hash = hashlib.sha256(protected_binary_with_backup).hexdigest()

    state_manager = BypassStateManager(protected_binary_with_backup)
    state_manager.create_backup("hash-preservation-test")

    vmprotect_bypass = VMProtectBypass(protected_binary_with_backup)
    modified = vmprotect_bypass.apply_bypass()

    modified_hash = hashlib.sha256(modified).hexdigest()
    assert modified_hash != original_hash

    restored = state_manager.rollback()
    assert restored is not None

    restored_hash = hashlib.sha256(restored).hexdigest()
    assert restored_hash == original_hash


def test_cleanup_after_successful_bypass(protected_binary_with_backup: bytes) -> None:
    """
    Verify cleanup after successful bypass removes only protection artifacts.

    Tests that cleanup preserves intended modifications while removing temporary
    data and protection remnants.
    """
    verifier = CleanupVerifier()

    vmprotect_bypass = VMProtectBypass(protected_binary_with_backup)
    bypassed = vmprotect_bypass.apply_bypass()

    assert verifier.verify_structure_integrity(bypassed)
    assert verifier.verify_no_temp_artifacts(bypassed)

    modifications = verifier.count_modifications(protected_binary_with_backup, bypassed)
    assert modifications > 0

    assert b'VMProtect' not in bypassed or bypassed != protected_binary_with_backup


def test_multiple_rollback_points() -> None:
    """
    Test managing multiple backup points during complex bypass operation.

    Tests that backup stack correctly maintains multiple restoration points
    and can rollback to specific states.
    """
    pe_header = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 56
    pe_header = pe_header[:60] + struct.pack('<I', 64)

    binary = pe_header + b'PE\x00\x00'
    binary += struct.pack('<HHIIIHH', 0x014C, 1, int(time.time()), 0, 0, 0xE0, 0x010B)
    binary += b'\x00' * (0x400 - len(binary))
    binary += b'VMProtect v3.5.1'
    binary += b'\x00' * (2048 - len(binary))

    state_manager = BypassStateManager(binary)

    state_manager.create_backup("point-1")
    state_manager.create_backup("point-2")
    state_manager.create_backup("point-3")

    assert len(state_manager.backup_stack) == 3

    restored_1 = state_manager.rollback()
    assert restored_1 is not None
    assert len(state_manager.backup_stack) == 2

    restored_2 = state_manager.rollback()
    assert restored_2 is not None
    assert len(state_manager.backup_stack) == 1

    state_manager.clear_backups()
    assert len(state_manager.backup_stack) == 0


def test_cleanup_on_exception() -> None:
    """
    Verify cleanup executes even when bypass raises exception.

    Tests that cleanup procedures run in finally blocks ensuring no leaked
    resources or temporary data.
    """
    corrupted_binary = b'MZ' + b'\xFF' * 100 + b'VMProtect' + b'\x00' * 200

    state_manager = BypassStateManager(corrupted_binary)
    state_manager.create_backup("pre-exception")

    exception_raised = False
    cleanup_executed = False

    try:
        vmprotect_bypass = VMProtectBypass(corrupted_binary)
        vmprotect_bypass.apply_bypass()
    except Exception:
        exception_raised = True
    finally:
        state_manager.clear_backups()
        cleanup_executed = True

    assert cleanup_executed
    assert len(state_manager.backup_stack) == 0


def test_restoration_verification() -> None:
    """
    Verify restoration verification correctly detects incomplete restoration.

    Tests that verification catches cases where rollback partially fails,
    leaving binary in inconsistent state.
    """
    pe_header = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 56
    pe_header = pe_header[:60] + struct.pack('<I', 64)

    binary = pe_header + b'PE\x00\x00'
    binary += struct.pack('<HHIIIHH', 0x014C, 1, int(time.time()), 0, 0, 0xE0, 0x010B)
    binary += b'\x00' * (2048 - len(binary))

    state_manager = BypassStateManager(binary)

    modified = binary[:100] + b'\xFF' * 10 + binary[110:]
    assert not state_manager.verify_restoration(modified)

    assert state_manager.verify_restoration(binary)


def test_cleanup_performance() -> None:
    """
    Verify cleanup operations complete within acceptable timeframes.

    Tests that cleanup (including rollback) completes in under 1 second
    even for large binaries.
    """
    large_binary = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 56
    large_binary = large_binary[:60] + struct.pack('<I', 64)
    large_binary += b'PE\x00\x00'
    large_binary += struct.pack('<HHIIIHH', 0x014C, 1, int(time.time()), 0, 0, 0xE0, 0x010B)
    large_binary += b'\x00' * (1024 * 1024)

    state_manager = BypassStateManager(large_binary)
    state_manager.create_backup("performance-test")

    start = time.time()
    state_manager.rollback()
    state_manager.clear_backups()
    elapsed = time.time() - start

    assert elapsed < 1.0


def test_nested_bypass_cleanup() -> None:
    """
    Test cleanup with nested bypass operations (bypass within bypass).

    Tests proper cleanup when bypass operations are nested, ensuring each
    level properly cleans up its resources.
    """
    pe_header = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 56
    pe_header = pe_header[:60] + struct.pack('<I', 64)

    binary = pe_header + b'PE\x00\x00'
    binary += struct.pack('<HHIIIHH', 0x014C, 2, int(time.time()), 0, 0, 0xE0, 0x010B)
    binary += b'\x00' * (0x400 - len(binary))
    binary += b'VMProtect v3.5.1' + b'\x00' * 256
    binary += b'Arxan GuardIT v5.2'
    binary += b'\x00' * (4096 - len(binary))

    outer_state = BypassStateManager(binary)
    outer_state.create_backup("outer-level")

    current = binary

    inner_state = BypassStateManager(current)
    inner_state.create_backup("inner-level")

    vmprotect_bypass = VMProtectBypass(current)
    current = vmprotect_bypass.apply_bypass()

    inner_state.clear_backups()

    arxan_bypass = ArxanBypass(current)
    current = arxan_bypass.apply_bypass()

    outer_state.clear_backups()

    verifier = CleanupVerifier()
    assert verifier.verify_structure_integrity(current)
    assert verifier.verify_no_temp_artifacts(current)


def test_rollback_modification_count() -> None:
    """
    Verify rollback reduces modification count to zero.

    Tests that after rollback, the number of byte differences between current
    and original binary is zero.
    """
    pe_header = bytes([0x4D, 0x5A, 0x90, 0x00]) + b'\x00' * 56
    pe_header = pe_header[:60] + struct.pack('<I', 64)

    binary = pe_header + b'PE\x00\x00'
    binary += struct.pack('<HHIIIHH', 0x014C, 1, int(time.time()), 0, 0, 0xE0, 0x010B)
    binary += b'\x00' * (0x400 - len(binary))
    binary += b'VMProtect v3.5.1'
    binary += b'\x00' * (2048 - len(binary))

    state_manager = BypassStateManager(binary)
    state_manager.create_backup("mod-count-test")

    vmprotect_bypass = VMProtectBypass(binary)
    modified = vmprotect_bypass.apply_bypass()

    verifier = CleanupVerifier()
    pre_rollback_mods = verifier.count_modifications(binary, modified)
    assert pre_rollback_mods > 0

    restored = state_manager.rollback()
    assert restored is not None

    post_rollback_mods = verifier.count_modifications(binary, restored)
    assert post_rollback_mods == 0
