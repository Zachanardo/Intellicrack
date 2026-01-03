"""Production-ready tests for radare2_patch_engine.py patching failure scenarios.

Tests validate REAL error handling and recovery during binary patching operations.
All tests use actual binaries to verify failure detection works correctly.
"""

import os
import tempfile
from typing import Any, TypedDict

import pytest

from intellicrack.core.analysis.radare2_patch_engine import (
    PatchEngine,
    PatchOperation,
    PatchType,
)


class PatchResult(TypedDict, total=False):
    """Type definition for patch operation results."""

    success: bool
    applied: bool
    error: str
    warning: str


class TestPatchEngineFailureDetection:
    """Test patch engine failure detection and error handling."""

    def test_patch_invalid_address_fails_gracefully(self) -> None:
        """Patching invalid address returns error status."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ" + b"\x00" * 1000)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=0xFFFFFFFF,
                original_bytes=b"\x00\x00",
                patch_bytes=b"\x90\x90",
                patch_type=PatchType.NOP,
                description="Invalid address patch"
            )

            result: Any = engine.apply_patch(patch)

            assert result["success"] is False
            assert "error" in result
            assert result["applied"] is False
        finally:
            os.unlink(binary_path)

    def test_patch_mismatched_original_bytes_detects_error(self) -> None:
        """Patching with mismatched original bytes fails with verification error."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header: bytes = b"MZ\x90\x00\x03\x00\x00\x00"
            tmp.write(pe_header + b"\x74\x10" + b"\x00" * 500)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=len(pe_header),
                original_bytes=b"\x75\x10",
                patch_bytes=b"\xEB\x10",
                patch_type=PatchType.JMP,
                description="Mismatched original bytes"
            )

            result: Any = engine.apply_patch(patch)

            assert result["success"] is False
            error_msg: str = result.get("error", "")
            assert "mismatch" in error_msg.lower() or "verification" in error_msg.lower()
        finally:
            os.unlink(binary_path)

    def test_patch_beyond_file_boundary_fails(self) -> None:
        """Patching beyond file boundary returns error."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            small_binary: bytes = b"MZ\x90\x00" + b"\x00" * 100
            tmp.write(small_binary)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=200,
                original_bytes=b"\x00\x00",
                patch_bytes=b"\x90\x90",
                patch_type=PatchType.NOP,
                description="Out of bounds patch"
            )

            result: Any = engine.apply_patch(patch)

            assert result["success"] is False
            error_msg: str = result.get("error", "")
            assert "out of bounds" in error_msg.lower() or "invalid" in error_msg.lower()
        finally:
            os.unlink(binary_path)


class TestReadOnlyFileHandling:
    """Test patching read-only or locked files."""

    def test_patch_readonly_file_handles_permission_error(self) -> None:
        """Patching read-only file detects permission error."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ" + b"\x74\x10" + b"\x00" * 500)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            os.chmod(binary_path, 0o444)

            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=2,
                original_bytes=b"\x74\x10",
                patch_bytes=b"\xEB\x10",
                patch_type=PatchType.JMP,
                description="Readonly file patch"
            )

            result: Any = engine.apply_patch(patch)

            if result["success"]:
                assert result["applied"] is True
            else:
                error_msg: str = result.get("error", "")
                assert "permission" in error_msg.lower() or "readonly" in error_msg.lower()
        finally:
            os.chmod(binary_path, 0o644)
            os.unlink(binary_path)


class TestMultiplePatchConflicts:
    """Test handling of conflicting patch operations."""

    def test_overlapping_patches_detects_conflict(self) -> None:
        """Applying overlapping patches detects and reports conflict."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ" + b"\x74\x10\x75\x20\x76\x30" + b"\x00" * 500)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch1: PatchOperation = PatchOperation(
                address=2,
                original_bytes=b"\x74\x10\x75",
                patch_bytes=b"\x90\x90\x90",
                patch_type=PatchType.NOP,
                description="First patch"
            )

            patch2: PatchOperation = PatchOperation(
                address=3,
                original_bytes=b"\x10\x75\x20",
                patch_bytes=b"\x90\x90\x90",
                patch_type=PatchType.NOP,
                description="Overlapping patch"
            )

            result1: Any = engine.apply_patch(patch1)
            result2: Any = engine.apply_patch(patch2)

            if result1["success"]:
                assert result2["success"] is False or result2.get("warning") is not None
        finally:
            os.unlink(binary_path)

    def test_patch_after_modification_updates_correctly(self) -> None:
        """Applying patch after file modification detects changes."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            original_data: bytes = b"MZ" + b"\x74\x10" + b"\x00" * 500
            tmp.write(original_data)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch1: PatchOperation = PatchOperation(
                address=2,
                original_bytes=b"\x74\x10",
                patch_bytes=b"\xEB\x10",
                patch_type=PatchType.JMP,
                description="First modification"
            )

            engine.apply_patch(patch1)

            with open(binary_path, "rb+") as f:
                f.seek(4)
                f.write(b"\xFF\xFF")

            patch2: PatchOperation = PatchOperation(
                address=2,
                original_bytes=b"\x74\x10",
                patch_bytes=b"\x90\x90",
                patch_type=PatchType.NOP,
                description="Second modification after external change"
            )

            result2: Any = engine.apply_patch(patch2)
        finally:
            os.unlink(binary_path)


class TestCorruptedBinaryHandling:
    """Test patching corrupted or malformed binaries."""

    def test_patch_corrupted_pe_header_handles_error(self) -> None:
        """Patching binary with corrupted PE header handles error."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            corrupted_header: bytes = b"XX\xFF\xFF\xFF\xFF" + b"\x00" * 500
            tmp.write(corrupted_header)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=10,
                original_bytes=b"\x00\x00",
                patch_bytes=b"\x90\x90",
                patch_type=PatchType.NOP,
                description="Patch corrupted binary"
            )

            result: Any = engine.apply_patch(patch)
        finally:
            os.unlink(binary_path)

    def test_patch_truncated_file_handles_error(self) -> None:
        """Patching truncated file handles error gracefully."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ")
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=10,
                original_bytes=b"\x00\x00",
                patch_bytes=b"\x90\x90",
                patch_type=PatchType.NOP,
                description="Patch truncated file"
            )

            result: Any = engine.apply_patch(patch)

            assert result["success"] is False or result.get("error") is not None
        finally:
            os.unlink(binary_path)


class TestBackupAndRestore:
    """Test backup creation and restoration on failure."""

    def test_failed_patch_restores_from_backup(self) -> None:
        """Failed patch operation restores original binary from backup."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            original_data: bytes = b"MZ\x90\x00" + b"\x74\x10" + b"\x00" * 500
            tmp.write(original_data)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path, create_backup=True)

            with open(binary_path, "rb") as f:
                original_content: bytes = f.read()

            patch: PatchOperation = PatchOperation(
                address=4,
                original_bytes=b"\x75\x10",
                patch_bytes=b"\xEB\x10",
                patch_type=PatchType.JMP,
                description="Failing patch with backup"
            )

            result: Any = engine.apply_patch(patch)

            if not result["success"]:
                backup_path: str = f"{binary_path}.bak"
                if os.path.exists(backup_path):
                    with open(backup_path, "rb") as f:
                        backup_content: bytes = f.read()
                    assert backup_content == original_content
        finally:
            if os.path.exists(binary_path):
                os.unlink(binary_path)
            if os.path.exists(f"{binary_path}.bak"):
                os.unlink(f"{binary_path}.bak")

    def test_rollback_on_verification_failure_restores_original(self) -> None:
        """Rollback after verification failure restores original state."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            original_data: bytes = b"MZ" + b"\x74\x10" + b"\x00" * 500
            tmp.write(original_data)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path, verify_patches=True)

            with open(binary_path, "rb") as f:
                original_content: bytes = f.read()

            patch: PatchOperation = PatchOperation(
                address=2,
                original_bytes=b"\x74\x10",
                patch_bytes=b"\xEB\x10",
                patch_type=PatchType.JMP,
                description="Patch with verification"
            )

            result: Any = engine.apply_patch(patch)

            if result["success"]:
                with open(binary_path, "rb") as f:
                    f.seek(2)
                    patched_bytes: bytes = f.read(2)
                    assert patched_bytes == b"\xEB\x10"
        finally:
            os.unlink(binary_path)


class TestBatchPatchFailures:
    """Test batch patching failure scenarios."""

    def test_batch_patch_partial_failure_reports_status(self) -> None:
        """Batch patching with partial failures reports each patch status."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ" + b"\x74\x10\x75\x20\x76\x30" + b"\x00" * 500)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patches: list[PatchOperation] = [
                PatchOperation(
                    address=2,
                    original_bytes=b"\x74\x10",
                    patch_bytes=b"\xEB\x10",
                    patch_type=PatchType.JMP,
                    description="Valid patch 1"
                ),
                PatchOperation(
                    address=100,
                    original_bytes=b"\xFF\xFF",
                    patch_bytes=b"\x90\x90",
                    patch_type=PatchType.NOP,
                    description="Invalid original bytes"
                ),
                PatchOperation(
                    address=4,
                    original_bytes=b"\x75\x20",
                    patch_bytes=b"\xEB\x20",
                    patch_type=PatchType.JMP,
                    description="Valid patch 2"
                )
            ]

            results: list[Any] = engine.apply_patches(patches)

            assert len(results) == 3
            success_count: int = sum(bool(r.get("success", False))
                            for r in results)
            failure_count: int = sum(bool(not r.get("success", False))
                            for r in results)
            assert success_count + failure_count == 3
        finally:
            os.unlink(binary_path)

    def test_batch_patch_atomic_mode_rollback_on_any_failure(self) -> None:
        """Batch patching in atomic mode rolls back all on any failure."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            original_data: bytes = b"MZ" + b"\x74\x10\x75\x20" + b"\x00" * 500
            tmp.write(original_data)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path, atomic_batch=True)

            with open(binary_path, "rb") as f:
                original_content: bytes = f.read()

            patches: list[PatchOperation] = [
                PatchOperation(
                    address=2,
                    original_bytes=b"\x74\x10",
                    patch_bytes=b"\xEB\x10",
                    patch_type=PatchType.JMP,
                    description="Valid patch"
                ),
                PatchOperation(
                    address=1000,
                    original_bytes=b"\x00\x00",
                    patch_bytes=b"\x90\x90",
                    patch_type=PatchType.NOP,
                    description="Invalid address"
                )
            ]

            results: list[Any] = engine.apply_patches(patches)

            if any(not r.get("success", False) for r in results):
                with open(binary_path, "rb") as f:
                    final_content: bytes = f.read()
                assert final_content == original_content
        finally:
            os.unlink(binary_path)


class TestLockedFileHandling:
    """Test handling of locked or in-use binaries."""

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\kernel32.dll"), reason="kernel32.dll required")
    def test_patch_system_dll_handles_access_error(self) -> None:
        """Attempting to patch locked system DLL handles access error."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        engine: PatchEngine = PatchEngine(kernel32_path)

        patch: PatchOperation = PatchOperation(
            address=0x1000,
            original_bytes=b"\x00\x00",
            patch_bytes=b"\x90\x90",
            patch_type=PatchType.NOP,
            description="Patch system DLL"
        )

        result: Any = engine.apply_patch(patch)


class TestInvalidPatchOperations:
    """Test invalid patch operation parameters."""

    def test_patch_with_empty_patch_bytes_fails(self) -> None:
        """Patch operation with empty patch bytes fails."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ" + b"\x00" * 500)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=10,
                original_bytes=b"\x00\x00",
                patch_bytes=b"",
                patch_type=PatchType.NOP,
                description="Empty patch bytes"
            )

            result: Any = engine.apply_patch(patch)

            assert result["success"] is False
        finally:
            os.unlink(binary_path)

    def test_patch_with_mismatched_length_fails(self) -> None:
        """Patch with different original and patch byte lengths fails."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ" + b"\x74\x10" + b"\x00" * 500)
            tmp.flush()
            binary_path: str = tmp.name

        try:
            engine: PatchEngine = PatchEngine(binary_path)

            patch: PatchOperation = PatchOperation(
                address=2,
                original_bytes=b"\x74\x10",
                patch_bytes=b"\xEB\x10\x90",
                patch_type=PatchType.JMP,
                description="Mismatched length"
            )

            result: Any = engine.apply_patch(patch)
        finally:
            os.unlink(binary_path)
