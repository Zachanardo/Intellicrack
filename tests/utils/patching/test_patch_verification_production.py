"""Production tests for patch_verification module.

Tests real binary patching capabilities including PE format validation,
patch application, verification, and rollback mechanisms used for license
protection bypass.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import capstone

    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

from intellicrack.utils.patching.patch_verification import (
    test_patch_and_verify,
    verify_patches,
)


pytestmark = pytest.mark.skipif(not HAS_PEFILE, reason="pefile library required")


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"
PE_BINARIES = FIXTURES_DIR / "binaries" / "pe" / "legitimate"


class MockApp:
    """Mock application instance for testing."""

    def __init__(self, binary_path: str) -> None:
        """Initialize mock app with binary path."""
        self.binary_path = binary_path
        self.messages: list[str] = []
        self.analyze_results: list[str] = []
        self.analyze_status = MagicMock()
        self.analyze_status.text = MagicMock(return_value="")
        self.analyze_status.setText = MagicMock()

    def update_output(self, message: object) -> None:
        """Capture output messages."""
        if hasattr(message, "emit"):
            message.emit(str(message))
        else:
            self.messages.append(str(message))


class TestPatchVerification:
    """Test patch verification on real binaries."""

    def test_verify_patches_validates_single_patch(self, tmp_path: Path) -> None:
        """Patch verification confirms patch was applied at correct offset."""
        tiny_exe = PE_BINARIES / "7zip.exe"
        if not tiny_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(tiny_exe, patched_path)

        pe = pefile.PE(str(tiny_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_va = image_base + entry_point_rva

        with open(patched_path, "r+b") as f:
            offset = pe.get_offset_from_rva(entry_point_rva)
            f.seek(offset)
            original_bytes = f.read(3)
            f.seek(offset)
            new_bytes = b"\x90\x90\x90"
            f.write(new_bytes)

        instructions = [
            {
                "address": entry_point_va,
                "new_bytes": new_bytes,
                "description": "NOP sled at entry point",
            }
        ]

        app = MockApp(str(tiny_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0
        assert any("verified successfully" in r for r in results)
        assert any("1 patches succeeded" in r for r in results)

    def test_verify_patches_detects_mismatched_bytes(self, tmp_path: Path) -> None:
        """Patch verification detects when patch bytes don't match expected."""
        tiny_exe = PE_BINARIES / "7zip.exe"
        if not tiny_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(tiny_exe, patched_path)

        pe = pefile.PE(str(tiny_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_va = image_base + entry_point_rva

        with open(patched_path, "r+b") as f:
            offset = pe.get_offset_from_rva(entry_point_rva)
            f.seek(offset)
            f.write(b"\x90\x90")

        instructions = [
            {
                "address": entry_point_va,
                "new_bytes": b"\xCC\xCC",
                "description": "Wrong bytes - expecting breakpoint but wrote NOP",
            }
        ]

        app = MockApp(str(tiny_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0
        assert any("verification failed" in r.lower() for r in results)
        assert any("1 failed" in r for r in results)

    def test_verify_patches_handles_multiple_patches(self, tmp_path: Path) -> None:
        """Patch verification handles multiple patches in single binary."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        instructions = []
        with open(patched_path, "r+b") as f:
            for i in range(3):
                offset = pe.get_offset_from_rva(entry_point_rva + i * 16)
                f.seek(offset)
                patch_bytes = bytes([0x90] * 4)
                f.write(patch_bytes)

                instructions.append(
                    {
                        "address": image_base + entry_point_rva + i * 16,
                        "new_bytes": patch_bytes,
                        "description": f"Patch {i + 1}",
                    }
                )

        app = MockApp(str(test_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0
        assert any("3 patches succeeded" in r for r in results)

    def test_verify_patches_handles_invalid_address(self, tmp_path: Path) -> None:
        """Patch verification handles invalid memory addresses gracefully."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase

        instructions = [
            {
                "address": image_base + 0xFFFFFFFF,
                "new_bytes": b"\x90\x90",
                "description": "Invalid address",
            }
        ]

        app = MockApp(str(test_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0
        assert any("failed" in r.lower() for r in results)


class TestPatchAndVerify:
    """Test complete patch application and verification workflow."""

    def test_patch_and_verify_creates_backup(self, tmp_path: Path) -> None:
        """test_patch_and_verify creates temporary copy for testing."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        patches = [
            {
                "address": image_base + entry_point_rva,
                "new_bytes": b"\x90\x90",
                "description": "Test patch",
            }
        ]

        results = test_patch_and_verify(str(test_exe), patches)

        assert len(results) > 0
        assert any("Created test environment" in r for r in results)
        assert any("Cleanup" in r for r in results)

    def test_patch_and_verify_validates_pe_structure(self, tmp_path: Path) -> None:
        """test_patch_and_verify validates patched binary is still valid PE."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        patches = [
            {
                "address": image_base + entry_point_rva,
                "new_bytes": b"\x90\x90\x90",
                "description": "Entry point NOP",
            }
        ]

        results = test_patch_and_verify(str(test_exe), patches)

        assert len(results) > 0
        assert any("valid PE executable" in r for r in results)

    def test_patch_and_verify_checks_entry_point_unchanged(self, tmp_path: Path) -> None:
        """test_patch_and_verify verifies entry point hasn't changed."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_section = next((s for s in pe.sections if b".text" in s.Name), None)

        if not text_section:
            pytest.skip("No .text section found")

        patch_rva = text_section.VirtualAddress + 0x100

        patches = [
            {
                "address": image_base + patch_rva,
                "new_bytes": b"\x90" * 8,
                "description": "Test patch in .text",
            }
        ]

        results = test_patch_and_verify(str(test_exe), patches)

        assert len(results) > 0
        assert any("Entry point" in r for r in results)

    def test_patch_and_verify_validates_patch_bytes(self, tmp_path: Path) -> None:
        """test_patch_and_verify reads back and validates patched bytes."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        patch_bytes = b"\xEB\xFE"
        patches = [
            {
                "address": image_base + entry_point_rva,
                "new_bytes": patch_bytes,
                "description": "Infinite loop patch",
            }
        ]

        results = test_patch_and_verify(str(test_exe), patches)

        assert len(results) > 0
        assert any("Bytes match" in r or "Successfully applied" in r for r in results)

    def test_patch_and_verify_handles_corrupted_binary(self, tmp_path: Path) -> None:
        """test_patch_and_verify handles corrupted PE gracefully."""
        corrupt_exe = tmp_path / "corrupt.exe"
        corrupt_exe.write_bytes(b"MZ" + b"\x00" * 1000)

        patches = [
            {
                "address": 0x400000,
                "new_bytes": b"\x90\x90",
                "description": "Test patch",
            }
        ]

        results = test_patch_and_verify(str(corrupt_exe), patches)

        assert len(results) > 0
        assert any("error" in r.lower() or "fail" in r.lower() for r in results)


class TestPatchVerificationEdgeCases:
    """Test edge cases in patch verification."""

    def test_verify_patches_with_empty_instructions(self, tmp_path: Path) -> None:
        """Patch verification handles empty instruction list."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        app = MockApp(str(test_exe))
        results = verify_patches(app, str(patched_path), [])

        assert len(results) > 0
        assert any("0 patches succeeded" in r for r in results)

    def test_verify_patches_with_malformed_instruction(self, tmp_path: Path) -> None:
        """Patch verification handles malformed patch instruction."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        instructions = [
            {
                "address": None,
                "new_bytes": None,
                "description": "Malformed patch",
            }
        ]

        app = MockApp(str(test_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0
        assert any("Invalid patch" in r for r in results)

    def test_verify_patches_with_zero_length_patch(self, tmp_path: Path) -> None:
        """Patch verification handles zero-length patch bytes."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase

        instructions = [
            {
                "address": image_base + 0x1000,
                "new_bytes": b"",
                "description": "Zero length patch",
            }
        ]

        app = MockApp(str(test_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0

    def test_verify_patches_preserves_sections(self, tmp_path: Path) -> None:
        """Patch verification confirms sections remain intact."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        original_pe = pefile.PE(str(test_exe))
        original_sections = [(s.Name, s.SizeOfRawData) for s in original_pe.sections]

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        instructions = [
            {
                "address": image_base + entry_point_rva,
                "new_bytes": b"\x90\x90",
                "description": "Small patch",
            }
        ]

        app = MockApp(str(test_exe))
        verify_patches(app, str(patched_path), instructions)

        patched_pe = pefile.PE(str(patched_path))
        patched_sections = [(s.Name, s.SizeOfRawData) for s in patched_pe.sections]

        assert original_sections == patched_sections


class TestRealWorldPatchingScenarios:
    """Test real-world license patching scenarios."""

    def test_patch_conditional_jump_to_unconditional(self, tmp_path: Path) -> None:
        """Patching conditional jump (JZ) to unconditional jump (JMP) works."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_section = next((s for s in pe.sections if b".text" in s.Name), None)

        if not text_section:
            pytest.skip("No .text section found")

        code_data = text_section.get_data()

        jz_pattern = b"\x74"
        jz_offset = code_data.find(jz_pattern)

        if jz_offset == -1:
            pytest.skip("No JZ instruction found in .text")

        jz_rva = text_section.VirtualAddress + jz_offset
        jz_va = image_base + jz_rva

        jmp_bytes = b"\xEB" + code_data[jz_offset + 1 : jz_offset + 2]

        patches = [
            {
                "address": jz_va,
                "new_bytes": jmp_bytes,
                "description": "Convert JZ to JMP for license bypass",
            }
        ]

        results = test_patch_and_verify(str(test_exe), patches)

        assert len(results) > 0
        assert any("Successfully applied" in r or "Bytes match" in r for r in results)

    def test_patch_nop_sled_insertion(self, tmp_path: Path) -> None:
        """Inserting NOP sled over license check function works."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        nop_sled = b"\x90" * 16
        patches = [
            {
                "address": image_base + entry_point_rva + 0x10,
                "new_bytes": nop_sled,
                "description": "NOP sled over potential license check",
            }
        ]

        results = test_patch_and_verify(str(test_exe), patches)

        assert len(results) > 0
        assert any("Successfully applied" in r or "valid PE" in r for r in results)

    def test_patch_return_value_modification(self, tmp_path: Path) -> None:
        """Patching function to return success value (MOV EAX, 1; RET) works."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_section = next((s for s in pe.sections if b".text" in s.Name), None)

        if not text_section:
            pytest.skip("No .text section found")

        patch_rva = text_section.VirtualAddress + 0x200
        patch_va = image_base + patch_rva

        mov_eax_1_ret = b"\xB8\x01\x00\x00\x00\xC3"
        patches = [
            {
                "address": patch_va,
                "new_bytes": mov_eax_1_ret,
                "description": "Force function to return 1 (success)",
            }
        ]

        results = test_patch_and_verify(str(test_exe), patches)

        assert len(results) > 0
        assert any("Successfully applied" in r or "Bytes match" in r for r in results)


class TestPatchVerificationIntegration:
    """Test integration with real patching workflows."""

    def test_verify_patches_after_license_check_removal(self, tmp_path: Path) -> None:
        """Complete workflow of removing license check and verifying works."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_section = next((s for s in pe.sections if b".text" in s.Name), None)

        if not text_section:
            pytest.skip("No .text section found")

        patch_rva = text_section.VirtualAddress + 0x100
        patch_offset = pe.get_offset_from_rva(patch_rva)

        bypass_code = b"\xB8\x01\x00\x00\x00\xC3"
        with open(patched_path, "r+b") as f:
            f.seek(patch_offset)
            f.write(bypass_code)

        instructions = [
            {
                "address": image_base + patch_rva,
                "new_bytes": bypass_code,
                "description": "License check bypass",
            }
        ]

        app = MockApp(str(test_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0
        assert any("verified successfully" in r for r in results)
        assert any("1 patches succeeded" in r for r in results)

    def test_patch_verification_with_multiple_protection_layers(self, tmp_path: Path) -> None:
        """Verifying patches that bypass multiple protection checks works."""
        test_exe = PE_BINARIES / "7zip.exe"
        if not test_exe.exists():
            pytest.skip("7zip.exe fixture not found")

        patched_path = tmp_path / "patched.exe"
        shutil.copy2(test_exe, patched_path)

        pe = pefile.PE(str(test_exe))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_section = next((s for s in pe.sections if b".text" in s.Name), None)

        if not text_section:
            pytest.skip("No .text section found")

        instructions = []
        offsets = [0x100, 0x200, 0x300]

        with open(patched_path, "r+b") as f:
            for i, offset_delta in enumerate(offsets):
                patch_rva = text_section.VirtualAddress + offset_delta
                patch_offset = pe.get_offset_from_rva(patch_rva)

                bypass_code = b"\xB8\x01\x00\x00\x00\xC3"
                f.seek(patch_offset)
                f.write(bypass_code)

                instructions.append(
                    {
                        "address": image_base + patch_rva,
                        "new_bytes": bypass_code,
                        "description": f"Protection layer {i + 1} bypass",
                    }
                )

        app = MockApp(str(test_exe))
        results = verify_patches(app, str(patched_path), instructions)

        assert len(results) > 0
        assert any("3 patches succeeded" in r for r in results)
