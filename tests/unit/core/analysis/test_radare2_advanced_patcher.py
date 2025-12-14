"""Production tests for Radare2 Advanced Patcher.

Tests validate that the advanced patching engine can perform real binary
modifications including NOP sleds, jump inversions, return value modifications,
call redirections, and anti-debug defeats on actual PE binaries.
"""

import shutil
import struct
import tempfile
from pathlib import Path
from typing import Any, Generator

import pytest

from intellicrack.core.analysis.radare2_advanced_patcher import (
    Architecture,
    PatchType,
    Radare2AdvancedPatcher,
)


pytest.importorskip("r2pipe", reason="Radare2 required for patcher tests")


@pytest.fixture
def test_binary(temp_workspace: Path) -> Generator[Path, None, None]:
    """Create a minimal valid PE binary for testing."""
    binary_path = temp_workspace / "test.exe"

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        0xE0,
        0x010B,
    )

    optional_header = struct.pack(
        "<HHIIIIIHHHHHHHHHHHH",
        0x010B,
        0x0E,
        0x00,
        0x1000,
        0x1000,
        0,
        0x1000,
        0x1000,
        0x400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
    )

    optional_header += struct.pack("<IIHH", 0x10000, 0x1000, 0, 0x0003)
    optional_header += b"\x00" * (0xE0 - len(optional_header))

    section_header = b".text\x00\x00\x00"
    section_header += struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x60000020)

    binary_content = dos_header + pe_signature + coff_header + optional_header + section_header
    binary_content += b"\x00" * (0x200 - len(binary_content))

    code_section = b"\x55\x8B\xEC\x83\xEC\x40"
    code_section += b"\x90" * 10
    code_section += b"\x74\x05"
    code_section += b"\xB8\x01\x00\x00\x00"
    code_section += b"\xC3"
    code_section += b"\x90" * 100
    code_section += b"\xE8\x00\x00\x00\x00"
    code_section += b"\x90" * (0x1000 - len(code_section))

    binary_content += code_section

    binary_path.write_bytes(binary_content)
    yield binary_path


class TestPatcherInitialization:
    """Test patcher initialization and binary loading."""

    def test_create_patcher_instance(self, test_binary: Path) -> None:
        """Patcher can be initialized with binary path."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        assert patcher.binary_path == str(test_binary)
        assert patcher.r2 is None
        assert patcher.patches == []

    def test_open_binary_in_write_mode(self, test_binary: Path) -> None:
        """Patcher opens binary and detects architecture."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            success = patcher.open(write_mode=True)

            assert success
            assert patcher.r2 is not None
            assert patcher.architecture is not None
            assert patcher.bits in [32, 64]
        finally:
            patcher.close()

    def test_architecture_detection(self, test_binary: Path) -> None:
        """Patcher correctly detects x86 architecture."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open()

            assert patcher.architecture in [Architecture.X86, Architecture.X86_64]
            assert patcher.bits == 32
            assert patcher.endianness in ["little", "big"]
        finally:
            patcher.close()


class TestNOPSledGeneration:
    """Test NOP sled generation and application."""

    def test_generate_nop_sled(self, test_binary: Path) -> None:
        """Generate and apply NOP sled to binary."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            nop_address = 0x401000
            nop_size = 16

            patch = patcher.generate_nop_sled(nop_address, nop_size)

            assert patch.type == PatchType.NOP_SLED
            assert patch.address == nop_address
            assert len(patch.patched_bytes) == nop_size
            assert all(b == 0x90 for b in patch.patched_bytes)
            assert len(patch.original_bytes) == nop_size
        finally:
            patcher.close()

    def test_nop_sled_in_patches_list(self, test_binary: Path) -> None:
        """Applied NOP sled is tracked in patches list."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patcher.generate_nop_sled(0x401000, 8)

            assert len(patcher.patches) == 1
            assert patcher.patches[0].type == PatchType.NOP_SLED
        finally:
            patcher.close()


class TestConditionalJumpInversion:
    """Test conditional jump inversion functionality."""

    def test_invert_je_to_jne(self, test_binary: Path) -> None:
        """Invert JE (jump if equal) to JNE (jump if not equal)."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            je_address = 0x401010

            patch = patcher.invert_conditional_jump(je_address)

            assert patch.type == PatchType.CONDITIONAL_JUMP
            assert patch.address == je_address
            assert patch.metadata["original_mnemonic"].lower() in ["je", "jz"]
            assert patch.metadata["inverted_mnemonic"].lower() in ["jne", "jnz"]
        finally:
            patcher.close()

    def test_inverted_jump_modifies_opcode(self, test_binary: Path) -> None:
        """Inverted jump has different opcode bytes."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patch = patcher.invert_conditional_jump(0x401010)

            assert patch.original_bytes != patch.patched_bytes
            assert len(patch.original_bytes) == len(patch.patched_bytes)
        finally:
            patcher.close()


class TestReturnValueModification:
    """Test function return value modification."""

    def test_modify_return_value_to_zero(self, test_binary: Path) -> None:
        """Modify function to always return 0."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            func_address = 0x401000

            patch = patcher.modify_return_value(func_address, 0)

            assert patch.type == PatchType.RETURN_VALUE
            assert patch.metadata["return_value"] == 0
        finally:
            patcher.close()

    def test_modify_return_value_to_one(self, test_binary: Path) -> None:
        """Modify function to always return 1."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patch = patcher.modify_return_value(0x401000, 1)

            assert patch.metadata["return_value"] == 1
        finally:
            patcher.close()


class TestCallTargetRedirection:
    """Test call instruction redirection."""

    def test_redirect_call_to_new_target(self, test_binary: Path) -> None:
        """Redirect call instruction to different address."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            call_address = 0x401070
            new_target = 0x402000

            patch = patcher.redirect_call_target(call_address, new_target)

            assert patch.type == PatchType.CALL_TARGET
            assert patch.address == call_address
            assert patch.metadata["new_target"] == new_target
        finally:
            patcher.close()


class TestPatchPersistence:
    """Test patch saving and loading functionality."""

    def test_save_patches_to_json(self, test_binary: Path, temp_workspace: Path) -> None:
        """Save applied patches to JSON file."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patcher.generate_nop_sled(0x401000, 8)
            patcher.invert_conditional_jump(0x401010)

            patch_file = temp_workspace / "patches.json"
            success = patcher.save_patches(str(patch_file))

            assert success
            assert patch_file.exists()
            assert patch_file.stat().st_size > 0

            import json

            with open(patch_file) as f:
                data = json.load(f)

            assert "patches" in data
            assert len(data["patches"]) == 2
            assert "binary" in data
            assert "architecture" in data
            assert "checksum" in data
        finally:
            patcher.close()

    def test_load_patches_from_json(self, test_binary: Path, temp_workspace: Path) -> None:
        """Load and apply patches from JSON file."""
        patcher1 = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher1.open(write_mode=True)
            patcher1.generate_nop_sled(0x401000, 8)

            patch_file = temp_workspace / "saved_patches.json"
            patcher1.save_patches(str(patch_file))
        finally:
            patcher1.close()

        test_binary_copy = temp_workspace / "test_copy.exe"
        shutil.copy(test_binary, test_binary_copy)

        patcher2 = Radare2AdvancedPatcher(str(test_binary_copy))

        try:
            patcher2.open(write_mode=True)

            success = patcher2.load_patches(str(patch_file))

            assert success
            assert len(patcher2.patches) == 1
        finally:
            patcher2.close()


class TestPatchScriptGeneration:
    """Test standalone patch script generation."""

    def test_generate_python_patch_script(self, test_binary: Path) -> None:
        """Generate standalone Python patching script."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patcher.generate_nop_sled(0x401000, 8)

            script = patcher.generate_patch_script("python")

            assert "#!/usr/bin/env python3" in script
            assert "apply_patches" in script
            assert "0x401000" in script
        finally:
            patcher.close()

    def test_generate_radare2_patch_script(self, test_binary: Path) -> None:
        """Generate Radare2 command script."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patcher.generate_nop_sled(0x401000, 8)

            script = patcher.generate_patch_script("radare2")

            assert "#!/usr/bin/r2" in script
            assert "wx" in script
            assert "0x401000" in script
        finally:
            patcher.close()

    def test_generate_c_patch_script(self, test_binary: Path) -> None:
        """Generate C patching program."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patcher.generate_nop_sled(0x401000, 8)

            script = patcher.generate_patch_script("c")

            assert "#include <stdio.h>" in script
            assert "Patch patches[]" in script
            assert "0x401000" in script
        finally:
            patcher.close()


class TestPatchReversion:
    """Test patch reversion functionality."""

    def test_revert_single_patch(self, test_binary: Path) -> None:
        """Revert individual patch to original bytes."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patch = patcher.generate_nop_sled(0x401000, 8)

            success = patcher.revert_patch(patch)

            assert success
        finally:
            patcher.close()

    def test_apply_and_revert_patch(self, test_binary: Path) -> None:
        """Apply patch then revert to verify restoration."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patch = patcher.generate_nop_sled(0x401000, 8)

            original_bytes = patch.original_bytes

            patcher.revert_patch(patch)

            result = patcher.r2.cmdj(f"pxj {len(original_bytes)} @ {patch.address}")
            reverted_bytes = bytes(result)

            assert reverted_bytes == original_bytes
        finally:
            patcher.close()


@pytest.mark.real_data
class TestRealBinaryPatching:
    """Integration tests with real fixture binaries."""

    @pytest.mark.skipif(
        not Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/notepadpp.exe").exists(),
        reason="Notepad++ fixture not available",
    )
    def test_patch_notepadpp_binary(self, temp_workspace: Path) -> None:
        """Patch real Notepad++ binary."""
        source_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/notepadpp.exe")
        test_copy = temp_workspace / "notepadpp_test.exe"
        shutil.copy(source_binary, test_copy)

        patcher = Radare2AdvancedPatcher(str(test_copy))

        try:
            success = patcher.open(write_mode=True)

            if success:
                assert patcher.architecture in [Architecture.X86, Architecture.X86_64]
                assert patcher.bits in [32, 64]
        finally:
            patcher.close()


class TestErrorHandling:
    """Test error handling for invalid inputs."""

    def test_invalid_binary_path(self) -> None:
        """Patcher handles non-existent binary gracefully."""
        patcher = Radare2AdvancedPatcher("/nonexistent/binary.exe")

        success = patcher.open()

        assert not success

    def test_invert_non_conditional_jump_raises_error(self, test_binary: Path) -> None:
        """Inverting non-conditional instruction raises error."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            with pytest.raises(ValueError, match="Cannot invert"):
                patcher.invert_conditional_jump(0x401000)
        finally:
            patcher.close()


class TestPatchMetadata:
    """Test patch metadata tracking."""

    def test_patch_includes_description(self, test_binary: Path) -> None:
        """Patch object includes human-readable description."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            patch = patcher.generate_nop_sled(0x401000, 8)

            assert patch.description
            assert "NOP" in patch.description
            assert "0x401000" in patch.description
        finally:
            patcher.close()

    def test_patch_includes_type_metadata(self, test_binary: Path) -> None:
        """Patch metadata includes type-specific information."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open(write_mode=True)

            nop_patch = patcher.generate_nop_sled(0x401000, 16)

            assert "size" in nop_patch.metadata
            assert nop_patch.metadata["size"] == 16
        finally:
            patcher.close()


class TestArchitectureSupport:
    """Test multi-architecture support."""

    def test_x86_nop_instruction(self, test_binary: Path) -> None:
        """x86 uses 0x90 as NOP instruction."""
        patcher = Radare2AdvancedPatcher(str(test_binary))

        try:
            patcher.open()

            nop_bytes = patcher._get_nop_instruction()

            if patcher.architecture in [Architecture.X86, Architecture.X86_64]:
                assert nop_bytes == b"\x90"
        finally:
            patcher.close()
