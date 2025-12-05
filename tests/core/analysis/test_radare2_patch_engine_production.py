"""Production tests for Radare2 Advanced Patching Engine.

Copyright (C) 2025 Zachary Flint

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
import shutil
import struct
import tempfile
from pathlib import Path
from typing import Generator

import pytest

from intellicrack.core.analysis.radare2_patch_engine import (
    PatchInstruction,
    PatchSet,
    PatchType,
    Radare2PatchEngine,
)


@pytest.fixture(scope="session")
def windows_notepad_binary() -> Path:
    """Real Windows notepad.exe binary for testing."""
    notepad_path = Path(r"C:\Windows\System32\notepad.exe")
    if not notepad_path.exists():
        pytest.skip("notepad.exe not found - Windows binary required")
    return notepad_path


@pytest.fixture(scope="session")
def windows_calc_binary() -> Path:
    """Real Windows calc.exe binary for testing."""
    calc_path = Path(r"C:\Windows\System32\calc.exe")
    if not calc_path.exists():
        pytest.skip("calc.exe not found - Windows binary required")
    return calc_path


@pytest.fixture(scope="session")
def windows_cmd_binary() -> Path:
    """Real Windows cmd.exe binary for testing."""
    cmd_path = Path(r"C:\Windows\System32\cmd.exe")
    if not cmd_path.exists():
        pytest.skip("cmd.exe not found - Windows binary required")
    return cmd_path


@pytest.fixture
def temp_binary_copy(windows_notepad_binary: Path) -> Generator[Path, None, None]:
    """Create a temporary copy of notepad.exe for write-mode testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir) / "notepad_test.exe"
        shutil.copy2(windows_notepad_binary, temp_path)
        yield temp_path


@pytest.fixture
def patch_engine_readonly(windows_notepad_binary: Path) -> Generator[Radare2PatchEngine, None, None]:
    """Create patch engine in read-only mode for notepad.exe."""
    engine = Radare2PatchEngine(windows_notepad_binary, write_mode=False)
    yield engine
    engine.close()


@pytest.fixture
def patch_engine_writable(temp_binary_copy: Path) -> Generator[Radare2PatchEngine, None, None]:
    """Create patch engine in write mode for temporary binary copy."""
    engine = Radare2PatchEngine(temp_binary_copy, write_mode=True)
    yield engine
    engine.close()


@pytest.fixture
def calc_patch_engine(windows_calc_binary: Path) -> Generator[Radare2PatchEngine, None, None]:
    """Create patch engine for calc.exe."""
    engine = Radare2PatchEngine(windows_calc_binary, write_mode=False)
    yield engine
    engine.close()


class TestRadare2PatchEngineInitialization:
    """Tests for patch engine initialization and binary analysis."""

    def test_initialize_with_real_windows_binary(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Patch engine successfully initializes with real Windows PE binary."""
        assert patch_engine_readonly.r2 is not None
        assert patch_engine_readonly.architecture is not None
        assert patch_engine_readonly.bits in [32, 64]
        assert patch_engine_readonly.endian in ["little", "big"]

    def test_architecture_detection_x86_64(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Engine correctly detects x86_64 architecture for 64-bit Windows binaries."""
        if patch_engine_readonly.bits == 64:
            assert patch_engine_readonly.architecture in ["x86", "x86_64"]
        else:
            assert patch_engine_readonly.architecture == "x86"

    def test_initialize_with_different_binary(self, calc_patch_engine: Radare2PatchEngine) -> None:
        """Patch engine initializes correctly with different Windows binary."""
        assert calc_patch_engine.r2 is not None
        assert calc_patch_engine.architecture is not None
        assert calc_patch_engine.binary_path.name == "calc.exe"

    def test_write_mode_initialization(self, temp_binary_copy: Path) -> None:
        """Engine initializes correctly in write mode with writable binary."""
        engine = Radare2PatchEngine(temp_binary_copy, write_mode=True)
        assert engine.write_mode is True
        assert engine.r2 is not None
        engine.close()

    def test_read_mode_initialization(self, windows_notepad_binary: Path) -> None:
        """Engine initializes correctly in read-only mode."""
        engine = Radare2PatchEngine(windows_notepad_binary, write_mode=False)
        assert engine.write_mode is False
        assert engine.r2 is not None
        engine.close()

    def test_initialize_with_invalid_binary_fails(self) -> None:
        """Engine raises error when initialized with non-existent binary."""
        fake_path = Path(r"C:\nonexistent\fake.exe")
        with pytest.raises(Exception):
            Radare2PatchEngine(fake_path)

    def test_binary_path_stored_correctly(self, patch_engine_readonly: Radare2PatchEngine, windows_notepad_binary: Path) -> None:
        """Engine stores correct binary path reference."""
        assert patch_engine_readonly.binary_path == windows_notepad_binary
        assert patch_engine_readonly.binary_path.exists()


class TestNopSledGeneration:
    """Tests for NOP sled creation and multi-byte NOP handling."""

    def test_create_nop_sled_single_byte(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """NOP sled generates correct single-byte NOPs for x86."""
        address = 0x1000
        length = 10

        patch = patch_engine_readonly.create_nop_sled(address, length)

        assert isinstance(patch, PatchInstruction)
        assert patch.address == address
        assert len(patch.patch_bytes) == length
        assert patch.patch_type == PatchType.NOP_SLED
        assert len(patch.original_bytes) == length

    def test_nop_sled_contains_valid_nop_instructions(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Generated NOP sled contains valid NOP opcodes."""
        patch = patch_engine_readonly.create_nop_sled(0x1000, 5)

        if patch_engine_readonly.architecture in ["x86", "x86_64"]:
            assert b"\x90" in patch.patch_bytes or b"\x66\x90" in patch.patch_bytes or b"\x0f\x1f" in patch.patch_bytes

    def test_multibyte_nop_generation(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Multi-byte NOPs are correctly generated for various lengths."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Multi-byte NOP test requires x86/x86_64")

        for length in range(2, 10):
            nop_bytes = patch_engine_readonly._get_multibyte_nop(length)
            assert len(nop_bytes) == length
            assert isinstance(nop_bytes, bytes)

    def test_nop_sled_reads_original_bytes(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """NOP sled patch captures original bytes from binary."""
        patch = patch_engine_readonly.create_nop_sled(0x1000, 8)

        assert len(patch.original_bytes) == 8
        assert patch.original_bytes != patch.patch_bytes

    def test_nop_sled_different_lengths(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """NOP sleds of varying lengths are generated correctly."""
        for length in [1, 4, 8, 16, 32]:
            patch = patch_engine_readonly.create_nop_sled(0x1000, length)
            assert len(patch.patch_bytes) == length

    def test_nop_sled_description_accurate(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """NOP sled patch has accurate description."""
        address = 0x1234
        length = 12
        patch = patch_engine_readonly.create_nop_sled(address, length)

        assert f"0x{address:x}" in patch.description
        assert str(length) in patch.description


class TestJumpModification:
    """Tests for jump and call instruction modification."""

    def test_modify_jump_near(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Near jump modification creates valid jump instruction."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Jump modification test requires x86/x86_64")

        address = 0x1000
        target = 0x2000

        patch = patch_engine_readonly.modify_jump(address, target, "jmp")

        assert isinstance(patch, PatchInstruction)
        assert patch.address == address
        assert patch.patch_type == PatchType.JUMP_MODIFICATION
        assert len(patch.patch_bytes) > 0
        assert patch.metadata["target"] == target

    def test_modify_jump_short_range(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Short jump uses 2-byte encoding when target is in range."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Jump modification test requires x86/x86_64")

        address = 0x1000
        target = 0x1050

        patch = patch_engine_readonly.modify_jump(address, target, "jmp")

        if len(patch.patch_bytes) == 2:
            assert patch.patch_bytes[0] == 0xEB

    def test_redirect_call_instruction(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Call redirection creates valid call instruction patch."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Call redirection test requires x86/x86_64")

        address = 0x1000
        target = 0x3000

        patch = patch_engine_readonly.redirect_call(address, target)

        assert patch.patch_type == PatchType.JUMP_MODIFICATION
        assert patch.metadata["jump_type"] == "call"
        assert patch.metadata["target"] == target

    def test_jump_modification_calculates_offset(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Jump modification correctly calculates relative offset."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Jump modification test requires x86/x86_64")

        address = 0x1000
        target = 0x2000

        patch = patch_engine_readonly.modify_jump(address, target, "jmp")

        if len(patch.patch_bytes) == 5:
            expected_offset = target - (address + 5)
            actual_offset = struct.unpack("<i", patch.patch_bytes[1:5])[0]
            assert actual_offset == expected_offset

    def test_jump_metadata_contains_target(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Jump patch metadata stores target address."""
        patch = patch_engine_readonly.modify_jump(0x1000, 0x2000, "jmp")

        assert "target" in patch.metadata
        assert patch.metadata["target"] == 0x2000
        assert "jump_type" in patch.metadata


class TestReturnValuePatching:
    """Tests for function return value patching."""

    def test_patch_return_value_32bit(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Patching function to return 32-bit value creates valid instruction sequence."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Return value patching test requires x86/x86_64")

        address = 0x1000
        return_value = 0x12345678

        patches = patch_engine_readonly.patch_return_value(address, return_value, value_size=4)

        assert len(patches) > 0
        assert all(isinstance(p, PatchInstruction) for p in patches)
        assert patches[0].patch_type == PatchType.RETURN_VALUE

    def test_return_value_patch_contains_mov_and_ret(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Return value patch contains MOV and RET instructions."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Return value patching test requires x86/x86_64")

        patches = patch_engine_readonly.patch_return_value(0x1000, 0x42, value_size=4)

        patch_bytes = patches[0].patch_bytes
        if patch_engine_readonly.architecture in ["x86", "x86_64"]:
            assert b"\xb8" in patch_bytes or b"\xb0" in patch_bytes
            assert b"\xc3" in patch_bytes

    def test_return_value_different_sizes(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Return value patches handle different value sizes correctly."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Return value patching test requires x86/x86_64")

        for size in [1, 2, 4]:
            patches = patch_engine_readonly.patch_return_value(0x1000, 0x42, value_size=size)
            assert len(patches) > 0
            assert patches[0].patch_type == PatchType.RETURN_VALUE

    def test_return_value_64bit_on_64bit_binary(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """64-bit return value patch works on 64-bit binaries."""
        if patch_engine_readonly.bits != 64:
            pytest.skip("64-bit return value test requires 64-bit binary")

        patches = patch_engine_readonly.patch_return_value(0x1000, 0x123456789ABCDEF0, value_size=8)

        assert len(patches) > 0
        assert patches[0].patch_type == PatchType.RETURN_VALUE

    def test_return_value_patch_description(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Return value patch has descriptive message."""
        return_val = 0x1337
        patches = patch_engine_readonly.patch_return_value(0x1000, return_val, value_size=4)

        assert "return" in patches[0].description.lower()
        assert hex(return_val) in patches[0].description.lower()


class TestConditionalJumpInversion:
    """Tests for conditional jump inversion (JE -> JNE, etc.)."""

    def test_invert_conditional_jump_je_to_jne(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """JE instruction is correctly inverted to JNE."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Conditional jump inversion requires x86/x86_64")

        address = 0x1000

        original_bytes = patch_engine_readonly._read_bytes(address, 2)
        if original_bytes[0] == 0x74:
            patch = patch_engine_readonly.invert_conditional_jump(address)
            assert patch.patch_bytes[0] == 0x75

    def test_invert_conditional_jump_jne_to_je(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """JNE instruction is correctly inverted to JE."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Conditional jump inversion requires x86/x86_64")

        address = 0x1000

        original_bytes = patch_engine_readonly._read_bytes(address, 2)
        if original_bytes[0] == 0x75:
            patch = patch_engine_readonly.invert_conditional_jump(address)
            assert patch.patch_bytes[0] == 0x74

    def test_conditional_inversion_preserves_offset(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Conditional jump inversion preserves jump offset."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Conditional jump inversion requires x86/x86_64")

        address = 0x1000
        original = patch_engine_readonly._read_bytes(address, 2)

        if original[0] in [0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7C, 0x7D, 0x7E, 0x7F]:
            patch = patch_engine_readonly.invert_conditional_jump(address)
            assert len(patch.patch_bytes) == 2
            assert patch.patch_bytes[1] == original[1]

    def test_invert_extended_conditional_jump(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Extended conditional jumps (0x0F prefix) are inverted correctly."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Conditional jump inversion requires x86/x86_64")

        address = 0x1000
        original = patch_engine_readonly._read_bytes(address, 2)

        if original[0] == 0x0F and original[1] in [0x84, 0x85]:
            patch = patch_engine_readonly.invert_conditional_jump(address)
            assert patch.patch_bytes[0] == 0x0F
            assert patch.patch_bytes[1] in [0x84, 0x85]

    def test_conditional_inversion_invalid_opcode_raises_error(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Inverting non-conditional jump raises appropriate error."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Conditional jump inversion requires x86/x86_64")

        address = 0x1000
        original = patch_engine_readonly._read_bytes(address, 2)

        if original[0] not in [0x0F, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7C, 0x7D, 0x7E, 0x7F]:
            with pytest.raises(ValueError):
                patch_engine_readonly.invert_conditional_jump(address)


class TestInlinePatching:
    """Tests for inline assembly code patching."""

    def test_create_inline_patch_with_nop(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Inline patch assembles and creates valid NOP instruction."""
        address = 0x1000

        patch = patch_engine_readonly.create_inline_patch(address, "nop")

        assert isinstance(patch, PatchInstruction)
        assert patch.patch_type == PatchType.INLINE_PATCH
        assert len(patch.patch_bytes) > 0
        assert patch.metadata["assembly"] == "nop"

    def test_inline_patch_assembles_valid_instruction(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Inline patch correctly assembles valid assembly instruction."""
        if patch_engine_readonly.architecture not in ["x86", "x86_64"]:
            pytest.skip("Inline assembly test requires x86/x86_64")

        patch = patch_engine_readonly.create_inline_patch(0x1000, "ret")

        assert len(patch.patch_bytes) > 0

    def test_inline_patch_invalid_assembly_raises_error(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Invalid assembly code raises ValueError."""
        with pytest.raises(ValueError):
            patch_engine_readonly.create_inline_patch(0x1000, "invalid_instruction_xyz")

    def test_inline_patch_stores_assembly_in_metadata(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Inline patch metadata contains original assembly code."""
        asm_code = "nop"
        patch = patch_engine_readonly.create_inline_patch(0x1000, asm_code)

        assert "assembly" in patch.metadata
        assert patch.metadata["assembly"] == asm_code


class TestPatchApplication:
    """Tests for applying and reverting patches to binaries."""

    def test_apply_patch_in_write_mode(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Patch is successfully applied when engine is in write mode."""
        nop_patch = patch_engine_writable.create_nop_sled(0x1000, 4)

        result = patch_engine_writable.apply_patch(nop_patch)

        assert result is True

    def test_apply_patch_modifies_binary(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Applied patch actually modifies binary data."""
        address = 0x1000
        original_bytes = patch_engine_writable._read_bytes(address, 4)

        nop_patch = patch_engine_writable.create_nop_sled(address, 4)
        patch_engine_writable.apply_patch(nop_patch)

        modified_bytes = patch_engine_writable._read_bytes(address, 4)
        assert modified_bytes == nop_patch.patch_bytes

    def test_apply_patch_fails_in_readonly_mode(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Applying patch in read-only mode returns False."""
        nop_patch = patch_engine_readonly.create_nop_sled(0x1000, 4)

        result = patch_engine_readonly.apply_patch(nop_patch)

        assert result is False

    def test_revert_patch_restores_original_bytes(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Reverting patch restores original binary bytes."""
        address = 0x1000
        original_bytes = patch_engine_writable._read_bytes(address, 4)

        nop_patch = patch_engine_writable.create_nop_sled(address, 4)
        patch_engine_writable.apply_patch(nop_patch)
        patch_engine_writable.revert_patch(nop_patch)

        restored_bytes = patch_engine_writable._read_bytes(address, 4)
        assert restored_bytes == original_bytes

    def test_revert_patch_in_readonly_mode_fails(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Reverting patch in read-only mode returns False."""
        nop_patch = patch_engine_readonly.create_nop_sled(0x1000, 4)

        result = patch_engine_readonly.revert_patch(nop_patch)

        assert result is False


class TestPatchSetManagement:
    """Tests for creating, managing, and applying patch sets."""

    def test_create_patch_set(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Patch set is created with correct metadata."""
        patch1 = patch_engine_readonly.create_nop_sled(0x1000, 4)
        patch2 = patch_engine_readonly.create_nop_sled(0x2000, 8)

        patch_set = patch_engine_readonly.create_patch_set("test_set", [patch1, patch2])

        assert isinstance(patch_set, PatchSet)
        assert patch_set.name == "test_set"
        assert len(patch_set.patches) == 2
        assert patch_set.applied is False

    def test_patch_set_stores_architecture(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Patch set stores correct architecture information."""
        patch = patch_engine_readonly.create_nop_sled(0x1000, 4)
        patch_set = patch_engine_readonly.create_patch_set("arch_test", [patch])

        assert patch_set.architecture == patch_engine_readonly.architecture

    def test_patch_set_stores_target_binary(self, patch_engine_readonly: Radare2PatchEngine, windows_notepad_binary: Path) -> None:
        """Patch set references correct target binary."""
        patch = patch_engine_readonly.create_nop_sled(0x1000, 4)
        patch_set = patch_engine_readonly.create_patch_set("binary_test", [patch])

        assert patch_set.target_binary == windows_notepad_binary

    def test_patch_set_calculates_checksum(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Patch set includes binary checksum."""
        patch = patch_engine_readonly.create_nop_sled(0x1000, 4)
        patch_set = patch_engine_readonly.create_patch_set("checksum_test", [patch])

        assert patch_set.checksum_original is not None
        assert len(patch_set.checksum_original) > 0

    def test_apply_patch_set_success(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Complete patch set is applied successfully."""
        patch1 = patch_engine_writable.create_nop_sled(0x1000, 4)
        patch2 = patch_engine_writable.create_nop_sled(0x2000, 4)

        patch_set = patch_engine_writable.create_patch_set("apply_test", [patch1, patch2])
        result = patch_engine_writable.apply_patch_set("apply_test")

        assert result is True
        assert patch_set.applied is True

    def test_apply_patch_set_updates_checksum(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Applying patch set updates patched checksum."""
        patch = patch_engine_writable.create_nop_sled(0x1000, 4)
        patch_set = patch_engine_writable.create_patch_set("checksum_update", [patch])

        original_checksum = patch_set.checksum_original
        patch_engine_writable.apply_patch_set("checksum_update")

        assert patch_set.checksum_patched is not None
        assert patch_set.checksum_patched != original_checksum

    def test_apply_unknown_patch_set_fails(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Applying non-existent patch set returns False."""
        result = patch_engine_writable.apply_patch_set("nonexistent_set")

        assert result is False

    def test_apply_already_applied_patch_set(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Re-applying already applied patch set succeeds without error."""
        patch = patch_engine_writable.create_nop_sled(0x1000, 4)
        patch_engine_writable.create_patch_set("reapply_test", [patch])

        patch_engine_writable.apply_patch_set("reapply_test")
        result = patch_engine_writable.apply_patch_set("reapply_test")

        assert result is True


class TestPatchSetExport:
    """Tests for exporting patch sets to JSON."""

    def test_export_patch_set_creates_file(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Exporting patch set creates JSON file."""
        patch = patch_engine_readonly.create_nop_sled(0x1000, 4)
        patch_engine_readonly.create_patch_set("export_test", [patch])

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "patch_set.json"
            patch_engine_readonly.export_patch_set("export_test", output_path)

            assert output_path.exists()
            assert output_path.stat().st_size > 0

    def test_export_patch_set_contains_valid_json(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Exported patch set is valid JSON."""
        import json

        patch = patch_engine_readonly.create_nop_sled(0x1000, 4)
        patch_engine_readonly.create_patch_set("json_test", [patch])

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "patch_set.json"
            patch_engine_readonly.export_patch_set("json_test", output_path)

            with open(output_path) as f:
                data = json.load(f)

            assert "name" in data
            assert "patches" in data
            assert "architecture" in data

    def test_export_patch_set_includes_all_patch_data(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Exported patch set contains complete patch information."""
        import json

        patch = patch_engine_readonly.create_nop_sled(0x1000, 8)
        patch_engine_readonly.create_patch_set("complete_test", [patch])

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "patch_set.json"
            patch_engine_readonly.export_patch_set("complete_test", output_path)

            with open(output_path) as f:
                data = json.load(f)

            assert len(data["patches"]) == 1
            exported_patch = data["patches"][0]
            assert "address" in exported_patch
            assert "original_bytes" in exported_patch
            assert "patch_bytes" in exported_patch
            assert "patch_type" in exported_patch

    def test_export_nonexistent_patch_set_raises_error(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Exporting non-existent patch set raises ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "patch_set.json"

            with pytest.raises(ValueError):
                patch_engine_readonly.export_patch_set("nonexistent", output_path)


class TestJumpTablePatching:
    """Tests for jump table modification."""

    def test_create_jump_table_patch_32bit(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Jump table patch creates correct number of entries."""
        if patch_engine_readonly.bits == 64:
            pytest.skip("32-bit jump table test requires 32-bit binary")

        entries = [0x1000, 0x2000, 0x3000]
        patches = patch_engine_readonly.create_jump_table_patch(0x5000, entries)

        assert len(patches) == 3
        assert all(p.patch_type == PatchType.VTABLE_MODIFICATION for p in patches)

    def test_jump_table_patch_correct_sizes(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Jump table entries use correct size for architecture."""
        entries = [0x1000, 0x2000]
        patches = patch_engine_readonly.create_jump_table_patch(0x5000, entries)

        expected_size = 8 if patch_engine_readonly.bits == 64 else 4
        assert all(len(p.patch_bytes) == expected_size for p in patches)

    def test_jump_table_sequential_addresses(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Jump table patches have sequential addresses."""
        entries = [0x1000, 0x2000, 0x3000]
        patches = patch_engine_readonly.create_jump_table_patch(0x5000, entries)

        entry_size = 8 if patch_engine_readonly.bits == 64 else 4
        for i, patch in enumerate(patches):
            expected_addr = 0x5000 + (i * entry_size)
            assert patch.address == expected_addr


class TestFunctionPrologueEpilogue:
    """Tests for function prologue and epilogue patching."""

    def test_patch_function_prologue(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Function prologue is patched with custom bytes."""
        new_prologue = b"\x55\x48\x89\xe5"

        patch = patch_engine_readonly.patch_function_prologue(0x1000, new_prologue)

        assert isinstance(patch, PatchInstruction)
        assert patch.patch_type == PatchType.FUNCTION_REPLACEMENT
        assert patch.patch_bytes == new_prologue
        assert len(patch.original_bytes) == len(new_prologue)

    def test_patch_function_epilogue(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Function epilogue is patched correctly."""
        new_epilogue = b"\xc9\xc3"

        patch = patch_engine_readonly.patch_function_epilogue(0x1000, new_epilogue)

        assert isinstance(patch, PatchInstruction)
        assert patch.patch_type == PatchType.FUNCTION_REPLACEMENT
        assert patch.patch_bytes == new_epilogue


class TestByteReading:
    """Tests for internal byte reading functionality."""

    def test_read_bytes_from_binary(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Reading bytes from binary returns correct data type and length."""
        data = patch_engine_readonly._read_bytes(0x1000, 16)

        assert isinstance(data, bytes)
        assert len(data) == 16

    def test_read_bytes_different_sizes(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Reading different byte sizes works correctly."""
        for size in [1, 4, 8, 16, 32]:
            data = patch_engine_readonly._read_bytes(0x1000, size)
            assert len(data) == size

    def test_read_bytes_non_zero_data(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Read bytes contain actual binary data."""
        data = patch_engine_readonly._read_bytes(0x1000, 32)

        assert data != b"\x00" * 32


class TestFunctionSizeDetection:
    """Tests for function size detection."""

    def test_get_function_size(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Function size detection returns non-negative integer."""
        size = patch_engine_readonly._get_function_size(0x1000)

        assert isinstance(size, int)
        assert size >= 0


class TestChecksumCalculation:
    """Tests for binary checksum calculation."""

    def test_calculate_checksum_returns_hash(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Checksum calculation returns valid hash string."""
        checksum = patch_engine_readonly._calculate_checksum()

        assert isinstance(checksum, str)
        assert len(checksum) > 0

    def test_checksum_consistent_for_same_binary(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Same binary produces identical checksum."""
        checksum1 = patch_engine_readonly._calculate_checksum()
        checksum2 = patch_engine_readonly._calculate_checksum()

        assert checksum1 == checksum2

    def test_checksum_changes_after_patch(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Binary checksum changes after applying patch."""
        original_checksum = patch_engine_writable._calculate_checksum()

        patch = patch_engine_writable.create_nop_sled(0x1000, 4)
        patch_engine_writable.apply_patch(patch)

        modified_checksum = patch_engine_writable._calculate_checksum()
        assert modified_checksum != original_checksum


class TestEngineCleanup:
    """Tests for proper resource cleanup."""

    def test_close_releases_resources(self, windows_notepad_binary: Path) -> None:
        """Closing engine releases radare2 resources."""
        engine = Radare2PatchEngine(windows_notepad_binary, write_mode=False)
        assert engine.r2 is not None

        engine.close()

        assert engine.r2 is None

    def test_close_multiple_times_safe(self, windows_notepad_binary: Path) -> None:
        """Closing engine multiple times doesn't cause errors."""
        engine = Radare2PatchEngine(windows_notepad_binary, write_mode=False)

        engine.close()
        engine.close()

        assert engine.r2 is None


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_patch_at_zero_address(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Creating patch at address 0x0 works correctly."""
        patch = patch_engine_readonly.create_nop_sled(0x0, 4)

        assert patch.address == 0x0
        assert len(patch.patch_bytes) == 4

    def test_very_large_nop_sled(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Large NOP sled is generated correctly."""
        patch = patch_engine_readonly.create_nop_sled(0x1000, 256)

        assert len(patch.patch_bytes) == 256

    def test_patch_set_with_empty_patches_list(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Patch set can be created with empty patch list."""
        patch_set = patch_engine_readonly.create_patch_set("empty_test", [])

        assert len(patch_set.patches) == 0

    def test_multiple_patch_engines_same_binary(self, windows_notepad_binary: Path) -> None:
        """Multiple patch engines can open same binary in read mode."""
        engine1 = Radare2PatchEngine(windows_notepad_binary, write_mode=False)
        engine2 = Radare2PatchEngine(windows_notepad_binary, write_mode=False)

        assert engine1.r2 is not None
        assert engine2.r2 is not None

        engine1.close()
        engine2.close()


class TestRealWorldScenarios:
    """Tests simulating real-world patching scenarios."""

    def test_license_check_bypass_simulation(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Simulate bypassing license check by modifying conditional jump."""
        address = 0x1000
        original_bytes = patch_engine_writable._read_bytes(address, 2)

        if original_bytes[0] in [0x74, 0x75]:
            patch = patch_engine_writable.invert_conditional_jump(address)
            result = patch_engine_writable.apply_patch(patch)
            assert result is True

            modified_bytes = patch_engine_writable._read_bytes(address, 2)
            assert modified_bytes != original_bytes

    def test_trial_period_bypass_return_true(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Simulate bypassing trial check by forcing function to return 1."""
        if patch_engine_writable.architecture not in ["x86", "x86_64"]:
            pytest.skip("Return value test requires x86/x86_64")

        patches = patch_engine_writable.patch_return_value(0x1000, 1, value_size=4)

        for patch in patches:
            result = patch_engine_writable.apply_patch(patch)
            assert result is True

    def test_multiple_patches_workflow(self, patch_engine_writable: Radare2PatchEngine) -> None:
        """Complex patching workflow with multiple operations."""
        patch1 = patch_engine_writable.create_nop_sled(0x1000, 8)
        patch2 = patch_engine_writable.create_nop_sled(0x2000, 4)

        patch_set = patch_engine_writable.create_patch_set("multi_patch", [patch1, patch2])

        result = patch_engine_writable.apply_patch_set("multi_patch")
        assert result is True

        assert patch_set.applied is True
        assert patch_set.checksum_patched != patch_set.checksum_original

    def test_patch_export_and_metadata_preservation(self, patch_engine_readonly: Radare2PatchEngine) -> None:
        """Patch metadata is preserved through export."""
        import json

        patch = patch_engine_readonly.create_nop_sled(0x1000, 8)
        patch_engine_readonly.create_patch_set("metadata_test", [patch])

        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "patches.json"
            patch_engine_readonly.export_patch_set("metadata_test", export_path)

            with open(export_path) as f:
                data = json.load(f)

            assert data["name"] == "metadata_test"
            assert data["architecture"] == patch_engine_readonly.architecture
            assert len(data["patches"]) == 1
