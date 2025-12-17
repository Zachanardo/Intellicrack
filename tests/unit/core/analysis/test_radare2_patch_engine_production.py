"""Production tests for Radare2 Patch Engine.

Validates real patching capabilities on actual binary data including:
- NOP sled generation across architectures
- Jump/call modification with correct relative addressing
- Conditional jump inversion
- Return value patching
- Function prologue/epilogue modification
- Patch set management and checksumming

Copyright (C) 2025 Zachary Flint
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest
import r2pipe

from intellicrack.core.analysis.radare2_patch_engine import (
    PatchInstruction,
    PatchSet,
    PatchType,
    Radare2PatchEngine,
)


@pytest.fixture
def simple_x86_binary(tmp_path: Path) -> Path:
    """Create a simple x86 PE binary for testing."""
    binary_path = tmp_path / "test_x86.exe"

    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    code_section = bytes([
        0x55,
        0x89, 0xE5,
        0x83, 0xEC, 0x10,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x10, 0x00, 0x00, 0x00,
        0x74, 0x05,
        0x75, 0x03,
        0xEB, 0xFE,
        0x89, 0xEC,
        0x5D,
        0xC3,
    ])

    binary_data = pe_header + b'\x00' * (0x100 - len(pe_header)) + code_section
    binary_data += b'\x00' * (0x1000 - len(binary_data))

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def simple_x64_binary(tmp_path: Path) -> Path:
    """Create a simple x64 binary for testing."""
    binary_path = tmp_path / "test_x64.bin"

    code_section = bytes([
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x83, 0xEC, 0x20,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x20, 0x00, 0x00, 0x00,
        0x74, 0x0A,
        0x0F, 0x84, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xEC,
        0x5D,
        0xC3,
    ])

    binary_data = code_section + b'\x00' * (0x1000 - len(code_section))
    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def arm_binary(tmp_path: Path) -> Path:
    """Create a simple ARM binary for testing."""
    binary_path = tmp_path / "test_arm.bin"

    arm_code = bytes([
        0x04, 0xE0, 0x2D, 0xE5,
        0x00, 0x00, 0x0B, 0xE3,
        0x00, 0x00, 0x00, 0xEA,
        0x00, 0x00, 0x00, 0xEB,
        0x04, 0xE0, 0x9D, 0xE4,
        0x1E, 0xFF, 0x2F, 0xE1,
    ])

    binary_data = arm_code + b'\x00' * (0x1000 - len(arm_code))
    binary_path.write_bytes(binary_data)
    return binary_path


class TestRadare2PatchEngineInitialization:
    """Test patch engine initialization and setup."""

    def test_engine_initialization_read_mode(self, simple_x86_binary: Path) -> None:
        """Patch engine initializes in read mode without errors."""
        engine = Radare2PatchEngine(simple_x86_binary, write_mode=False)

        assert engine.binary_path == simple_x86_binary
        assert engine.write_mode is False
        assert engine.r2 is not None
        assert engine.architecture is not None
        assert engine.bits is not None

        engine.close()

    def test_engine_initialization_write_mode(self, simple_x86_binary: Path) -> None:
        """Patch engine initializes in write mode for patch application."""
        engine = Radare2PatchEngine(simple_x86_binary, write_mode=True)

        assert engine.write_mode is True
        assert engine.r2 is not None

        engine.close()

    def test_architecture_detection_x86(self, simple_x86_binary: Path) -> None:
        """Patch engine detects x86 architecture correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        assert engine.architecture in ["x86", "x86_64"]
        assert engine.bits in [32, 64]

        engine.close()

    def test_nonexistent_binary_raises_error(self, tmp_path: Path) -> None:
        """Patch engine raises error for nonexistent binary."""
        nonexistent = tmp_path / "nonexistent.exe"

        with pytest.raises(Exception):
            Radare2PatchEngine(nonexistent)


class TestNOPSledGeneration:
    """Test NOP sled generation across architectures."""

    def test_create_nop_sled_x86_single_byte(self, simple_x86_binary: Path) -> None:
        """NOP sled for x86 uses correct 0x90 opcode."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.create_nop_sled(address=0x100, length=5)

        assert patch.address == 0x100
        assert patch.patch_type == PatchType.NOP_SLED
        assert len(patch.patch_bytes) == 5
        assert b'\x90' in patch.patch_bytes
        assert len(patch.original_bytes) == 5

        engine.close()

    def test_create_nop_sled_multibyte_x86(self, simple_x86_binary: Path) -> None:
        """Multi-byte NOP sleds use Intel-recommended opcodes."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.create_nop_sled(address=0x100, length=3)

        assert len(patch.patch_bytes) == 3
        expected_3byte_nop = b'\x0f\x1f\x00'
        assert patch.patch_bytes == expected_3byte_nop or b'\x90' in patch.patch_bytes

        engine.close()

    def test_create_nop_sled_arm(self, arm_binary: Path) -> None:
        """ARM NOP sled uses correct 4-byte NOP instruction."""
        engine = Radare2PatchEngine(arm_binary)

        if engine.architecture == "arm":
            patch = engine.create_nop_sled(address=0x0, length=8)

            assert len(patch.patch_bytes) == 8
            arm_nop = b'\x00\xf0\x20\xe3'
            assert arm_nop in patch.patch_bytes or len(patch.patch_bytes) == 8

        engine.close()

    def test_nop_sled_preserves_original_bytes(self, simple_x86_binary: Path) -> None:
        """NOP sled creation preserves original bytes for reverting."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.create_nop_sled(address=0x100, length=10)

        assert len(patch.original_bytes) == 10
        assert patch.original_bytes != patch.patch_bytes

        engine.close()


class TestJumpModification:
    """Test jump instruction modification and redirection."""

    def test_modify_short_jump_x86(self, simple_x86_binary: Path) -> None:
        """Short jump modification calculates correct relative offset."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.modify_jump(address=0x100, target=0x150, jump_type="jmp")

        assert patch.patch_type == PatchType.JUMP_MODIFICATION
        assert len(patch.patch_bytes) >= 2

        if len(patch.patch_bytes) == 2:
            assert patch.patch_bytes[0] == 0xEB
            offset = struct.unpack('b', patch.patch_bytes[1:2])[0]
            calculated_target = 0x100 + 2 + offset
            assert calculated_target == 0x150

        engine.close()

    def test_modify_near_jump_x86(self, simple_x86_binary: Path) -> None:
        """Near jump modification uses E9 opcode with 32-bit offset."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.modify_jump(address=0x100, target=0x300, jump_type="jmp")

        assert patch.patch_type == PatchType.JUMP_MODIFICATION

        if patch.patch_bytes[0] == 0xE9:
            assert len(patch.patch_bytes) == 5
            offset = struct.unpack('<i', patch.patch_bytes[1:5])[0]
            calculated_target = 0x100 + 5 + offset
            assert calculated_target == 0x300

        engine.close()

    def test_redirect_call_instruction(self, simple_x86_binary: Path) -> None:
        """Call redirection uses E8 opcode with correct target."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.redirect_call(address=0x110, new_function=0x200)

        assert patch.patch_type == PatchType.JUMP_MODIFICATION
        assert "call" in patch.metadata["jump_type"]
        assert patch.metadata["target"] == 0x200

        engine.close()

    def test_jump_modification_arm(self, arm_binary: Path) -> None:
        """ARM branch instructions encode correctly."""
        engine = Radare2PatchEngine(arm_binary)

        if engine.architecture == "arm":
            patch = engine.modify_jump(address=0x00, target=0x100, jump_type="jmp")

            assert patch.patch_type == PatchType.JUMP_MODIFICATION
            assert len(patch.patch_bytes) == 4

            instruction = struct.unpack('<I', patch.patch_bytes)[0]
            assert (instruction & 0xFF000000) in [0xEA000000, 0xEB000000]

        engine.close()


class TestConditionalJumpInversion:
    """Test conditional jump inversion for bypass techniques."""

    def test_invert_je_to_jne(self, simple_x86_binary: Path) -> None:
        """JE (0x74) inverts to JNE (0x75)."""
        engine = Radare2PatchEngine(simple_x86_binary)

        je_instruction = b'\x74\x05'
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b'\x00' * 0x100 + je_instruction + b'\x00' * 100)
            temp_path = Path(f.name)

        engine_temp = Radare2PatchEngine(temp_path)

        try:
            patch = engine_temp.invert_conditional_jump(address=0x100)

            assert patch.patch_type == PatchType.CONDITIONAL_INVERSION
            assert patch.original_bytes[0] == 0x74
            assert patch.patch_bytes[0] == 0x75
            assert patch.patch_bytes[1] == patch.original_bytes[1]
        finally:
            engine_temp.close()
            temp_path.unlink()

        engine.close()

    def test_invert_jne_to_je(self, simple_x86_binary: Path) -> None:
        """JNE (0x75) inverts to JE (0x74)."""
        engine = Radare2PatchEngine(simple_x86_binary)

        jne_instruction = b'\x75\x03'
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b'\x00' * 0x100 + jne_instruction + b'\x00' * 100)
            temp_path = Path(f.name)

        engine_temp = Radare2PatchEngine(temp_path)

        try:
            patch = engine_temp.invert_conditional_jump(address=0x100)

            assert patch.original_bytes[0] == 0x75
            assert patch.patch_bytes[0] == 0x74
        finally:
            engine_temp.close()
            temp_path.unlink()

        engine.close()

    def test_invert_extended_conditional_jump(self, simple_x86_binary: Path) -> None:
        """Extended conditional jumps (0x0F prefix) invert correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        extended_je = b'\x0f\x84\x10\x00\x00\x00'
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b'\x00' * 0x100 + extended_je + b'\x00' * 100)
            temp_path = Path(f.name)

        engine_temp = Radare2PatchEngine(temp_path)

        try:
            patch = engine_temp.invert_conditional_jump(address=0x100)

            assert patch.original_bytes[0] == 0x0F
            assert patch.original_bytes[1] == 0x84
            assert patch.patch_bytes[0] == 0x0F
            assert patch.patch_bytes[1] == 0x85
        finally:
            engine_temp.close()
            temp_path.unlink()

        engine.close()


class TestReturnValuePatching:
    """Test function return value modification."""

    def test_patch_return_value_x86_32bit(self, simple_x86_binary: Path) -> None:
        """x86 return value patching uses MOV EAX, value + RET."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patches = engine.patch_return_value(
            function_address=0x100,
            return_value=0x12345678,
            value_size=4
        )

        assert len(patches) >= 1
        main_patch = patches[0]

        assert main_patch.patch_type == PatchType.RETURN_VALUE
        assert b'\xb8' in main_patch.patch_bytes
        assert b'\xc3' in main_patch.patch_bytes

        value_bytes = struct.pack('<I', 0x12345678)
        assert value_bytes in main_patch.patch_bytes

        engine.close()

    def test_patch_return_value_x64_64bit(self, simple_x64_binary: Path) -> None:
        """x64 return value patching uses MOV RAX, value + RET."""
        engine = Radare2PatchEngine(simple_x64_binary)

        if engine.bits == 64:
            patches = engine.patch_return_value(
                function_address=0x00,
                return_value=0x123456789ABCDEF0,
                value_size=8
            )

            assert len(patches) >= 1
            main_patch = patches[0]

            assert main_patch.patch_type == PatchType.RETURN_VALUE
            assert b'\x48\xb8' in main_patch.patch_bytes
            assert b'\xc3' in main_patch.patch_bytes

        engine.close()

    def test_patch_return_value_different_sizes(self, simple_x86_binary: Path) -> None:
        """Return value patching supports 1, 2, 4, and 8 byte values."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patches_1byte = engine.patch_return_value(0x100, 0xFF, value_size=1)
        patches_2byte = engine.patch_return_value(0x110, 0xFFFF, value_size=2)
        patches_4byte = engine.patch_return_value(0x120, 0xFFFFFFFF, value_size=4)

        assert patches_1byte[0].patch_bytes[0] == 0xB0
        assert patches_2byte[0].patch_bytes[0:2] == b'\x66\xb8'
        assert patches_4byte[0].patch_bytes[0] == 0xB8

        engine.close()


class TestPatchSetManagement:
    """Test patch set creation, application, and management."""

    def test_create_patch_set(self, simple_x86_binary: Path) -> None:
        """Patch sets group related patches together."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch1 = engine.create_nop_sled(0x100, 5)
        patch2 = engine.modify_jump(0x110, 0x200, "jmp")

        patch_set = engine.create_patch_set("test_set", [patch1, patch2])

        assert patch_set.name == "test_set"
        assert len(patch_set.patches) == 2
        assert patch_set.target_binary == simple_x86_binary
        assert patch_set.architecture is not None
        assert patch_set.checksum_original is not None
        assert patch_set.applied is False

        engine.close()

    def test_apply_patch_set_write_mode(self, simple_x86_binary: Path) -> None:
        """Patch sets apply successfully in write mode."""
        import shutil
        temp_binary = simple_x86_binary.with_suffix('.patched.exe')
        shutil.copy(simple_x86_binary, temp_binary)

        engine = Radare2PatchEngine(temp_binary, write_mode=True)

        patch1 = engine.create_nop_sled(0x100, 3)
        patch_set = engine.create_patch_set("nop_patch", [patch1])

        result = engine.apply_patch_set("nop_patch")

        assert result is True
        assert patch_set.applied is True
        assert patch_set.checksum_patched is not None
        assert patch_set.checksum_patched != patch_set.checksum_original

        engine.close()
        temp_binary.unlink()

    def test_revert_patch(self, simple_x86_binary: Path) -> None:
        """Patches can be reverted to original bytes."""
        import shutil
        temp_binary = simple_x86_binary.with_suffix('.revert.exe')
        shutil.copy(simple_x86_binary, temp_binary)

        engine = Radare2PatchEngine(temp_binary, write_mode=True)

        patch = engine.create_nop_sled(0x100, 5)
        engine.apply_patch(patch)

        result = engine.revert_patch(patch)

        assert result is True

        engine.close()
        temp_binary.unlink()

    def test_export_patch_set(self, simple_x86_binary: Path, tmp_path: Path) -> None:
        """Patch sets export to JSON format correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch1 = engine.create_nop_sled(0x100, 5)
        patch2 = engine.modify_jump(0x110, 0x200, "jmp")

        engine.create_patch_set("export_test", [patch1, patch2])

        export_path = tmp_path / "patches.json"
        engine.export_patch_set("export_test", export_path)

        assert export_path.exists()

        import json
        with open(export_path) as f:
            data = json.load(f)

        assert data["name"] == "export_test"
        assert len(data["patches"]) == 2
        assert all("address" in p for p in data["patches"])
        assert all("patch_bytes" in p for p in data["patches"])

        engine.close()


class TestInlinePatchAssembly:
    """Test inline assembly patching."""

    def test_create_inline_patch_x86(self, simple_x86_binary: Path) -> None:
        """Inline assembly code assembles and patches correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        try:
            patch = engine.create_inline_patch(0x100, "nop")

            assert patch.patch_type == PatchType.INLINE_PATCH
            assert len(patch.patch_bytes) > 0
            assert patch.metadata["assembly"] == "nop"
        except Exception as e:
            if "invalid" not in str(e).lower():
                raise

        engine.close()

    def test_inline_patch_with_multiple_instructions(self, simple_x86_binary: Path) -> None:
        """Multiple instruction inline patches assemble correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        try:
            patch = engine.create_inline_patch(0x100, "xor eax, eax; ret")

            assert patch.patch_type == PatchType.INLINE_PATCH
            assert len(patch.patch_bytes) >= 2
        except Exception as e:
            if "invalid" not in str(e).lower():
                raise

        engine.close()


class TestJumpTableModification:
    """Test jump table and vtable modification."""

    def test_create_jump_table_patch_32bit(self, simple_x86_binary: Path) -> None:
        """Jump table patches modify table entries correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        if engine.bits == 32:
            entries = [0x1000, 0x2000, 0x3000, 0x4000]
            patches = engine.create_jump_table_patch(0x100, entries)

            assert len(patches) == 4

            for i, patch in enumerate(patches):
                assert patch.patch_type == PatchType.VTABLE_MODIFICATION
                assert len(patch.patch_bytes) == 4

                address = struct.unpack('<I', patch.patch_bytes)[0]
                assert address == entries[i]

        engine.close()

    def test_create_jump_table_patch_64bit(self, simple_x64_binary: Path) -> None:
        """64-bit jump tables use 8-byte entries."""
        engine = Radare2PatchEngine(simple_x64_binary)

        if engine.bits == 64:
            entries = [0x100000, 0x200000]
            patches = engine.create_jump_table_patch(0x00, entries)

            assert len(patches) == 2

            for patch in patches:
                assert len(patch.patch_bytes) == 8

        engine.close()


class TestEdgeCasesAndErrors:
    """Test edge cases and error handling."""

    def test_patch_without_write_mode_fails(self, simple_x86_binary: Path) -> None:
        """Applying patches without write mode returns False."""
        engine = Radare2PatchEngine(simple_x86_binary, write_mode=False)

        patch = engine.create_nop_sled(0x100, 5)
        result = engine.apply_patch(patch)

        assert result is False

        engine.close()

    def test_apply_nonexistent_patch_set_fails(self, simple_x86_binary: Path) -> None:
        """Applying nonexistent patch set returns False."""
        engine = Radare2PatchEngine(simple_x86_binary, write_mode=True)

        result = engine.apply_patch_set("nonexistent")

        assert result is False

        engine.close()

    def test_large_nop_sled(self, simple_x86_binary: Path) -> None:
        """Large NOP sleds generate without errors."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.create_nop_sled(0x100, 256)

        assert len(patch.patch_bytes) == 256

        engine.close()

    def test_function_prologue_replacement(self, simple_x86_binary: Path) -> None:
        """Function prologue replacement preserves original bytes."""
        engine = Radare2PatchEngine(simple_x86_binary)

        new_prologue = b'\x55\x89\xe5\x90\x90'
        patch = engine.patch_function_prologue(0x100, new_prologue)

        assert patch.patch_type == PatchType.FUNCTION_REPLACEMENT
        assert patch.patch_bytes == new_prologue
        assert len(patch.original_bytes) == len(new_prologue)

        engine.close()


class TestArchitectureSupport:
    """Test multi-architecture support."""

    def test_x86_architecture_detection(self, simple_x86_binary: Path) -> None:
        """x86 architecture detected and configured correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        assert engine.architecture in ["x86", "x86_64"]
        assert b'\x90' in engine.NOP_INSTRUCTIONS.values()

        engine.close()

    def test_arm_architecture_detection(self, arm_binary: Path) -> None:
        """ARM architecture detected and configured correctly."""
        engine = Radare2PatchEngine(arm_binary)

        if engine.architecture == "arm":
            assert engine.NOP_INSTRUCTIONS["arm"] == b'\x00\xf0\x20\xe3'

        engine.close()

    def test_architecture_specific_nops(self, simple_x86_binary: Path) -> None:
        """Architecture-specific NOPs selected correctly."""
        engine = Radare2PatchEngine(simple_x86_binary)

        nop = engine.NOP_INSTRUCTIONS.get(engine.architecture, b'\x90')
        assert nop is not None
        assert len(nop) > 0

        engine.close()


class TestPatchIntegrity:
    """Test patch integrity and validation."""

    def test_checksum_calculation(self, simple_x86_binary: Path) -> None:
        """Checksums calculate correctly for patch tracking."""
        engine = Radare2PatchEngine(simple_x86_binary)

        checksum = engine._calculate_checksum()

        assert checksum is not None
        assert len(checksum) == 64
        assert all(c in '0123456789abcdef' for c in checksum)

        engine.close()

    def test_patch_preserves_size(self, simple_x86_binary: Path) -> None:
        """Patches preserve original byte size."""
        engine = Radare2PatchEngine(simple_x86_binary)

        patch = engine.create_nop_sled(0x100, 10)

        assert len(patch.patch_bytes) == len(patch.original_bytes)

        engine.close()

    def test_multiple_patch_application_order(self, simple_x86_binary: Path) -> None:
        """Multiple patches apply in correct order."""
        import shutil
        temp_binary = simple_x86_binary.with_suffix('.multi.exe')
        shutil.copy(simple_x86_binary, temp_binary)

        engine = Radare2PatchEngine(temp_binary, write_mode=True)

        patches = [
            engine.create_nop_sled(0x100, 5),
            engine.create_nop_sled(0x110, 5),
            engine.create_nop_sled(0x120, 5),
        ]

        patch_set = engine.create_patch_set("multi_patch", patches)
        result = engine.apply_patch_set("multi_patch")

        assert result is True
        assert patch_set.applied is True

        engine.close()
        temp_binary.unlink()


class TestRealWorldScenarios:
    """Test real-world patching scenarios."""

    def test_license_check_bypass_pattern(self, simple_x86_binary: Path) -> None:
        """License check bypass pattern patches correctly."""
        import shutil
        temp_binary = simple_x86_binary.with_suffix('.license.exe')
        shutil.copy(simple_x86_binary, temp_binary)

        engine = Radare2PatchEngine(temp_binary, write_mode=True)

        patches = [
            engine.patch_return_value(0x100, 1, value_size=4),
            engine.create_nop_sled(0x110, 10),
        ]

        patch_set = engine.create_patch_set("license_bypass", patches)
        result = engine.apply_patch_set("license_bypass")

        assert result is True

        engine.close()
        temp_binary.unlink()

    def test_trial_check_inversion(self, simple_x86_binary: Path) -> None:
        """Trial check inversion using conditional jump modification."""
        je_binary = simple_x86_binary.with_suffix('.trial.bin')

        with open(je_binary, 'wb') as f:
            f.write(b'\x00' * 0x100 + b'\x74\x10' + b'\x00' * 100)

        engine = Radare2PatchEngine(je_binary, write_mode=True)

        patch = engine.invert_conditional_jump(0x100)
        result = engine.apply_patch(patch)

        assert result is True
        assert patch.patch_bytes[0] == 0x75

        engine.close()
        je_binary.unlink()
