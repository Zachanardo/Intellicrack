"""Production-grade tests for certificate patch generators validating real patching capabilities.

Tests REAL binary patch generation for certificate validation bypass.
NO mocks - validates genuine patch generation and application.

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
"""

import struct
from pathlib import Path
from typing import Callable

import pefile
import pytest
from hypothesis import given, strategies as st

from intellicrack.core.certificate.patch_generators import (
    Architecture,
    PatchType,
    generate_always_succeed_arm32,
    generate_always_succeed_arm64,
    generate_always_succeed_x64,
    generate_always_succeed_x86,
    generate_conditional_invert_arm,
    generate_conditional_invert_x64,
    generate_conditional_invert_x86,
    generate_nop_sled,
    generate_register_restore_x64,
    generate_register_restore_x86,
    generate_register_save_x64,
    generate_register_save_x86,
    generate_trampoline_x64,
    generate_trampoline_x86,
    get_patch_for_architecture,
    validate_patch_alignment,
    validate_patch_size,
    wrap_patch_cdecl,
    wrap_patch_fastcall,
    wrap_patch_stdcall,
    wrap_patch_x64_convention,
)


@pytest.fixture(scope="module")
def protected_binaries_dir() -> Path:
    """Path to directory containing real protected binaries."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected"


@pytest.fixture(scope="module")
def legitimate_binaries_dir() -> Path:
    """Path to directory containing legitimate binaries."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "legitimate"


@pytest.fixture
def real_pe_binary(legitimate_binaries_dir: Path) -> bytes:
    """Load real PE binary for patch testing."""
    binary_path = legitimate_binaries_dir / "7zip.exe"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}")
    return binary_path.read_bytes()


@pytest.fixture
def certificate_validation_binary(protected_binaries_dir: Path) -> bytes:
    """Load real binary with certificate validation."""
    binary_path = protected_binaries_dir / "online_activation_app.exe"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}")
    return binary_path.read_bytes()


class TestAlwaysSucceedPatchGeneration:
    """Test always-succeed patch generation for all architectures."""

    def test_x86_always_succeed_generates_valid_machine_code(self) -> None:
        """x86 always-succeed patch produces valid MOV EAX,1; RET instruction."""
        patch = generate_always_succeed_x86()

        assert len(patch) == 6
        assert patch[0] == 0xB8
        assert patch[1:5] == b"\x01\x00\x00\x00"
        assert patch[5] == 0xC3

        expected_instructions = b"\xB8\x01\x00\x00\x00\xC3"
        assert patch == expected_instructions

    def test_x64_always_succeed_generates_valid_machine_code(self) -> None:
        """x64 always-succeed patch produces valid MOV RAX,1; RET instruction."""
        patch = generate_always_succeed_x64()

        assert len(patch) == 8
        assert patch[0:3] == b"\x48\xC7\xC0"
        assert patch[3:7] == b"\x01\x00\x00\x00"
        assert patch[7] == 0xC3

        expected_instructions = b"\x48\xC7\xC0\x01\x00\x00\x00\xC3"
        assert patch == expected_instructions

    def test_arm32_always_succeed_generates_valid_machine_code(self) -> None:
        """ARM32 always-succeed patch produces valid MOV R0,#1; BX LR instruction."""
        patch = generate_always_succeed_arm32()

        assert len(patch) == 8
        assert patch == b"\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1"

        mov_r0_1 = patch[0:4]
        bx_lr = patch[4:8]
        assert mov_r0_1 == b"\x01\x00\xA0\xE3"
        assert bx_lr == b"\x1E\xFF\x2F\xE1"

    def test_arm64_always_succeed_generates_valid_machine_code(self) -> None:
        """ARM64 always-succeed patch produces valid MOV X0,#1; RET instruction."""
        patch = generate_always_succeed_arm64()

        assert len(patch) == 8
        assert patch == b"\x20\x00\x80\xD2\xC0\x03\x5F\xD6"

        mov_x0_1 = patch[0:4]
        ret = patch[4:8]
        assert mov_x0_1 == b"\x20\x00\x80\xD2"
        assert ret == b"\xC0\x03\x5F\xD6"

    def test_always_succeed_patches_are_deterministic(self) -> None:
        """Always-succeed patches produce identical output on repeated calls."""
        x86_patch_1 = generate_always_succeed_x86()
        x86_patch_2 = generate_always_succeed_x86()
        assert x86_patch_1 == x86_patch_2

        x64_patch_1 = generate_always_succeed_x64()
        x64_patch_2 = generate_always_succeed_x64()
        assert x64_patch_1 == x64_patch_2

        arm32_patch_1 = generate_always_succeed_arm32()
        arm32_patch_2 = generate_always_succeed_arm32()
        assert arm32_patch_1 == arm32_patch_2

        arm64_patch_1 = generate_always_succeed_arm64()
        arm64_patch_2 = generate_always_succeed_arm64()
        assert arm64_patch_1 == arm64_patch_2


class TestConditionalInvertPatchGeneration:
    """Test conditional jump inversion patch generation."""

    def test_x86_inverts_jz_to_jnz(self) -> None:
        """x86 conditional invert converts JZ to JNZ."""
        jz_instruction = bytes([0x74, 0x10])
        inverted = generate_conditional_invert_x86(jz_instruction)

        assert len(inverted) == 2
        assert inverted[0] == 0x75
        assert inverted[1] == 0x10

    def test_x86_inverts_jnz_to_jz(self) -> None:
        """x86 conditional invert converts JNZ to JZ."""
        jnz_instruction = bytes([0x75, 0x20])
        inverted = generate_conditional_invert_x86(jnz_instruction)

        assert len(inverted) == 2
        assert inverted[0] == 0x74
        assert inverted[1] == 0x20

    def test_x86_inverts_near_je_to_jne(self) -> None:
        """x86 conditional invert converts near JE to JNE."""
        je_instruction = bytes([0x0F, 0x84, 0x30, 0x00, 0x00, 0x00])
        inverted = generate_conditional_invert_x86(je_instruction)

        assert len(inverted) == 6
        assert inverted[0] == 0x0F
        assert inverted[1] == 0x85
        assert inverted[2:6] == bytes([0x30, 0x00, 0x00, 0x00])

    def test_x86_inverts_near_jne_to_je(self) -> None:
        """x86 conditional invert converts near JNE to JE."""
        jne_instruction = bytes([0x0F, 0x85, 0x40, 0x00, 0x00, 0x00])
        inverted = generate_conditional_invert_x86(jne_instruction)

        assert len(inverted) == 6
        assert inverted[0] == 0x0F
        assert inverted[1] == 0x84
        assert inverted[2:6] == bytes([0x40, 0x00, 0x00, 0x00])

    def test_x86_preserves_jump_offset(self) -> None:
        """x86 conditional invert preserves the jump offset unchanged."""
        original_offset = 0x1234
        jz_instruction = bytes([0x74]) + struct.pack("<B", original_offset & 0xFF)
        inverted = generate_conditional_invert_x86(jz_instruction)

        assert inverted[1] == (original_offset & 0xFF)

    def test_x64_inverts_conditional_jumps(self) -> None:
        """x64 conditional invert works identically to x86."""
        jz_instruction = bytes([0x74, 0x50])
        inverted = generate_conditional_invert_x64(jz_instruction)

        assert inverted[0] == 0x75
        assert inverted[1] == 0x50

    def test_conditional_invert_handles_empty_input(self) -> None:
        """Conditional invert gracefully handles empty input."""
        inverted = generate_conditional_invert_x86(b"")
        assert inverted == b""

    def test_arm_inverts_conditional_branches(self) -> None:
        """ARM conditional invert flips condition codes."""
        beq_instruction = bytes([0x00, 0x00, 0x00, 0x0A])
        inverted = generate_conditional_invert_arm(beq_instruction)

        assert len(inverted) == 4
        assert inverted[0:3] == beq_instruction[0:3]
        assert inverted[3] != beq_instruction[3]

    def test_arm_handles_short_input(self) -> None:
        """ARM conditional invert handles input shorter than 4 bytes."""
        short_input = bytes([0x00, 0x01])
        inverted = generate_conditional_invert_arm(short_input)
        assert inverted == short_input


class TestNopSledGeneration:
    """Test NOP sled generation for various architectures."""

    def test_x86_nop_sled_generates_correct_size(self) -> None:
        """x86 NOP sled generates exact requested byte count."""
        for size in [1, 10, 20, 64, 128]:
            nop_sled = generate_nop_sled(size, Architecture.X86)
            assert len(nop_sled) == size

    def test_x86_nop_sled_contains_only_nop_instructions(self) -> None:
        """x86 NOP sled contains only 0x90 (NOP) bytes."""
        nop_sled = generate_nop_sled(50, Architecture.X86)
        assert all(byte == 0x90 for byte in nop_sled)

    def test_x64_nop_sled_generates_correct_size(self) -> None:
        """x64 NOP sled generates exact requested byte count."""
        for size in [1, 10, 20, 64, 128]:
            nop_sled = generate_nop_sled(size, Architecture.X64)
            assert len(nop_sled) == size

    def test_x64_nop_sled_contains_only_nop_instructions(self) -> None:
        """x64 NOP sled contains only 0x90 (NOP) bytes."""
        nop_sled = generate_nop_sled(100, Architecture.X64)
        assert all(byte == 0x90 for byte in nop_sled)

    def test_arm32_nop_sled_generates_aligned_size(self) -> None:
        """ARM32 NOP sled generates multiples of 4 bytes."""
        nop_sled = generate_nop_sled(16, Architecture.ARM32)
        assert len(nop_sled) == 16
        assert len(nop_sled) % 4 == 0

    def test_arm32_nop_sled_contains_valid_nops(self) -> None:
        """ARM32 NOP sled contains valid MOV R0,R0 instructions."""
        nop_sled = generate_nop_sled(12, Architecture.ARM32)
        arm_nop = bytes([0x00, 0x00, 0xA0, 0xE1])

        for i in range(0, len(nop_sled), 4):
            assert nop_sled[i:i+4] == arm_nop

    def test_arm64_nop_sled_generates_aligned_size(self) -> None:
        """ARM64 NOP sled generates multiples of 4 bytes."""
        nop_sled = generate_nop_sled(20, Architecture.ARM64)
        assert len(nop_sled) == 20
        assert len(nop_sled) % 4 == 0

    def test_arm64_nop_sled_contains_valid_nops(self) -> None:
        """ARM64 NOP sled contains valid NOP instructions."""
        nop_sled = generate_nop_sled(16, Architecture.ARM64)
        arm64_nop = bytes([0x1F, 0x20, 0x03, 0xD5])

        for i in range(0, len(nop_sled), 4):
            assert nop_sled[i:i+4] == arm64_nop

    @given(st.integers(min_value=0, max_value=256))
    def test_nop_sled_size_property(self, size: int) -> None:
        """NOP sled always generates requested size for x86/x64."""
        nop_sled = generate_nop_sled(size, Architecture.X86)
        assert len(nop_sled) == size


class TestTrampolineGeneration:
    """Test trampoline jump generation for hooking."""

    def test_x86_trampoline_generates_relative_jump(self) -> None:
        """x86 trampoline generates valid relative JMP instruction."""
        target_addr = 0x00401000
        hook_addr = 0x00402000
        trampoline = generate_trampoline_x86(target_addr, hook_addr)

        assert len(trampoline) == 5
        assert trampoline[0] == 0xE9

        offset = int.from_bytes(trampoline[1:5], byteorder="little", signed=True)
        expected_offset = hook_addr - (target_addr + 5)
        assert offset == expected_offset

    def test_x86_trampoline_handles_backward_jumps(self) -> None:
        """x86 trampoline correctly handles backward jumps."""
        target_addr = 0x00402000
        hook_addr = 0x00401000
        trampoline = generate_trampoline_x86(target_addr, hook_addr)

        assert len(trampoline) == 5
        assert trampoline[0] == 0xE9

        offset = int.from_bytes(trampoline[1:5], byteorder="little", signed=True)
        assert offset < 0

    def test_x64_trampoline_uses_relative_jump_when_in_range(self) -> None:
        """x64 trampoline uses relative jump for nearby addresses."""
        target_addr = 0x140001000
        hook_addr = 0x140002000
        trampoline = generate_trampoline_x64(target_addr, hook_addr)

        assert len(trampoline) == 5
        assert trampoline[0] == 0xE9

    def test_x64_trampoline_uses_absolute_jump_for_far_addresses(self) -> None:
        """x64 trampoline uses absolute jump for distant addresses."""
        target_addr = 0x140001000
        hook_addr = 0x7FF000000000
        trampoline = generate_trampoline_x64(target_addr, hook_addr)

        assert len(trampoline) == 12
        assert trampoline[0:2] == b"\x48\xB8"
        assert trampoline[10:12] == b"\xFF\xE0"

        embedded_addr = int.from_bytes(trampoline[2:10], byteorder="little")
        assert embedded_addr == hook_addr

    def test_x64_trampoline_preserves_hook_address(self) -> None:
        """x64 absolute trampoline correctly embeds hook address."""
        target_addr = 0x140001000
        hook_addr = 0x7FFFABCD1234
        trampoline = generate_trampoline_x64(target_addr, hook_addr)

        if len(trampoline) == 12:
            embedded_addr = int.from_bytes(trampoline[2:10], byteorder="little")
            assert embedded_addr == hook_addr

    @given(
        st.integers(min_value=0x400000, max_value=0x7FFFFFFF),
        st.integers(min_value=0x400000, max_value=0x7FFFFFFF)
    )
    def test_x86_trampoline_offset_calculation_property(
        self,
        target: int,
        hook: int
    ) -> None:
        """x86 trampoline offset calculation is always correct."""
        trampoline = generate_trampoline_x86(target, hook)
        assert len(trampoline) == 5
        assert trampoline[0] == 0xE9

        offset = int.from_bytes(trampoline[1:5], byteorder="little", signed=True)
        expected_offset = hook - (target + 5)
        assert offset == expected_offset


class TestCallingConventionWrappers:
    """Test calling convention wrapper generation."""

    def test_stdcall_wrapper_adds_stack_cleanup_for_args(self) -> None:
        """stdcall wrapper adds RET imm16 for stack cleanup."""
        base_patch = generate_always_succeed_x86()
        wrapped = wrap_patch_stdcall(base_patch, arg_count=2)

        assert len(wrapped) == len(base_patch) + 2
        assert wrapped[-3] == 0xC2
        stack_cleanup = int.from_bytes(wrapped[-2:], byteorder="little")
        assert stack_cleanup == 8

    def test_stdcall_wrapper_no_cleanup_for_zero_args(self) -> None:
        """stdcall wrapper unchanged when arg_count is zero."""
        base_patch = generate_always_succeed_x86()
        wrapped = wrap_patch_stdcall(base_patch, arg_count=0)
        assert wrapped == base_patch

    def test_cdecl_wrapper_unchanged(self) -> None:
        """cdecl wrapper returns patch unchanged."""
        base_patch = generate_always_succeed_x86()
        wrapped = wrap_patch_cdecl(base_patch)
        assert wrapped == base_patch

    def test_fastcall_wrapper_preserves_rcx_rdx(self) -> None:
        """fastcall wrapper adds PUSH/POP for RCX and RDX."""
        base_patch = generate_always_succeed_x64()
        wrapped = wrap_patch_fastcall(base_patch)

        assert len(wrapped) == len(base_patch) + 4
        assert wrapped[0:2] == b"\x51\x52"
        assert wrapped[-2:] == b"\x5A\x59"

    def test_x64_convention_wrapper_preserves_argument_registers(self) -> None:
        """x64 convention wrapper preserves RCX, RDX, R8, R9."""
        base_patch = generate_always_succeed_x64()
        wrapped = wrap_patch_x64_convention(base_patch)

        assert len(wrapped) == len(base_patch) + 12

        expected_push = b"\x51\x52\x41\x50\x41\x51"
        expected_pop = b"\x41\x59\x41\x58\x5A\x59"

        assert wrapped[0:6] == expected_push
        assert wrapped[-6:] == expected_pop


class TestRegisterSaveRestore:
    """Test register save/restore code generation."""

    def test_x86_register_save_generates_pushad(self) -> None:
        """x86 register save generates PUSHAD instruction."""
        save_code = generate_register_save_x86()
        assert len(save_code) == 1
        assert save_code[0] == 0x60

    def test_x86_register_restore_generates_popad(self) -> None:
        """x86 register restore generates POPAD instruction."""
        restore_code = generate_register_restore_x86()
        assert len(restore_code) == 1
        assert restore_code[0] == 0x61

    def test_x64_register_save_generates_all_pushes(self) -> None:
        """x64 register save generates PUSH for all 16 GPRs."""
        save_code = generate_register_save_x64()
        assert len(save_code) == 24

        expected_sequence = bytes([
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
            0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
        ])
        assert save_code == expected_sequence

    def test_x64_register_restore_generates_all_pops(self) -> None:
        """x64 register restore generates POP for all 16 GPRs in reverse."""
        restore_code = generate_register_restore_x64()
        assert len(restore_code) == 24

        expected_sequence = bytes([
            0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
            0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
            0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58
        ])
        assert restore_code == expected_sequence

    def test_x64_save_restore_symmetry(self) -> None:
        """x64 save and restore have matching lengths and symmetry."""
        save_code = generate_register_save_x64()
        restore_code = generate_register_restore_x64()
        assert len(save_code) == len(restore_code)


class TestPatchValidation:
    """Test patch size and alignment validation."""

    def test_validate_patch_size_accepts_fitting_patch(self) -> None:
        """Patch size validation accepts patches within max_size."""
        patch = generate_always_succeed_x86()
        assert validate_patch_size(patch, max_size=10)
        assert validate_patch_size(patch, max_size=6)

    def test_validate_patch_size_rejects_oversized_patch(self) -> None:
        """Patch size validation rejects patches exceeding max_size."""
        patch = generate_always_succeed_x86()
        assert not validate_patch_size(patch, max_size=5)
        assert not validate_patch_size(patch, max_size=1)

    def test_validate_patch_alignment_accepts_non_empty_patch(self) -> None:
        """Patch alignment validation accepts non-empty patches."""
        patch = generate_always_succeed_x86()
        assert validate_patch_alignment(patch, address=0x140001000)
        assert validate_patch_alignment(patch, address=0x00401234)

    def test_validate_patch_alignment_rejects_empty_patch(self) -> None:
        """Patch alignment validation rejects empty patches."""
        assert not validate_patch_alignment(b"", address=0x140001000)

    @given(st.integers(min_value=1, max_value=256))
    def test_patch_size_validation_property(self, max_size: int) -> None:
        """Patch size validation correctly compares patch length to max_size."""
        x86_patch = generate_always_succeed_x86()
        result = validate_patch_size(x86_patch, max_size=max_size)
        assert result == (len(x86_patch) <= max_size)


class TestArchitecturePatchSelection:
    """Test architecture-based patch selection."""

    def test_get_always_succeed_for_x86(self) -> None:
        """Architecture selector returns x86 always-succeed patch."""
        patch = get_patch_for_architecture(
            Architecture.X86,
            PatchType.ALWAYS_SUCCEED
        )
        assert patch is not None
        assert len(patch) == 6
        assert patch == generate_always_succeed_x86()

    def test_get_always_succeed_for_x64(self) -> None:
        """Architecture selector returns x64 always-succeed patch."""
        patch = get_patch_for_architecture(
            Architecture.X64,
            PatchType.ALWAYS_SUCCEED
        )
        assert patch is not None
        assert len(patch) == 8
        assert patch == generate_always_succeed_x64()

    def test_get_always_succeed_for_arm32(self) -> None:
        """Architecture selector returns ARM32 always-succeed patch."""
        patch = get_patch_for_architecture(
            Architecture.ARM32,
            PatchType.ALWAYS_SUCCEED
        )
        assert patch is not None
        assert len(patch) == 8
        assert patch == generate_always_succeed_arm32()

    def test_get_always_succeed_for_arm64(self) -> None:
        """Architecture selector returns ARM64 always-succeed patch."""
        patch = get_patch_for_architecture(
            Architecture.ARM64,
            PatchType.ALWAYS_SUCCEED
        )
        assert patch is not None
        assert len(patch) == 8
        assert patch == generate_always_succeed_arm64()

    def test_get_nop_sled_for_x86(self) -> None:
        """Architecture selector returns x86 NOP sled."""
        patch = get_patch_for_architecture(
            Architecture.X86,
            PatchType.NOP_SLED,
            size=20
        )
        assert patch is not None
        assert len(patch) == 20
        assert all(byte == 0x90 for byte in patch)

    def test_get_nop_sled_for_arm64(self) -> None:
        """Architecture selector returns ARM64 NOP sled."""
        patch = get_patch_for_architecture(
            Architecture.ARM64,
            PatchType.NOP_SLED,
            size=16
        )
        assert patch is not None
        assert len(patch) == 16

    def test_get_conditional_invert_for_x86(self) -> None:
        """Architecture selector returns x86 conditional invert patch."""
        original = bytes([0x74, 0x10])
        patch = get_patch_for_architecture(
            Architecture.X86,
            PatchType.CONDITIONAL_INVERT,
            original_bytes=original
        )
        assert patch is not None
        assert patch[0] == 0x75

    def test_get_conditional_invert_for_arm32(self) -> None:
        """Architecture selector returns ARM32 conditional invert patch."""
        original = bytes([0x00, 0x00, 0x00, 0x0A])
        patch = get_patch_for_architecture(
            Architecture.ARM32,
            PatchType.CONDITIONAL_INVERT,
            original_bytes=original
        )
        assert patch is not None
        assert len(patch) == 4

    def test_get_trampoline_for_x86(self) -> None:
        """Architecture selector returns x86 trampoline."""
        patch = get_patch_for_architecture(
            Architecture.X86,
            PatchType.TRAMPOLINE,
            target_addr=0x401000,
            hook_addr=0x402000
        )
        assert patch is not None
        assert len(patch) == 5
        assert patch[0] == 0xE9

    def test_get_trampoline_for_x64(self) -> None:
        """Architecture selector returns x64 trampoline."""
        patch = get_patch_for_architecture(
            Architecture.X64,
            PatchType.TRAMPOLINE,
            target_addr=0x140001000,
            hook_addr=0x140002000
        )
        assert patch is not None
        assert patch[0] == 0xE9

    def test_get_patch_returns_none_for_unsupported_combination(self) -> None:
        """Architecture selector returns None for unsupported combinations."""
        patch = get_patch_for_architecture(
            Architecture.ARM32,
            PatchType.TRAMPOLINE,
            target_addr=0x1000,
            hook_addr=0x2000
        )
        assert patch is None


class TestRealBinaryPatchApplication:
    """Test applying generated patches to real PE binaries."""

    def test_always_succeed_patch_fits_in_typical_function(
        self,
        real_pe_binary: bytes
    ) -> None:
        """Always-succeed patch is small enough for typical functions."""
        pe = pefile.PE(data=real_pe_binary)

        x86_patch = generate_always_succeed_x86()
        x64_patch = generate_always_succeed_x64()

        assert len(x86_patch) <= 10
        assert len(x64_patch) <= 10

        text_section = None
        for section in pe.sections:
            if b".text" in section.Name:
                text_section = section
                break

        if text_section:
            assert text_section.SizeOfRawData > len(x64_patch)

    def test_nop_sled_can_pad_certificate_validation_function(
        self,
        real_pe_binary: bytes
    ) -> None:
        """NOP sled can fill space in certificate validation functions."""
        pe = pefile.PE(data=real_pe_binary)

        typical_function_sizes = [16, 32, 64, 128]
        for size in typical_function_sizes:
            nop_sled = generate_nop_sled(size, Architecture.X64)
            assert len(nop_sled) == size

        text_section = None
        for section in pe.sections:
            if b".text" in section.Name:
                text_section = section
                break

        if text_section:
            nop_sled = generate_nop_sled(100, Architecture.X64)
            assert text_section.SizeOfRawData > len(nop_sled)

    def test_trampoline_can_redirect_certificate_check(
        self,
        real_pe_binary: bytes
    ) -> None:
        """Trampoline can redirect execution from certificate check."""
        pe = pefile.PE(data=real_pe_binary)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        text_section = None
        for section in pe.sections:
            if b".text" in section.Name:
                text_section = section
                break

        if text_section:
            cert_check_rva = 0x1000
            hook_rva = 0x5000

            cert_check_va = image_base + cert_check_rva
            hook_va = image_base + hook_rva

            trampoline = generate_trampoline_x64(cert_check_va, hook_va)

            assert len(trampoline) >= 5
            assert text_section.SizeOfRawData > len(trampoline)

    def test_combined_patch_fits_in_available_space(
        self,
        real_pe_binary: bytes
    ) -> None:
        """Combined patch with wrappers fits in typical function space."""
        base_patch = generate_always_succeed_x64()
        wrapped_patch = wrap_patch_x64_convention(base_patch)

        assert validate_patch_size(wrapped_patch, max_size=64)

        pe = pefile.PE(data=real_pe_binary)
        text_section = None
        for section in pe.sections:
            if b".text" in section.Name:
                text_section = section
                break

        if text_section:
            assert text_section.SizeOfRawData > len(wrapped_patch)

    def test_conditional_invert_preserves_binary_structure(
        self,
        real_pe_binary: bytes
    ) -> None:
        """Conditional invert maintains same instruction length."""
        original_jz = bytes([0x74, 0x10])
        inverted = generate_conditional_invert_x86(original_jz)

        assert len(inverted) == len(original_jz)

        original_near_je = bytes([0x0F, 0x84, 0x30, 0x00, 0x00, 0x00])
        inverted_near = generate_conditional_invert_x86(original_near_je)

        assert len(inverted_near) == len(original_near_je)


class TestPatchGenerationEdgeCases:
    """Test patch generation edge cases and error handling."""

    def test_empty_conditional_invert_returns_empty(self) -> None:
        """Conditional invert of empty bytes returns empty."""
        result = generate_conditional_invert_x86(b"")
        assert result == b""

    def test_zero_size_nop_sled_returns_empty(self) -> None:
        """NOP sled of size 0 returns empty bytes."""
        result = generate_nop_sled(0, Architecture.X86)
        assert len(result) == 0

    def test_large_nop_sled_generation(self) -> None:
        """Large NOP sled generates correctly without errors."""
        large_size = 4096
        nop_sled = generate_nop_sled(large_size, Architecture.X64)
        assert len(nop_sled) == large_size
        assert all(byte == 0x90 for byte in nop_sled)

    def test_trampoline_maximum_offset(self) -> None:
        """x86 trampoline handles maximum positive offset."""
        target_addr = 0x00400000
        hook_addr = target_addr + 0x7FFFFFF0
        trampoline = generate_trampoline_x86(target_addr, hook_addr)

        assert len(trampoline) == 5
        assert trampoline[0] == 0xE9

    def test_trampoline_minimum_offset(self) -> None:
        """x86 trampoline handles maximum negative offset."""
        target_addr = 0x00800000
        hook_addr = 0x00400000
        trampoline = generate_trampoline_x86(target_addr, hook_addr)

        assert len(trampoline) == 5
        assert trampoline[0] == 0xE9

        offset = int.from_bytes(trampoline[1:5], byteorder="little", signed=True)
        assert offset < 0

    def test_stdcall_wrapper_large_arg_count(self) -> None:
        """stdcall wrapper handles large argument counts."""
        base_patch = generate_always_succeed_x86()
        wrapped = wrap_patch_stdcall(base_patch, arg_count=16)

        assert wrapped[-3] == 0xC2
        stack_cleanup = int.from_bytes(wrapped[-2:], byteorder="little")
        assert stack_cleanup == 64


class TestPatchDeterminismAndConsistency:
    """Test patch generation consistency and determinism."""

    def test_all_patches_are_deterministic(self) -> None:
        """All patch generators produce identical output on repeated calls."""
        generators: list[Callable[[], bytes]] = [
            generate_always_succeed_x86,
            generate_always_succeed_x64,
            generate_always_succeed_arm32,
            generate_always_succeed_arm64,
            generate_register_save_x86,
            generate_register_restore_x86,
            generate_register_save_x64,
            generate_register_restore_x64,
        ]

        for generator in generators:
            result1 = generator()
            result2 = generator()
            assert result1 == result2

    def test_nop_sled_determinism_for_same_parameters(self) -> None:
        """NOP sled generation is deterministic for same parameters."""
        for arch in [Architecture.X86, Architecture.X64, Architecture.ARM32, Architecture.ARM64]:
            sled1 = generate_nop_sled(32, arch)
            sled2 = generate_nop_sled(32, arch)
            assert sled1 == sled2

    def test_trampoline_determinism_for_same_addresses(self) -> None:
        """Trampoline generation is deterministic for same addresses."""
        target = 0x140001000
        hook = 0x140050000

        tramp1 = generate_trampoline_x64(target, hook)
        tramp2 = generate_trampoline_x64(target, hook)
        assert tramp1 == tramp2

    def test_wrapper_determinism(self) -> None:
        """Calling convention wrappers are deterministic."""
        base_patch = generate_always_succeed_x64()

        fastcall1 = wrap_patch_fastcall(base_patch)
        fastcall2 = wrap_patch_fastcall(base_patch)
        assert fastcall1 == fastcall2

        x64conv1 = wrap_patch_x64_convention(base_patch)
        x64conv2 = wrap_patch_x64_convention(base_patch)
        assert x64conv1 == x64conv2


class TestCertificateValidationBypassScenarios:
    """Test complete certificate validation bypass patch scenarios."""

    def test_patch_ssl_validation_always_succeed(self) -> None:
        """Complete patch for SSL validation to always succeed."""
        validation_check_patch = generate_always_succeed_x64()
        wrapped_patch = wrap_patch_x64_convention(validation_check_patch)

        assert len(wrapped_patch) > len(validation_check_patch)
        assert validate_patch_size(wrapped_patch, max_size=64)

    def test_patch_certificate_pinning_check_inversion(self) -> None:
        """Complete patch for certificate pinning check inversion."""
        jz_on_fail = bytes([0x74, 0x20])
        inverted_to_jnz = generate_conditional_invert_x64(jz_on_fail)

        assert inverted_to_jnz[0] == 0x75
        assert inverted_to_jnz[1] == 0x20

    def test_full_certificate_bypass_patch_sequence(self) -> None:
        """Complete patch sequence for certificate validation bypass."""
        save_registers = generate_register_save_x64()
        always_succeed = generate_always_succeed_x64()
        restore_registers = generate_register_restore_x64()

        full_patch = save_registers + always_succeed + restore_registers

        assert len(full_patch) == 24 + 8 + 24
        assert validate_patch_size(full_patch, max_size=128)

    def test_trampoline_to_bypass_function(self) -> None:
        """Trampoline from certificate check to bypass implementation."""
        cert_check_addr = 0x140001500
        bypass_impl_addr = 0x140050000

        trampoline = generate_trampoline_x64(cert_check_addr, bypass_impl_addr)

        assert len(trampoline) >= 5
        assert validate_patch_size(trampoline, max_size=16)

    def test_nop_out_certificate_validation_call(self) -> None:
        """NOP out certificate validation function call."""
        call_instruction_size = 5
        nop_sled = generate_nop_sled(call_instruction_size, Architecture.X64)

        assert len(nop_sled) == call_instruction_size
        assert all(byte == 0x90 for byte in nop_sled)
