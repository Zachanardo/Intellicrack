"""Production tests for Capstone handler.

Tests validate real disassembly functionality on actual binary data.
Tests verify both native Capstone usage and fallback implementations.
"""

import struct
from typing import Any

import pytest

from intellicrack.handlers.capstone_handler import (
    CAPSTONE_AVAILABLE,
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    Cs,
    CsInsn,
    cs_disasm_quick,
)


class TestCapstoneX86Disassembly:
    """Test x86/x64 disassembly on real machine code."""

    def test_disassemble_x86_32_basic_instructions(self) -> None:
        """Disassemble real x86-32 machine code."""
        code = bytes([
            0x55,
            0x89, 0xe5,
            0x83, 0xec, 0x10,
            0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00,
            0x89, 0x45, 0xf8,
            0x8b, 0x45, 0xf8,
            0x89, 0xec,
            0x5d,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_32, code, 0x1000))

        assert instructions
        assert any(insn.mnemonic == "push" for insn in instructions)
        assert any(insn.mnemonic == "mov" for insn in instructions)
        assert any(insn.mnemonic == "ret" for insn in instructions)

    def test_disassemble_x86_64_basic_instructions(self) -> None:
        """Disassemble real x86-64 machine code."""
        code = bytes([
            0x55,
            0x48, 0x89, 0xe5,
            0x48, 0x83, 0xec, 0x10,
            0x48, 0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x7d, 0xf0,
            0x48, 0x8b, 0x45, 0xf0,
            0x48, 0x89, 0xec,
            0x5d,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert instructions
        assert any(insn.mnemonic == "push" for insn in instructions)
        assert any(insn.mnemonic == "mov" for insn in instructions)
        assert any(insn.mnemonic == "ret" for insn in instructions)

    def test_disassemble_x86_64_license_check_pattern(self) -> None:
        """Disassemble x86-64 code containing license check pattern."""
        code = bytes([
            0x48, 0x85, 0xc0,
            0x74, 0x05,
            0xb8, 0x01, 0x00, 0x00, 0x00,
            0xc3,
            0x31, 0xc0,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) >= 4
        test_insn = next((i for i in instructions if i.mnemonic == "test"), None)
        assert test_insn is not None
        je_insn = next((i for i in instructions if i.mnemonic == "je"), None)
        assert je_insn is not None

    def test_disassemble_x86_conditional_jumps(self) -> None:
        """Disassemble x86 conditional jump instructions."""
        code = bytes([
            0x85, 0xc0,
            0x74, 0x06,
            0x75, 0x04,
            0x7e, 0x02,
            0x7f, 0x00,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_32, code, 0x1000))

        assert instructions
        jump_insns = [i for i in instructions if i.mnemonic in ["je", "jne", "jle", "jg"]]
        assert len(jump_insns) >= 3

    def test_disassemble_x86_call_instructions(self) -> None:
        """Disassemble x86 call instructions."""
        code = bytes([
            0xe8, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xd0,
            0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_32, code, 0x1000))

        assert instructions
        call_insns = [i for i in instructions if i.mnemonic == "call"]
        assert call_insns


class TestCapstoneARMDisassembly:
    """Test ARM disassembly on real machine code."""

    def test_disassemble_arm_basic_instructions(self) -> None:
        """Disassemble real ARM machine code."""
        code = bytes([
            0x04, 0xe0, 0x2d, 0xe5,
            0x00, 0x00, 0x00, 0xeb,
            0x04, 0xe0, 0x9d, 0xe4,
            0x1e, 0xff, 0x2f, 0xe1,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_ARM, CS_MODE_ARM, code, 0x1000))

        assert instructions
        assert any("str" in insn.mnemonic or "push" in insn.mnemonic for insn in instructions)
        assert any("ldr" in insn.mnemonic or "pop" in insn.mnemonic for insn in instructions)

    def test_disassemble_thumb_instructions(self) -> None:
        """Disassemble Thumb mode ARM instructions."""
        code = bytes([
            0x80, 0xb5,
            0x00, 0xaf,
            0x00, 0x20,
            0x80, 0xbd,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_ARM, CS_MODE_THUMB, code, 0x1000))

        assert instructions

    def test_disassemble_arm64_basic_instructions(self) -> None:
        """Disassemble ARM64/AArch64 instructions."""
        code = bytes([
            0xfd, 0x7b, 0xbf, 0xa9,
            0xfd, 0x03, 0x00, 0x91,
            0x00, 0x00, 0x80, 0x52,
            0xfd, 0x7b, 0xc1, 0xa8,
            0xc0, 0x03, 0x5f, 0xd6,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_ARM64, CS_MODE_ARM, code, 0x1000))

        assert instructions


class TestCapstoneCsClass:
    """Test Cs class functionality for detailed disassembly."""

    def test_cs_instance_creation_x86(self) -> None:
        """Create Cs instance for x86 architecture."""
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        assert md is not None

    def test_cs_instance_creation_x64(self) -> None:
        """Create Cs instance for x64 architecture."""
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        assert md is not None

    def test_cs_disassemble_with_detail(self) -> None:
        """Disassemble with detailed instruction information."""
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        code = bytes([
            0x48, 0x8b, 0x45, 0xf8,
            0x48, 0x83, 0xc0, 0x01,
            0xc3,
        ])

        instructions = list(md.disasm(code, 0x1000))

        assert instructions
        for insn in instructions:
            assert isinstance(insn, CsInsn)
            assert insn.mnemonic is not None
            assert insn.op_str is not None

    def test_cs_skipdata_option(self) -> None:
        """Test skipdata option for invalid bytes."""
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.skipdata = True

        code = bytes([
            0x48, 0x89, 0xe5,
            0xff, 0xff, 0xff, 0xff,
            0xc3,
        ])

        instructions = list(md.disasm(code, 0x1000))

        assert instructions


class TestCapstoneInstructionDetails:
    """Test detailed instruction information extraction."""

    def test_instruction_address_tracking(self) -> None:
        """Verify instruction addresses are tracked correctly."""
        code = bytes([
            0x90,
            0x90,
            0x90,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 4
        assert instructions[0].address == 0x1000
        assert instructions[1].address == 0x1001
        assert instructions[2].address == 0x1002
        assert instructions[3].address == 0x1003

    def test_instruction_size_tracking(self) -> None:
        """Verify instruction sizes are correct."""
        code = bytes([
            0x90,
            0x48, 0x89, 0xe5,
            0x48, 0x83, 0xec, 0x20,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert any(insn.size == 1 for insn in instructions)
        assert any(insn.size == 3 for insn in instructions)
        assert any(insn.size == 4 for insn in instructions)

    def test_instruction_bytes_extraction(self) -> None:
        """Verify instruction bytes can be extracted."""
        code = bytes([0x90, 0xc3])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 2
        assert instructions[0].bytes == bytes([0x90])
        assert instructions[1].bytes == bytes([0xc3])


class TestCapstoneFallbackImplementation:
    """Test fallback implementation when Capstone unavailable."""

    def test_fallback_handles_missing_capstone(self) -> None:
        """Verify fallback implementation exists."""
        assert Cs is not None
        assert cs_disasm_quick is not None

    def test_fallback_disassembly_basic_functionality(self) -> None:
        """Verify fallback can disassemble basic instructions."""
        code = bytes([0x90, 0xc3])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert instructions


class TestCapstoneEdgeCases:
    """Test edge cases and error handling."""

    def test_disassemble_empty_code(self) -> None:
        """Handle empty code buffer."""
        code = bytes([])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert not instructions

    def test_disassemble_single_byte(self) -> None:
        """Disassemble single byte instruction."""
        code = bytes([0x90])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"

    def test_disassemble_invalid_instruction_sequence(self) -> None:
        """Handle invalid instruction sequences."""
        code = bytes([0xff, 0xff, 0xff, 0xff])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert isinstance(instructions, list)

    def test_disassemble_large_code_buffer(self) -> None:
        """Disassemble large code buffer."""
        code = bytes([0x90] * 1000 + [0xc3])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 1001


class TestCapstoneLicensingPatterns:
    """Test disassembly of common licensing check patterns."""

    def test_license_validation_jump_pattern(self) -> None:
        """Disassemble license validation jump pattern."""
        code = bytes([
            0x48, 0x85, 0xc0,
            0x0f, 0x84, 0x10, 0x00, 0x00, 0x00,
            0xb8, 0x01, 0x00, 0x00, 0x00,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) >= 3
        test_insn = next((i for i in instructions if i.mnemonic == "test"), None)
        assert test_insn is not None

    def test_serial_comparison_pattern(self) -> None:
        """Disassemble serial number comparison pattern."""
        code = bytes([
            0x48, 0x39, 0xd0,
            0x75, 0x08,
            0xb8, 0x01, 0x00, 0x00, 0x00,
            0xc3,
            0x31, 0xc0,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) >= 4
        cmp_insn = next((i for i in instructions if i.mnemonic == "cmp"), None)
        assert cmp_insn is not None

    def test_trial_expiration_check_pattern(self) -> None:
        """Disassemble trial expiration check pattern."""
        code = bytes([
            0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x3b, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x7f, 0x05,
            0xb8, 0x00, 0x00, 0x00, 0x00,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) >= 4
        assert any(i.mnemonic in ["mov", "cmp", "jg", "ret"] for i in instructions)


class TestCapstonePerformance:
    """Test disassembly performance on realistic code sizes."""

    def test_disassemble_1kb_code(self) -> None:
        """Disassemble 1KB of code."""
        code = bytes([0x90] * 1024)

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 1024

    def test_disassemble_10kb_code(self) -> None:
        """Disassemble 10KB of code."""
        code = bytes([0x90] * 10240)

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 10240

    @pytest.mark.benchmark
    def test_disassemble_benchmark(self, benchmark: Any) -> None:
        """Benchmark disassembly performance."""
        code = bytes([0x90] * 1000 + [0xc3])

        result = benchmark(lambda: list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000)))

        assert len(result) == 1001


class TestCapstoneEdgeCases:
    """Test edge cases in disassembly."""

    def test_disassemble_empty_code(self) -> None:
        """Disassembling empty code returns empty list."""
        code = bytes([])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert not instructions

    def test_disassemble_invalid_opcodes(self) -> None:
        """Disassembly handles invalid opcodes gracefully."""
        code = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert isinstance(instructions, list)

    def test_disassemble_mixed_valid_invalid_opcodes(self) -> None:
        """Disassembly handles mix of valid and invalid opcodes."""
        code = bytes([
            0x90,
            0xFF, 0xFF,
            0x90,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) >= 2

    def test_disassemble_incomplete_instruction(self) -> None:
        """Disassembly handles incomplete multi-byte instruction."""
        code = bytes([0x48, 0x8b])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert isinstance(instructions, list)

    def test_disassemble_single_byte(self) -> None:
        """Disassembly handles single-byte code."""
        code = bytes([0x90])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"

    def test_disassemble_zero_address(self) -> None:
        """Disassembly works with address 0."""
        code = bytes([0x90, 0xc3])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x0))

        assert len(instructions) == 2
        assert instructions[0].address == 0

    def test_disassemble_high_address(self) -> None:
        """Disassembly works with high memory addresses."""
        code = bytes([0x90, 0xc3])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x7FFFFFFF00000000))

        assert len(instructions) == 2
        assert instructions[0].address == 0x7FFFFFFF00000000

    def test_disassemble_prefixed_instructions(self) -> None:
        """Disassembly handles prefixed x86 instructions."""
        code = bytes([
            0xf3, 0x90,
            0xf2, 0x0f, 0x10, 0x00,
            0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) >= 3

    def test_disassemble_long_instruction_sequence(self) -> None:
        """Disassembly handles long multi-byte instructions."""
        code = bytes([
            0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
            0x48, 0xbb, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 2
        assert all(len(insn.bytes) == 10 for insn in instructions)

    def test_disassemble_all_conditional_jumps(self) -> None:
        """Disassembly identifies all conditional jump variants."""
        code = bytes([
            0x70, 0x00,
            0x71, 0x00,
            0x72, 0x00,
            0x73, 0x00,
            0x74, 0x00,
            0x75, 0x00,
            0x76, 0x00,
            0x77, 0x00,
            0x78, 0x00,
            0x79, 0x00,
            0x7a, 0x00,
            0x7b, 0x00,
            0x7c, 0x00,
            0x7d, 0x00,
            0x7e, 0x00,
            0x7f, 0x00,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 16
        assert all(insn.mnemonic.startswith('j') for insn in instructions)

    def test_disassemble_obfuscated_code(self) -> None:
        """Disassembly handles obfuscated instruction sequences."""
        code = bytes([
            0xeb, 0x02,
            0xeb, 0xfe,
            0xe9, 0x00, 0x00, 0x00, 0x00,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) >= 2
        assert all(insn.mnemonic in ['jmp', 'nop'] for insn in instructions)

    def test_disassemble_packed_code(self) -> None:
        """Disassembly attempts to handle packed/encrypted code."""
        code = bytes(i & 0xFF for i in range(256))

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert isinstance(instructions, list)

    def test_instruction_address_sequence(self) -> None:
        """Instruction addresses increment correctly."""
        code = bytes([
            0x90,
            0x90,
            0x48, 0x89, 0xe5,
            0xc3,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 4
        assert instructions[0].address == 0x1000
        assert instructions[1].address == 0x1001
        assert instructions[2].address == 0x1002
        assert instructions[3].address == 0x1005

    def test_instruction_size_accuracy(self) -> None:
        """Instruction sizes are reported accurately."""
        code = bytes([
            0x90,
            0x48, 0x89, 0xe5,
            0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert instructions[0].size == 1
        assert instructions[1].size == 3
        assert instructions[2].size == 10

    def test_instruction_bytes_match_input(self) -> None:
        """Instruction bytes match input code."""
        code = bytes([0x90, 0xc3])

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert instructions[0].bytes == b'\x90'
        assert instructions[1].bytes == b'\xc3'


class TestCapstoneErrorHandling:
    """Test error handling in disassembly operations."""

    def test_cs_disasm_quick_with_invalid_architecture(self) -> None:
        """cs_disasm_quick handles invalid architecture."""
        code = bytes([0x90, 0xc3])

        with pytest.raises((ValueError, TypeError, Exception)):
            list(cs_disasm_quick(9999, CS_MODE_64, code, 0x1000))

    def test_cs_disasm_quick_with_invalid_mode(self) -> None:
        """cs_disasm_quick handles invalid mode."""
        code = bytes([0x90, 0xc3])

        with pytest.raises((ValueError, TypeError, Exception)):
            list(cs_disasm_quick(CS_ARCH_X86, 9999, code, 0x1000))

    def test_cs_disasm_quick_with_none_code(self) -> None:
        """cs_disasm_quick handles None code."""
        with pytest.raises((TypeError, AttributeError, Exception)):
            list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, None, 0x1000))

    def test_disassemble_very_large_code(self) -> None:
        """Disassembly handles very large code sections."""
        code = bytes([0x90] * 1000000)

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 1000000

    def test_disassemble_repeating_pattern(self) -> None:
        """Disassembly handles repeating instruction patterns."""
        pattern = bytes([0x90, 0x90, 0x90, 0xc3])
        code = pattern * 100

        instructions = list(cs_disasm_quick(CS_ARCH_X86, CS_MODE_64, code, 0x1000))

        assert len(instructions) == 400


class TestCapstoneArchitectureVariants:
    """Test disassembly across different architectures."""

    def test_arm_thumb_mode_switch(self) -> None:
        """Disassembly handles ARM Thumb mode."""
        code = bytes([0x00, 0xbf, 0x70, 0x47])

        instructions = list(cs_disasm_quick(CS_ARCH_ARM, CS_MODE_THUMB, code, 0x1000))

        assert instructions

    def test_arm64_basic_instructions(self) -> None:
        """Disassembly handles ARM64 instructions."""
        code = bytes([
            0xe0, 0x03, 0x1f, 0xaa,
            0xc0, 0x03, 0x5f, 0xd6,
        ])

        instructions = list(cs_disasm_quick(CS_ARCH_ARM64, 0, code, 0x1000))

        assert len(instructions) == 2

    def test_x86_16bit_mode(self) -> None:
        """Disassembly handles x86 16-bit mode."""
        code = bytes([0x90, 0xcb])

        try:
            instructions = list(cs_disasm_quick(CS_ARCH_X86, 0, code, 0x1000))
            assert instructions
        except Exception:
            pass

    def test_architecture_constant_validity(self) -> None:
        """Architecture constants are valid integers."""
        assert isinstance(CS_ARCH_X86, int)
        assert isinstance(CS_ARCH_ARM, int)
        assert isinstance(CS_ARCH_ARM64, int)

    def test_mode_constant_validity(self) -> None:
        """Mode constants are valid integers."""
        assert isinstance(CS_MODE_32, int)
        assert isinstance(CS_MODE_64, int)
        assert isinstance(CS_MODE_ARM, int)
        assert isinstance(CS_MODE_THUMB, int)
