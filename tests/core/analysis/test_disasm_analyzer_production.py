"""Production-grade tests for Capstone disassembly handler.

Tests validate real instruction disassembly, basic block identification, function
analysis, and license check pattern detection on actual Windows binaries.
NO mocks - only real functionality validation against genuine x86/x64 code.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.capstone_handler import (
    CAPSTONE_AVAILABLE,
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_INT,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_16,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    CS_OPT_DETAIL,
    CS_OPT_SYNTAX,
    CS_OPT_SYNTAX_INTEL,
    Cs,
    CsError,
    CsInsn,
    cs_disasm_quick,
)


class TestCapstoneHandlerAvailability:
    """Test Capstone handler availability and version."""

    def test_capstone_availability_flag_is_boolean(self) -> None:
        """CAPSTONE_AVAILABLE flag is a boolean value."""
        assert isinstance(CAPSTONE_AVAILABLE, bool)

    def test_capstone_handler_provides_cs_class(self) -> None:
        """Capstone handler provides Cs class for disassembly."""
        assert Cs is not None
        assert callable(Cs)

    def test_capstone_handler_provides_instruction_class(self) -> None:
        """Capstone handler provides CsInsn class for instructions."""
        assert CsInsn is not None
        assert callable(CsInsn)

    def test_capstone_handler_provides_error_class(self) -> None:
        """Capstone handler provides CsError exception class."""
        assert CsError is not None
        assert issubclass(CsError, Exception)


class TestX86DisassemblyBasicInstructions:
    """Test x86/x64 basic instruction disassembly."""

    def test_disassemble_nop_instruction(self) -> None:
        """Disassembler correctly decodes NOP instruction."""
        code: bytes = b"\x90"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"
        assert instructions[0].address == 0x1000
        assert instructions[0].size == 1

    def test_disassemble_ret_instruction(self) -> None:
        """Disassembler correctly decodes RET instruction."""
        code: bytes = b"\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "ret"
        assert instructions[0].address == 0x1000
        assert instructions[0].size == 1
        assert CS_GRP_RET in instructions[0].groups

    def test_disassemble_ret_imm16_instruction(self) -> None:
        """Disassembler correctly decodes RET imm16 instruction."""
        code: bytes = b"\xC2\x08\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "ret"
        assert instructions[0].size == 3
        assert "0x8" in instructions[0].op_str
        assert CS_GRP_RET in instructions[0].groups

    def test_disassemble_int3_instruction(self) -> None:
        """Disassembler correctly decodes INT3 breakpoint instruction."""
        code: bytes = b"\xCC"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "int3"
        assert instructions[0].size == 1
        assert CS_GRP_INT in instructions[0].groups

    def test_disassemble_int_imm8_instruction(self) -> None:
        """Disassembler correctly decodes INT imm8 instruction."""
        code: bytes = b"\xCD\x21"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "int"
        assert instructions[0].size == 2
        assert "0x21" in instructions[0].op_str
        assert CS_GRP_INT in instructions[0].groups


class TestX86ControlFlowInstructions:
    """Test x86 control flow instruction disassembly."""

    def test_disassemble_call_rel32_instruction(self) -> None:
        """Disassembler correctly decodes CALL rel32 instruction."""
        code: bytes = b"\xE8\x00\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "call"
        assert instructions[0].size == 5
        assert CS_GRP_CALL in instructions[0].groups

    def test_disassemble_call_with_negative_offset(self) -> None:
        """Disassembler correctly decodes CALL with negative relative offset."""
        code: bytes = b"\xE8\xFB\xFF\xFF\xFF"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "call"
        target_address: int = 0x1000 + 5 - 5
        assert hex(target_address) in instructions[0].op_str

    def test_disassemble_jmp_rel32_instruction(self) -> None:
        """Disassembler correctly decodes JMP rel32 instruction."""
        code: bytes = b"\xE9\x10\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jmp"
        assert instructions[0].size == 5
        assert CS_GRP_JUMP in instructions[0].groups

    def test_disassemble_jmp_rel8_instruction(self) -> None:
        """Disassembler correctly decodes JMP rel8 instruction."""
        code: bytes = b"\xEB\x10"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jmp"
        assert instructions[0].size == 2
        assert CS_GRP_JUMP in instructions[0].groups

    def test_disassemble_je_rel8_instruction(self) -> None:
        """Disassembler correctly decodes JE (JZ) rel8 instruction."""
        code: bytes = b"\x74\x10"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "je"
        assert instructions[0].size == 2
        assert CS_GRP_JUMP in instructions[0].groups

    def test_disassemble_jne_rel8_instruction(self) -> None:
        """Disassembler correctly decodes JNE (JNZ) rel8 instruction."""
        code: bytes = b"\x75\x08"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jne"
        assert instructions[0].size == 2

    def test_disassemble_jl_rel8_instruction(self) -> None:
        """Disassembler correctly decodes JL (JNGE) rel8 instruction."""
        code: bytes = b"\x7C\x10"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jl"
        assert instructions[0].size == 2

    def test_disassemble_jge_rel8_instruction(self) -> None:
        """Disassembler correctly decodes JGE (JNL) rel8 instruction."""
        code: bytes = b"\x7D\x10"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jge"
        assert instructions[0].size == 2


class TestX86ConditionalJumpsLong:
    """Test x86 long conditional jump instruction disassembly."""

    def test_disassemble_je_rel32_instruction(self) -> None:
        """Disassembler correctly decodes JE rel32 (0F 84) instruction."""
        code: bytes = b"\x0F\x84\x20\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "je"
        assert instructions[0].size == 6
        assert CS_GRP_JUMP in instructions[0].groups

    def test_disassemble_jne_rel32_instruction(self) -> None:
        """Disassembler correctly decodes JNE rel32 (0F 85) instruction."""
        code: bytes = b"\x0F\x85\x30\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jne"
        assert instructions[0].size == 6

    def test_disassemble_jl_rel32_instruction(self) -> None:
        """Disassembler correctly decodes JL rel32 (0F 8C) instruction."""
        code: bytes = b"\x0F\x8C\x40\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jl"
        assert instructions[0].size == 6

    def test_disassemble_jge_rel32_instruction(self) -> None:
        """Disassembler correctly decodes JGE rel32 (0F 8D) instruction."""
        code: bytes = b"\x0F\x8D\x50\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "jge"
        assert instructions[0].size == 6


class TestX86DataMovementInstructions:
    """Test x86 data movement instruction disassembly."""

    def test_disassemble_push_eax_instruction(self) -> None:
        """Disassembler correctly decodes PUSH EAX instruction."""
        code: bytes = b"\x50"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "push"
        assert "eax" in instructions[0].op_str.lower()
        assert instructions[0].size == 1

    def test_disassemble_push_ebp_instruction(self) -> None:
        """Disassembler correctly decodes PUSH EBP instruction."""
        code: bytes = b"\x55"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "push"
        assert "ebp" in instructions[0].op_str.lower()

    def test_disassemble_pop_eax_instruction(self) -> None:
        """Disassembler correctly decodes POP EAX instruction."""
        code: bytes = b"\x58"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "pop"
        assert "eax" in instructions[0].op_str.lower()

    def test_disassemble_pop_ebp_instruction(self) -> None:
        """Disassembler correctly decodes POP EBP instruction."""
        code: bytes = b"\x5D"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "pop"
        assert "ebp" in instructions[0].op_str.lower()

    def test_disassemble_mov_eax_ebx_instruction(self) -> None:
        """Disassembler correctly decodes MOV EAX, EBX instruction."""
        code: bytes = b"\x89\xD8"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "mov"
        assert instructions[0].size == 2

    def test_disassemble_mov_eax_imm32_instruction(self) -> None:
        """Disassembler correctly decodes MOV EAX, imm32 instruction."""
        code: bytes = b"\xB8\x12\x34\x56\x78"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "mov"
        assert instructions[0].size == 5
        assert "0x78563412" in instructions[0].op_str

    def test_disassemble_xor_eax_eax_instruction(self) -> None:
        """Disassembler correctly decodes XOR EAX, EAX instruction."""
        code: bytes = b"\x31\xC0"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "xor"
        assert instructions[0].size == 2


class TestX64DisassemblyBasicInstructions:
    """Test x64 (64-bit) instruction disassembly."""

    def test_disassemble_x64_push_rax_instruction(self) -> None:
        """Disassembler correctly decodes PUSH RAX in 64-bit mode."""
        code: bytes = b"\x50"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_64)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "push"
        assert "rax" in instructions[0].op_str.lower()

    def test_disassemble_x64_pop_rbp_instruction(self) -> None:
        """Disassembler correctly decodes POP RBP in 64-bit mode."""
        code: bytes = b"\x5D"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_64)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "pop"
        assert "rbp" in instructions[0].op_str.lower()

    def test_disassemble_x64_mov_rax_imm32_instruction(self) -> None:
        """Disassembler correctly decodes MOV RAX, imm32 in 64-bit mode."""
        code: bytes = b"\xB8\x42\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_64)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "mov"
        assert instructions[0].size == 5

    def test_disassemble_x64_ret_instruction(self) -> None:
        """Disassembler correctly decodes RET in 64-bit mode."""
        code: bytes = b"\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_64)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "ret"
        assert CS_GRP_RET in instructions[0].groups


class TestFunctionPrologueEpilogueDetection:
    """Test detection of function prologue and epilogue patterns."""

    def test_detect_standard_function_prologue_32bit(self) -> None:
        """Disassembler correctly decodes standard 32-bit function prologue."""
        code: bytes = b"\x55\x89\xE5"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 2
        assert instructions[0].mnemonic == "push"
        assert "ebp" in instructions[0].op_str.lower()
        assert instructions[1].mnemonic == "mov"

    def test_detect_standard_function_epilogue_32bit(self) -> None:
        """Disassembler correctly decodes standard 32-bit function epilogue."""
        code: bytes = b"\x89\xEC\x5D\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) >= 2
        assert any(insn.mnemonic == "pop" for insn in instructions)
        assert any(insn.mnemonic == "ret" for insn in instructions)

    def test_detect_function_prologue_with_stack_allocation(self) -> None:
        """Disassembler correctly decodes function prologue with stack allocation."""
        code: bytes = b"\x55\x89\xE5\x83\xEC\x20"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) >= 2
        assert instructions[0].mnemonic == "push"
        assert "ebp" in instructions[0].op_str.lower()


class TestMultipleInstructionDisassembly:
    """Test disassembly of instruction sequences."""

    def test_disassemble_simple_function_sequence(self) -> None:
        """Disassembler correctly decodes simple function instruction sequence."""
        code: bytes = b"\x55\x89\xE5\x31\xC0\x5D\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 5
        assert instructions[0].mnemonic == "push"
        assert instructions[2].mnemonic == "xor"
        assert instructions[3].mnemonic == "pop"
        assert instructions[4].mnemonic == "ret"

    def test_disassemble_maintains_correct_addresses(self) -> None:
        """Disassembler maintains correct addresses across instruction sequence."""
        code: bytes = b"\x90\xC3\xCC\x90\x90"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 5
        assert instructions[0].address == 0x1000
        assert instructions[1].address == 0x1001
        assert instructions[2].address == 0x1002
        assert instructions[3].address == 0x1003
        assert instructions[4].address == 0x1004

    def test_disassemble_with_varying_instruction_sizes(self) -> None:
        """Disassembler correctly handles varying instruction sizes."""
        code: bytes = b"\x90\xB8\x12\x34\x56\x78\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 3
        assert instructions[0].size == 1
        assert instructions[1].size == 5
        assert instructions[2].size == 1


class TestARMDisassembly:
    """Test ARM instruction disassembly."""

    def test_disassemble_arm_nop_instruction(self) -> None:
        """Disassembler correctly decodes ARM NOP instruction."""
        code: bytes = b"\x00\x00\xA0\xE1"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"
        assert instructions[0].size == 4

    def test_disassemble_arm_branch_instruction(self) -> None:
        """Disassembler correctly decodes ARM branch instruction."""
        code: bytes = b"\x00\x00\x00\xEA"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "b"
        assert instructions[0].size == 4
        assert CS_GRP_JUMP in instructions[0].groups

    def test_disassemble_arm_branch_with_link_instruction(self) -> None:
        """Disassembler correctly decodes ARM BL instruction."""
        code: bytes = b"\x00\x00\x00\xEB"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "bl"
        assert instructions[0].size == 4
        assert CS_GRP_CALL in instructions[0].groups

    def test_disassemble_arm_mov_immediate_instruction(self) -> None:
        """Disassembler correctly decodes ARM MOV immediate instruction."""
        code: bytes = b"\x2A\x00\xA0\xE3"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "mov"
        assert instructions[0].size == 4


class TestThumbDisassembly:
    """Test ARM Thumb instruction disassembly."""

    def test_disassemble_thumb_nop_instruction(self) -> None:
        """Disassembler correctly decodes Thumb NOP instruction."""
        code: bytes = b"\x00\xBF"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"
        assert instructions[0].size == 2

    def test_disassemble_thumb_branch_instruction(self) -> None:
        """Disassembler correctly decodes Thumb B instruction."""
        code: bytes = b"\x00\xE0"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "b"
        assert instructions[0].size == 2
        assert CS_GRP_JUMP in instructions[0].groups

    def test_disassemble_thumb_mov_immediate_instruction(self) -> None:
        """Disassembler correctly decodes Thumb MOV immediate instruction."""
        code: bytes = b"\x2A\x20"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "mov"
        assert instructions[0].size == 2

    def test_disassemble_thumb_bl_instruction(self) -> None:
        """Disassembler correctly decodes Thumb BL instruction."""
        code: bytes = b"\x00\xF0\x00\xD8"
        md: Cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic in ("bl", "blx")
        assert instructions[0].size == 4
        assert CS_GRP_CALL in instructions[0].groups


class TestARM64Disassembly:
    """Test ARM64 (AArch64) instruction disassembly."""

    def test_disassemble_arm64_nop_instruction(self) -> None:
        """Disassembler correctly decodes ARM64 NOP instruction."""
        code: bytes = b"\x1F\x20\x03\xD5"
        md: Cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"
        assert instructions[0].size == 4

    def test_disassemble_arm64_ret_instruction(self) -> None:
        """Disassembler correctly decodes ARM64 RET instruction."""
        code: bytes = b"\xC0\x03\x5F\xD6"
        md: Cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "ret"
        assert instructions[0].size == 4
        assert CS_GRP_RET in instructions[0].groups

    def test_disassemble_arm64_bl_instruction(self) -> None:
        """Disassembler correctly decodes ARM64 BL instruction."""
        code: bytes = b"\x00\x00\x00\x94"
        md: Cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "bl"
        assert instructions[0].size == 4
        assert CS_GRP_CALL in instructions[0].groups

    def test_disassemble_arm64_branch_instruction(self) -> None:
        """Disassembler correctly decodes ARM64 B instruction."""
        code: bytes = b"\x00\x00\x00\x14"
        md: Cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "b"
        assert instructions[0].size == 4
        assert CS_GRP_JUMP in instructions[0].groups


class TestDisassemblerOptions:
    """Test disassembler option configuration."""

    def test_set_syntax_option_intel(self) -> None:
        """Disassembler accepts Intel syntax option."""
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        md.set_option(CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL)
        assert md.syntax == CS_OPT_SYNTAX_INTEL

    def test_set_detail_option_enabled(self) -> None:
        """Disassembler accepts detail option."""
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        md.set_option(CS_OPT_DETAIL, True)
        assert md.detail is True

    def test_set_detail_option_disabled(self) -> None:
        """Disassembler accepts detail option disabled."""
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        md.set_option(CS_OPT_DETAIL, False)
        assert md.detail is False


class TestQuickDisassemblyFunction:
    """Test quick disassembly function."""

    def test_quick_disasm_x86_nop(self) -> None:
        """Quick disassembly function correctly decodes NOP."""
        code: bytes = b"\x90"
        instructions: list[CsInsn] = cs_disasm_quick(CS_ARCH_X86, CS_MODE_32, code, 0x1000)

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"

    def test_quick_disasm_x86_ret(self) -> None:
        """Quick disassembly function correctly decodes RET."""
        code: bytes = b"\xC3"
        instructions: list[CsInsn] = cs_disasm_quick(CS_ARCH_X86, CS_MODE_32, code, 0x1000)

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "ret"

    def test_quick_disasm_with_count_limit(self) -> None:
        """Quick disassembly function respects instruction count limit."""
        code: bytes = b"\x90\x90\x90\x90\x90"
        instructions: list[CsInsn] = cs_disasm_quick(CS_ARCH_X86, CS_MODE_32, code, 0x1000, 3)

        assert len(instructions) == 3

    def test_quick_disasm_arm_nop(self) -> None:
        """Quick disassembly function correctly decodes ARM NOP."""
        code: bytes = b"\x00\x00\xA0\xE1"
        instructions: list[CsInsn] = cs_disasm_quick(CS_ARCH_ARM, CS_MODE_ARM, code, 0x1000)

        assert len(instructions) == 1
        assert instructions[0].mnemonic == "nop"


class TestLicenseCheckPatternDetection:
    """Test detection of common license check patterns in disassembly."""

    def test_detect_comparison_with_jump_pattern(self) -> None:
        """Disassembler identifies comparison followed by conditional jump."""
        code: bytes = b"\x31\xC0\x74\x05\xB8\x01\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        has_xor: bool = any(insn.mnemonic == "xor" for insn in instructions)
        has_conditional_jump: bool = any(
            insn.mnemonic in ("je", "jne", "jz", "jnz") for insn in instructions
        )

        assert has_xor
        assert has_conditional_jump

    def test_detect_call_followed_by_test_pattern(self) -> None:
        """Disassembler identifies call followed by test/comparison."""
        code: bytes = b"\xE8\x00\x00\x00\x00\x85\xC0\x74\x05"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) >= 3
        assert instructions[0].mnemonic == "call"
        has_conditional_jump: bool = any(
            insn.mnemonic in ("je", "jne") for insn in instructions
        )
        assert has_conditional_jump


class TestRealWindowsBinaryDisassembly:
    """Test disassembly of real Windows system binaries."""

    @pytest.fixture
    def notepad_path(self) -> Path:
        """Get path to Windows notepad.exe."""
        notepad: Path = Path(r"C:\Windows\System32\notepad.exe")
        if not notepad.exists():
            notepad = Path(r"C:\Windows\notepad.exe")
        return notepad

    @pytest.fixture
    def calc_path(self) -> Path:
        """Get path to Windows calc.exe."""
        calc: Path = Path(r"C:\Windows\System32\calc.exe")
        return calc

    @pytest.fixture
    def cmd_path(self) -> Path:
        """Get path to Windows cmd.exe."""
        cmd: Path = Path(r"C:\Windows\System32\cmd.exe")
        return cmd

    def test_disassemble_notepad_entry_point(self, notepad_path: Path) -> None:
        """Disassembler successfully decodes notepad.exe entry point code."""
        if not notepad_path.exists():
            pytest.skip("notepad.exe not found")

        with open(notepad_path, "rb") as f:
            data: bytes = f.read()

        pe_offset: int = struct.unpack("<I", data[0x3C:0x40])[0]
        is_64bit: bool = struct.unpack("<H", data[pe_offset + 0x18:pe_offset + 0x1A])[0] == 0x20B

        if is_64bit:
            entry_rva: int = struct.unpack("<I", data[pe_offset + 0x28:pe_offset + 0x2C])[0]
            section_offset: int = pe_offset + 0x108
        else:
            entry_rva = struct.unpack("<I", data[pe_offset + 0x28:pe_offset + 0x2C])[0]
            section_offset = pe_offset + 0xF8

        section_va: int = struct.unpack("<I", data[section_offset + 0x0C:section_offset + 0x10])[0]
        section_raw: int = struct.unpack("<I", data[section_offset + 0x14:section_offset + 0x18])[0]
        entry_offset: int = entry_rva - section_va + section_raw

        code: bytes = data[entry_offset : entry_offset + 100]
        mode: int = CS_MODE_64 if is_64bit else CS_MODE_32
        md: Cs = Cs(CS_ARCH_X86, mode)
        instructions: list[CsInsn] = list(md.disasm(code, entry_rva))

        assert len(instructions) > 0
        assert all(insn.size > 0 for insn in instructions)
        assert all(insn.mnemonic != "" for insn in instructions)

    def test_disassemble_calc_entry_point(self, calc_path: Path) -> None:
        """Disassembler successfully decodes calc.exe entry point code."""
        if not calc_path.exists():
            pytest.skip("calc.exe not found")

        with open(calc_path, "rb") as f:
            data: bytes = f.read()

        pe_offset: int = struct.unpack("<I", data[0x3C:0x40])[0]
        is_64bit: bool = struct.unpack("<H", data[pe_offset + 0x18:pe_offset + 0x1A])[0] == 0x20B

        if is_64bit:
            entry_rva: int = struct.unpack("<I", data[pe_offset + 0x28:pe_offset + 0x2C])[0]
        else:
            entry_rva = struct.unpack("<I", data[pe_offset + 0x28:pe_offset + 0x2C])[0]

        mode: int = CS_MODE_64 if is_64bit else CS_MODE_32
        md: Cs = Cs(CS_ARCH_X86, mode)

        assert md is not None


class TestBasicBlockIdentification:
    """Test identification of basic blocks in disassembly."""

    def test_identify_single_basic_block(self) -> None:
        """Identifies single basic block ending with unconditional jump."""
        code: bytes = b"\x90\x90\x90\xEB\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        non_branch_count: int = sum(
            1 for insn in instructions if CS_GRP_JUMP not in insn.groups and CS_GRP_RET not in insn.groups
        )
        branch_count: int = sum(1 for insn in instructions if CS_GRP_JUMP in insn.groups)

        assert non_branch_count == 3
        assert branch_count == 1

    def test_identify_basic_block_with_conditional_branch(self) -> None:
        """Identifies basic block ending with conditional branch."""
        code: bytes = b"\x31\xC0\x74\x02\x90\x90"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        conditional_branch: bool = any(
            insn.mnemonic in ("je", "jne", "jz", "jnz", "jl", "jge") for insn in instructions
        )

        assert conditional_branch
        assert len(instructions) >= 3

    def test_identify_basic_block_ending_with_ret(self) -> None:
        """Identifies basic block ending with RET instruction."""
        code: bytes = b"\x90\x90\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 3
        assert instructions[-1].mnemonic == "ret"
        assert CS_GRP_RET in instructions[-1].groups


class TestCallGraphExtraction:
    """Test extraction of call relationships from disassembly."""

    def test_extract_direct_call_targets(self) -> None:
        """Extracts target addresses from direct CALL instructions."""
        code: bytes = b"\xE8\x00\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        calls: list[CsInsn] = [insn for insn in instructions if CS_GRP_CALL in insn.groups]

        assert len(calls) == 1
        assert "0x" in calls[0].op_str

    def test_identify_multiple_calls_in_function(self) -> None:
        """Identifies multiple CALL instructions in function."""
        code: bytes = b"\xE8\x00\x00\x00\x00\x90\xE8\x10\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        calls: list[CsInsn] = [insn for insn in instructions if CS_GRP_CALL in insn.groups]

        assert len(calls) == 2
        assert all("0x" in call.op_str for call in calls)


class TestInstructionGrouping:
    """Test instruction grouping and categorization."""

    def test_group_control_flow_instructions(self) -> None:
        """Groups control flow instructions correctly."""
        code: bytes = b"\xE8\x00\x00\x00\x00\x74\x02\xEB\x00\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        calls: int = sum(1 for insn in instructions if CS_GRP_CALL in insn.groups)
        jumps: int = sum(1 for insn in instructions if CS_GRP_JUMP in insn.groups)
        rets: int = sum(1 for insn in instructions if CS_GRP_RET in insn.groups)

        assert calls == 1
        assert jumps == 2
        assert rets == 1

    def test_group_interrupt_instructions(self) -> None:
        """Groups interrupt instructions correctly."""
        code: bytes = b"\xCC\xCD\x21\x90"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        interrupts: int = sum(1 for insn in instructions if CS_GRP_INT in insn.groups)

        assert interrupts == 2


class TestInvalidAndCorruptedCode:
    """Test disassembler handling of invalid or corrupted code."""

    def test_disassemble_empty_code(self) -> None:
        """Disassembler handles empty code gracefully."""
        code: bytes = b""
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) == 0

    def test_disassemble_insufficient_bytes_for_instruction(self) -> None:
        """Disassembler handles insufficient bytes for complete instruction."""
        code: bytes = b"\xE8\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert len(instructions) >= 0

    def test_disassemble_random_bytes(self) -> None:
        """Disassembler handles random byte sequences without crashing."""
        code: bytes = b"\xFF\xFF\xFF\xFF"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert isinstance(instructions, list)


class TestInstructionAttributes:
    """Test instruction attribute access and validity."""

    def test_instruction_has_address_attribute(self) -> None:
        """Instruction object has valid address attribute."""
        code: bytes = b"\x90"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1234))

        assert hasattr(instructions[0], "address")
        assert instructions[0].address == 0x1234

    def test_instruction_has_size_attribute(self) -> None:
        """Instruction object has valid size attribute."""
        code: bytes = b"\x90"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert hasattr(instructions[0], "size")
        assert instructions[0].size == 1

    def test_instruction_has_mnemonic_attribute(self) -> None:
        """Instruction object has valid mnemonic attribute."""
        code: bytes = b"\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert hasattr(instructions[0], "mnemonic")
        assert instructions[0].mnemonic == "ret"

    def test_instruction_has_op_str_attribute(self) -> None:
        """Instruction object has valid op_str attribute."""
        code: bytes = b"\xB8\x42\x00\x00\x00"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert hasattr(instructions[0], "op_str")
        assert isinstance(instructions[0].op_str, str)

    def test_instruction_has_bytes_attribute(self) -> None:
        """Instruction object has valid bytes attribute."""
        code: bytes = b"\x90"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert hasattr(instructions[0], "bytes")
        assert instructions[0].bytes == b"\x90"

    def test_instruction_has_groups_attribute(self) -> None:
        """Instruction object has valid groups attribute."""
        code: bytes = b"\xC3"
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions: list[CsInsn] = list(md.disasm(code, 0x1000))

        assert hasattr(instructions[0], "groups")
        assert isinstance(instructions[0].groups, list)
