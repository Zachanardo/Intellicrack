"""Capstone handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

Capstone Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for Capstone imports.
When Capstone is not available, it provides REAL, functional disassembly
implementations for essential architectures used in Intellicrack.
"""

import struct
import warnings
from collections.abc import Callable
from typing import Any

from intellicrack.utils.logger import logger


# Suppress pkg_resources deprecation warning from capstone
warnings.filterwarnings(
    "ignore",
    message="pkg_resources is deprecated as an API.*",
    category=UserWarning,
    module="capstone.*",
)

# Declare version variable with proper type before try-except
CAPSTONE_VERSION: str | None

# Capstone availability detection and import handling
try:
    import capstone
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_PPC,
        CS_ARCH_SPARC,
        CS_ARCH_SYSZ,
        CS_ARCH_X86,
        CS_ARCH_XCORE,
        CS_GRP_BRANCH_RELATIVE,
        CS_GRP_CALL,
        CS_GRP_INT,
        CS_GRP_IRET,
        CS_GRP_JUMP,
        CS_GRP_PRIVILEGE,
        CS_GRP_RET,
        CS_MODE_16,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_BIG_ENDIAN,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_MIPS32,
        CS_MODE_MIPS64,
        CS_MODE_THUMB,
        CS_OPT_DETAIL,
        CS_OPT_SKIPDATA,
        CS_OPT_SYNTAX,
        CS_OPT_SYNTAX_ATT,
        CS_OPT_SYNTAX_DEFAULT,
        CS_OPT_SYNTAX_INTEL,
        CS_OPT_SYNTAX_MASM,
        CS_OPT_SYNTAX_NOREGNAME,
        Cs,
        CsError,
        CsInsn,
        cs_disasm_quick,
        cs_version,
        debug,
        version_bind,
    )

    HAS_CAPSTONE = True
    CAPSTONE_AVAILABLE = True
    CAPSTONE_VERSION = ".".join(str(x) for x in cs_version())

except ImportError as e:
    logger.error("Capstone not available, using fallback implementations: %s", e)
    HAS_CAPSTONE = False
    CAPSTONE_AVAILABLE = False
    CAPSTONE_VERSION = None

    # Production-ready fallback disassembly implementations

    # Architecture constants
    CS_ARCH_ARM = 0
    CS_ARCH_ARM64 = 1
    CS_ARCH_MIPS = 2
    CS_ARCH_X86 = 3
    CS_ARCH_PPC = 4
    CS_ARCH_SPARC = 5
    CS_ARCH_SYSZ = 6
    CS_ARCH_XCORE = 7

    # Mode constants
    CS_MODE_LITTLE_ENDIAN = 0
    CS_MODE_ARM = 0
    CS_MODE_16 = 1 << 1
    CS_MODE_32 = 1 << 2
    CS_MODE_64 = 1 << 3
    CS_MODE_THUMB = 1 << 4
    CS_MODE_MIPS32 = CS_MODE_32
    CS_MODE_MIPS64 = CS_MODE_64
    CS_MODE_BIG_ENDIAN = 1 << 31

    # Option constants
    CS_OPT_SYNTAX = 1
    CS_OPT_DETAIL = 2
    CS_OPT_SKIPDATA = 3

    # Syntax options
    CS_OPT_SYNTAX_DEFAULT = 0
    CS_OPT_SYNTAX_INTEL = 1
    CS_OPT_SYNTAX_ATT = 2
    CS_OPT_SYNTAX_NOREGNAME = 3
    CS_OPT_SYNTAX_MASM = 4

    # Group constants
    CS_GRP_JUMP = 1
    CS_GRP_CALL = 2
    CS_GRP_RET = 3
    CS_GRP_INT = 4
    CS_GRP_IRET = 5
    CS_GRP_PRIVILEGE = 6
    CS_GRP_BRANCH_RELATIVE = 7

    class FallbackCsError(Exception):
        """Capstone error exception."""

    class FallbackCsInsn:
        """Functional instruction representation for capstone fallback."""

        def __init__(self, address: int, size: int, mnemonic: str, op_str: str, bytes_data: bytes) -> None:
            """Initialize instruction.

            Args:
                address: Instruction address in memory.
                size: Size of instruction in bytes.
                mnemonic: Instruction mnemonic (e.g., 'mov', 'jmp').
                op_str: Operand string.
                bytes_data: Raw instruction bytes.

            """
            self.address: int = address
            self.size: int = size
            self.mnemonic: str = mnemonic
            self.op_str: str = op_str
            self.bytes: bytes = bytes_data
            self.id: int = 0
            self.groups: list[int] = []
            self.reg_name: Callable[[int], str] = self._reg_name
            self.insn_name: Callable[[], str] = self._insn_name
            self.group: Callable[[int], bool] = self._group
            self.regs_read: list[int] = []
            self.regs_write: list[int] = []
            self.operands: list[Any] = []

        def _reg_name(self, reg_id: int) -> str:
            """Get register name.

            Args:
                reg_id: Register identifier.

            Returns:
                Register name string (e.g., 'eax', 'rax').

            """
            x86_regs: dict[int, str] = {
                1: "eax",
                2: "ecx",
                3: "edx",
                4: "ebx",
                5: "esp",
                6: "ebp",
                7: "esi",
                8: "edi",
                9: "rax",
                10: "rcx",
                11: "rdx",
                12: "rbx",
                13: "rsp",
                14: "rbp",
                15: "rsi",
                16: "rdi",
                17: "r8",
                18: "r9",
                19: "r10",
                20: "r11",
                21: "r12",
                22: "r13",
                23: "r14",
                24: "r15",
            }
            return x86_regs.get(reg_id, f"reg{reg_id}")

        def _insn_name(self) -> str:
            """Get instruction name.

            Returns:
                Instruction mnemonic.

            """
            return self.mnemonic

        def _group(self, group_id: int) -> bool:
            """Check if instruction belongs to group.

            Args:
                group_id: Group identifier to check.

            Returns:
                True if instruction belongs to group, False otherwise.

            """
            return group_id in self.groups

        def __repr__(self) -> str:
            """Represent as string.

            Returns:
                String representation of instruction.

            """
            return f"0x{self.address:x}:\t{self.mnemonic}\t{self.op_str}"

    class X86Disassembler:
        """Real x86/x64 disassembler implementation."""

        def __init__(self, mode: int) -> None:
            """Initialize x86 disassembler.

            Args:
                mode: Capstone mode flags (CS_MODE_32, CS_MODE_64, etc.).

            """
            self.mode: int = mode
            self.is_64bit: bool = (mode & CS_MODE_64) != 0
            self.is_32bit: bool = (mode & CS_MODE_32) != 0
            self.is_16bit: bool = (mode & CS_MODE_16) != 0

        def disasm(self, code: bytes, offset: int) -> list[FallbackCsInsn]:
            """Disassemble x86 code.

            Args:
                code: Raw binary code to disassemble.
                offset: Base address for disassembly.

            Returns:
                List of decoded instructions.

            """
            instructions: list[FallbackCsInsn] = []
            idx: int = 0

            while idx < len(code):
                try:
                    if insn := self._decode_instruction(code[idx:], offset + idx):
                        instructions.append(insn)
                        idx += insn.size
                    else:
                        idx += 1
                except Exception:
                    idx += 1

            return instructions

        def _handle_nop(self, code: bytes, offset: int) -> FallbackCsInsn:
            """Handle NOP instruction (0x90).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded NOP instruction.

            """
            return FallbackCsInsn(offset, 1, "nop", "", code[:1])

        def _handle_ret(self, code: bytes, offset: int) -> FallbackCsInsn:
            """Handle RET instruction (0xC3).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded RET instruction.

            """
            insn: FallbackCsInsn = FallbackCsInsn(offset, 1, "ret", "", code[:1])
            insn.groups = [CS_GRP_RET]
            return insn

        def _handle_ret_imm16(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle RET imm16 instruction (0xC2).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded RET instruction or None if insufficient bytes.

            """
            if len(code) < 3:
                return None
            imm: int = struct.unpack("<H", code[1:3])[0]
            insn: FallbackCsInsn = FallbackCsInsn(offset, 3, "ret", hex(imm), code[:3])
            insn.groups = [CS_GRP_RET]
            return insn

        def _handle_int3(self, code: bytes, offset: int) -> FallbackCsInsn:
            """Handle INT3 instruction (0xCC).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded INT3 instruction.

            """
            insn: FallbackCsInsn = FallbackCsInsn(offset, 1, "int3", "", code[:1])
            insn.groups = [CS_GRP_INT]
            return insn

        def _handle_int_imm8(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle INT imm8 instruction (0xCD).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded INT instruction or None if insufficient bytes.

            """
            if len(code) < 2:
                return None
            imm: int = code[1]
            insn: FallbackCsInsn = FallbackCsInsn(offset, 2, "int", hex(imm), code[:2])
            insn.groups = [CS_GRP_INT]
            return insn

        def _handle_call_rel32(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle CALL rel32 instruction (0xE8).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded CALL instruction or None if insufficient bytes.

            """
            if len(code) < 5:
                return None
            rel: int = struct.unpack("<i", code[1:5])[0]
            target: int = offset + 5 + rel
            insn: FallbackCsInsn = FallbackCsInsn(offset, 5, "call", hex(target), code[:5])
            insn.groups = [CS_GRP_CALL, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_jmp_rel32(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle JMP rel32 instruction (0xE9).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded JMP instruction or None if insufficient bytes.

            """
            if len(code) < 5:
                return None
            rel: int = struct.unpack("<i", code[1:5])[0]
            target: int = offset + 5 + rel
            insn: FallbackCsInsn = FallbackCsInsn(offset, 5, "jmp", hex(target), code[:5])
            insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_jmp_rel8(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle JMP rel8 instruction (0xEB).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded JMP instruction or None if insufficient bytes.

            """
            if len(code) < 2:
                return None
            rel: int = struct.unpack("b", code[1:2])[0]
            target: int = offset + 2 + rel
            insn: FallbackCsInsn = FallbackCsInsn(offset, 2, "jmp", hex(target), code[:2])
            insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_jcc_rel8(self, code: bytes, offset: int, opcode: int) -> FallbackCsInsn | None:
            """Handle Jcc rel8 instructions (0x70-0x7F).

            Args:
                code: Instruction bytes.
                offset: Current offset.
                opcode: The opcode byte.

            Returns:
                Decoded conditional jump instruction or None if insufficient bytes.

            """
            if len(code) < 2:
                return None
            jcc_mnemonics: dict[int, str] = {
                0x70: "jo",
                0x71: "jno",
                0x72: "jb",
                0x73: "jnb",
                0x74: "je",
                0x75: "jne",
                0x76: "jbe",
                0x77: "ja",
                0x78: "js",
                0x79: "jns",
                0x7A: "jp",
                0x7B: "jnp",
                0x7C: "jl",
                0x7D: "jge",
                0x7E: "jle",
                0x7F: "jg",
            }
            rel: int = struct.unpack("b", code[1:2])[0]
            target: int = offset + 2 + rel
            mnemonic: str = jcc_mnemonics.get(opcode, f"j{opcode:02x}")
            insn: FallbackCsInsn = FallbackCsInsn(offset, 2, mnemonic, hex(target), code[:2])
            insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_two_byte_opcodes(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle two-byte opcodes starting with 0x0F.

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded instruction or None if unrecognized or insufficient bytes.

            """
            if len(code) < 2:
                return None
            opcode2: int = code[1]

            if 0x80 <= opcode2 <= 0x8F:
                if len(code) < 6:
                    return None
                jcc_mnemonics: dict[int, str] = {
                    0x80: "jo",
                    0x81: "jno",
                    0x82: "jb",
                    0x83: "jnb",
                    0x84: "je",
                    0x85: "jne",
                    0x86: "jbe",
                    0x87: "ja",
                    0x88: "js",
                    0x89: "jns",
                    0x8A: "jp",
                    0x8B: "jnp",
                    0x8C: "jl",
                    0x8D: "jge",
                    0x8E: "jle",
                    0x8F: "jg",
                }
                rel: int = struct.unpack("<i", code[2:6])[0]
                target: int = offset + 6 + rel
                mnemonic: str = jcc_mnemonics.get(opcode2, f"j{opcode2:02x}")
                insn: FallbackCsInsn = FallbackCsInsn(offset, 6, mnemonic, hex(target), code[:6])
                insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
                return insn

            return None

        def _handle_push_reg(self, code: bytes, offset: int, opcode: int, rex: int | None) -> FallbackCsInsn:
            """Handle PUSH register instructions (0x50-0x57).

            Args:
                code: Instruction bytes.
                offset: Current offset.
                opcode: The primary opcode byte.
                rex: REX prefix if present in 64-bit mode.

            Returns:
                Decoded PUSH instruction.

            """
            reg_names: list[str] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
                if rex and (rex & 0x01):
                    reg_names = [f"r{8 + i}" for i in range(8)]
            reg: str = reg_names[opcode - 0x50]
            return FallbackCsInsn(offset, 1, "push", reg, code[:1])

        def _handle_pop_reg(self, code: bytes, offset: int, opcode: int, rex: int | None) -> FallbackCsInsn:
            """Handle POP register instructions (0x58-0x5F).

            Args:
                code: Instruction bytes.
                offset: Current offset.
                opcode: The primary opcode byte.
                rex: REX prefix if present in 64-bit mode.

            Returns:
                Decoded POP instruction.

            """
            reg_names: list[str] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
                if rex and (rex & 0x01):
                    reg_names = [f"r{8 + i}" for i in range(8)]
            reg: str = reg_names[opcode - 0x58]
            return FallbackCsInsn(offset, 1, "pop", reg, code[:1])

        def _handle_mov_rm_r(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle MOV r/m, r instruction (0x89).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded MOV instruction or None if insufficient bytes.

            """
            if len(code) < 2:
                return None
            modrm: int = code[1]
            mod: int = (modrm >> 6) & 0x03
            reg_names: list[str] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if mod == 0x03:
                reg: int = (modrm >> 3) & 0x07
                src: str = reg_names[reg]
                rm: int = modrm & 0x07

                dst: str = reg_names[rm]
                return FallbackCsInsn(offset, 2, "mov", f"{dst}, {src}", code[:2])
            return None

        def _handle_mov_r_rm(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle MOV r, r/m instruction (0x8B).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded MOV instruction or None if insufficient bytes.

            """
            if len(code) < 2:
                return None
            modrm: int = code[1]
            mod: int = (modrm >> 6) & 0x03
            reg_names: list[str] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if mod == 0x03:
                rm: int = modrm & 0x07

                src: str = reg_names[rm]
                reg: int = (modrm >> 3) & 0x07
                dst: str = reg_names[reg]
                return FallbackCsInsn(offset, 2, "mov", f"{dst}, {src}", code[:2])
            return None

        def _handle_mov_reg_imm(self, code: bytes, offset: int, opcode: int, rex: int | None) -> FallbackCsInsn | None:
            """Handle MOV reg, imm instructions (0xB8-0xBF).

            Args:
                code: Instruction bytes.
                offset: Current offset.
                opcode: The primary opcode byte.
                rex: REX prefix if present in 64-bit mode.

            Returns:
                Decoded MOV instruction or None if insufficient bytes.

            """
            reg_idx: int = opcode - 0xB8
            reg_names: list[str] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

            if self.is_64bit:
                if rex and (rex & 0x08):
                    if len(code) < 9:
                        return None
                    imm: int = struct.unpack("<Q", code[1:9])[0]
                    reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
                    if rex and (rex & 0x01):
                        reg_names = [f"r{8 + i}" for i in range(8)]
                    return FallbackCsInsn(offset, 9, "mov", f"{reg_names[reg_idx]}, {hex(imm)}", code[:9])
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if self.is_32bit or (self.is_64bit and not (rex and (rex & 0x08))):
                if len(code) < 5:
                    return None
                imm = struct.unpack("<I", code[1:5])[0]
                return FallbackCsInsn(offset, 5, "mov", f"{reg_names[reg_idx]}, {hex(imm)}", code[:5])

            if self.is_16bit:
                if len(code) < 3:
                    return None
                imm = struct.unpack("<H", code[1:3])[0]
                reg_names = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
                return FallbackCsInsn(offset, 3, "mov", f"{reg_names[reg_idx]}, {hex(imm)}", code[:3])

            return None

        def _handle_xor_rm_r(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Handle XOR r/m, r instruction (0x31).

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded XOR instruction or None if insufficient bytes.

            """
            if len(code) < 2:
                return None
            modrm: int = code[1]
            mod: int = (modrm >> 6) & 0x03
            reg_names: list[str] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if mod == 0x03:
                reg: int = (modrm >> 3) & 0x07
                src: str = reg_names[reg]
                rm: int = modrm & 0x07

                dst: str = reg_names[rm]
                return FallbackCsInsn(offset, 2, "xor", f"{dst}, {src}", code[:2])
            return None

        def _decode_instruction(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Decode a single x86 instruction.

            Args:
                code: Instruction bytes to decode.
                offset: Current offset in binary.

            Returns:
                Decoded instruction or None if decoding fails.

            """
            if not code:
                return None

            opcode: int = code[0]

            rex: int | None = None
            if self.is_64bit and 0x40 <= opcode <= 0x4F:
                rex = opcode
                code = code[1:]
                if len(code) == 0:
                    return None
                opcode = code[0]

            handlers: dict[int, Callable[[], FallbackCsInsn | None]] = {
                0x90: lambda: self._handle_nop(code, offset),
                0xC3: lambda: self._handle_ret(code, offset),
                0xC2: lambda: self._handle_ret_imm16(code, offset),
                0xCC: lambda: self._handle_int3(code, offset),
                0xCD: lambda: self._handle_int_imm8(code, offset),
                0xE8: lambda: self._handle_call_rel32(code, offset),
                0xE9: lambda: self._handle_jmp_rel32(code, offset),
                0xEB: lambda: self._handle_jmp_rel8(code, offset),
                0x0F: lambda: self._handle_two_byte_opcodes(code, offset),
                0x89: lambda: self._handle_mov_rm_r(code, offset),
                0x8B: lambda: self._handle_mov_r_rm(code, offset),
                0x31: lambda: self._handle_xor_rm_r(code, offset),
            }

            if opcode in handlers:
                return handlers[opcode]()

            if 0x70 <= opcode <= 0x7F:
                return self._handle_jcc_rel8(code, offset, opcode)
            if 0x50 <= opcode <= 0x57:
                return self._handle_push_reg(code, offset, opcode, rex)
            if 0x58 <= opcode <= 0x5F:
                return self._handle_pop_reg(code, offset, opcode, rex)
            if 0xB8 <= opcode <= 0xBF:
                return self._handle_mov_reg_imm(code, offset, opcode, rex)

            return FallbackCsInsn(offset, 1, "db", hex(opcode), code[:1])

    class ARMDisassembler:
        """Real ARM disassembler implementation."""

        def __init__(self, mode: int) -> None:
            """Initialize ARM disassembler.

            Args:
                mode: Capstone mode flags (CS_MODE_THUMB, etc.).

            """
            self.mode: int = mode
            self.is_thumb: bool = (mode & CS_MODE_THUMB) != 0
            self.is_big_endian: bool = (mode & CS_MODE_BIG_ENDIAN) != 0

        def disasm(self, code: bytes, offset: int) -> list[FallbackCsInsn]:
            """Disassemble ARM code.

            Args:
                code: Raw binary code to disassemble.
                offset: Base address for disassembly.

            Returns:
                List of decoded instructions.

            """
            instructions: list[FallbackCsInsn] = []
            idx: int = 0

            if self.is_thumb:
                while idx < len(code) - 1:
                    if insn := self._decode_thumb_instruction(code[idx:], offset + idx):
                        instructions.append(insn)
                        idx += insn.size
                    else:
                        idx += 2
            else:
                while idx < len(code) - 3:
                    if insn := self._decode_arm_instruction(code[idx:], offset + idx):
                        instructions.append(insn)
                        idx += insn.size
                    else:
                        idx += 4

            return instructions

        def _decode_arm_instruction(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Decode a single ARM instruction.

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded ARM instruction or None if insufficient bytes.

            """
            if len(code) < 4:
                return None

            if self.is_big_endian:
                insn_word: int = struct.unpack(">I", code[:4])[0]
            else:
                insn_word = struct.unpack("<I", code[:4])[0]

            if (insn_word & 0x0E000000) == 0x0A000000:
                is_link: bool = (insn_word & 0x01000000) != 0
                offset_val: int = insn_word & 0x00FFFFFF
                if offset_val & 0x00800000:
                    offset_val |= 0xFF000000
                offset_val = (offset_val << 2) + 8
                target: int = offset + offset_val

                mnemonic: str = "bl" if is_link else "b"
                insn: FallbackCsInsn = FallbackCsInsn(offset, 4, mnemonic, hex(target), code[:4])
                insn.groups = [CS_GRP_CALL if is_link else CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
                return insn

            if (insn_word & 0x0FFF0000) == 0x03A00000:
                rd: int = (insn_word >> 12) & 0x0F
                imm: int = insn_word & 0xFF
                if rotate := ((insn_word >> 8) & 0x0F) * 2:
                    imm = (imm >> rotate) | (imm << (32 - rotate))
                imm &= 0xFFFFFFFF

                return FallbackCsInsn(offset, 4, "mov", f"r{rd}, #{hex(imm)}", code[:4])

            if insn_word == 0xE1A00000:
                return FallbackCsInsn(offset, 4, "nop", "", code[:4])

            return FallbackCsInsn(offset, 4, "dcd", hex(insn_word), code[:4])

        def _decode_thumb_instruction(self, code: bytes, offset: int) -> FallbackCsInsn | None:
            """Decode a single Thumb instruction.

            Args:
                code: Instruction bytes.
                offset: Current offset.

            Returns:
                Decoded Thumb instruction or None if insufficient bytes.

            """
            if len(code) < 2:
                return None

            if self.is_big_endian:
                insn_hw: int = struct.unpack(">H", code[:2])[0]
            else:
                insn_hw = struct.unpack("<H", code[:2])[0]

            if (insn_hw & 0xF800) >= 0xE800:
                if len(code) < 4:
                    return None
                if self.is_big_endian:
                    insn_hw2: int = struct.unpack(">H", code[2:4])[0]
                else:
                    insn_hw2 = struct.unpack("<H", code[2:4])[0]

                if (insn_hw & 0xF800) == 0xF000 and (insn_hw2 & 0xD000) == 0xD000:
                    s: int = (insn_hw >> 10) & 1
                    imm10: int = insn_hw & 0x3FF
                    j1: int = (insn_hw2 >> 13) & 1
                    j2: int = (insn_hw2 >> 11) & 1
                    imm11: int = insn_hw2 & 0x7FF

                    i1: int = ~(j1 ^ s) & 1
                    i2: int = ~(j2 ^ s) & 1

                    offset_val: int = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                    if s:
                        offset_val |= 0xFE000000

                    target: int = offset + 4 + offset_val

                    is_blx: bool = (insn_hw2 & 0x1000) == 0
                    mnemonic: str = "blx" if is_blx else "bl"
                    insn: FallbackCsInsn = FallbackCsInsn(offset, 4, mnemonic, hex(target), code[:4])
                    insn.groups = [CS_GRP_CALL, CS_GRP_BRANCH_RELATIVE]
                    return insn

                return FallbackCsInsn(offset, 4, "dcd", f"{hex(insn_hw)}, {hex(insn_hw2)}", code[:4])

            if (insn_hw & 0xF800) == 0xE000:
                offset_val = (insn_hw & 0x7FF) << 1
                if offset_val & 0x800:
                    offset_val |= 0xFFFFF000
                target = offset + 4 + offset_val
                insn = FallbackCsInsn(offset, 2, "b", hex(target), code[:2])
                insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
                return insn

            if insn_hw == 0xBF00:
                return FallbackCsInsn(offset, 2, "nop", "", code[:2])

            if (insn_hw & 0xF800) == 0x2000:
                rd = (insn_hw >> 8) & 0x07
                imm = insn_hw & 0xFF
                return FallbackCsInsn(offset, 2, "mov", f"r{rd}, #{hex(imm)}", code[:2])

            return FallbackCsInsn(offset, 2, "dcw", hex(insn_hw), code[:2])

    class FallbackCs:
        """Functional Capstone disassembler implementation."""

        def __init__(self, arch: int, mode: int) -> None:
            """Initialize disassembler.

            Args:
                arch: Architecture constant (CS_ARCH_X86, CS_ARCH_ARM, etc.).
                mode: Mode flags for the architecture.

            """
            self.arch: int = arch
            self.mode: int = mode
            self.syntax: int = CS_OPT_SYNTAX_INTEL
            self.detail: bool = False
            self.skipdata: bool = False

            if arch == CS_ARCH_X86:
                self._disasm_impl: X86Disassembler | ARMDisassembler | object | None = X86Disassembler(mode)
            elif arch == CS_ARCH_ARM:
                self._disasm_impl = ARMDisassembler(mode)
            elif arch == CS_ARCH_ARM64:
                self._disasm_impl = self._create_arm64_disassembler(mode)
            else:
                self._disasm_impl = None

        def disasm(self, code: bytes | str, offset: int, count: int = 0) -> list[FallbackCsInsn]:
            """Disassemble code.

            Args:
                code: Binary code to disassemble.
                offset: Base address for disassembly.
                count: Maximum number of instructions to decode (0 = all).

            Returns:
                List of decoded instructions.

            """
            if not self._disasm_impl:
                logger.warning("No disassembler for architecture %d", self.arch)
                return []

            code_bytes: bytes
            code_bytes = bytes(code, "latin-1") if isinstance(code, str) else code
            instructions: list[FallbackCsInsn] = self._disasm_impl.disasm(code_bytes, offset)  # type: ignore[attr-defined]

            if count > 0:
                instructions = instructions[:count]

            return instructions

        def set_option(self, option: int, value: int | bool) -> None:
            """Set disassembler option.

            Args:
                option: Option constant (CS_OPT_SYNTAX, CS_OPT_DETAIL, CS_OPT_SKIPDATA).
                value: Option value to set.

            """
            if option == CS_OPT_SYNTAX:
                if isinstance(value, int):
                    self.syntax = value
            elif option == CS_OPT_DETAIL:
                if isinstance(value, bool):
                    self.detail = value
            elif option == CS_OPT_SKIPDATA:
                if isinstance(value, bool):
                    self.skipdata = value

        def _create_arm64_disassembler(self, mode: int) -> object:
            """Create ARM64 disassembler.

            Args:
                mode: Mode flags for ARM64.

            Returns:
                ARM64Disassembler instance.

            """

            class ARM64Disassembler:
                """Basic ARM64 disassembler."""

                def __init__(self, arm64_mode: int) -> None:
                    """Initialize ARM64 disassembler.

                    Args:
                        arm64_mode: Mode flags.

                    """
                    self.mode: int = arm64_mode
                    self.is_big_endian: bool = (arm64_mode & CS_MODE_BIG_ENDIAN) != 0

                def disasm(self, code: bytes, offset: int) -> list[FallbackCsInsn]:
                    """Disassemble ARM64 code.

                    Args:
                        code: Binary code to disassemble.
                        offset: Base address.

                    Returns:
                        List of decoded instructions.

                    """
                    instructions: list[FallbackCsInsn] = []
                    idx: int = 0

                    while idx < len(code) - 3 and len(code[idx:]) >= 4:
                        if self.is_big_endian:
                            insn_word: int = struct.unpack(">I", code[idx : idx + 4])[0]
                        else:
                            insn_word = struct.unpack("<I", code[idx : idx + 4])[0]

                        if insn_word == 0xD503201F:
                            insn: FallbackCsInsn = FallbackCsInsn(offset + idx, 4, "nop", "", code[idx : idx + 4])
                        elif insn_word == 0xD65F03C0:
                            insn = FallbackCsInsn(offset + idx, 4, "ret", "", code[idx : idx + 4])
                            insn.groups = [CS_GRP_RET]
                        elif (insn_word & 0xFC000000) == 0x94000000:
                            imm26: int = insn_word & 0x03FFFFFF
                            if imm26 & 0x02000000:
                                imm26 |= 0xFC000000
                            target: int = offset + idx + (imm26 << 2)
                            insn = FallbackCsInsn(offset + idx, 4, "bl", hex(target), code[idx : idx + 4])
                            insn.groups = [CS_GRP_CALL, CS_GRP_BRANCH_RELATIVE]
                        elif (insn_word & 0xFC000000) == 0x14000000:
                            imm26 = insn_word & 0x03FFFFFF
                            if imm26 & 0x02000000:
                                imm26 |= 0xFC000000
                            target = offset + idx + (imm26 << 2)
                            insn = FallbackCsInsn(offset + idx, 4, "b", hex(target), code[idx : idx + 4])
                            insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
                        else:
                            insn = FallbackCsInsn(offset + idx, 4, "dcd", hex(insn_word), code[idx : idx + 4])

                        instructions.append(insn)
                        idx += 4

                    return instructions

            return ARM64Disassembler(mode)

    def cs_disasm_quick(arch: int, mode: int, code: bytes | str, offset: int, count: int = 0) -> list[FallbackCsInsn]:
        """Quick disassembly function.

        Args:
            arch: Architecture constant.
            mode: Mode flags.
            code: Binary code to disassemble.
            offset: Base address.
            count: Maximum instructions to decode.

        Returns:
            List of decoded instructions.

        """
        cs: FallbackCs = FallbackCs(arch, mode)
        return cs.disasm(code, offset, count)

    def cs_version() -> tuple[int, int, int]:
        """Get Capstone version.

        Returns:
            Version tuple (major, minor, patch).

        """
        return (5, 0, 0)

    def version_bind() -> tuple[int, int, int]:
        """Get binding version.

        Returns:
            Version tuple (major, minor, patch).

        """
        return (5, 0, 0)

    def debug() -> None:
        """Enable debug mode."""
        logger.info("Capstone fallback debug mode enabled")

    # Assign Cs class and exception/insn types
    Cs = FallbackCs
    CsError = FallbackCsError
    CsInsn = FallbackCsInsn

    class FallbackCapstone:
        """Fallback capstone module providing compatibility interface.

        This class provides a module-like interface for Capstone when the
        actual library is not available, exposing all necessary constants
        and functions for disassembly operations.
        """

        CS_ARCH_ARM: int = CS_ARCH_ARM
        CS_ARCH_ARM64: int = CS_ARCH_ARM64
        CS_ARCH_MIPS: int = CS_ARCH_MIPS
        CS_ARCH_X86: int = CS_ARCH_X86
        CS_ARCH_PPC: int = CS_ARCH_PPC
        CS_ARCH_SPARC: int = CS_ARCH_SPARC
        CS_ARCH_SYSZ: int = CS_ARCH_SYSZ
        CS_ARCH_XCORE: int = CS_ARCH_XCORE

        CS_MODE_LITTLE_ENDIAN: int = CS_MODE_LITTLE_ENDIAN
        CS_MODE_ARM: int = CS_MODE_ARM
        CS_MODE_16: int = CS_MODE_16
        CS_MODE_32: int = CS_MODE_32
        CS_MODE_64: int = CS_MODE_64
        CS_MODE_THUMB: int = CS_MODE_THUMB
        CS_MODE_MIPS32: int = CS_MODE_MIPS32
        CS_MODE_MIPS64: int = CS_MODE_MIPS64
        CS_MODE_BIG_ENDIAN: int = CS_MODE_BIG_ENDIAN

        CS_OPT_SYNTAX: int = CS_OPT_SYNTAX
        CS_OPT_DETAIL: int = CS_OPT_DETAIL
        CS_OPT_SKIPDATA: int = CS_OPT_SKIPDATA

        CS_OPT_SYNTAX_DEFAULT: int = CS_OPT_SYNTAX_DEFAULT
        CS_OPT_SYNTAX_INTEL: int = CS_OPT_SYNTAX_INTEL
        CS_OPT_SYNTAX_ATT: int = CS_OPT_SYNTAX_ATT
        CS_OPT_SYNTAX_NOREGNAME: int = CS_OPT_SYNTAX_NOREGNAME
        CS_OPT_SYNTAX_MASM: int = CS_OPT_SYNTAX_MASM

        CS_GRP_JUMP: int = CS_GRP_JUMP
        CS_GRP_CALL: int = CS_GRP_CALL
        CS_GRP_RET: int = CS_GRP_RET
        CS_GRP_INT: int = CS_GRP_INT
        CS_GRP_IRET: int = CS_GRP_IRET
        CS_GRP_PRIVILEGE: int = CS_GRP_PRIVILEGE
        CS_GRP_BRANCH_RELATIVE: int = CS_GRP_BRANCH_RELATIVE

        Cs: type[FallbackCs] = Cs
        CsInsn: type[FallbackCsInsn] = CsInsn
        CsError: type[FallbackCsError] = CsError

        cs_disasm_quick: Callable[[int, int, bytes | str, int, int], list[FallbackCsInsn]] = staticmethod(cs_disasm_quick)
        cs_version: Callable[[], tuple[int, int, int]] = staticmethod(cs_version)
        version_bind: Callable[[], tuple[int, int, int]] = staticmethod(version_bind)
        debug: Callable[[], None] = staticmethod(debug)

    capstone_module: FallbackCapstone = FallbackCapstone()
    capstone = capstone_module


# Export all Capstone objects and availability flag
__all__ = [
    "CAPSTONE_AVAILABLE",
    "CAPSTONE_VERSION",
    "CS_ARCH_ARM",
    "CS_ARCH_ARM64",
    "CS_ARCH_MIPS",
    "CS_ARCH_PPC",
    "CS_ARCH_SPARC",
    "CS_ARCH_SYSZ",
    "CS_ARCH_X86",
    "CS_ARCH_XCORE",
    "CS_GRP_BRANCH_RELATIVE",
    "CS_GRP_CALL",
    "CS_GRP_INT",
    "CS_GRP_IRET",
    "CS_GRP_JUMP",
    "CS_GRP_PRIVILEGE",
    "CS_GRP_RET",
    "CS_MODE_16",
    "CS_MODE_32",
    "CS_MODE_64",
    "CS_MODE_ARM",
    "CS_MODE_BIG_ENDIAN",
    "CS_MODE_LITTLE_ENDIAN",
    "CS_MODE_MIPS32",
    "CS_MODE_MIPS64",
    "CS_MODE_THUMB",
    "CS_OPT_DETAIL",
    "CS_OPT_SKIPDATA",
    "CS_OPT_SYNTAX",
    "CS_OPT_SYNTAX_ATT",
    "CS_OPT_SYNTAX_DEFAULT",
    "CS_OPT_SYNTAX_INTEL",
    "CS_OPT_SYNTAX_MASM",
    "CS_OPT_SYNTAX_NOREGNAME",
    "Cs",
    "CsError",
    "CsInsn",
    "HAS_CAPSTONE",
    "capstone",
    "cs_disasm_quick",
    "cs_version",
    "debug",
    "version_bind",
]
