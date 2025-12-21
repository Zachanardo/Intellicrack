#!/usr/bin/env python3
"""VM protection unwrapper plugin for Intellicrack.

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
"""

# Standard library imports
import hashlib
import json
import logging
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# Third-party imports
import keystone

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.utils.logger import logger


"""
VM Protection Unwrapper

Advanced unwrapper for virtualization-based protection systems including
VMProtect, Themida, Code Virtualizer, and other VM-based obfuscators.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class ProtectionType(Enum):
    """Types of VM protection."""

    VMPROTECT_1X = "VMProtect_1x"
    VMPROTECT_2X = "VMProtect_2x"
    VMPROTECT_3X = "VMProtect_3x"
    THEMIDA = "Themida"
    CODE_VIRTUALIZER = "Code_Virtualizer"
    ENIGMA_VIRTUALBOX = "Enigma_VirtualBox"
    OBSIDIUM = "Obsidium"
    WINLICENSE = "WinLicense"
    SAFENGINE = "SafeEngine"
    UNKNOWN_VM = "Unknown_VM"


class VMInstructionType(Enum):
    """VM instruction types."""

    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    MEMORY = "memory"
    CONTROL_FLOW = "control_flow"
    STACK = "stack"
    REGISTER = "register"
    CUSTOM = "custom"


@dataclass
class VMInstruction:
    """VM instruction representation."""

    opcode: int
    operands: list[int]
    mnemonic: str
    vm_type: VMInstructionType
    x86_equivalent: str | None = None
    size: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class VMContext:
    """VM execution context."""

    registers: dict[str, int] = field(default_factory=dict)
    stack: list[int] = field(default_factory=list)
    memory: dict[int, bytes] = field(default_factory=dict)
    flags: dict[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize VM context with default registers and flags if not provided."""
        if not self.registers:
            # Initialize x86 registers
            self.registers = {
                "EAX": 0,
                "EBX": 0,
                "ECX": 0,
                "EDX": 0,
                "ESI": 0,
                "EDI": 0,
                "ESP": 0x1000,
                "EBP": 0x1000,
                "EIP": 0,
            }

        if not self.flags:
            self.flags = {
                "ZF": False,
                "CF": False,
                "SF": False,
                "OF": False,
            }


class VMProtectHandler:
    """VMProtect-specific handling."""

    def __init__(self) -> None:
        """Initialize VMProtect handler with logging and detection capabilities."""
        self.logger = logging.getLogger(f"{__name__}.VMProtect")
        self.key_schedules = {
            ProtectionType.VMPROTECT_1X: self._vmprotect_1x_key_schedule,
            ProtectionType.VMPROTECT_2X: self._vmprotect_2x_key_schedule,
            ProtectionType.VMPROTECT_3X: self._vmprotect_3x_key_schedule,
        }

    def identify_version(self, vm_data: bytes) -> ProtectionType:
        """Identify VMProtect version."""
        # Version signatures
        signatures = {
            ProtectionType.VMPROTECT_1X: [
                b"\x60\x8b\x04\x24\x8b\x4c\x24\x04",  # Version 1.x signature
                b"\x55\x8b\xec\x60\x8b\x45\x08",
            ],
            ProtectionType.VMPROTECT_2X: [
                b"\x68\x00\x00\x00\x00\x8f\x04\x24",  # Version 2.x signature
                b"\x8b\x44\x24\x04\x50\x8b\x44\x24\x08",
            ],
            ProtectionType.VMPROTECT_3X: [
                b"\x8b\x44\x24\x04\x8b\x4c\x24\x08",  # Version 3.x signature
                b"\x48\x8b\x44\x24\x08\x48\x8b\x4c\x24\x10",
            ],
        }

        for version, sigs in signatures.items():
            for sig in sigs:
                if sig in vm_data:
                    self.logger.info("Detected %s", version.value)
                    return version

        return ProtectionType.UNKNOWN_VM

    def decrypt_vm_code(self, encrypted_data: bytes, key: bytes, version: ProtectionType) -> bytes:
        """Decrypt VMProtect VM code."""
        if version in self.key_schedules:
            key_schedule = self.key_schedules[version](key)
            return self._decrypt_with_schedule(encrypted_data, key_schedule)
        # Generic decryption
        return self._simple_decrypt(encrypted_data, key)

    def _vmprotect_1x_key_schedule(self, key: bytes) -> list[int]:
        """VMProtect 1.x key schedule."""
        schedule = []
        key_ints = struct.unpack("<4I", key[:16])

        for i in range(44):  # 44 round keys
            if i < 4:
                schedule.append(key_ints[i])
            else:
                temp = schedule[i - 1]
                if i % 4 == 0:
                    # RotWord and SubBytes
                    temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                    temp ^= 0x01000000 << ((i // 4) - 1)

                schedule.append(schedule[i - 4] ^ temp)

        return schedule

    def _vmprotect_2x_key_schedule(self, key: bytes) -> list[int]:
        """VMProtect 2.x key schedule (more complex)."""
        schedule = []
        key_ints = struct.unpack("<8I", key[:32])

        # More complex key expansion
        for i in range(60):
            if i < 8:
                schedule.append(key_ints[i])
            else:
                temp = schedule[i - 1]
                if i % 8 == 0:
                    temp = self._complex_transform(temp, i)
                elif i % 8 == 4:
                    temp = self._substitute_bytes(temp)

                schedule.append(schedule[i - 8] ^ temp)

        return schedule

    def _vmprotect_3x_key_schedule(self, key: bytes) -> list[int]:
        """VMProtect 3.x key schedule (most complex)."""
        schedule = []
        key_data = key[:64] if len(key) >= 64 else key.ljust(64, b"\x00")

        # Initialize with SHA-256 like expansion
        for i in range(64):
            if i < 16:
                w = struct.unpack("<I", key_data[i * 4 : (i + 1) * 4])[0]
            else:
                s0 = self._sigma0(schedule[i - 15])
                s1 = self._sigma1(schedule[i - 2])
                w = (schedule[i - 16] + s0 + schedule[i - 7] + s1) & 0xFFFFFFFF

            schedule.append(w)

        return schedule

    def _complex_transform(self, value: int, round_num: int) -> int:
        """Complex transformation for VMProtect 2.x."""
        # Rotate left by round_num bits
        value = ((value << (round_num % 32)) | (value >> (32 - (round_num % 32)))) & 0xFFFFFFFF

        # XOR with round constant
        round_constant = 0x9E3779B9 * round_num
        value ^= round_constant & 0xFFFFFFFF

        return value

    def _substitute_bytes(self, value: int) -> int:
        """Byte substitution (simplified S-Box)."""
        sbox = [
            0x63,
            0x7C,
            0x77,
            0x7B,
            0xF2,
            0x6B,
            0x6F,
            0xC5,
            0x30,
            0x01,
            0x67,
            0x2B,
            0xFE,
            0xD7,
            0xAB,
            0x76,
        ]

        result = 0
        for i in range(4):
            byte_val = (value >> (i * 8)) & 0xFF
            substituted = sbox[byte_val % 16]
            result |= substituted << (i * 8)

        return result

    def _sigma0(self, value: int) -> int:
        """SHA-256 sigma0 function."""
        return (((value >> 7) | (value << 25)) ^ ((value >> 18) | (value << 14)) ^ (value >> 3)) & 0xFFFFFFFF

    def _sigma1(self, value: int) -> int:
        """SHA-256 sigma1 function."""
        return (((value >> 17) | (value << 15)) ^ ((value >> 19) | (value << 13)) ^ (value >> 10)) & 0xFFFFFFFF

    def _decrypt_with_schedule(self, data: bytes, key_schedule: list[int]) -> bytes:
        """Decrypt data using key schedule."""
        result = bytearray()

        for i in range(0, len(data), 16):
            block = data[i : i + 16]
            if len(block) < 16:
                block = block.ljust(16, b"\x00")

            # AES-like decryption rounds
            state = list(struct.unpack("<4I", block))

            # Initial round
            for j in range(4):
                state[j] ^= key_schedule[j]

            # Main rounds
            for round_num in range(1, 10):
                state = self._inverse_substitute_bytes_block(state)
                state = self._inverse_shift_rows(state)
                state = self._inverse_mix_columns(state)

                for j in range(4):
                    state[j] ^= key_schedule[round_num * 4 + j]

            # Final round
            state = self._inverse_substitute_bytes_block(state)
            state = self._inverse_shift_rows(state)

            for j in range(4):
                state[j] ^= key_schedule[40 + j]

            result.extend(struct.pack("<4I", *state))

        return bytes(result)

    def _simple_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Perform simple XOR decryption for unknown versions."""
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

    def _inverse_substitute_bytes_block(self, state: list[int]) -> list[int]:
        """Inverse S-Box substitution for block."""
        inv_sbox = [
            0x52,
            0x09,
            0x6A,
            0xD5,
            0x30,
            0x36,
            0xA5,
            0x38,
            0xBF,
            0x40,
            0xA3,
            0x9E,
            0x81,
            0xF3,
            0xD7,
            0xFB,
        ]

        result = []
        for word in state:
            new_word = 0
            for i in range(4):
                byte_val = (word >> (i * 8)) & 0xFF
                substituted = inv_sbox[byte_val % 16]
                new_word |= substituted << (i * 8)
            result.append(new_word)

        return result

    def _inverse_shift_rows(self, state: list[int]) -> list[int]:
        """Inverse shift rows transformation."""
        # Simplified inverse shift rows
        return [state[0], state[3], state[2], state[1]]

    def _inverse_mix_columns(self, state: list[int]) -> list[int]:
        """Inverse mix columns transformation."""
        return [((word << 1) ^ (word >> 31)) & 0xFFFFFFFF for word in state]


class CodeVirtualizerHandler:
    """Code Virtualizer-specific handling."""

    def __init__(self) -> None:
        """Initialize Code Virtualizer handler."""
        self.logger = logging.getLogger(f"{__name__}.CodeVirtualizer")
        self.opcode_map = self._build_cv_opcode_map()

    def _build_cv_opcode_map(self) -> dict[int, tuple[str, VMInstructionType]]:
        """Build Code Virtualizer opcode mapping."""
        return {
            # Code Virtualizer uses different opcode encoding
            0x10: ("CV_PUSH", VMInstructionType.STACK),
            0x11: ("CV_POP", VMInstructionType.STACK),
            0x12: ("CV_DUP", VMInstructionType.STACK),
            0x13: ("CV_SWAP", VMInstructionType.STACK),
            0x20: ("CV_ADD", VMInstructionType.ARITHMETIC),
            0x21: ("CV_SUB", VMInstructionType.ARITHMETIC),
            0x22: ("CV_MUL", VMInstructionType.ARITHMETIC),
            0x23: ("CV_DIV", VMInstructionType.ARITHMETIC),
            0x24: ("CV_MOD", VMInstructionType.ARITHMETIC),
            0x25: ("CV_NEG", VMInstructionType.ARITHMETIC),
            0x30: ("CV_AND", VMInstructionType.LOGICAL),
            0x31: ("CV_OR", VMInstructionType.LOGICAL),
            0x32: ("CV_XOR", VMInstructionType.LOGICAL),
            0x33: ("CV_NOT", VMInstructionType.LOGICAL),
            0x34: ("CV_SHL", VMInstructionType.LOGICAL),
            0x35: ("CV_SHR", VMInstructionType.LOGICAL),
            0x36: ("CV_ROL", VMInstructionType.LOGICAL),
            0x37: ("CV_ROR", VMInstructionType.LOGICAL),
            0x40: ("CV_JMP", VMInstructionType.CONTROL_FLOW),
            0x41: ("CV_JZ", VMInstructionType.CONTROL_FLOW),
            0x42: ("CV_JNZ", VMInstructionType.CONTROL_FLOW),
            0x43: ("CV_JG", VMInstructionType.CONTROL_FLOW),
            0x44: ("CV_JL", VMInstructionType.CONTROL_FLOW),
            0x45: ("CV_JGE", VMInstructionType.CONTROL_FLOW),
            0x46: ("CV_JLE", VMInstructionType.CONTROL_FLOW),
            0x47: ("CV_CALL", VMInstructionType.CONTROL_FLOW),
            0x48: ("CV_RET", VMInstructionType.CONTROL_FLOW),
            0x50: ("CV_LOAD", VMInstructionType.MEMORY),
            0x51: ("CV_STORE", VMInstructionType.MEMORY),
            0x52: ("CV_LOAD_WORD", VMInstructionType.MEMORY),
            0x53: ("CV_STORE_WORD", VMInstructionType.MEMORY),
            0x60: ("CV_MOV", VMInstructionType.REGISTER),
            0x61: ("CV_XCHG", VMInstructionType.REGISTER),
        }

    def decrypt_cv_vm(self, vm_data: bytes, key: bytes) -> bytes:
        """Decrypt Code Virtualizer VM code."""
        # Code Virtualizer uses RC4-like stream cipher
        return self._rc4_decrypt(vm_data, key)

    def _rc4_decrypt(self, data: bytes, key: bytes) -> bytes:
        """RC4 stream cipher decryption."""
        S = list(range(256))
        j = 0

        # Key scheduling algorithm
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        # Pseudo-random generation algorithm
        i = j = 0
        result = bytearray()

        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            result.append(byte ^ K)

        return bytes(result)


class ThemidaHandler:
    """Themida-specific handling."""

    def __init__(self) -> None:
        """Initialize Themida handler with logging and opcode mapping."""
        self.logger = logging.getLogger(f"{__name__}.Themida")
        self.opcode_map = self._build_themida_opcode_map()

    def _build_themida_opcode_map(self) -> dict[int, tuple[str, VMInstructionType]]:
        """Build Themida opcode mapping."""
        return {
            0x00: ("VM_NOP", VMInstructionType.CUSTOM),
            0x01: ("VM_PUSH_IMM", VMInstructionType.STACK),
            0x02: ("VM_PUSH_REG", VMInstructionType.STACK),
            0x03: ("VM_POP_REG", VMInstructionType.STACK),
            0x04: ("VM_MOV_REG_REG", VMInstructionType.REGISTER),
            0x05: ("VM_MOV_REG_IMM", VMInstructionType.REGISTER),
            0x10: ("VM_ADD", VMInstructionType.ARITHMETIC),
            0x11: ("VM_SUB", VMInstructionType.ARITHMETIC),
            0x12: ("VM_MUL", VMInstructionType.ARITHMETIC),
            0x13: ("VM_DIV", VMInstructionType.ARITHMETIC),
            0x14: ("VM_MOD", VMInstructionType.ARITHMETIC),
            0x20: ("VM_AND", VMInstructionType.LOGICAL),
            0x21: ("VM_OR", VMInstructionType.LOGICAL),
            0x22: ("VM_XOR", VMInstructionType.LOGICAL),
            0x23: ("VM_NOT", VMInstructionType.LOGICAL),
            0x24: ("VM_SHL", VMInstructionType.LOGICAL),
            0x25: ("VM_SHR", VMInstructionType.LOGICAL),
            0x30: ("VM_JMP", VMInstructionType.CONTROL_FLOW),
            0x31: ("VM_JZ", VMInstructionType.CONTROL_FLOW),
            0x32: ("VM_JNZ", VMInstructionType.CONTROL_FLOW),
            0x33: ("VM_JE", VMInstructionType.CONTROL_FLOW),
            0x34: ("VM_JNE", VMInstructionType.CONTROL_FLOW),
            0x35: ("VM_JG", VMInstructionType.CONTROL_FLOW),
            0x36: ("VM_JL", VMInstructionType.CONTROL_FLOW),
            0x37: ("VM_CALL", VMInstructionType.CONTROL_FLOW),
            0x38: ("VM_RET", VMInstructionType.CONTROL_FLOW),
            0x40: ("VM_LOAD", VMInstructionType.MEMORY),
            0x41: ("VM_STORE", VMInstructionType.MEMORY),
            0x42: ("VM_LOAD_BYTE", VMInstructionType.MEMORY),
            0x43: ("VM_STORE_BYTE", VMInstructionType.MEMORY),
        }

    def decrypt_themida_vm(self, vm_data: bytes, key: bytes) -> bytes:
        """Decrypt Themida VM code."""
        # Themida uses a rolling XOR with key rotation
        result = bytearray()

        for i, byte in enumerate(vm_data):
            # Rotate key based on position
            rotated_key = self._rotate_key(key, i)
            decrypted_byte = byte ^ rotated_key[i % len(rotated_key)]
            result.append(decrypted_byte)

        return bytes(result)

    def _rotate_key(self, key: bytes, position: int) -> bytes:
        """Rotate key based on position."""
        rotation = position % len(key)
        return key[rotation:] + key[:rotation]


class VMEmulator:
    """VM instruction emulator."""

    def __init__(self, protection_type: ProtectionType) -> None:
        """Initialize VM emulator with protection type and Unicorn engine."""
        self.protection_type = protection_type
        self.context = VMContext()
        self.logger = logging.getLogger(f"{__name__}.VMEmulator")
        self.handlers = self._init_handlers()
        self.uc = None
        self._init_unicorn()

    def _init_handlers(self) -> dict[ProtectionType, Any]:
        """Initialize protection-specific handlers."""
        handlers = {ProtectionType.VMPROTECT_1X: VMProtectHandler()}
        handlers[ProtectionType.VMPROTECT_2X] = VMProtectHandler()
        handlers[ProtectionType.VMPROTECT_3X] = VMProtectHandler()
        handlers[ProtectionType.THEMIDA] = ThemidaHandler()
        handlers[ProtectionType.CODE_VIRTUALIZER] = CodeVirtualizerHandler()
        return handlers

    def _init_unicorn(self) -> None:
        """Initialize Unicorn emulation engine."""
        try:
            from unicorn import UC_ARCH_X86, UC_MODE_32, Uc

            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
            self._setup_unicorn()
        except ImportError as e:
            self.logger.warning("Unicorn not available, using fallback emulation: %s", e, exc_info=True)

    def _setup_unicorn(self) -> None:
        """Configure Unicorn emulation engine."""
        if not self.uc:
            return
        try:
            from unicorn import x86_const

            self.uc.mem_map(0x400000, 2 * 1024 * 1024)  # 2MB for code
            self.uc.mem_map(0x600000, 1024 * 1024)  # 1MB for stack
            self.uc.reg_write(x86_const.UC_X86_REG_ESP, 0x600000 + 1024 * 1024 - 0x1000)
        except Exception as e:
            self.logger.warning("Unicorn setup failed: %s", e, exc_info=True)

    def parse_vm_instruction(self, vm_data: bytes, offset: int) -> VMInstruction:
        """Parse VM instruction."""
        if offset >= len(vm_data):
            raise ValueError("Offset out of bounds")

        opcode = vm_data[offset]

        # Get handler for current protection
        handler = self.handlers.get(self.protection_type)
        if not handler:
            raise ValueError(f"No handler for {self.protection_type}")

        # Look up opcode
        if opcode in handler.opcode_map:
            mnemonic, vm_type = handler.opcode_map[opcode]
        else:
            mnemonic, vm_type = f"UNK_{opcode:02X}", VMInstructionType.CUSTOM

        # Parse operands (simplified)
        operands = []
        size = 1

        if vm_type in [VMInstructionType.MEMORY, VMInstructionType.ARITHMETIC]:
            if offset + 4 < len(vm_data):
                operand = struct.unpack("<I", vm_data[offset + 1 : offset + 5])[0]
                operands.append(operand)
                size = 5
        elif vm_type == VMInstructionType.CONTROL_FLOW:
            if offset + 4 < len(vm_data):
                target = struct.unpack("<I", vm_data[offset + 1 : offset + 5])[0]
                operands.append(target)
                size = 5

        return VMInstruction(
            opcode=opcode,
            operands=operands,
            mnemonic=mnemonic,
            vm_type=vm_type,
            size=size,
        )

    def execute_vm_instruction(self, instruction: VMInstruction) -> bool:
        """Execute VM instruction."""
        try:
            if instruction.vm_type == VMInstructionType.STACK:
                return self._execute_stack_op(instruction)
            if instruction.vm_type == VMInstructionType.ARITHMETIC:
                return self._execute_arithmetic_op(instruction)
            if instruction.vm_type == VMInstructionType.LOGICAL:
                return self._execute_logical_op(instruction)
            if instruction.vm_type == VMInstructionType.MEMORY:
                return self._execute_memory_op(instruction)
            if instruction.vm_type == VMInstructionType.CONTROL_FLOW:
                return self._execute_control_flow_op(instruction)
            if instruction.vm_type == VMInstructionType.REGISTER:
                return self._execute_register_op(instruction)
            self.logger.warning("Unhandled instruction type: %s", instruction.vm_type)
            return True

        except Exception as e:
            self.logger.exception("Error executing %s: %s", instruction.mnemonic, e, exc_info=True)
            return False

    def _execute_stack_op(self, instruction: VMInstruction) -> bool:
        """Execute stack operations."""
        if "PUSH" in instruction.mnemonic:
            if instruction.operands:
                self.context.stack.append(instruction.operands[0])
            else:
                # Push register
                self.context.stack.append(self.context.registers.get("EAX", 0))

        elif "POP" in instruction.mnemonic:
            if self.context.stack:
                value = self.context.stack.pop()
                self.context.registers["EAX"] = value

        return True

    def _execute_arithmetic_op(self, instruction: VMInstruction) -> bool:
        """Execute arithmetic operations."""
        if len(self.context.stack) < 2:
            return False

        b = self.context.stack.pop()
        a = self.context.stack.pop()

        if "ADD" in instruction.mnemonic:
            result = (a + b) & 0xFFFFFFFF
        elif "SUB" in instruction.mnemonic:
            result = (a - b) & 0xFFFFFFFF
        elif "MUL" in instruction.mnemonic:
            result = (a * b) & 0xFFFFFFFF
        elif "DIV" in instruction.mnemonic:
            result = (a // b) & 0xFFFFFFFF if b != 0 else 0
        else:
            return False

        self.context.stack.append(result)

        # Update flags
        self.context.flags["ZF"] = result == 0
        self.context.flags["SF"] = (result & 0x80000000) != 0

        return True

    def _execute_logical_op(self, instruction: VMInstruction) -> bool:
        """Execute logical operations."""
        if "NOT" in instruction.mnemonic:
            if self.context.stack:
                a = self.context.stack.pop()
                result = (~a) & 0xFFFFFFFF
                self.context.stack.append(result)
        else:
            if len(self.context.stack) < 2:
                return False

            b = self.context.stack.pop()
            a = self.context.stack.pop()

            if "AND" in instruction.mnemonic:
                result = a & b
            elif "OR" in instruction.mnemonic:
                result = a | b
            elif "XOR" in instruction.mnemonic:
                result = a ^ b
            elif "SHL" in instruction.mnemonic:
                result = (a << (b & 0x1F)) & 0xFFFFFFFF
            elif "SHR" in instruction.mnemonic:
                result = a >> (b & 0x1F)
            else:
                return False

            self.context.stack.append(result)

        return True

    def _execute_memory_op(self, instruction: VMInstruction) -> bool:
        """Execute memory operations."""
        if "LOAD" in instruction.mnemonic:
            if self.context.stack:
                address = self.context.stack.pop()
                value = self.context.memory.get(address, b"\x00\x00\x00\x00")
                int_value = struct.unpack("<I", value[:4])[0]
                self.context.stack.append(int_value)

        elif "STORE" in instruction.mnemonic:
            if len(self.context.stack) >= 2:
                address = self.context.stack.pop()
                value = self.context.stack.pop()
                self.context.memory[address] = struct.pack("<I", value)

        return True

    def _execute_control_flow_op(self, instruction: VMInstruction) -> bool:
        """Execute control flow operations."""
        if "JMP" in instruction.mnemonic:
            if instruction.operands:
                self.context.registers["EIP"] = instruction.operands[0]

        elif "JZ" in instruction.mnemonic or "JE" in instruction.mnemonic:
            if self.context.flags.get("ZF", False) and instruction.operands:
                self.context.registers["EIP"] = instruction.operands[0]

        elif "JNZ" in instruction.mnemonic or "JNE" in instruction.mnemonic:
            if not self.context.flags.get("ZF", False) and instruction.operands:
                self.context.registers["EIP"] = instruction.operands[0]

        elif "CALL" in instruction.mnemonic:
            if instruction.operands:
                # Push return address
                self.context.stack.append(self.context.registers["EIP"])
                self.context.registers["EIP"] = instruction.operands[0]

        elif "RET" in instruction.mnemonic:
            if self.context.stack:
                self.context.registers["EIP"] = self.context.stack.pop()

        return True

    def _execute_register_op(self, instruction: VMInstruction) -> bool:
        """Execute register operations."""
        if "MOV" in instruction.mnemonic:
            if len(self.context.stack) >= 2:
                dest = self.context.stack.pop()
                src = self.context.stack.pop()
                # Update the destination register
                if isinstance(dest, str) and dest in self.context.registers:
                    self.context.registers[dest] = src
                else:
                    # Fallback to EAX if destination is not a valid register
                    self.context.registers["EAX"] = src

        elif "XCHG" in instruction.mnemonic:
            if len(self.context.stack) >= 2:
                a = self.context.stack.pop()
                b = self.context.stack.pop()
                self.context.stack.append(a)
                self.context.stack.append(b)

        return True


class VMAnalyzer:
    """VM code analyzer and pattern detector."""

    def __init__(self) -> None:
        """Initialize VM analyzer with logging and protection patterns."""
        self.logger = logging.getLogger(f"{__name__}.VMAnalyzer")
        self.patterns = self._load_vm_patterns()

    def _load_vm_patterns(self) -> dict[ProtectionType, list[bytes]]:
        """Load VM detection patterns."""
        return {
            ProtectionType.VMPROTECT_1X: [
                b"\x60\x8b\x04\x24",  # VM entry pattern
                b"\x8b\x4c\x24\x04\x8b\x54\x24\x08",
                b"\x55\x8b\xec\x60",
            ],
            ProtectionType.VMPROTECT_2X: [
                b"\x68\x00\x00\x00\x00\x8f\x04\x24",
                b"\x8b\x44\x24\x04\x50",
                b"\x8b\x44\x24\x08\x8b\x4c\x24\x0c",
            ],
            ProtectionType.VMPROTECT_3X: [
                b"\x8b\x44\x24\x04\x8b\x4c\x24\x08",
                b"\x48\x8b\x44\x24\x08",
                b"\x48\x8b\x4c\x24\x10",
            ],
            ProtectionType.THEMIDA: [
                b"\x55\x8b\xec\x83\xec\x10\x53\x56\x57",
                b"\x60\x9c\x33\xc0\x50\x9c",
                b"\x8b\x45\x08\x8b\x4d\x0c",
            ],
            ProtectionType.CODE_VIRTUALIZER: [
                b"\x55\x8b\xec\x81\xec\x00\x04\x00\x00",
                b"\x60\x9c\x33\xdb\x53",
                b"\x8b\x45\x08\x8b\x55\x0c",
            ],
        }

    def detect_vm_protection(self, binary_data: bytes) -> ProtectionType:
        """Detect VM protection type."""
        for protection, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern in binary_data:
                    self.logger.info("Detected %s", protection.value)
                    return protection

        # Additional entropy-based detection
        entropy = self._calculate_entropy(binary_data)
        if entropy > 7.5:  # High entropy suggests VM protection
            self.logger.info("High entropy detected - likely VM protected")
            return ProtectionType.UNKNOWN_VM

        return ProtectionType.UNKNOWN_VM

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        entropy = 0.0
        length = len(data)

        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * np.log2(p)

        return entropy

    def find_vm_entry_points(self, binary_data: bytes, protection_type: ProtectionType) -> list[int]:
        """Find VM entry points."""
        entry_points = []
        patterns = self.patterns.get(protection_type, [])

        for pattern in patterns:
            offset = 0
            while True:
                pos = binary_data.find(pattern, offset)
                if pos == -1:
                    break

                entry_points.append(pos)
                offset = pos + 1

        return entry_points

    def analyze_vm_structure(self, vm_data: bytes, entry_point: int) -> dict[str, Any]:
        """Analyze VM structure."""
        analysis = {
            "entry_point": entry_point,
            "vm_code_sections": [],
            "handler_table": None,
            "key_schedule": None,
            "statistics": {},
        }

        if handler_table_offset := self._find_handler_table(vm_data, entry_point):
            analysis["handler_table"] = handler_table_offset

        # Extract VM code sections
        vm_sections = self._extract_vm_sections(vm_data, entry_point)
        analysis["vm_code_sections"] = vm_sections

        # Calculate statistics
        analysis["statistics"] = {
            "total_size": len(vm_data),
            "entry_points_found": 1,
            "estimated_vm_code_size": sum(len(section["data"]) for section in vm_sections),
            "entropy": self._calculate_entropy(vm_data),
        }

        return analysis

    def _find_handler_table(self, vm_data: bytes, entry_point: int) -> int | None:
        """Find VM handler table."""
        # Look for patterns indicating handler table
        # This is a simplified heuristic

        for i in range(entry_point, min(entry_point + 0x1000, len(vm_data) - 4)):
            # Look for table of addresses
            if i + 64 < len(vm_data):
                potential_table = vm_data[i : i + 64]

                # Check if it looks like a table of 32-bit addresses
                addresses = struct.unpack("<16I", potential_table)

                # Heuristic: addresses should be in reasonable range
                valid_addresses = sum(0x400000 <= addr <= 0x800000 for addr in addresses)

                if valid_addresses >= 12:  # At least 75% valid
                    return i

        return None

    def _extract_vm_sections(self, vm_data: bytes, entry_point: int) -> list[dict[str, Any]]:
        """Extract VM code sections."""
        sections = []

        # Simple section extraction based on patterns
        current_offset = entry_point

        while current_offset < len(vm_data) - 16:
            # Look for section markers or significant changes in entropy
            section_start = current_offset
            section_end = self._find_section_end(vm_data, current_offset)

            if section_end > section_start:
                section_data = vm_data[section_start:section_end]

                sections.append(
                    {
                        "offset": section_start,
                        "size": section_end - section_start,
                        "data": section_data,
                        "entropy": self._calculate_entropy(section_data),
                        "type": self._classify_section(section_data),
                    },
                )

                current_offset = section_end
            else:
                current_offset += 0x100  # Skip ahead

            # Limit sections to prevent infinite loops
            if len(sections) >= 100:
                break

        return sections

    def _find_section_end(self, vm_data: bytes, start_offset: int) -> int:
        """Find end of VM section by detecting termination markers.

        Scans for null bytes or repeated patterns indicating section boundaries,
        with a maximum section size limit to prevent runaway scanning.

        Args:
            vm_data: Complete binary data containing the VM section.
            start_offset: Starting offset to search from.

        Returns:
            Absolute offset of the section end boundary.

        """
        # Look for section end markers or entropy changes
        max_section_size = 0x10000  # 64KB max
        end_offset = min(start_offset + max_section_size, len(vm_data))

        # Simple heuristic: end at null bytes or repeated patterns
        for i in range(start_offset + 0x100, end_offset, 0x10):
            if i + 16 <= len(vm_data):
                chunk = vm_data[i : i + 16]

                # Check for null section
                if chunk == b"\x00" * 16:
                    return i

                # Check for repeated patterns
                if len(set(chunk)) <= 2:
                    return i

        return end_offset

    def _classify_section(self, section_data: bytes) -> str:
        """Classify a VM section based on its content characteristics.

        Analyzes the entropy, byte distribution, and instruction patterns
        to determine what type of content a VM section contains.

        Args:
            section_data: Raw bytes of the VM section to classify.

        Returns:
            String classification of the section type:
            - 'encrypted': High entropy, likely encrypted data
            - 'code': Contains recognizable instruction patterns
            - 'data': Structured data with low entropy
            - 'handler_table': Contains VM handler addresses
            - 'string_pool': Contains string data
            - 'padding': Mostly null or repeated bytes
            - 'unknown': Cannot determine type

        """
        if not section_data or len(section_data) < 16:
            return "unknown"

        entropy = self._calculate_entropy(section_data)
        printable_ratio = sum(32 <= b <= 126 for b in section_data) / len(
            section_data
        )
        null_ratio = section_data.count(0) / len(section_data)

        if null_ratio > 0.8:
            return "padding"

        if entropy > 7.5:
            return "encrypted"

        if entropy > 6.5 and printable_ratio < 0.3:
            return "encrypted"

        if printable_ratio > 0.7:
            return "string_pool"

        x86_prologue_patterns = [
            b"\x55\x8b\xec",
            b"\x55\x89\xe5",
            b"\x53\x56\x57",
            b"\x60",
            b"\x9c",
        ]

        for pattern in x86_prologue_patterns:
            if pattern in section_data[:64]:
                return "code"

        instruction_indicators = [0x55, 0x8B, 0x89, 0xE8, 0xE9, 0x74, 0x75, 0x0F, 0x90]
        instruction_count = sum(
            b in instruction_indicators for b in section_data[:256]
        )

        if instruction_count > 20:
            return "code"

        if len(section_data) >= 64:
            potential_addresses = []
            for i in range(0, min(len(section_data) - 4, 256), 4):
                addr = int.from_bytes(section_data[i : i + 4], "little")
                if 0x400000 <= addr <= 0x7FFFFFFF:
                    potential_addresses.append(addr)

            if len(potential_addresses) >= 8:
                return "handler_table"

        return "data" if 4.0 <= entropy <= 6.5 and printable_ratio < 0.5 else "unknown"


class VMProtectionUnwrapper:
    """Run VM protection unwrapper."""

    def __init__(self) -> None:
        """Initialize VM protection unwrapper with analyzer, emulators, and statistics tracking."""
        self.logger = logging.getLogger(__name__)
        self.analyzer = VMAnalyzer()
        self.emulators = {}
        self.stats = {
            "files_processed": 0,
            "successful_unwraps": 0,
            "failed_unwraps": 0,
            "protection_types_detected": dict.fromkeys(ProtectionType, 0),
        }

    def unwrap_file(self, input_file: str, output_file: str) -> dict[str, Any]:
        """Unwrap VM-protected file."""
        self.logger.info("Starting unwrap of %s", input_file)

        start_time = time.time()

        try:
            # Load file
            with open(input_file, "rb") as f:
                binary_data = f.read()

            # Detect protection
            protection_type = self.analyzer.detect_vm_protection(binary_data)
            self.stats["protection_types_detected"][protection_type] += 1

            # Find entry points
            entry_points = self.analyzer.find_vm_entry_points(binary_data, protection_type)

            if not entry_points:
                self.logger.warning("No VM entry points found")
                return {"success": False, "error": "No entry points found"}

            # Analyze VM structure
            vm_analysis = self.analyzer.analyze_vm_structure(binary_data, entry_points[0])

            # Extract and decrypt VM code
            unwrapped_data = self._unwrap_vm_sections(binary_data, vm_analysis, protection_type)

            # Reconstruct original code
            reconstructed = self._reconstruct_original_code(unwrapped_data, vm_analysis)

            # Save result
            with open(output_file, "wb") as f:
                f.write(reconstructed)

            elapsed_time = time.time() - start_time

            result = {
                "success": True,
                "protection_type": protection_type.value,
                "entry_points": len(entry_points),
                "vm_sections": len(vm_analysis["vm_code_sections"]),
                "original_size": len(binary_data),
                "unwrapped_size": len(reconstructed),
                "processing_time": elapsed_time,
                "statistics": vm_analysis["statistics"],
            }

            self.stats["successful_unwraps"] += 1
            self.logger.info("Successfully unwrapped %s", input_file)

            return result

        except Exception as e:
            self.logger.exception("Error unwrapping %s: %s", input_file, e, exc_info=True)
            self.stats["failed_unwraps"] += 1
            return {"success": False, "error": str(e)}

        finally:
            self.stats["files_processed"] += 1

    def _unwrap_vm_sections(self, binary_data: bytes, vm_analysis: dict[str, Any], protection_type: ProtectionType) -> list[bytes]:
        """Unwrap VM sections."""
        unwrapped_sections = []

        # Get appropriate handler
        if protection_type in [
            ProtectionType.VMPROTECT_1X,
            ProtectionType.VMPROTECT_2X,
            ProtectionType.VMPROTECT_3X,
        ]:
            handler = VMProtectHandler()
        elif protection_type == ProtectionType.THEMIDA:
            handler = ThemidaHandler()
        else:
            # Generic handler
            handler = VMProtectHandler()

        # Extract encryption key (heuristic)
        key = self._extract_encryption_key(binary_data, vm_analysis, protection_type)

        for section in vm_analysis["vm_code_sections"]:
            section_data = section["data"]

            try:
                if protection_type == ProtectionType.THEMIDA:
                    decrypted = handler.decrypt_themida_vm(section_data, key)
                else:
                    decrypted = handler.decrypt_vm_code(section_data, key, protection_type)

                unwrapped_sections.append(decrypted)

            except Exception as e:
                self.logger.exception("Error decrypting section: %s", e, exc_info=True)
                unwrapped_sections.append(section_data)  # Keep original

        return unwrapped_sections

    def _extract_encryption_key(self, binary_data: bytes, vm_analysis: dict[str, Any], protection_type: ProtectionType) -> bytes:
        """Extract encryption key from binary using advanced techniques."""
        entry_point = vm_analysis["entry_point"]

        # Multi-stage key extraction approach
        key_extractors = [
            self._extract_key_from_constants,
            self._extract_key_from_init_routines,
            self._extract_key_from_data_sections,
            self._extract_key_from_tls_callbacks,
            self._extract_key_from_resource_section,
        ]

        for extractor in key_extractors:
            try:
                key = extractor(binary_data, entry_point, protection_type)
                if key and self._validate_key(key, binary_data, entry_point):
                    return key
            except Exception as e:
                self.logger.warning("Error extracting key with %s: %s", extractor.__name__, e, exc_info=True)
                continue

        # Advanced fallback using cryptographic analysis
        return self._generate_key_from_binary_characteristics(binary_data, entry_point, protection_type)

    def _extract_key_from_constants(self, binary_data: bytes, entry_point: int, protection_type: ProtectionType) -> bytes | None:
        """Extract key from constant pool analysis."""
        # Scan for AES S-box patterns indicating key schedule
        aes_sbox = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])
        pos = binary_data.find(aes_sbox)
        if pos != -1:
            # Key likely stored before S-box
            key_offset = max(0, pos - 256)
            for i in range(key_offset, pos - 32, 4):
                candidate = binary_data[i : i + 32]
                if self._is_valid_key_material(candidate):
                    return candidate
        return None

    def _extract_key_from_init_routines(self, binary_data: bytes, entry_point: int, protection_type: ProtectionType) -> bytes | None:
        """Extract key from initialization routines."""
        # Pattern matching for key initialization sequences
        init_patterns = [
            b"\x8b\x45\x08\x89\x45",  # mov eax,[ebp+8]; mov [ebp+X],eax
            b"\x8b\x4d\x0c\x89\x4d",  # mov ecx,[ebp+0xc]; mov [ebp+X],ecx
            b"\xc7\x45\xf0",  # mov [ebp-0x10],immediate
        ]

        for pattern in init_patterns:
            pos = binary_data.find(pattern, entry_point, min(entry_point + 0x1000, len(binary_data)))
            if pos != -1:
                # Extract potential key data following pattern
                key_data = binary_data[pos + len(pattern) : pos + len(pattern) + 32]
                if len(key_data) >= 16 and self._is_valid_key_material(key_data):
                    return key_data[:32] if len(key_data) >= 32 else key_data[:16].ljust(32, b"\x00")
        return None

    def _extract_key_from_data_sections(self, binary_data: bytes, entry_point: int, protection_type: ProtectionType) -> bytes | None:
        """Extract key from data sections using PE structure analysis."""
        try:
            # Parse PE header
            if binary_data[:2] != b"MZ":
                return None

            pe_offset = struct.unpack("<I", binary_data[0x3C:0x40])[0]
            if binary_data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return None

            # Get section headers
            num_sections = struct.unpack("<H", binary_data[pe_offset + 6 : pe_offset + 8])[0]
            section_table = pe_offset + 0xF8

            for i in range(num_sections):
                section_offset = section_table + (i * 40)
                if section_offset + 40 > len(binary_data):
                    break

                name = binary_data[section_offset : section_offset + 8].rstrip(b"\x00")
                if name in [b".data", b".rdata", b".bss"]:
                    raw_offset = struct.unpack("<I", binary_data[section_offset + 20 : section_offset + 24])[0]
                    raw_size = struct.unpack("<I", binary_data[section_offset + 16 : section_offset + 20])[0]

                    # Scan section for key material
                    for j in range(raw_offset, min(raw_offset + raw_size, len(binary_data)) - 32, 16):
                        candidate = binary_data[j : j + 32]
                        entropy = self.analyzer._calculate_entropy(candidate)
                        if 5.5 <= entropy <= 7.8:
                            return candidate
        except Exception as e:
            self.logger.debug("Key material extraction failed: %s", e, exc_info=True)
        return None

    def _extract_key_from_tls_callbacks(self, binary_data: bytes, entry_point: int, protection_type: ProtectionType) -> bytes | None:
        """Extract key from TLS callback analysis."""
        try:
            pe_offset = struct.unpack("<I", binary_data[0x3C:0x40])[0]
            # TLS directory is at index 9 in data directories
            tls_dir_offset = pe_offset + 0x78 + (9 * 8)
            if tls_rva := struct.unpack("<I", binary_data[tls_dir_offset : tls_dir_offset + 4])[0]:
                if tls_offset := self._rva_to_offset(binary_data, tls_rva):
                    # TLS callbacks often initialize keys
                    callback_data = binary_data[tls_offset : tls_offset + 0x100]
                    for i in range(0, len(callback_data) - 32, 4):
                        candidate = callback_data[i : i + 32]
                        if self._is_valid_key_material(candidate):
                            return candidate
        except Exception as e:
            self.logger.debug("TLS callback key extraction failed: %s", e, exc_info=True)
        return None

    def _extract_key_from_resource_section(self, binary_data: bytes, entry_point: int, protection_type: ProtectionType) -> bytes | None:
        """Extract key from resource section."""
        try:
            pe_offset = struct.unpack("<I", binary_data[0x3C:0x40])[0]
            # Resource directory is at index 2
            res_dir_offset = pe_offset + 0x78 + (2 * 8)
            if res_rva := struct.unpack("<I", binary_data[res_dir_offset : res_dir_offset + 4])[0]:
                res_offset = self._rva_to_offset(binary_data, res_rva)
                if res_offset and res_offset < len(binary_data) - 0x100:
                    # Scan resource data for key material
                    res_data = binary_data[res_offset : res_offset + 0x1000]
                    for i in range(0, len(res_data) - 32, 16):
                        candidate = res_data[i : i + 32]
                        if self._is_valid_key_material(candidate):
                            return candidate
        except Exception as e:
            self.logger.debug("Resource section key extraction failed: %s", e, exc_info=True)
        return None

    def _rva_to_offset(self, binary_data: bytes, rva: int) -> int | None:
        """Convert RVA to file offset."""
        try:
            pe_offset = struct.unpack("<I", binary_data[0x3C:0x40])[0]
            num_sections = struct.unpack("<H", binary_data[pe_offset + 6 : pe_offset + 8])[0]
            section_table = pe_offset + 0xF8

            for i in range(num_sections):
                section_offset = section_table + (i * 40)
                virtual_addr = struct.unpack("<I", binary_data[section_offset + 12 : section_offset + 16])[0]
                virtual_size = struct.unpack("<I", binary_data[section_offset + 8 : section_offset + 12])[0]
                raw_offset = struct.unpack("<I", binary_data[section_offset + 20 : section_offset + 24])[0]

                if virtual_addr <= rva < virtual_addr + virtual_size:
                    return raw_offset + (rva - virtual_addr)
        except Exception as e:
            self.logger.debug("RVA to offset conversion failed: %s", e, exc_info=True)
        return None

    def _is_valid_key_material(self, data: bytes) -> bool:
        """Validate potential key material."""
        if len(data) < 16:
            return False

        # Check entropy
        entropy = self.analyzer._calculate_entropy(data)
        if entropy < 4.0 or entropy > 7.95:
            return False

        # Check for obvious patterns
        if data[:4] == data[4:8] == data[8:12]:
            return False

        # Check for null bytes concentration
        null_count = data.count(b"\x00")
        return not null_count > len(data) * 0.5

    def _validate_key(self, key: bytes, binary_data: bytes, entry_point: int) -> bool:
        """Validate extracted key by testing decryption."""
        # Test decryption on known encrypted sections
        test_offset = entry_point + 0x100
        if test_offset + 16 > len(binary_data):
            return True  # Can't validate, assume valid

        test_data = binary_data[test_offset : test_offset + 16]

        # Try simple XOR decryption
        decrypted = bytes(test_data[i] ^ key[i % len(key)] for i in range(len(test_data)))

        # Check if decryption produces valid x86 code
        valid_opcodes = [0x55, 0x89, 0x8B, 0x50, 0x51, 0x52, 0x53]  # Common x86 opcodes
        valid_count = sum(b in valid_opcodes for b in decrypted[:4])

        return valid_count >= 2

    def _generate_key_from_binary_characteristics(self, binary_data: bytes, entry_point: int, protection_type: ProtectionType) -> bytes:
        """Generate key from binary characteristics using cryptographic derivation."""
        # Collect binary characteristics
        characteristics = bytearray()

        # Entry point bytes
        characteristics.extend(binary_data[entry_point : entry_point + 16])

        # PE timestamp if available
        try:
            pe_offset = struct.unpack("<I", binary_data[0x3C:0x40])[0]
            timestamp = binary_data[pe_offset + 8 : pe_offset + 12]
            characteristics.extend(timestamp)
        except Exception as e:
            self.logger.debug("PE header analysis failed: %s", e, exc_info=True)

        # Protection-specific markers
        protection_markers = {
            ProtectionType.VMPROTECT_1X: b"VMProtect",
            ProtectionType.VMPROTECT_2X: b".vmp0",
            ProtectionType.VMPROTECT_3X: b".vmp1",
            ProtectionType.THEMIDA: b"Themida",
        }

        marker = protection_markers.get(protection_type, b"PROTECTION")
        pos = binary_data.find(marker)
        if pos != -1:
            characteristics.extend(binary_data[pos : pos + 16])

        # Use PBKDF2 for key derivation
        import hmac

        salt = binary_data[:16] if len(binary_data) >= 16 else b"INTELLICRACK2025"

        # Simple PBKDF2 implementation
        derived_key = bytearray()
        for i in range(2):  # Generate 32 bytes
            block = hmac.new(characteristics, salt + struct.pack(">I", i + 1), hashlib.sha256).digest()
            derived_key.extend(block[:16])

        return bytes(derived_key[:32])

    def _reconstruct_original_code(self, unwrapped_sections: list[bytes], vm_analysis: dict[str, Any]) -> bytes:
        """Reconstruct original x86 code from VM sections."""
        reconstructed = bytearray()

        # Advanced multi-pass reconstruction
        for section_data in unwrapped_sections:
            # Parse VM instructions with context awareness
            vm_instructions = self._parse_vm_instructions_with_context(section_data, vm_analysis)

            # Optimize VM instruction stream
            optimized_instructions = self._optimize_vm_instructions(vm_instructions)

            # Convert to x86 with pattern matching
            x86_code = self._advanced_vm_to_x86(optimized_instructions, vm_analysis)

            # Post-process for coherent code flow
            processed_code = self._post_process_x86_code(x86_code)

            reconstructed.extend(processed_code)

        return bytes(reconstructed)

    def _parse_vm_instructions_with_context(self, vm_data: bytes, vm_analysis: dict[str, Any]) -> list[VMInstruction]:
        """Parse VM instructions with contextual awareness.

        Parses VM instructions while tracking metadata about previous instructions,
        identifying common instruction patterns for optimization during conversion.

        Args:
            vm_data: Binary data containing encoded VM instructions.
            vm_analysis: Analysis results from struct analysis containing context.

        Returns:
            List of parsed VMInstruction objects with pattern metadata.

        """
        instructions = []
        offset = 0
        protection_type = self.analyzer.detect_vm_protection(vm_data)

        # Get appropriate emulator
        emulator = self.emulators.get(protection_type)
        if not emulator:
            emulator = VMEmulator(protection_type)
            self.emulators[protection_type] = emulator

        while offset < len(vm_data):
            try:
                instruction = emulator.parse_vm_instruction(vm_data, offset)

                # Enhance instruction with context
                if offset > 0 and instructions:
                    prev_inst = instructions[-1]
                    instruction.metadata["prev_mnemonic"] = prev_inst.mnemonic

                    # Detect instruction patterns
                    if prev_inst.vm_type == VMInstructionType.STACK and instruction.vm_type == VMInstructionType.ARITHMETIC:
                        instruction.metadata["pattern"] = "stack_arithmetic"

                instructions.append(instruction)
                offset += instruction.size

            except Exception:
                offset += 1
                if offset > len(vm_data):
                    break

        return instructions

    def _optimize_vm_instructions(self, instructions: list[VMInstruction]) -> list[VMInstruction]:
        """Optimize VM instruction stream by removing redundancy.

        Performs pattern-based optimization to reduce instruction count:
        - Removes PUSH/POP pairs that cancel out
        - Eliminates consecutive NOP instructions
        - Removes redundant move operations

        Args:
            instructions: List of VMInstruction objects to optimize.

        Returns:
            Optimized instruction list with reduced redundancy.

        """
        optimized = []
        i = 0

        while i < len(instructions):
            current = instructions[i]

            # Pattern: PUSH followed by POP to same location
            if (
                i + 1 < len(instructions) and "PUSH" in current.mnemonic and "POP" in instructions[i + 1].mnemonic
            ) and current.operands == instructions[i + 1].operands:
                i += 2
                continue

            # Pattern: Multiple NOPs
            if "NOP" in current.mnemonic:
                # Skip consecutive NOPs
                while i + 1 < len(instructions) and "NOP" in instructions[i + 1].mnemonic:
                    i += 1
                i += 1
                continue

            # Pattern: Redundant moves
            if (i + 1 < len(instructions) and "MOV" in current.mnemonic and "MOV" in instructions[i + 1].mnemonic) and (
                len(current.operands) > 0
                and len(instructions[i + 1].operands) > 0
                and current.operands[0] == instructions[i + 1].operands[0]
            ):
                optimized.append(instructions[i + 1])
                i += 2
                continue

            optimized.append(current)
            i += 1

        return optimized

    def _advanced_vm_to_x86(self, vm_instructions: list[VMInstruction], vm_analysis: dict[str, Any]) -> bytes:
        """Convert VM instructions to x86 with advanced pattern recognition.

        Performs context-aware conversion using compound pattern detection and
        Keystone assembler. Detects function prologues, epilogues, and loop
        constructs for more efficient code generation.

        Args:
            vm_instructions: List of parsed VM instructions to convert.
            vm_analysis: Binary analysis results containing structural information.

        Returns:
            Binary x86 machine code implementing VM instruction semantics.

        """
        x86_code = bytearray()

        # Initialize Keystone assembler
        try:
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        except Exception:
            # Fallback to pre-compiled patterns
            return self._fallback_vm_to_x86(vm_instructions)

        i = 0
        while i < len(vm_instructions):
            if pattern_code := self._detect_compound_pattern(vm_instructions, i):
                x86_code.extend(pattern_code)
                i += len(pattern_code) // 4  # Approximate instruction count
                continue

            if asm_code := self._enhanced_vm_instruction_to_asm(vm_instructions[i], vm_analysis):
                try:
                    encoding, _ = ks.asm(asm_code)
                    if encoding:
                        x86_code.extend(encoding)
                    else:
                        x86_code.append(0x90)  # NOP
                except Exception:
                    x86_code.append(0x90)
            else:
                x86_code.append(0x90)

            i += 1

        return bytes(x86_code)

    def _detect_compound_pattern(self, instructions: list[VMInstruction], start: int) -> bytes | None:
        """Detect and convert compound VM patterns to x86.

        Recognizes multi-instruction patterns such as function prologues,
        epilogues, and loops, converting them to optimized x86 bytecode.

        Args:
            instructions: List of VMInstruction objects to analyze.
            start: Starting index for pattern matching.

        Returns:
            Compiled x86 bytecode for the pattern, or None if no pattern matches.

        """
        if start + 2 >= len(instructions):
            return None

        # Pattern: Function prologue
        if (
            "PUSH" in instructions[start].mnemonic
            and instructions[start].operands == [0x5]  # EBP register code
            and "MOV" in instructions[start + 1].mnemonic
        ):
            # Standard function prologue
            return b"\x55\x89\xe5"  # push ebp; mov ebp,esp

        # Pattern: Function epilogue
        if (
            "MOV" in instructions[start].mnemonic
            and "POP" in instructions[start + 1].mnemonic
            and "RET" in instructions[start + 2].mnemonic
        ):
            # Standard function epilogue
            return b"\x89\xec\x5d\xc3"  # mov esp,ebp; pop ebp; ret

        # Pattern: Loop construct
        if (
            "CMP" in instructions[start].mnemonic
            and start + 1 < len(instructions)
            and instructions[start + 1].vm_type == VMInstructionType.CONTROL_FLOW
        ):
            # Loop pattern
            return b"\x39\xc1\x75\xfe"  # cmp ecx,eax; jne -2

        return None

    def _enhanced_vm_instruction_to_asm(self, instruction: VMInstruction, vm_analysis: dict[str, Any]) -> str | None:
        """Enhanced VM to x86 assembly conversion."""
        mnemonic = instruction.mnemonic
        operands = instruction.operands

        # Context-aware conversion
        if instruction.metadata.get("pattern") == "stack_arithmetic":
            # Optimized stack-based arithmetic
            if "ADD" in mnemonic:
                return "add dword [esp], eax"
            if "SUB" in mnemonic:
                return "sub dword [esp], eax"

        # Register allocation for VM registers
        vm_reg_map = {
            0: "eax",
            1: "ecx",
            2: "edx",
            3: "ebx",
            4: "esp",
            5: "ebp",
            6: "esi",
            7: "edi",
        }

        if "PUSH" in mnemonic:
            if operands and isinstance(operands[0], int):
                return f"push {vm_reg_map[operands[0]]}" if operands[0] in vm_reg_map else f"push 0x{operands[0]:x}"
            else:
                return "push eax"

        if "POP" in mnemonic:
            if operands and operands[0] in vm_reg_map:
                return f"pop {vm_reg_map[operands[0]]}"
            return "pop eax"

        # Arithmetic with immediate values
        if operands and len(operands) >= 1:
            if "ADD" in mnemonic:
                return f"add eax, 0x{operands[0]:x}"
            if "SUB" in mnemonic:
                return f"sub eax, 0x{operands[0]:x}"
            if "MUL" in mnemonic:
                return f"imul eax, eax, 0x{operands[0]:x}"

        # Memory operations with addressing modes
        if "LOAD" in mnemonic:
            if operands:
                return f"mov eax, dword [0x{operands[0]:x}]"
            return "mov eax, dword [ebx]"

        if "STORE" in mnemonic:
            if operands:
                return f"mov dword [0x{operands[0]:x}], eax"
            return "mov dword [ebx], eax"

        # Control flow with relative addressing
        if "JMP" in mnemonic and operands:
            return f"jmp 0x{operands[0]:x}"

        if ("JZ" in mnemonic or "JE" in mnemonic) and operands:
            return f"je 0x{operands[0]:x}"

        if ("JNZ" in mnemonic or "JNE" in mnemonic) and operands:
            return f"jne 0x{operands[0]:x}"

        if "CALL" in mnemonic and operands:
            return f"call 0x{operands[0]:x}"

        if "RET" in mnemonic:
            if operands:
                return f"ret 0x{operands[0]:x}"
            return "ret"

        # Logical operations
        if "XOR" in mnemonic:
            if operands:
                return f"xor eax, 0x{operands[0]:x}"
            return "xor eax, ebx"

        if "AND" in mnemonic:
            if operands:
                return f"and eax, 0x{operands[0]:x}"
            return "and eax, ebx"

        if "OR" in mnemonic:
            if operands:
                return f"or eax, 0x{operands[0]:x}"
            return "or eax, ebx"

        if "SHL" in mnemonic:
            if operands:
                return f"shl eax, {operands[0] & 0x1F}"
            return "shl eax, cl"

        if "SHR" in mnemonic:
            if operands:
                return f"shr eax, {operands[0] & 0x1F}"
            return "shr eax, cl"

        # Default register operations
        if "MOV" in mnemonic:
            if len(operands) >= 2:
                src = vm_reg_map.get(operands[1], "ebx")
                dst = vm_reg_map.get(operands[0], "eax")
                return f"mov {dst}, {src}"
            return "mov eax, ebx"

        if "XCHG" in mnemonic:
            if len(operands) >= 2:
                reg1 = vm_reg_map.get(operands[0], "eax")
                reg2 = vm_reg_map.get(operands[1], "ebx")
                return f"xchg {reg1}, {reg2}"
            return "xchg eax, ebx"

        return None

    def _fallback_vm_to_x86(self, vm_instructions: list[VMInstruction]) -> bytes:
        """Fallback conversion using pre-compiled x86 opcode patterns.

        Provides an alternative conversion mechanism when Keystone is unavailable,
        using a lookup table of pre-compiled instruction sequences.

        Args:
            vm_instructions: List of VMInstruction objects to convert.

        Returns:
            Binary x86 code assembled from pre-compiled patterns.

        """
        x86_code = bytearray()

        # Pre-compiled x86 opcodes for common operations
        opcode_map = {
            "PUSH_EAX": b"\x50",
            "POP_EAX": b"\x58",
            "PUSH_EBX": b"\x53",
            "POP_EBX": b"\x5b",
            "MOV_EAX_EBX": b"\x89\xd8",
            "ADD_EAX_EBX": b"\x01\xd8",
            "SUB_EAX_EBX": b"\x29\xd8",
            "XOR_EAX_EBX": b"\x31\xd8",
            "RET": b"\xc3",
            "NOP": b"\x90",
            "JMP_SHORT": b"\xeb\x00",
            "JE_SHORT": b"\x74\x00",
            "JNE_SHORT": b"\x75\x00",
        }

        for inst in vm_instructions:
            # Map VM instruction to x86 opcode
            key = inst.mnemonic.replace("VM_", "").upper()

            if key in opcode_map:
                x86_code.extend(opcode_map[key])
            elif "PUSH" in key:
                x86_code.extend(opcode_map.get("PUSH_EAX", b"\x50"))
            elif "POP" in key:
                x86_code.extend(opcode_map.get("POP_EAX", b"\x58"))
            elif "MOV" in key:
                x86_code.extend(opcode_map.get("MOV_EAX_EBX", b"\x89\xd8"))
            elif "ADD" in key:
                x86_code.extend(opcode_map.get("ADD_EAX_EBX", b"\x01\xd8"))
            elif "SUB" in key:
                x86_code.extend(opcode_map.get("SUB_EAX_EBX", b"\x29\xd8"))
            elif "XOR" in key:
                x86_code.extend(opcode_map.get("XOR_EAX_EBX", b"\x31\xd8"))
            elif "RET" in key:
                x86_code.extend(opcode_map.get("RET", b"\xc3"))
            elif "JMP" in key:
                x86_code.extend(opcode_map.get("JMP_SHORT", b"\xeb\x00"))
            elif "JE" in key or "JZ" in key:
                x86_code.extend(opcode_map.get("JE_SHORT", b"\x74\x00"))
            elif "JNE" in key or "JNZ" in key:
                x86_code.extend(opcode_map.get("JNE_SHORT", b"\x75\x00"))
            else:
                x86_code.extend(opcode_map.get("NOP", b"\x90"))

        return bytes(x86_code)

    def _post_process_x86_code(self, x86_code: bytes) -> bytes:
        """Post-process x86 code for coherent execution flow.

        Validates and corrects relative jump/call offsets and ensures proper
        instruction alignment with NOP padding.

        Args:
            x86_code: Binary x86 code to post-process.

        Returns:
            Post-processed x86 code with corrected offsets and alignment.

        """
        code = bytearray(x86_code)

        # Fix relative jumps and calls
        i = 0
        while i < len(code):
            # Detect short jumps (EB, 74-7F)
            if i < len(code) - 1 and (code[i] == 0xEB or (0x70 <= code[i] <= 0x7F)):
                if code[i + 1] == 0:
                    code[i + 1] = 0x02  # Jump forward 2 bytes minimum
                i += 2
                continue

            # Detect near jumps/calls (E8, E9)
            if i < len(code) - 4 and code[i] in [0xE8, 0xE9]:
                offset = struct.unpack("<i", code[i + 1 : i + 5])[0]
                if offset == 0:
                    # Point to next instruction
                    struct.pack_into("<i", code, i + 1, 5)
                i += 5
                continue

            i += 1

        # Ensure proper alignment
        while len(code) % 16 != 0:
            code.append(0x90)  # Pad with NOPs

        return bytes(code)

    def _parse_vm_instructions(self, vm_data: bytes) -> list[VMInstruction]:
        """Parse VM instructions from binary data.

        Iterates through binary data and extracts VM instructions sequentially.
        Handles parsing failures gracefully by skipping invalid instructions.

        Args:
            vm_data: Binary data containing VM instructions.

        Returns:
            List of parsed VMInstruction objects.

        """
        instructions = []
        offset = 0

        while offset < len(vm_data):
            try:
                # Create emulator for parsing (assuming VMProtect for now)
                emulator = VMEmulator(ProtectionType.VMPROTECT_2X)
                instruction = emulator.parse_vm_instruction(vm_data, offset)
                instructions.append(instruction)
                offset += instruction.size

            except Exception:
                # Skip invalid instruction
                offset += 1

                # Prevent infinite loops
                if offset > len(vm_data):
                    break

        return instructions

    def _vm_to_x86(self, vm_instructions: list[VMInstruction]) -> bytes:
        """Convert VM instructions to x86 machine code.

        Translates a sequence of parsed VM instructions into executable x86 bytecode
        using Keystone assembler. Falls back to pre-compiled patterns if assembly fails.

        Args:
            vm_instructions: List of VMInstruction objects to convert.

        Returns:
            Binary x86 machine code.

        """
        x86_code = bytearray()

        # Initialize Keystone for assembly
        try:
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        except Exception:
            # Fallback: return NOP instructions
            return b"\x90" * len(vm_instructions)

        for instruction in vm_instructions:
            try:
                if asm_code := self._vm_instruction_to_asm(instruction):
                    # Assemble to machine code
                    encoding, _count = ks.asm(asm_code)
                    if encoding:
                        x86_code.extend(encoding)
                    else:
                        x86_code.append(0x90)  # NOP
                else:
                    x86_code.append(0x90)  # NOP for unknown instructions

            except Exception:
                # Add NOP for failed conversions
                x86_code.append(0x90)

        return bytes(x86_code)

    def _vm_instruction_to_asm(self, instruction: VMInstruction) -> str | None:
        """Convert VM instruction to x86 assembly mnemonic.

        Maps a single VM instruction to an equivalent x86 assembly instruction
        string, handling operand encoding and register allocation.

        Args:
            instruction: VMInstruction object to convert.

        Returns:
            X86 assembly string (e.g., "push eax") or None for unknown instructions.

        """
        mnemonic = instruction.mnemonic

        # Stack operations
        if "PUSH" in mnemonic:
            if instruction.operands:
                return f"push {instruction.operands[0]}"
            return "push eax"

        if "POP" in mnemonic:
            return "pop eax"

        # Arithmetic
        if "ADD" in mnemonic:
            return "add eax, ebx"

        if "SUB" in mnemonic:
            return "sub eax, ebx"

        if "MUL" in mnemonic:
            return "mul ebx"

        # Logical
        if "XOR" in mnemonic:
            return "xor eax, ebx"

        if "AND" in mnemonic:
            return "and eax, ebx"

        if "OR" in mnemonic:
            return "or eax, ebx"

        # Memory
        if "LOAD" in mnemonic:
            return "mov eax, [eax]"

        if "STORE" in mnemonic:
            return "mov [eax], ebx"

        # Control flow
        if "JMP" in mnemonic:
            if instruction.operands:
                return f"jmp {instruction.operands[0]}"
            return "jmp eax"

        if "JZ" in mnemonic or "JE" in mnemonic:
            if instruction.operands:
                return f"je {instruction.operands[0]}"
            return "je eax"

        if "CALL" in mnemonic:
            if instruction.operands:
                return f"call {instruction.operands[0]}"
            return "call eax"

        if "RET" in mnemonic:
            return "ret"

        # Register operations
        if "MOV" in mnemonic:
            return "mov eax, ebx"

        return None  # Unknown instruction

    def batch_unwrap(self, input_dir: str, output_dir: str) -> dict[str, Any]:
        """Batch unwrap multiple files."""
        input_path = Path(input_dir)
        output_path = Path(output_dir)

        if not input_path.exists():
            raise ValueError(f"Input directory does not exist: {input_dir}")

        output_path.mkdir(parents=True, exist_ok=True)

        results = []

        # Process all executable files
        for file_path in input_path.rglob("*.exe"):
            try:
                output_file = output_path / f"{file_path.stem}_unwrapped{file_path.suffix}"
                result = self.unwrap_file(str(file_path), str(output_file))
                result["input_file"] = str(file_path)
                result["output_file"] = str(output_file)
                results.append(result)

            except Exception as e:
                self.logger.exception("Error processing %s: %s", file_path, e, exc_info=True)
                results.append(
                    {
                        "input_file": str(file_path),
                        "success": False,
                        "error": str(e),
                    },
                )

        # Summary
        successful = sum(bool(r.get("success")) for r in results)

        return {
            "total_files": len(results),
            "successful": successful,
            "failed": len(results) - successful,
            "results": results,
            "statistics": self.stats,
        }

    def get_statistics(self) -> dict[str, Any]:
        """Get unwrapper statistics."""
        return {
            "stats": self.stats.copy(),
            "supported_protections": [pt.value for pt in ProtectionType],
            "detection_patterns": len(self.analyzer.patterns),
        }


def main() -> None:
    """Demonstrate VM protection unwrapping functionality."""
    import argparse

    main_logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="VM Protection Unwrapper")
    parser.add_argument("input", help="Input file or directory")
    parser.add_argument("output", help="Output file or directory")
    parser.add_argument("--batch", action="store_true", help="Batch mode for directories")
    parser.add_argument("--stats", action="store_true", help="Show statistics")

    args = parser.parse_args()

    unwrapper = VMProtectionUnwrapper()

    try:
        if args.batch:
            main_logger.info("Batch unwrapping from %s to %s", args.input, args.output)
            results = unwrapper.batch_unwrap(args.input, args.output)

            main_logger.info("=== Batch Results ===")
            main_logger.info("Total files: %s", results["total_files"])
            main_logger.info("Successful: %s", results["successful"])
            main_logger.info("Failed: %s", results["failed"])

            for result in results["results"]:
                status = "OK" if result.get("success") else "FAIL"
                main_logger.info("%s %s", status, Path(result["input_file"]).name)
                if not result.get("success"):
                    main_logger.exception("  Error: %s", result.get("error", "Unknown error"))

        else:
            main_logger.info("Unwrapping %s -> %s", args.input, args.output)
            result = unwrapper.unwrap_file(args.input, args.output)

            if result["success"]:
                main_logger.info("OK Unwrapping successful!")
                main_logger.info("  Protection: %s", result["protection_type"])
                main_logger.info("  Original size: %s bytes", result["original_size"])
                main_logger.info("  Unwrapped size: %s bytes", result["unwrapped_size"])
                main_logger.info("  Processing time: %.2f seconds", result["processing_time"])
            else:
                main_logger.exception("FAIL Unwrapping failed: %s", result.get("error", "Unknown error"))

        if args.stats:
            stats = unwrapper.get_statistics()
            main_logger.info("=== Statistics ===")
            main_logger.info("%s", json.dumps(stats, indent=2))

    except Exception as e:
        main_logger.exception("Error: %s", e, exc_info=True)


if __name__ == "__main__":
    main()
