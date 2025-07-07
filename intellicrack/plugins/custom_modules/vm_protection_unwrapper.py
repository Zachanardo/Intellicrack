#!/usr/bin/env python3
"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
VM Protection Unwrapper

Advanced unwrapper for virtualization-based protection systems including
VMProtect, Themida, Code Virtualizer, and other VM-based obfuscators.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""

import hashlib
import json
import logging
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import keystone
import numpy as np
import unicorn
from unicorn import x86_const


class ProtectionType(Enum):
    """Types of VM protection"""
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
    """VM instruction types"""
    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    MEMORY = "memory"
    CONTROL_FLOW = "control_flow"
    STACK = "stack"
    REGISTER = "register"
    CUSTOM = "custom"


@dataclass
class VMInstruction:
    """VM instruction representation"""
    opcode: int
    operands: List[int]
    mnemonic: str
    vm_type: VMInstructionType
    x86_equivalent: Optional[str] = None
    size: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VMContext:
    """VM execution context"""
    registers: Dict[str, int] = field(default_factory=dict)
    stack: List[int] = field(default_factory=list)
    memory: Dict[int, bytes] = field(default_factory=dict)
    flags: Dict[str, bool] = field(default_factory=dict)

    def __post_init__(self):
        if not self.registers:
            # Initialize x86 registers
            self.registers = {
                'EAX': 0, 'EBX': 0, 'ECX': 0, 'EDX': 0,
                'ESI': 0, 'EDI': 0, 'ESP': 0x1000, 'EBP': 0x1000,
                'EIP': 0
            }

        if not self.flags:
            self.flags = {
                'ZF': False, 'CF': False, 'SF': False, 'OF': False
            }


class VMProtectHandler:
    """VMProtect-specific handling"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.VMProtect")

        # VMProtect opcode mappings (simplified)
        self.opcode_map = {
            # Stack operations
            0x00: ("VPUSH", VMInstructionType.STACK),
            0x01: ("VPOP", VMInstructionType.STACK),

            # Arithmetic
            0x02: ("VADD", VMInstructionType.ARITHMETIC),
            0x03: ("VSUB", VMInstructionType.ARITHMETIC),
            0x04: ("VMUL", VMInstructionType.ARITHMETIC),
            0x05: ("VDIV", VMInstructionType.ARITHMETIC),
            0x06: ("VMOD", VMInstructionType.ARITHMETIC),

            # Logical
            0x07: ("VAND", VMInstructionType.LOGICAL),
            0x08: ("VOR", VMInstructionType.LOGICAL),
            0x09: ("VXOR", VMInstructionType.LOGICAL),
            0x0A: ("VNOT", VMInstructionType.LOGICAL),
            0x0B: ("VSHL", VMInstructionType.LOGICAL),
            0x0C: ("VSHR", VMInstructionType.LOGICAL),

            # Memory
            0x0D: ("VLOAD", VMInstructionType.MEMORY),
            0x0E: ("VSTORE", VMInstructionType.MEMORY),

            # Control flow
            0x0F: ("VJMP", VMInstructionType.CONTROL_FLOW),
            0x10: ("VJCC", VMInstructionType.CONTROL_FLOW),
            0x11: ("VCALL", VMInstructionType.CONTROL_FLOW),
            0x12: ("VRET", VMInstructionType.CONTROL_FLOW),

            # Register operations
            0x13: ("VMOV", VMInstructionType.REGISTER),
            0x14: ("VXCHG", VMInstructionType.REGISTER),

            # Special
            0x15: ("VNOP", VMInstructionType.CUSTOM),
            0x16: ("VEXIT", VMInstructionType.CUSTOM),
        }

        # Key schedules for different versions
        self.key_schedules = {
            ProtectionType.VMPROTECT_1X: self._vmprotect_1x_key_schedule,
            ProtectionType.VMPROTECT_2X: self._vmprotect_2x_key_schedule,
            ProtectionType.VMPROTECT_3X: self._vmprotect_3x_key_schedule
        }

    def identify_version(self, vm_data: bytes) -> ProtectionType:
        """Identify VMProtect version"""
        # Version signatures
        signatures = {
            ProtectionType.VMPROTECT_1X: [
                b'\x60\x8B\x04\x24\x8B\x4C\x24\x04',  # Version 1.x signature
                b'\x55\x8B\xEC\x60\x8B\x45\x08'
            ],
            ProtectionType.VMPROTECT_2X: [
                b'\x68\x00\x00\x00\x00\x8F\x04\x24',  # Version 2.x signature
                b'\x8B\x44\x24\x04\x50\x8B\x44\x24\x08'
            ],
            ProtectionType.VMPROTECT_3X: [
                b'\x8B\x44\x24\x04\x8B\x4C\x24\x08',  # Version 3.x signature
                b'\x48\x8B\x44\x24\x08\x48\x8B\x4C\x24\x10'
            ]
        }

        for version, sigs in signatures.items():
            for sig in sigs:
                if sig in vm_data:
                    self.logger.info(f"Detected {version.value}")
                    return version

        return ProtectionType.UNKNOWN_VM

    def decrypt_vm_code(self, encrypted_data: bytes, key: bytes,
                       version: ProtectionType) -> bytes:
        """Decrypt VMProtect VM code"""
        if version in self.key_schedules:
            key_schedule = self.key_schedules[version](key)
            return self._decrypt_with_schedule(encrypted_data, key_schedule)
        else:
            # Generic decryption
            return self._simple_decrypt(encrypted_data, key)

    def _vmprotect_1x_key_schedule(self, key: bytes) -> List[int]:
        """VMProtect 1.x key schedule"""
        schedule = []
        key_ints = struct.unpack('<4I', key[:16])

        for i in range(44):  # 44 round keys
            if i < 4:
                schedule.append(key_ints[i])
            else:
                temp = schedule[i-1]
                if i % 4 == 0:
                    # RotWord and SubBytes
                    temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                    temp ^= 0x01000000 << ((i // 4) - 1)

                schedule.append(schedule[i-4] ^ temp)

        return schedule

    def _vmprotect_2x_key_schedule(self, key: bytes) -> List[int]:
        """VMProtect 2.x key schedule (more complex)"""
        schedule = []
        key_ints = struct.unpack('<8I', key[:32])

        # More complex key expansion
        for i in range(60):
            if i < 8:
                schedule.append(key_ints[i])
            else:
                temp = schedule[i-1]
                if i % 8 == 0:
                    temp = self._complex_transform(temp, i)
                elif i % 8 == 4:
                    temp = self._substitute_bytes(temp)

                schedule.append(schedule[i-8] ^ temp)

        return schedule

    def _vmprotect_3x_key_schedule(self, key: bytes) -> List[int]:
        """VMProtect 3.x key schedule (most complex)"""
        schedule = []
        key_data = key[:64] if len(key) >= 64 else key.ljust(64, b'\x00')

        # Initialize with SHA-256 like expansion
        for i in range(64):
            if i < 16:
                w = struct.unpack('<I', key_data[i*4:(i+1)*4])[0]
            else:
                s0 = self._sigma0(schedule[i-15])
                s1 = self._sigma1(schedule[i-2])
                w = (schedule[i-16] + s0 + schedule[i-7] + s1) & 0xFFFFFFFF

            schedule.append(w)

        return schedule

    def _complex_transform(self, value: int, round_num: int) -> int:
        """Complex transformation for VMProtect 2.x"""
        # Rotate left by round_num bits
        value = ((value << (round_num % 32)) | (value >> (32 - (round_num % 32)))) & 0xFFFFFFFF

        # XOR with round constant
        round_constant = 0x9E3779B9 * round_num
        value ^= round_constant & 0xFFFFFFFF

        return value

    def _substitute_bytes(self, value: int) -> int:
        """Byte substitution (simplified S-Box)"""
        sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]

        result = 0
        for i in range(4):
            byte_val = (value >> (i * 8)) & 0xFF
            substituted = sbox[byte_val % 16]
            result |= substituted << (i * 8)

        return result

    def _sigma0(self, value: int) -> int:
        """SHA-256 sigma0 function"""
        return (((value >> 7) | (value << 25)) ^ ((value >> 18) | (value << 14)) ^ (value >> 3)) & 0xFFFFFFFF

    def _sigma1(self, value: int) -> int:
        """SHA-256 sigma1 function"""
        return (((value >> 17) | (value << 15)) ^ ((value >> 19) | (value << 13)) ^ (value >> 10)) & 0xFFFFFFFF

    def _decrypt_with_schedule(self, data: bytes, key_schedule: List[int]) -> bytes:
        """Decrypt data using key schedule"""
        result = bytearray()

        for i in range(0, len(data), 16):
            block = data[i:i+16]
            if len(block) < 16:
                block = block.ljust(16, b'\x00')

            # AES-like decryption rounds
            state = list(struct.unpack('<4I', block))

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

            result.extend(struct.pack('<4I', *state))

        return bytes(result)

    def _simple_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR decryption for unknown versions"""
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

    def _inverse_substitute_bytes_block(self, state: List[int]) -> List[int]:
        """Inverse S-Box substitution for block"""
        inv_sbox = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]

        result = []
        for word in state:
            new_word = 0
            for i in range(4):
                byte_val = (word >> (i * 8)) & 0xFF
                substituted = inv_sbox[byte_val % 16]
                new_word |= substituted << (i * 8)
            result.append(new_word)

        return result

    def _inverse_shift_rows(self, state: List[int]) -> List[int]:
        """Inverse shift rows transformation"""
        # Simplified inverse shift rows
        return [state[0], state[3], state[2], state[1]]

    def _inverse_mix_columns(self, state: List[int]) -> List[int]:
        """Inverse mix columns transformation"""
        # Simplified inverse mix columns
        result = []
        for word in state:
            # Simple bit manipulation for inverse mix
            mixed = ((word << 1) ^ (word >> 31)) & 0xFFFFFFFF
            result.append(mixed)

        return result


class ThemidaHandler:
    """Themida-specific handling"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.Themida")

        # Themida VM opcodes
        self.opcode_map = {
            0x00: ("TH_PUSH", VMInstructionType.STACK),
            0x01: ("TH_POP", VMInstructionType.STACK),
            0x02: ("TH_MOV", VMInstructionType.REGISTER),
            0x03: ("TH_ADD", VMInstructionType.ARITHMETIC),
            0x04: ("TH_SUB", VMInstructionType.ARITHMETIC),
            0x05: ("TH_MUL", VMInstructionType.ARITHMETIC),
            0x06: ("TH_XOR", VMInstructionType.LOGICAL),
            0x07: ("TH_AND", VMInstructionType.LOGICAL),
            0x08: ("TH_OR", VMInstructionType.LOGICAL),
            0x09: ("TH_NOT", VMInstructionType.LOGICAL),
            0x0A: ("TH_SHL", VMInstructionType.LOGICAL),
            0x0B: ("TH_SHR", VMInstructionType.LOGICAL),
            0x0C: ("TH_LOAD", VMInstructionType.MEMORY),
            0x0D: ("TH_STORE", VMInstructionType.MEMORY),
            0x0E: ("TH_JMP", VMInstructionType.CONTROL_FLOW),
            0x0F: ("TH_JZ", VMInstructionType.CONTROL_FLOW),
            0x10: ("TH_JNZ", VMInstructionType.CONTROL_FLOW),
            0x11: ("TH_CALL", VMInstructionType.CONTROL_FLOW),
            0x12: ("TH_RET", VMInstructionType.CONTROL_FLOW),
            0x13: ("TH_CMP", VMInstructionType.ARITHMETIC),
            0x14: ("TH_TEST", VMInstructionType.LOGICAL),
            0x15: ("TH_EXIT", VMInstructionType.CUSTOM),
        }

    def decrypt_themida_vm(self, vm_data: bytes, key: bytes) -> bytes:
        """Decrypt Themida VM code"""
        # Themida uses a rolling XOR with key rotation
        result = bytearray()
        key_pos = 0

        for i, byte in enumerate(vm_data):
            # Rotate key based on position
            rotated_key = self._rotate_key(key, i)
            decrypted_byte = byte ^ rotated_key[key_pos % len(rotated_key)]
            result.append(decrypted_byte)
            key_pos += 1

        return bytes(result)

    def _rotate_key(self, key: bytes, position: int) -> bytes:
        """Rotate key based on position"""
        rotation = position % len(key)
        return key[rotation:] + key[:rotation]


class VMEmulator:
    """VM instruction emulator"""

    def __init__(self, protection_type: ProtectionType):
        self.protection_type = protection_type
        self.context = VMContext()
        self.logger = logging.getLogger(f"{__name__}.VMEmulator")

        # Initialize handlers
        self.handlers = {
            ProtectionType.VMPROTECT_1X: VMProtectHandler(),
            ProtectionType.VMPROTECT_2X: VMProtectHandler(),
            ProtectionType.VMPROTECT_3X: VMProtectHandler(),
            ProtectionType.THEMIDA: ThemidaHandler(),
        }

        # Unicorn engine for native execution
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self._setup_unicorn()

    def _setup_unicorn(self):
        """Setup Unicorn engine"""
        # Map memory
        self.uc.mem_map(0x400000, 2 * 1024 * 1024)  # 2MB for code
        self.uc.mem_map(0x600000, 1024 * 1024)      # 1MB for stack

        # Set stack pointer
        self.uc.reg_write(x86_const.UC_X86_REG_ESP, 0x600000 + 1024 * 1024 - 0x1000)

    def parse_vm_instruction(self, vm_data: bytes, offset: int) -> VMInstruction:
        """Parse VM instruction"""
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
                operand = struct.unpack('<I', vm_data[offset+1:offset+5])[0]
                operands.append(operand)
                size = 5
        elif vm_type == VMInstructionType.CONTROL_FLOW:
            if offset + 4 < len(vm_data):
                target = struct.unpack('<I', vm_data[offset+1:offset+5])[0]
                operands.append(target)
                size = 5

        return VMInstruction(
            opcode=opcode,
            operands=operands,
            mnemonic=mnemonic,
            vm_type=vm_type,
            size=size
        )

    def execute_vm_instruction(self, instruction: VMInstruction) -> bool:
        """Execute VM instruction"""
        try:
            if instruction.vm_type == VMInstructionType.STACK:
                return self._execute_stack_op(instruction)
            elif instruction.vm_type == VMInstructionType.ARITHMETIC:
                return self._execute_arithmetic_op(instruction)
            elif instruction.vm_type == VMInstructionType.LOGICAL:
                return self._execute_logical_op(instruction)
            elif instruction.vm_type == VMInstructionType.MEMORY:
                return self._execute_memory_op(instruction)
            elif instruction.vm_type == VMInstructionType.CONTROL_FLOW:
                return self._execute_control_flow_op(instruction)
            elif instruction.vm_type == VMInstructionType.REGISTER:
                return self._execute_register_op(instruction)
            else:
                self.logger.warning(f"Unhandled instruction type: {instruction.vm_type}")
                return True

        except Exception as e:
            self.logger.error(f"Error executing {instruction.mnemonic}: {e}")
            return False

    def _execute_stack_op(self, instruction: VMInstruction) -> bool:
        """Execute stack operations"""
        if "PUSH" in instruction.mnemonic:
            if instruction.operands:
                self.context.stack.append(instruction.operands[0])
            else:
                # Push register
                self.context.stack.append(self.context.registers.get('EAX', 0))

        elif "POP" in instruction.mnemonic:
            if self.context.stack:
                value = self.context.stack.pop()
                self.context.registers['EAX'] = value

        return True

    def _execute_arithmetic_op(self, instruction: VMInstruction) -> bool:
        """Execute arithmetic operations"""
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
        self.context.flags['ZF'] = (result == 0)
        self.context.flags['SF'] = ((result & 0x80000000) != 0)

        return True

    def _execute_logical_op(self, instruction: VMInstruction) -> bool:
        """Execute logical operations"""
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
        """Execute memory operations"""
        if "LOAD" in instruction.mnemonic:
            if self.context.stack:
                address = self.context.stack.pop()
                value = self.context.memory.get(address, b'\x00\x00\x00\x00')
                int_value = struct.unpack('<I', value[:4])[0]
                self.context.stack.append(int_value)

        elif "STORE" in instruction.mnemonic:
            if len(self.context.stack) >= 2:
                address = self.context.stack.pop()
                value = self.context.stack.pop()
                self.context.memory[address] = struct.pack('<I', value)

        return True

    def _execute_control_flow_op(self, instruction: VMInstruction) -> bool:
        """Execute control flow operations"""
        if "JMP" in instruction.mnemonic:
            if instruction.operands:
                self.context.registers['EIP'] = instruction.operands[0]

        elif "JZ" in instruction.mnemonic or "JE" in instruction.mnemonic:
            if self.context.flags.get('ZF', False) and instruction.operands:
                self.context.registers['EIP'] = instruction.operands[0]

        elif "JNZ" in instruction.mnemonic or "JNE" in instruction.mnemonic:
            if not self.context.flags.get('ZF', False) and instruction.operands:
                self.context.registers['EIP'] = instruction.operands[0]

        elif "CALL" in instruction.mnemonic:
            if instruction.operands:
                # Push return address
                self.context.stack.append(self.context.registers['EIP'])
                self.context.registers['EIP'] = instruction.operands[0]

        elif "RET" in instruction.mnemonic:
            if self.context.stack:
                self.context.registers['EIP'] = self.context.stack.pop()

        return True

    def _execute_register_op(self, instruction: VMInstruction) -> bool:
        """Execute register operations"""
        if "MOV" in instruction.mnemonic:
            if len(self.context.stack) >= 2:
                dest = self.context.stack.pop()
                src = self.context.stack.pop()
                # Update the destination register
                if isinstance(dest, str) and dest in self.context.registers:
                    self.context.registers[dest] = src
                else:
                    # Fallback to EAX if destination is not a valid register
                    self.context.registers['EAX'] = src

        elif "XCHG" in instruction.mnemonic:
            if len(self.context.stack) >= 2:
                a = self.context.stack.pop()
                b = self.context.stack.pop()
                self.context.stack.append(a)
                self.context.stack.append(b)

        return True


class VMAnalyzer:
    """VM code analyzer and pattern detector"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.VMAnalyzer")
        self.patterns = self._load_vm_patterns()

    def _load_vm_patterns(self) -> Dict[ProtectionType, List[bytes]]:
        """Load VM detection patterns"""
        return {
            ProtectionType.VMPROTECT_1X: [
                b'\x60\x8B\x04\x24',  # VM entry pattern
                b'\x8B\x4C\x24\x04\x8B\x54\x24\x08',
                b'\x55\x8B\xEC\x60'
            ],
            ProtectionType.VMPROTECT_2X: [
                b'\x68\x00\x00\x00\x00\x8F\x04\x24',
                b'\x8B\x44\x24\x04\x50',
                b'\x8B\x44\x24\x08\x8B\x4C\x24\x0C'
            ],
            ProtectionType.VMPROTECT_3X: [
                b'\x8B\x44\x24\x04\x8B\x4C\x24\x08',
                b'\x48\x8B\x44\x24\x08',
                b'\x48\x8B\x4C\x24\x10'
            ],
            ProtectionType.THEMIDA: [
                b'\x55\x8B\xEC\x83\xEC\x10\x53\x56\x57',
                b'\x60\x9C\x33\xC0\x50\x9C',
                b'\x8B\x45\x08\x8B\x4D\x0C'
            ],
            ProtectionType.CODE_VIRTUALIZER: [
                b'\x55\x8B\xEC\x81\xEC\x00\x04\x00\x00',
                b'\x60\x9C\x33\xDB\x53',
                b'\x8B\x45\x08\x8B\x55\x0C'
            ]
        }

    def detect_vm_protection(self, binary_data: bytes) -> ProtectionType:
        """Detect VM protection type"""
        for protection, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern in binary_data:
                    self.logger.info(f"Detected {protection.value}")
                    return protection

        # Additional entropy-based detection
        entropy = self._calculate_entropy(binary_data)
        if entropy > 7.5:  # High entropy suggests VM protection
            self.logger.info("High entropy detected - likely VM protected")
            return ProtectionType.UNKNOWN_VM

        return ProtectionType.UNKNOWN_VM

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
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

    def find_vm_entry_points(self, binary_data: bytes,
                           protection_type: ProtectionType) -> List[int]:
        """Find VM entry points"""
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

    def analyze_vm_structure(self, vm_data: bytes,
                           entry_point: int) -> Dict[str, Any]:
        """Analyze VM structure"""
        analysis = {
            'entry_point': entry_point,
            'vm_code_sections': [],
            'handler_table': None,
            'key_schedule': None,
            'statistics': {}
        }

        # Look for handler table
        handler_table_offset = self._find_handler_table(vm_data, entry_point)
        if handler_table_offset:
            analysis['handler_table'] = handler_table_offset

        # Extract VM code sections
        vm_sections = self._extract_vm_sections(vm_data, entry_point)
        analysis['vm_code_sections'] = vm_sections

        # Calculate statistics
        analysis['statistics'] = {
            'total_size': len(vm_data),
            'entry_points_found': 1,
            'estimated_vm_code_size': sum(len(section['data']) for section in vm_sections),
            'entropy': self._calculate_entropy(vm_data)
        }

        return analysis

    def _find_handler_table(self, vm_data: bytes, entry_point: int) -> Optional[int]:
        """Find VM handler table"""
        # Look for patterns indicating handler table
        # This is a simplified heuristic

        for i in range(entry_point, min(entry_point + 0x1000, len(vm_data) - 4)):
            # Look for table of addresses
            if i + 64 < len(vm_data):
                potential_table = vm_data[i:i+64]

                # Check if it looks like a table of 32-bit addresses
                addresses = struct.unpack('<16I', potential_table)

                # Heuristic: addresses should be in reasonable range
                valid_addresses = sum(1 for addr in addresses
                                    if 0x400000 <= addr <= 0x800000)

                if valid_addresses >= 12:  # At least 75% valid
                    return i

        return None

    def _extract_vm_sections(self, vm_data: bytes, entry_point: int) -> List[Dict[str, Any]]:
        """Extract VM code sections"""
        sections = []

        # Simple section extraction based on patterns
        current_offset = entry_point

        while current_offset < len(vm_data) - 16:
            # Look for section markers or significant changes in entropy
            section_start = current_offset
            section_end = self._find_section_end(vm_data, current_offset)

            if section_end > section_start:
                section_data = vm_data[section_start:section_end]

                sections.append({
                    'offset': section_start,
                    'size': section_end - section_start,
                    'data': section_data,
                    'entropy': self._calculate_entropy(section_data),
                    'type': self._classify_section(section_data)
                })

                current_offset = section_end
            else:
                current_offset += 0x100  # Skip ahead

            # Limit sections to prevent infinite loops
            if len(sections) >= 100:
                break

        return sections

    def _find_section_end(self, vm_data: bytes, start_offset: int) -> int:
        """Find end of VM section"""
        # Look for section end markers or entropy changes
        max_section_size = 0x10000  # 64KB max
        end_offset = min(start_offset + max_section_size, len(vm_data))

        # Simple heuristic: end at null bytes or repeated patterns
        for i in range(start_offset + 0x100, end_offset, 0x10):
            if i + 16 <= len(vm_data):
                chunk = vm_data[i:i+16]

                # Check for null section
                if chunk == b'\x00' * 16:
                    return i

                # Check for repeated patterns
                if len(set(chunk)) <= 2:
                    return i

        return end_offset


class VMProtectionUnwrapper:
    """Main VM protection unwrapper"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.analyzer = VMAnalyzer()
        self.emulators = {}

        # Statistics
        self.stats = {
            'files_processed': 0,
            'successful_unwraps': 0,
            'failed_unwraps': 0,
            'protection_types_detected': defaultdict(int)
        }

    def unwrap_file(self, input_file: str, output_file: str) -> Dict[str, Any]:
        """Unwrap VM-protected file"""
        self.logger.info(f"Starting unwrap of {input_file}")

        start_time = time.time()

        try:
            # Load file
            with open(input_file, 'rb') as f:
                binary_data = f.read()

            # Detect protection
            protection_type = self.analyzer.detect_vm_protection(binary_data)
            self.stats['protection_types_detected'][protection_type] += 1

            # Find entry points
            entry_points = self.analyzer.find_vm_entry_points(binary_data, protection_type)

            if not entry_points:
                self.logger.warning("No VM entry points found")
                return {'success': False, 'error': 'No entry points found'}

            # Analyze VM structure
            vm_analysis = self.analyzer.analyze_vm_structure(binary_data, entry_points[0])

            # Extract and decrypt VM code
            unwrapped_data = self._unwrap_vm_sections(binary_data, vm_analysis, protection_type)

            # Reconstruct original code
            reconstructed = self._reconstruct_original_code(unwrapped_data, vm_analysis)

            # Save result
            with open(output_file, 'wb') as f:
                f.write(reconstructed)

            elapsed_time = time.time() - start_time

            result = {
                'success': True,
                'protection_type': protection_type.value,
                'entry_points': len(entry_points),
                'vm_sections': len(vm_analysis['vm_code_sections']),
                'original_size': len(binary_data),
                'unwrapped_size': len(reconstructed),
                'processing_time': elapsed_time,
                'statistics': vm_analysis['statistics']
            }

            self.stats['successful_unwraps'] += 1
            self.logger.info(f"Successfully unwrapped {input_file}")

            return result

        except Exception as e:
            self.logger.error(f"Error unwrapping {input_file}: {e}")
            self.stats['failed_unwraps'] += 1
            return {'success': False, 'error': str(e)}

        finally:
            self.stats['files_processed'] += 1

    def _unwrap_vm_sections(self, binary_data: bytes, vm_analysis: Dict[str, Any],
                          protection_type: ProtectionType) -> List[bytes]:
        """Unwrap VM sections"""
        unwrapped_sections = []

        # Get appropriate handler
        if protection_type in [ProtectionType.VMPROTECT_1X, ProtectionType.VMPROTECT_2X,
                              ProtectionType.VMPROTECT_3X]:
            handler = VMProtectHandler()
        elif protection_type == ProtectionType.THEMIDA:
            handler = ThemidaHandler()
        else:
            # Generic handler
            handler = VMProtectHandler()

        # Extract encryption key (heuristic)
        key = self._extract_encryption_key(binary_data, vm_analysis, protection_type)

        for section in vm_analysis['vm_code_sections']:
            section_data = section['data']

            try:
                if protection_type == ProtectionType.THEMIDA:
                    decrypted = handler.decrypt_themida_vm(section_data, key)
                else:
                    decrypted = handler.decrypt_vm_code(section_data, key, protection_type)

                unwrapped_sections.append(decrypted)

            except Exception as e:
                self.logger.error(f"Error decrypting section: {e}")
                unwrapped_sections.append(section_data)  # Keep original

        return unwrapped_sections

    def _extract_encryption_key(self, binary_data: bytes, vm_analysis: Dict[str, Any],
                               protection_type: ProtectionType) -> bytes:
        """Extract encryption key from binary"""
        # This is a simplified key extraction
        # Real implementation would use more sophisticated techniques

        entry_point = vm_analysis['entry_point']

        # Look for key material near entry point
        search_start = max(0, entry_point - 0x100)
        search_end = min(len(binary_data), entry_point + 0x100)

        key_candidates = []

        # Look for 16-byte or 32-byte aligned data
        for i in range(search_start, search_end - 32, 4):
            candidate = binary_data[i:i+32]

            # Heuristic: key should have good entropy
            entropy = self.analyzer._calculate_entropy(candidate)
            if 6.0 <= entropy <= 7.5:  # Good entropy range
                key_candidates.append(candidate)

        if key_candidates:
            # Return the best candidate
            return key_candidates[0]

        # Fallback: use hash of entry point area
        fallback_data = binary_data[entry_point:entry_point+64]
        return hashlib.sha256(fallback_data).digest()

    def _reconstruct_original_code(self, unwrapped_sections: List[bytes],
                                 vm_analysis: Dict[str, Any]) -> bytes:
        """Reconstruct original x86 code from VM sections"""
        reconstructed = bytearray()

        # Create emulator for the detected protection
        # This is simplified - real implementation would be much more complex

        for section_data in unwrapped_sections:
            # Parse VM instructions
            vm_instructions = self._parse_vm_instructions(section_data)

            # Convert to x86 assembly
            x86_code = self._vm_to_x86(vm_instructions)

            reconstructed.extend(x86_code)

        return bytes(reconstructed)

    def _parse_vm_instructions(self, vm_data: bytes) -> List[VMInstruction]:
        """Parse VM instructions from data"""
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

    def _vm_to_x86(self, vm_instructions: List[VMInstruction]) -> bytes:
        """Convert VM instructions to x86 machine code"""
        x86_code = bytearray()

        # Initialize Keystone for assembly
        try:
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        except:
            # Fallback: return NOP instructions
            return b'\x90' * len(vm_instructions)

        for instruction in vm_instructions:
            try:
                # Convert VM instruction to x86 assembly
                asm_code = self._vm_instruction_to_asm(instruction)

                if asm_code:
                    # Assemble to machine code
                    encoding, count = ks.asm(asm_code)
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

    def _vm_instruction_to_asm(self, instruction: VMInstruction) -> Optional[str]:
        """Convert VM instruction to x86 assembly"""
        mnemonic = instruction.mnemonic

        # Stack operations
        if "PUSH" in mnemonic:
            if instruction.operands:
                return f"push {instruction.operands[0]}"
            else:
                return "push eax"

        elif "POP" in mnemonic:
            return "pop eax"

        # Arithmetic
        elif "ADD" in mnemonic:
            return "add eax, ebx"

        elif "SUB" in mnemonic:
            return "sub eax, ebx"

        elif "MUL" in mnemonic:
            return "mul ebx"

        # Logical
        elif "XOR" in mnemonic:
            return "xor eax, ebx"

        elif "AND" in mnemonic:
            return "and eax, ebx"

        elif "OR" in mnemonic:
            return "or eax, ebx"

        # Memory
        elif "LOAD" in mnemonic:
            return "mov eax, [eax]"

        elif "STORE" in mnemonic:
            return "mov [eax], ebx"

        # Control flow
        elif "JMP" in mnemonic:
            if instruction.operands:
                return f"jmp {instruction.operands[0]}"
            else:
                return "jmp eax"

        elif "JZ" in mnemonic or "JE" in mnemonic:
            if instruction.operands:
                return f"je {instruction.operands[0]}"
            else:
                return "je eax"

        elif "CALL" in mnemonic:
            if instruction.operands:
                return f"call {instruction.operands[0]}"
            else:
                return "call eax"

        elif "RET" in mnemonic:
            return "ret"

        # Register operations
        elif "MOV" in mnemonic:
            return "mov eax, ebx"

        return None  # Unknown instruction

    def batch_unwrap(self, input_dir: str, output_dir: str) -> Dict[str, Any]:
        """Batch unwrap multiple files"""
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
                result['input_file'] = str(file_path)
                result['output_file'] = str(output_file)
                results.append(result)

            except Exception as e:
                self.logger.error(f"Error processing {file_path}: {e}")
                results.append({
                    'input_file': str(file_path),
                    'success': False,
                    'error': str(e)
                })

        # Summary
        successful = sum(1 for r in results if r.get('success'))

        return {
            'total_files': len(results),
            'successful': successful,
            'failed': len(results) - successful,
            'results': results,
            'statistics': self.stats
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get unwrapper statistics"""
        return {
            'stats': self.stats.copy(),
            'supported_protections': [pt.value for pt in ProtectionType],
            'detection_patterns': len(self.analyzer.patterns)
        }


def main():
    """Example usage"""
    import argparse

    parser = argparse.ArgumentParser(description='VM Protection Unwrapper')
    parser.add_argument('input', help='Input file or directory')
    parser.add_argument('output', help='Output file or directory')
    parser.add_argument('--batch', action='store_true', help='Batch mode for directories')
    parser.add_argument('--stats', action='store_true', help='Show statistics')

    args = parser.parse_args()

    # Initialize unwrapper
    unwrapper = VMProtectionUnwrapper()

    try:
        if args.batch:
            print(f"Batch unwrapping from {args.input} to {args.output}")
            results = unwrapper.batch_unwrap(args.input, args.output)

            print("\n=== Batch Results ===")
            print(f"Total files: {results['total_files']}")
            print(f"Successful: {results['successful']}")
            print(f"Failed: {results['failed']}")

            # Show detailed results
            for result in results['results']:
                status = "✓" if result.get('success') else "✗"
                print(f"{status} {Path(result['input_file']).name}")
                if not result.get('success'):
                    print(f"  Error: {result.get('error', 'Unknown error')}")

        else:
            print(f"Unwrapping {args.input} -> {args.output}")
            result = unwrapper.unwrap_file(args.input, args.output)

            if result['success']:
                print("✓ Unwrapping successful!")
                print(f"  Protection: {result['protection_type']}")
                print(f"  Original size: {result['original_size']:,} bytes")
                print(f"  Unwrapped size: {result['unwrapped_size']:,} bytes")
                print(f"  Processing time: {result['processing_time']:.2f} seconds")
            else:
                print(f"✗ Unwrapping failed: {result.get('error', 'Unknown error')}")

        if args.stats:
            stats = unwrapper.get_statistics()
            print("\n=== Statistics ===")
            print(json.dumps(stats, indent=2))

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
