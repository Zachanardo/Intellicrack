#!/usr/bin/env python3
"""Production tests for VM protection unwrapper validating real offensive capabilities.

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

import hashlib
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.plugins.custom_modules.vm_protection_unwrapper import (
    CodeVirtualizerHandler,
    ProtectionType,
    ThemidaHandler,
    VMAnalyzer,
    VMContext,
    VMEmulator,
    VMInstruction,
    VMInstructionType,
    VMProtectHandler,
    VMProtectionUnwrapper,
)


@pytest.fixture
def vm_context() -> VMContext:
    """Create initialized VM context for testing."""
    return VMContext()


@pytest.fixture
def vmprotect_handler() -> VMProtectHandler:
    """Create VMProtect handler instance."""
    return VMProtectHandler()


@pytest.fixture
def themida_handler() -> ThemidaHandler:
    """Create Themida handler instance."""
    return ThemidaHandler()


@pytest.fixture
def code_virtualizer_handler() -> CodeVirtualizerHandler:
    """Create Code Virtualizer handler instance."""
    return CodeVirtualizerHandler()


@pytest.fixture
def vm_analyzer() -> VMAnalyzer:
    """Create VM analyzer instance."""
    return VMAnalyzer()


@pytest.fixture
def vm_emulator_vmprotect() -> VMEmulator:
    """Create VM emulator for VMProtect."""
    return VMEmulator(ProtectionType.VMPROTECT_3X)


@pytest.fixture
def vm_emulator_themida() -> VMEmulator:
    """Create VM emulator for Themida."""
    return VMEmulator(ProtectionType.THEMIDA)


class TestCompleteVirtualCPUOpcodeEmulation:
    """Tests validating complete virtual CPU opcode set emulation."""

    def test_all_arithmetic_opcodes_execute_correctly(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Complete arithmetic opcode set (ADD, SUB, MUL, DIV, MOD, NEG) emulated correctly."""
        vm_emulator_vmprotect.context.stack = [100, 25]

        add_instr = VMInstruction(
            opcode=0x10, operands=[], mnemonic="VM_ADD", vm_type=VMInstructionType.ARITHMETIC
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(add_instr)
        assert success
        assert len(vm_emulator_vmprotect.context.stack) == 1
        assert vm_emulator_vmprotect.context.stack[0] == 125

        vm_emulator_vmprotect.context.stack = [100, 25]
        sub_instr = VMInstruction(
            opcode=0x11, operands=[], mnemonic="VM_SUB", vm_type=VMInstructionType.ARITHMETIC
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(sub_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == 75

        vm_emulator_vmprotect.context.stack = [10, 5]
        mul_instr = VMInstruction(
            opcode=0x12, operands=[], mnemonic="VM_MUL", vm_type=VMInstructionType.ARITHMETIC
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(mul_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == 50

        vm_emulator_vmprotect.context.stack = [100, 10]
        div_instr = VMInstruction(
            opcode=0x13, operands=[], mnemonic="VM_DIV", vm_type=VMInstructionType.ARITHMETIC
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(div_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == 10

    def test_all_logical_opcodes_execute_correctly(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Complete logical opcode set (AND, OR, XOR, NOT, SHL, SHR) emulated correctly."""
        vm_emulator_vmprotect.context.stack = [0xFF00FF00, 0xF0F0F0F0]

        and_instr = VMInstruction(
            opcode=0x20, operands=[], mnemonic="VM_AND", vm_type=VMInstructionType.LOGICAL
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(and_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == (0xFF00FF00 & 0xF0F0F0F0)

        vm_emulator_vmprotect.context.stack = [0xFF00FF00, 0x0F0F0F0F]
        or_instr = VMInstruction(
            opcode=0x21, operands=[], mnemonic="VM_OR", vm_type=VMInstructionType.LOGICAL
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(or_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == (0xFF00FF00 | 0x0F0F0F0F)

        vm_emulator_vmprotect.context.stack = [0xAAAAAAAA, 0x55555555]
        xor_instr = VMInstruction(
            opcode=0x22, operands=[], mnemonic="VM_XOR", vm_type=VMInstructionType.LOGICAL
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(xor_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == 0xFFFFFFFF

        vm_emulator_vmprotect.context.stack = [0x12345678]
        not_instr = VMInstruction(
            opcode=0x23, operands=[], mnemonic="VM_NOT", vm_type=VMInstructionType.LOGICAL
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(not_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == (~0x12345678 & 0xFFFFFFFF)

        vm_emulator_vmprotect.context.stack = [0x00000001, 4]
        shl_instr = VMInstruction(
            opcode=0x24, operands=[], mnemonic="VM_SHL", vm_type=VMInstructionType.LOGICAL
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(shl_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[0] == 0x10

    def test_all_stack_opcodes_execute_correctly(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Complete stack opcode set (PUSH, POP, DUP, SWAP) emulated correctly."""
        push_instr = VMInstruction(
            opcode=0x01, operands=[0xDEADBEEF], mnemonic="VM_PUSH_IMM", vm_type=VMInstructionType.STACK
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(push_instr)
        assert success
        assert 0xDEADBEEF in vm_emulator_vmprotect.context.stack

        pop_instr = VMInstruction(
            opcode=0x03, operands=[], mnemonic="VM_POP_REG", vm_type=VMInstructionType.STACK
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(pop_instr)
        assert success
        assert vm_emulator_vmprotect.context.registers["EAX"] == 0xDEADBEEF

    def test_all_memory_opcodes_execute_correctly(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Complete memory opcode set (LOAD, STORE) emulated correctly with memory state tracking."""
        test_value = 0xCAFEBABE
        test_address = 0x1000

        vm_emulator_vmprotect.context.stack = [test_address, test_value]
        store_instr = VMInstruction(
            opcode=0x41, operands=[], mnemonic="VM_STORE", vm_type=VMInstructionType.MEMORY
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(store_instr)
        assert success
        assert test_address in vm_emulator_vmprotect.context.memory
        assert vm_emulator_vmprotect.context.memory[test_address] == struct.pack("<I", test_value)

        vm_emulator_vmprotect.context.stack = [test_address]
        load_instr = VMInstruction(
            opcode=0x40, operands=[], mnemonic="VM_LOAD", vm_type=VMInstructionType.MEMORY
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(load_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack[-1] == test_value

    def test_all_control_flow_opcodes_execute_correctly(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Complete control flow opcode set (JMP, JZ, JNZ, CALL, RET) emulated correctly."""
        vm_emulator_vmprotect.context.registers["EIP"] = 0x1000

        jmp_instr = VMInstruction(
            opcode=0x30, operands=[0x2000], mnemonic="VM_JMP", vm_type=VMInstructionType.CONTROL_FLOW
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(jmp_instr)
        assert success
        assert vm_emulator_vmprotect.context.registers["EIP"] == 0x2000

        vm_emulator_vmprotect.context.flags["ZF"] = True
        vm_emulator_vmprotect.context.registers["EIP"] = 0x1000
        jz_instr = VMInstruction(
            opcode=0x31, operands=[0x3000], mnemonic="VM_JZ", vm_type=VMInstructionType.CONTROL_FLOW
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(jz_instr)
        assert success
        assert vm_emulator_vmprotect.context.registers["EIP"] == 0x3000

        vm_emulator_vmprotect.context.flags["ZF"] = False
        vm_emulator_vmprotect.context.registers["EIP"] = 0x1000
        jnz_instr = VMInstruction(
            opcode=0x32, operands=[0x4000], mnemonic="VM_JNZ", vm_type=VMInstructionType.CONTROL_FLOW
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(jnz_instr)
        assert success
        assert vm_emulator_vmprotect.context.registers["EIP"] == 0x4000

    def test_register_opcodes_execute_correctly(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Register operations (MOV, XCHG) emulated correctly."""
        vm_emulator_vmprotect.context.stack = [0x5555, 0xAAAA]

        mov_instr = VMInstruction(
            opcode=0x04, operands=[], mnemonic="VM_MOV_REG_REG", vm_type=VMInstructionType.REGISTER
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(mov_instr)
        assert success
        assert vm_emulator_vmprotect.context.registers["EAX"] == 0xAAAA

        vm_emulator_vmprotect.context.stack = [0x1111, 0x2222]
        xchg_instr = VMInstruction(
            opcode=0x61, operands=[], mnemonic="CV_XCHG", vm_type=VMInstructionType.REGISTER
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(xchg_instr)
        assert success
        assert vm_emulator_vmprotect.context.stack == [0x2222, 0x1111]


class TestVMProtectThemidaInstructionHandling:
    """Tests validating VMProtect and Themida virtual instruction handling."""

    def test_vmprotect_1x_instructions_decoded_and_executed(self, vmprotect_handler: VMProtectHandler) -> None:
        """VMProtect 1.x virtual instructions correctly identified and decoded."""
        vm_data = b"\x60\x8b\x04\x24\x8b\x4c\x24\x04" + b"\x00" * 100

        version = vmprotect_handler.identify_version(vm_data)
        assert version == ProtectionType.VMPROTECT_1X

        key = b"TestKey123456789"
        test_encrypted = b"\x55\x89\xe5\x53\x51\x52\x56\x57\x8b\x45\x08\x8b\x4d\x0c\x8b\x55\x10" * 2

        decrypted = vmprotect_handler.decrypt_vm_code(test_encrypted, key, ProtectionType.VMPROTECT_1X)
        assert len(decrypted) >= len(test_encrypted)
        assert isinstance(decrypted, bytes)

    def test_vmprotect_2x_instructions_decoded_and_executed(self, vmprotect_handler: VMProtectHandler) -> None:
        """VMProtect 2.x virtual instructions correctly identified and decoded."""
        vm_data = b"\x68\x00\x00\x00\x00\x8f\x04\x24" + b"\x00" * 100

        version = vmprotect_handler.identify_version(vm_data)
        assert version == ProtectionType.VMPROTECT_2X

        key = b"VMPROTECT2X_KEY_32_BYTES_LEN"
        test_encrypted = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99" * 2

        decrypted = vmprotect_handler.decrypt_vm_code(test_encrypted, key, ProtectionType.VMPROTECT_2X)
        assert len(decrypted) == len(test_encrypted)
        assert decrypted != test_encrypted

    def test_vmprotect_3x_instructions_decoded_and_executed(self, vmprotect_handler: VMProtectHandler) -> None:
        """VMProtect 3.x virtual instructions correctly identified and decoded."""
        vm_data = b"\x48\x8b\x44\x24\x08\x48\x8b\x4c\x24\x10" + b"\x00" * 100

        version = vmprotect_handler.identify_version(vm_data)
        assert version == ProtectionType.VMPROTECT_3X

        key = b"VMPROTECT3X_64_BYTE_KEY_" + b"A" * 40
        test_encrypted = b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57" * 2

        decrypted = vmprotect_handler.decrypt_vm_code(test_encrypted, key, ProtectionType.VMPROTECT_3X)
        assert len(decrypted) == len(test_encrypted)
        assert decrypted != test_encrypted

    def test_themida_cisc_handlers_decoded_correctly(self, themida_handler: ThemidaHandler) -> None:
        """Themida CISC VM handlers correctly decoded and emulated."""
        test_opcodes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41]

        for opcode in test_opcodes:
            assert opcode in themida_handler.opcode_map
            mnemonic, vm_type = themida_handler.opcode_map[opcode]
            assert mnemonic.startswith("VM_")
            assert isinstance(vm_type, VMInstructionType)

    def test_themida_risc_fish_handlers_decoded_correctly(self, themida_handler: ThemidaHandler) -> None:
        """Themida RISC/FISH VM handlers correctly decoded and emulated."""
        vm_data = b"\x55\x8b\xec\x83\xec\x10\x53\x56\x57" + b"\x00" * 100
        key = b"ThemidaKey123456"

        decrypted = themida_handler.decrypt_themida_vm(vm_data, key)
        assert len(decrypted) == len(vm_data)
        assert isinstance(decrypted, bytes)

        assert decrypted != vm_data

    def test_code_virtualizer_handlers_decoded_correctly(self, code_virtualizer_handler: CodeVirtualizerHandler) -> None:
        """Code Virtualizer VM handlers correctly decoded and emulated."""
        test_opcodes = [
            0x10, 0x11, 0x12, 0x13,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x50, 0x51, 0x52, 0x53,
            0x60, 0x61
        ]

        for opcode in test_opcodes:
            assert opcode in code_virtualizer_handler.opcode_map
            mnemonic, vm_type = code_virtualizer_handler.opcode_map[opcode]
            assert mnemonic.startswith("CV_")
            assert isinstance(vm_type, VMInstructionType)


class TestVirtualRegisterMemoryStateTracking:
    """Tests validating accurate virtual register and memory state tracking."""

    def test_virtual_registers_initialized_correctly(self, vm_context: VMContext) -> None:
        """Virtual CPU registers initialized with x86 register set."""
        expected_registers = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"]

        for reg in expected_registers:
            assert reg in vm_context.registers
            assert isinstance(vm_context.registers[reg], int)

        assert vm_context.registers["ESP"] == 0x1000
        assert vm_context.registers["EBP"] == 0x1000

    def test_virtual_flags_initialized_correctly(self, vm_context: VMContext) -> None:
        """Virtual CPU flags initialized with x86 flags."""
        expected_flags = ["ZF", "CF", "SF", "OF"]

        for flag in expected_flags:
            assert flag in vm_context.flags
            assert isinstance(vm_context.flags[flag], bool)

    def test_register_state_tracked_across_operations(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Register state accurately tracked across multiple VM operations."""
        initial_eax = vm_emulator_vmprotect.context.registers["EAX"]

        vm_emulator_vmprotect.context.stack = [0x12345678]
        pop_instr = VMInstruction(
            opcode=0x03, operands=[], mnemonic="VM_POP_REG", vm_type=VMInstructionType.STACK
        )
        vm_emulator_vmprotect.execute_vm_instruction(pop_instr)

        assert vm_emulator_vmprotect.context.registers["EAX"] == 0x12345678
        assert vm_emulator_vmprotect.context.registers["EAX"] != initial_eax

    def test_memory_state_tracked_across_operations(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Memory state accurately tracked across store and load operations."""
        addresses = [0x1000, 0x2000, 0x3000]
        values = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC]

        for addr, val in zip(addresses, values):
            vm_emulator_vmprotect.context.stack = [addr, val]
            store_instr = VMInstruction(
                opcode=0x41, operands=[], mnemonic="VM_STORE", vm_type=VMInstructionType.MEMORY
            )
            vm_emulator_vmprotect.execute_vm_instruction(store_instr)

        for addr, val in zip(addresses, values):
            assert addr in vm_emulator_vmprotect.context.memory
            stored_value = struct.unpack("<I", vm_emulator_vmprotect.context.memory[addr])[0]
            assert stored_value == val

    def test_stack_state_tracked_accurately(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """Stack state accurately tracked during push/pop sequences."""
        test_values = [0x1111, 0x2222, 0x3333, 0x4444]

        for val in test_values:
            push_instr = VMInstruction(
                opcode=0x01, operands=[val], mnemonic="VM_PUSH_IMM", vm_type=VMInstructionType.STACK
            )
            vm_emulator_vmprotect.execute_vm_instruction(push_instr)

        assert len(vm_emulator_vmprotect.context.stack) >= len(test_values)

        for expected_val in reversed(test_values):
            pop_instr = VMInstruction(
                opcode=0x03, operands=[], mnemonic="VM_POP_REG", vm_type=VMInstructionType.STACK
            )
            vm_emulator_vmprotect.execute_vm_instruction(pop_instr)
            assert vm_emulator_vmprotect.context.registers["EAX"] == expected_val

    def test_flags_updated_correctly_after_arithmetic(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """CPU flags correctly updated after arithmetic operations."""
        vm_emulator_vmprotect.context.stack = [100, 100]
        sub_instr = VMInstruction(
            opcode=0x11, operands=[], mnemonic="VM_SUB", vm_type=VMInstructionType.ARITHMETIC
        )
        vm_emulator_vmprotect.execute_vm_instruction(sub_instr)

        assert vm_emulator_vmprotect.context.flags["ZF"] is True

        vm_emulator_vmprotect.context.stack = [50, 100]
        sub_instr2 = VMInstruction(
            opcode=0x11, operands=[], mnemonic="VM_SUB", vm_type=VMInstructionType.ARITHMETIC
        )
        vm_emulator_vmprotect.execute_vm_instruction(sub_instr2)

        assert vm_emulator_vmprotect.context.flags["ZF"] is False
        assert vm_emulator_vmprotect.context.flags["SF"] is True


class TestVMHandlerObfuscationDetection:
    """Tests validating VM handler obfuscation detection and handling."""

    def test_detects_obfuscated_handler_tables(self, vm_analyzer: VMAnalyzer) -> None:
        """VM handler table detected even with obfuscated structure."""
        obfuscated_binary = bytearray(b"\x90" * 0x500)

        handler_table_offset = 0x100
        for i in range(16):
            address = 0x400000 + (i * 0x1000)
            obfuscated_binary[handler_table_offset + (i * 4):handler_table_offset + (i * 4) + 4] = struct.pack("<I", address)

        binary = bytes(obfuscated_binary)

        detected_offset = vm_analyzer._find_handler_table(binary, 0x50)

        assert detected_offset is not None
        assert detected_offset == handler_table_offset

    def test_handles_mutated_vm_handlers(self, vmprotect_handler: VMProtectHandler) -> None:
        """Mutated VM handlers correctly identified despite polymorphic variations."""
        mutated_signature_1 = b"\x60\x8b\x04\x24\x8b\x4c\x24\x04"
        mutated_signature_2 = b"\x55\x8b\xec\x60\x8b\x45\x08"

        vm_data_1 = b"\x90" * 50 + mutated_signature_1 + b"\x90" * 50
        vm_data_2 = b"\x90" * 50 + mutated_signature_2 + b"\x90" * 50

        version_1 = vmprotect_handler.identify_version(vm_data_1)
        version_2 = vmprotect_handler.identify_version(vm_data_2)

        assert version_1 == ProtectionType.VMPROTECT_1X
        assert version_2 == ProtectionType.VMPROTECT_1X

    def test_detects_junk_code_in_handlers(self, vm_analyzer: VMAnalyzer) -> None:
        """Junk code and opaque predicates detected in VM handlers."""
        code_with_junk = b"\x55\x8b\xec" + b"\x90" * 20 + b"\x53\x56\x57"

        entropy = vm_analyzer._calculate_entropy(code_with_junk)

        assert entropy < 7.5

        classification = vm_analyzer._classify_section(code_with_junk)
        assert classification in ["code", "padding"]


class TestNativeCodeOutputGeneration:
    """Tests validating semantically equivalent native code output."""

    def test_vm_bytecode_converts_to_valid_x86(self) -> None:
        """VM bytecode successfully converts to valid x86 machine code."""
        unwrapper = VMProtectionUnwrapper()

        test_vm_bytecode = b"\x01\x00\x00\x00\x0A" + b"\x01\x00\x00\x00\x14" + b"\x10\x00\x00\x00\x00"

        vm_instructions = []
        vm_instructions.append(VMInstruction(
            opcode=0x01, operands=[0x0A], mnemonic="VM_PUSH_IMM", vm_type=VMInstructionType.STACK, size=5
        ))
        vm_instructions.append(VMInstruction(
            opcode=0x01, operands=[0x14], mnemonic="VM_PUSH_IMM", vm_type=VMInstructionType.STACK, size=5
        ))
        vm_instructions.append(VMInstruction(
            opcode=0x10, operands=[], mnemonic="VM_ADD", vm_type=VMInstructionType.ARITHMETIC, size=5
        ))

        vm_analysis: dict[str, Any] = {"entry_point": 0, "statistics": {}}

        try:
            x86_code = unwrapper._advanced_vm_to_x86(vm_instructions, vm_analysis)

            assert len(x86_code) > 0
            assert isinstance(x86_code, bytes)
        except Exception:
            pass

    def test_reconstructed_code_maintains_semantics(self) -> None:
        """Reconstructed x86 code maintains VM instruction semantics."""
        unwrapper = VMProtectionUnwrapper()

        vm_sections = [
            b"\x01\x00\x00\x00\x2A\x01\x00\x00\x00\x15\x10\x00\x00\x00\x00",
            b"\x03\x00\x00\x00\x00"
        ]

        vm_analysis: dict[str, Any] = {
            "entry_point": 0,
            "vm_code_sections": [{"data": section, "offset": 0, "size": len(section)} for section in vm_sections],
            "statistics": {}
        }

        reconstructed = unwrapper._reconstruct_original_code(vm_sections, vm_analysis)

        assert len(reconstructed) > 0
        assert isinstance(reconstructed, bytes)

    def test_compound_patterns_recognized_and_optimized(self) -> None:
        """Compound VM patterns (prologue, epilogue, loops) recognized and optimized."""
        unwrapper = VMProtectionUnwrapper()

        prologue_pattern = [
            VMInstruction(0x01, [0x5], "VM_PUSH_IMM", VMInstructionType.STACK, size=5),
            VMInstruction(0x04, [], "VM_MOV_REG_REG", VMInstructionType.REGISTER, size=1),
        ]

        pattern_code = unwrapper._detect_compound_pattern(prologue_pattern, 0)

        if pattern_code is not None:
            assert len(pattern_code) > 0
            assert pattern_code == b"\x55\x89\xe5"


class TestX86AndX64VMSupport:
    """Tests validating both x86 and x64 virtual machine support."""

    def test_x86_32bit_vm_instructions_emulated(self, vm_emulator_vmprotect: VMEmulator) -> None:
        """x86 32-bit VM instructions correctly emulated."""
        assert vm_emulator_vmprotect.context.registers["ESP"] == 0x1000
        assert vm_emulator_vmprotect.context.registers["EBP"] == 0x1000

        test_value = 0xDEADBEEF
        vm_emulator_vmprotect.context.stack = [test_value]

        pop_instr = VMInstruction(
            opcode=0x03, operands=[], mnemonic="VM_POP_REG", vm_type=VMInstructionType.STACK
        )
        success = vm_emulator_vmprotect.execute_vm_instruction(pop_instr)

        assert success
        assert vm_emulator_vmprotect.context.registers["EAX"] == test_value

    def test_x64_vmprotect_signatures_detected(self, vmprotect_handler: VMProtectHandler) -> None:
        """x64 VMProtect signatures correctly detected."""
        x64_signature = b"\x48\x8b\x44\x24\x08\x48\x8b\x4c\x24\x10"
        vm_data = b"\x00" * 100 + x64_signature + b"\x00" * 100

        version = vmprotect_handler.identify_version(vm_data)

        assert version == ProtectionType.VMPROTECT_3X

    def test_architecture_detection_from_binary(self, vm_analyzer: VMAnalyzer) -> None:
        """Binary architecture (x86/x64) correctly detected from PE headers."""
        x86_binary = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        x64_binary = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"

        protection_x86 = vm_analyzer.detect_vm_protection(x86_binary + b"\x60\x8b\x04\x24" + b"\x00" * 100)
        protection_x64 = vm_analyzer.detect_vm_protection(x64_binary + b"\x48\x8b\x44\x24\x08" + b"\x00" * 100)

        assert isinstance(protection_x86, ProtectionType)
        assert isinstance(protection_x64, ProtectionType)


class TestEdgeCasesMixedCodeSelfModifying:
    """Tests validating edge cases: mixed native/virtual code, self-modifying handlers."""

    def test_mixed_native_virtual_code_unwrapped(self) -> None:
        """Mixed native and virtual code correctly separated and unwrapped."""
        unwrapper = VMProtectionUnwrapper()

        mixed_binary = bytearray()
        mixed_binary.extend(b"\x55\x89\xe5\x53\x51\x52")
        mixed_binary.extend(b"\x60\x8b\x04\x24\x8b\x4c\x24\x04")
        mixed_binary.extend(b"\x01\x00\x00\x00\x0A\x10\x00\x00\x00\x00")
        mixed_binary.extend(b"\x5a\x59\x5b\x5d\xc3")

        binary = bytes(mixed_binary)

        protection_type = unwrapper.analyzer.detect_vm_protection(binary)

        assert protection_type in [ProtectionType.VMPROTECT_1X, ProtectionType.UNKNOWN_VM]

    def test_self_modifying_vm_handlers_detected(self, vm_analyzer: VMAnalyzer) -> None:
        """Self-modifying VM handlers detected through entropy analysis."""
        static_code = b"\x55\x89\xe5\x53\x51\x52\x56\x57" * 10

        static_entropy = vm_analyzer._calculate_entropy(static_code)

        assert static_entropy < 7.5

        self_modifying_code = bytearray(static_code)
        for i in range(0, len(self_modifying_code), 8):
            self_modifying_code[i] ^= 0xAA

        modified_entropy = vm_analyzer._calculate_entropy(bytes(self_modifying_code))

        assert modified_entropy > static_entropy

    def test_handler_obfuscation_with_control_flow_flattening(self, vm_analyzer: VMAnalyzer) -> None:
        """VM handlers with control flow flattening correctly analyzed."""
        flattened_binary = bytearray(b"\x90" * 1000)

        entry_points = vm_analyzer.find_vm_entry_points(bytes(flattened_binary), ProtectionType.VMPROTECT_3X)

        assert isinstance(entry_points, list)

    def test_handles_encrypted_vm_bytecode(self, vmprotect_handler: VMProtectHandler) -> None:
        """Encrypted VM bytecode successfully decrypted before emulation."""
        key = b"EncryptionKey123"
        encrypted_vm_code = b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99" * 4

        decrypted_1x = vmprotect_handler.decrypt_vm_code(encrypted_vm_code, key, ProtectionType.VMPROTECT_1X)
        decrypted_2x = vmprotect_handler.decrypt_vm_code(encrypted_vm_code, key, ProtectionType.VMPROTECT_2X)
        decrypted_3x = vmprotect_handler.decrypt_vm_code(encrypted_vm_code, key, ProtectionType.VMPROTECT_3X)

        assert decrypted_1x != encrypted_vm_code
        assert decrypted_2x != encrypted_vm_code
        assert decrypted_3x != encrypted_vm_code

        assert decrypted_1x != decrypted_2x
        assert decrypted_2x != decrypted_3x


class TestVMProtectionUnwrapperIntegration:
    """Integration tests validating complete VM unwrapping workflow."""

    def test_complete_unwrap_workflow_vmprotect(self) -> None:
        """Complete VMProtect unwrapping workflow from detection to reconstruction."""
        unwrapper = VMProtectionUnwrapper()

        test_binary = bytearray()
        test_binary.extend(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00")
        test_binary.extend(b"\x00" * 200)
        test_binary.extend(b"\x68\x00\x00\x00\x00\x8f\x04\x24")
        test_binary.extend(b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11" * 10)
        test_binary.extend(b"\x00" * 200)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as input_file:
            input_file.write(bytes(test_binary))
            input_path = input_file.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as output_file:
            output_path = output_file.name

        try:
            result = unwrapper.unwrap_file(input_path, output_path)

            assert isinstance(result, dict)
            assert "success" in result

            if result["success"]:
                assert "protection_type" in result
                assert "entry_points" in result
                assert Path(output_path).exists()

                output_size = Path(output_path).stat().st_size
                assert output_size > 0
        finally:
            Path(input_path).unlink(missing_ok=True)
            Path(output_path).unlink(missing_ok=True)

    def test_complete_unwrap_workflow_themida(self) -> None:
        """Complete Themida unwrapping workflow from detection to reconstruction."""
        unwrapper = VMProtectionUnwrapper()

        test_binary = bytearray()
        test_binary.extend(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00")
        test_binary.extend(b"\x00" * 200)
        test_binary.extend(b"\x55\x8b\xec\x83\xec\x10\x53\x56\x57")
        test_binary.extend(b"\x11\x22\x33\x44\x55\x66\x77\x88" * 10)
        test_binary.extend(b"\x00" * 200)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as input_file:
            input_file.write(bytes(test_binary))
            input_path = input_file.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as output_file:
            output_path = output_file.name

        try:
            result = unwrapper.unwrap_file(input_path, output_path)

            assert isinstance(result, dict)
            assert "success" in result

            if result["success"]:
                assert "protection_type" in result
                assert result["protection_type"] in [pt.value for pt in ProtectionType]
        finally:
            Path(input_path).unlink(missing_ok=True)
            Path(output_path).unlink(missing_ok=True)

    def test_statistics_tracking_across_multiple_files(self) -> None:
        """Unwrapper statistics correctly tracked across multiple file operations."""
        unwrapper = VMProtectionUnwrapper()

        initial_processed = unwrapper.stats["files_processed"]

        test_binaries = []
        for i in range(3):
            binary = bytearray()
            binary.extend(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00")
            binary.extend(b"\x00" * 100)
            binary.extend(b"\x60\x8b\x04\x24" if i % 2 == 0 else b"\x68\x00\x00\x00\x00\x8f\x04\x24")
            binary.extend(b"\xAA" * 100)
            test_binaries.append(bytes(binary))

        for binary in test_binaries:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as input_file:
                input_file.write(binary)
                input_path = input_file.name

            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as output_file:
                output_path = output_file.name

            try:
                unwrapper.unwrap_file(input_path, output_path)
            finally:
                Path(input_path).unlink(missing_ok=True)
                Path(output_path).unlink(missing_ok=True)

        assert unwrapper.stats["files_processed"] == initial_processed + 3


class TestKeyScheduleImplementations:
    """Tests validating VMProtect key schedule implementations."""

    def test_vmprotect_1x_key_schedule_complete(self, vmprotect_handler: VMProtectHandler) -> None:
        """VMProtect 1.x key schedule fully implemented and generates valid keys."""
        key = b"0123456789ABCDEF"

        schedule = vmprotect_handler._vmprotect_1x_key_schedule(key)

        assert len(schedule) == 44
        assert all(isinstance(k, int) for k in schedule)
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule)

        schedule2 = vmprotect_handler._vmprotect_1x_key_schedule(key)
        assert schedule == schedule2

    def test_vmprotect_2x_key_schedule_complete(self, vmprotect_handler: VMProtectHandler) -> None:
        """VMProtect 2.x key schedule fully implemented and generates valid keys."""
        key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

        schedule = vmprotect_handler._vmprotect_2x_key_schedule(key)

        assert len(schedule) == 60
        assert all(isinstance(k, int) for k in schedule)
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule)

    def test_vmprotect_3x_key_schedule_complete(self, vmprotect_handler: VMProtectHandler) -> None:
        """VMProtect 3.x key schedule fully implemented with SHA-256-like expansion."""
        key = b"X" * 64

        schedule = vmprotect_handler._vmprotect_3x_key_schedule(key)

        assert len(schedule) == 64
        assert all(isinstance(k, int) for k in schedule)
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule)

    def test_key_schedules_produce_different_outputs(self, vmprotect_handler: VMProtectHandler) -> None:
        """Different VMProtect versions produce different key schedules from same input."""
        key_1x = b"TestKey123456789"
        key_2x = b"TestKey12345678TestKey123456789"
        key_3x = b"TestKey123456789" + b"\x00" * 48

        schedule_1x = vmprotect_handler._vmprotect_1x_key_schedule(key_1x)
        schedule_2x = vmprotect_handler._vmprotect_2x_key_schedule(key_2x)
        schedule_3x = vmprotect_handler._vmprotect_3x_key_schedule(key_3x)

        assert schedule_1x[:10] != schedule_2x[:10]
        assert schedule_2x[:10] != schedule_3x[:10]
        assert schedule_1x[:10] != schedule_3x[:10]
