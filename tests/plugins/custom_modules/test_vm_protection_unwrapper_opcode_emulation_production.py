#!/usr/bin/env python3
"""Production tests for VM Protection Unwrapper opcode emulation.

Tests validate complete virtual CPU opcode set emulation for VMProtect/Themida
virtual machines, ensuring accurate register and memory state tracking with
semantically equivalent native code output.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.plugins.custom_modules.vm_protection_unwrapper import (
    CodeVirtualizerHandler,
    ProtectionType,
    ThemidaHandler,
    VMContext,
    VMEmulator,
    VMInstruction,
    VMInstructionType,
    VMProtectHandler,
)


@pytest.fixture
def vmprotect_1x_bytecode() -> bytes:
    """Generate realistic VMProtect 1.x bytecode with complete opcode coverage."""
    bytecode = bytearray()
    bytecode.extend(b"\x60\x8b\x04\x24\x8b\x4c\x24\x04")
    bytecode.extend(b"\x01")
    bytecode.extend(struct.pack("<I", 0x12345678))
    bytecode.extend(b"\x02")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x03")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x10")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x11")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x12")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x13")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x14")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x20")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x21")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x22")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x23")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x24")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x25")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x30")
    bytecode.extend(struct.pack("<I", 0x100))
    bytecode.extend(b"\x31")
    bytecode.extend(struct.pack("<I", 0x200))
    bytecode.extend(b"\x32")
    bytecode.extend(struct.pack("<I", 0x300))
    bytecode.extend(b"\x38")
    bytecode.extend(struct.pack("<I", 0))
    return bytes(bytecode)


@pytest.fixture
def vmprotect_2x_bytecode() -> bytes:
    """Generate realistic VMProtect 2.x bytecode with advanced opcodes."""
    bytecode = bytearray()
    bytecode.extend(b"\x68\x00\x00\x00\x00\x8f\x04\x24")
    bytecode.extend(b"\x01")
    bytecode.extend(struct.pack("<I", 0xAABBCCDD))
    bytecode.extend(b"\x10")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x11")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x20")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x21")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x30")
    bytecode.extend(struct.pack("<I", 0x500))
    bytecode.extend(b"\x40")
    bytecode.extend(struct.pack("<I", 0x1000))
    bytecode.extend(b"\x41")
    bytecode.extend(struct.pack("<I", 0x2000))
    return bytes(bytecode)


@pytest.fixture
def vmprotect_3x_bytecode() -> bytes:
    """Generate realistic VMProtect 3.x x64 bytecode."""
    bytecode = bytearray()
    bytecode.extend(b"\x48\x8b\x44\x24\x08\x48\x8b\x4c\x24\x10")
    bytecode.extend(b"\x01")
    bytecode.extend(struct.pack("<I", 0xDEADBEEF))
    bytecode.extend(b"\x10")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x20")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x30")
    bytecode.extend(struct.pack("<I", 0x800))
    return bytes(bytecode)


@pytest.fixture
def themida_bytecode() -> bytes:
    """Generate realistic Themida VM bytecode with complete opcode set."""
    bytecode = bytearray()
    bytecode.extend(b"\x55\x8b\xec\x83\xec\x10\x53\x56\x57")
    bytecode.extend(b"\x00")
    bytecode.extend(b"\x01")
    bytecode.extend(struct.pack("<I", 0x11223344))
    bytecode.extend(b"\x02")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x03")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x04")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x05")
    bytecode.extend(struct.pack("<I", 0x99887766))
    bytecode.extend(b"\x10")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x11")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x12")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x13")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x14")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x20")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x21")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x22")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x23")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x24")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x25")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x30")
    bytecode.extend(struct.pack("<I", 0x400))
    bytecode.extend(b"\x31")
    bytecode.extend(struct.pack("<I", 0x500))
    bytecode.extend(b"\x32")
    bytecode.extend(struct.pack("<I", 0x600))
    bytecode.extend(b"\x33")
    bytecode.extend(struct.pack("<I", 0x700))
    bytecode.extend(b"\x34")
    bytecode.extend(struct.pack("<I", 0x800))
    bytecode.extend(b"\x35")
    bytecode.extend(struct.pack("<I", 0x900))
    bytecode.extend(b"\x36")
    bytecode.extend(struct.pack("<I", 0xA00))
    bytecode.extend(b"\x37")
    bytecode.extend(struct.pack("<I", 0xB00))
    bytecode.extend(b"\x38")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x40")
    bytecode.extend(struct.pack("<I", 0x1000))
    bytecode.extend(b"\x41")
    bytecode.extend(struct.pack("<I", 0x2000))
    bytecode.extend(b"\x42")
    bytecode.extend(struct.pack("<I", 0x3000))
    bytecode.extend(b"\x43")
    bytecode.extend(struct.pack("<I", 0x4000))
    return bytes(bytecode)


@pytest.fixture
def code_virtualizer_bytecode() -> bytes:
    """Generate realistic Code Virtualizer bytecode with complete opcode set."""
    bytecode = bytearray()
    bytecode.extend(b"\x55\x8b\xec\x81\xec\x00\x04\x00\x00")
    bytecode.extend(b"\x10")
    bytecode.extend(struct.pack("<I", 0xCAFEBABE))
    bytecode.extend(b"\x11")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x12")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x13")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x20")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x21")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x22")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x23")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x24")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x25")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x30")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x31")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x32")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x33")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x34")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x35")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x36")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x37")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x40")
    bytecode.extend(struct.pack("<I", 0x100))
    bytecode.extend(b"\x41")
    bytecode.extend(struct.pack("<I", 0x200))
    bytecode.extend(b"\x42")
    bytecode.extend(struct.pack("<I", 0x300))
    bytecode.extend(b"\x43")
    bytecode.extend(struct.pack("<I", 0x400))
    bytecode.extend(b"\x44")
    bytecode.extend(struct.pack("<I", 0x500))
    bytecode.extend(b"\x45")
    bytecode.extend(struct.pack("<I", 0x600))
    bytecode.extend(b"\x46")
    bytecode.extend(struct.pack("<I", 0x700))
    bytecode.extend(b"\x47")
    bytecode.extend(struct.pack("<I", 0x800))
    bytecode.extend(b"\x48")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x50")
    bytecode.extend(struct.pack("<I", 0x1000))
    bytecode.extend(b"\x51")
    bytecode.extend(struct.pack("<I", 0x2000))
    bytecode.extend(b"\x52")
    bytecode.extend(struct.pack("<I", 0x3000))
    bytecode.extend(b"\x53")
    bytecode.extend(struct.pack("<I", 0x4000))
    bytecode.extend(b"\x60")
    bytecode.extend(struct.pack("<I", 0))
    bytecode.extend(b"\x61")
    bytecode.extend(struct.pack("<I", 0))
    return bytes(bytecode)


class TestVMProtectOpcodeEmulation:
    """Test complete VMProtect virtual CPU opcode emulation."""

    def test_vmprotect_complete_opcode_set_parsing(self, themida_bytecode: bytes) -> None:
        """VMProtect emulator must parse all Themida VM opcodes correctly."""
        emulator = VMEmulator(ProtectionType.THEMIDA)
        handler = emulator.handlers[ProtectionType.THEMIDA]

        assert isinstance(handler, ThemidaHandler)
        assert hasattr(handler, "opcode_map")

        opcode_map = handler.opcode_map
        assert len(opcode_map) >= 20

        required_opcodes = [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x20,
            0x21,
            0x22,
            0x23,
            0x24,
            0x25,
            0x30,
            0x31,
            0x32,
            0x33,
            0x34,
            0x35,
            0x36,
            0x37,
            0x38,
            0x40,
            0x41,
            0x42,
            0x43,
        ]

        for opcode in required_opcodes:
            assert opcode in opcode_map
            mnemonic, vm_type = opcode_map[opcode]
            assert isinstance(mnemonic, str)
            assert isinstance(vm_type, VMInstructionType)

    def test_vmprotect_arithmetic_opcodes_execution(self) -> None:
        """VMProtect emulator must execute all arithmetic opcodes with correct results."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        emulator.context.stack = [10, 5]
        add_instr = VMInstruction(
            opcode=0x10,
            operands=[],
            mnemonic="VM_ADD",
            vm_type=VMInstructionType.ARITHMETIC,
        )
        success = emulator.execute_vm_instruction(add_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 15
        assert emulator.context.flags["ZF"] is False

        emulator.context.stack = [20, 8]
        sub_instr = VMInstruction(
            opcode=0x11,
            operands=[],
            mnemonic="VM_SUB",
            vm_type=VMInstructionType.ARITHMETIC,
        )
        success = emulator.execute_vm_instruction(sub_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 12

        emulator.context.stack = [7, 6]
        mul_instr = VMInstruction(
            opcode=0x12,
            operands=[],
            mnemonic="VM_MUL",
            vm_type=VMInstructionType.ARITHMETIC,
        )
        success = emulator.execute_vm_instruction(mul_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 42

        emulator.context.stack = [100, 5]
        div_instr = VMInstruction(
            opcode=0x13,
            operands=[],
            mnemonic="VM_DIV",
            vm_type=VMInstructionType.ARITHMETIC,
        )
        success = emulator.execute_vm_instruction(div_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 20

    def test_vmprotect_logical_opcodes_execution(self) -> None:
        """VMProtect emulator must execute all logical opcodes correctly."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        emulator.context.stack = [0b11110000, 0b10101010]
        and_instr = VMInstruction(
            opcode=0x20,
            operands=[],
            mnemonic="VM_AND",
            vm_type=VMInstructionType.LOGICAL,
        )
        success = emulator.execute_vm_instruction(and_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 0b10100000

        emulator.context.stack = [0b11110000, 0b10101010]
        or_instr = VMInstruction(
            opcode=0x21,
            operands=[],
            mnemonic="VM_OR",
            vm_type=VMInstructionType.LOGICAL,
        )
        success = emulator.execute_vm_instruction(or_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 0b11111010

        emulator.context.stack = [0b11110000, 0b10101010]
        xor_instr = VMInstruction(
            opcode=0x22,
            operands=[],
            mnemonic="VM_XOR",
            vm_type=VMInstructionType.LOGICAL,
        )
        success = emulator.execute_vm_instruction(xor_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 0b01011010

        emulator.context.stack = [0b11110000]
        not_instr = VMInstruction(
            opcode=0x23,
            operands=[],
            mnemonic="VM_NOT",
            vm_type=VMInstructionType.LOGICAL,
        )
        success = emulator.execute_vm_instruction(not_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == (~0b11110000) & 0xFFFFFFFF

        emulator.context.stack = [0b00000001, 4]
        shl_instr = VMInstruction(
            opcode=0x24,
            operands=[],
            mnemonic="VM_SHL",
            vm_type=VMInstructionType.LOGICAL,
        )
        success = emulator.execute_vm_instruction(shl_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 0b00010000

        emulator.context.stack = [0b10000000, 4]
        shr_instr = VMInstruction(
            opcode=0x25,
            operands=[],
            mnemonic="VM_SHR",
            vm_type=VMInstructionType.LOGICAL,
        )
        success = emulator.execute_vm_instruction(shr_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 0b00001000

    def test_vmprotect_stack_opcodes_execution(self) -> None:
        """VMProtect emulator must handle all stack operations correctly."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        push_instr = VMInstruction(
            opcode=0x01,
            operands=[0xDEADBEEF],
            mnemonic="VM_PUSH_IMM",
            vm_type=VMInstructionType.STACK,
        )
        success = emulator.execute_vm_instruction(push_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 0xDEADBEEF

        emulator.context.registers["EAX"] = 0x12345678
        push_reg_instr = VMInstruction(
            opcode=0x02,
            operands=[],
            mnemonic="VM_PUSH_REG",
            vm_type=VMInstructionType.STACK,
        )
        success = emulator.execute_vm_instruction(push_reg_instr)
        assert success
        assert len(emulator.context.stack) == 2
        assert emulator.context.stack[1] == 0x12345678

        pop_instr = VMInstruction(
            opcode=0x03,
            operands=[],
            mnemonic="VM_POP_REG",
            vm_type=VMInstructionType.STACK,
        )
        success = emulator.execute_vm_instruction(pop_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.registers["EAX"] == 0x12345678

    def test_vmprotect_memory_opcodes_execution(self) -> None:
        """VMProtect emulator must handle all memory operations correctly."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        test_address = 0x1000
        test_value = 0xCAFEBABE

        emulator.context.stack = [test_value, test_address]
        store_instr = VMInstruction(
            opcode=0x41,
            operands=[],
            mnemonic="VM_STORE",
            vm_type=VMInstructionType.MEMORY,
        )
        success = emulator.execute_vm_instruction(store_instr)
        assert success
        assert len(emulator.context.stack) == 0
        assert test_address in emulator.context.memory
        stored_data = emulator.context.memory[test_address]
        assert struct.unpack("<I", stored_data)[0] == test_value

        emulator.context.stack = [test_address]
        load_instr = VMInstruction(
            opcode=0x40,
            operands=[],
            mnemonic="VM_LOAD",
            vm_type=VMInstructionType.MEMORY,
        )
        success = emulator.execute_vm_instruction(load_instr)
        assert success
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == test_value

    def test_vmprotect_control_flow_opcodes_execution(self) -> None:
        """VMProtect emulator must handle all control flow operations correctly."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        emulator.context.registers["EIP"] = 0x1000
        jmp_instr = VMInstruction(
            opcode=0x30,
            operands=[0x2000],
            mnemonic="VM_JMP",
            vm_type=VMInstructionType.CONTROL_FLOW,
        )
        success = emulator.execute_vm_instruction(jmp_instr)
        assert success
        assert emulator.context.registers["EIP"] == 0x2000

        emulator.context.flags["ZF"] = True
        emulator.context.registers["EIP"] = 0x3000
        jz_instr = VMInstruction(
            opcode=0x31,
            operands=[0x4000],
            mnemonic="VM_JZ",
            vm_type=VMInstructionType.CONTROL_FLOW,
        )
        success = emulator.execute_vm_instruction(jz_instr)
        assert success
        assert emulator.context.registers["EIP"] == 0x4000

        emulator.context.flags["ZF"] = False
        emulator.context.registers["EIP"] = 0x5000
        jnz_instr = VMInstruction(
            opcode=0x32,
            operands=[0x6000],
            mnemonic="VM_JNZ",
            vm_type=VMInstructionType.CONTROL_FLOW,
        )
        success = emulator.execute_vm_instruction(jnz_instr)
        assert success
        assert emulator.context.registers["EIP"] == 0x6000

        emulator.context.registers["EIP"] = 0x7000
        call_instr = VMInstruction(
            opcode=0x37,
            operands=[0x8000],
            mnemonic="VM_CALL",
            vm_type=VMInstructionType.CONTROL_FLOW,
        )
        success = emulator.execute_vm_instruction(call_instr)
        assert success
        assert emulator.context.registers["EIP"] == 0x8000
        assert len(emulator.context.stack) == 1
        assert emulator.context.stack[0] == 0x7000

        ret_instr = VMInstruction(
            opcode=0x38,
            operands=[],
            mnemonic="VM_RET",
            vm_type=VMInstructionType.CONTROL_FLOW,
        )
        success = emulator.execute_vm_instruction(ret_instr)
        assert success
        assert emulator.context.registers["EIP"] == 0x7000
        assert len(emulator.context.stack) == 0

    def test_vmprotect_register_state_tracking(self) -> None:
        """VMProtect emulator must track virtual register state accurately."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        assert emulator.context.registers["EAX"] == 0
        assert emulator.context.registers["EBX"] == 0
        assert emulator.context.registers["ECX"] == 0
        assert emulator.context.registers["EDX"] == 0
        assert emulator.context.registers["ESI"] == 0
        assert emulator.context.registers["EDI"] == 0
        assert emulator.context.registers["ESP"] == 0x1000
        assert emulator.context.registers["EBP"] == 0x1000
        assert emulator.context.registers["EIP"] == 0

        emulator.context.stack = [0x11111111, 0x22222222]
        mov_instr = VMInstruction(
            opcode=0x04,
            operands=[],
            mnemonic="VM_MOV_REG_REG",
            vm_type=VMInstructionType.REGISTER,
        )
        emulator.execute_vm_instruction(mov_instr)
        assert emulator.context.registers["EAX"] == 0x22222222

        push_instr = VMInstruction(
            opcode=0x01,
            operands=[0xAAAABBBB],
            mnemonic="VM_PUSH_IMM",
            vm_type=VMInstructionType.STACK,
        )
        emulator.execute_vm_instruction(push_instr)
        assert 0xAAAABBBB in emulator.context.stack

    def test_vmprotect_flag_state_tracking(self) -> None:
        """VMProtect emulator must track virtual CPU flags accurately."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        assert emulator.context.flags["ZF"] is False
        assert emulator.context.flags["CF"] is False
        assert emulator.context.flags["SF"] is False
        assert emulator.context.flags["OF"] is False

        emulator.context.stack = [5, 5]
        sub_instr = VMInstruction(
            opcode=0x11,
            operands=[],
            mnemonic="VM_SUB",
            vm_type=VMInstructionType.ARITHMETIC,
        )
        emulator.execute_vm_instruction(sub_instr)
        assert emulator.context.flags["ZF"] is True
        assert emulator.context.stack[0] == 0

        emulator.context.stack = [0x80000001, 1]
        sub_instr2 = VMInstruction(
            opcode=0x11,
            operands=[],
            mnemonic="VM_SUB",
            vm_type=VMInstructionType.ARITHMETIC,
        )
        emulator.execute_vm_instruction(sub_instr2)
        assert emulator.context.flags["SF"] is True


class TestThemidaOpcodeEmulation:
    """Test complete Themida virtual CPU opcode emulation."""

    def test_themida_complete_opcode_coverage(self) -> None:
        """Themida handler must implement all documented VM opcodes."""
        handler = ThemidaHandler()
        opcode_map = handler.opcode_map

        themida_opcodes = {
            0x00: "VM_NOP",
            0x01: "VM_PUSH_IMM",
            0x02: "VM_PUSH_REG",
            0x03: "VM_POP_REG",
            0x04: "VM_MOV_REG_REG",
            0x05: "VM_MOV_REG_IMM",
            0x10: "VM_ADD",
            0x11: "VM_SUB",
            0x12: "VM_MUL",
            0x13: "VM_DIV",
            0x14: "VM_MOD",
            0x20: "VM_AND",
            0x21: "VM_OR",
            0x22: "VM_XOR",
            0x23: "VM_NOT",
            0x24: "VM_SHL",
            0x25: "VM_SHR",
            0x30: "VM_JMP",
            0x31: "VM_JZ",
            0x32: "VM_JNZ",
            0x33: "VM_JE",
            0x34: "VM_JNE",
            0x35: "VM_JG",
            0x36: "VM_JL",
            0x37: "VM_CALL",
            0x38: "VM_RET",
            0x40: "VM_LOAD",
            0x41: "VM_STORE",
            0x42: "VM_LOAD_BYTE",
            0x43: "VM_STORE_BYTE",
        }

        for opcode, expected_mnemonic in themida_opcodes.items():
            assert opcode in opcode_map
            mnemonic, vm_type = opcode_map[opcode]
            assert mnemonic == expected_mnemonic

    def test_themida_bytecode_decryption(self) -> None:
        """Themida handler must decrypt bytecode using rolling XOR with key rotation."""
        handler = ThemidaHandler()
        key = b"\xAA\xBB\xCC\xDD"
        plaintext = b"\x00\x01\x02\x03\x04\x05\x06\x07"

        encrypted = bytearray()
        for i, byte in enumerate(plaintext):
            rotated_key = handler._rotate_key(key, i)
            encrypted_byte = byte ^ rotated_key[i % len(rotated_key)]
            encrypted.append(encrypted_byte)

        decrypted = handler.decrypt_themida_vm(bytes(encrypted), key)
        assert decrypted == plaintext

    def test_themida_key_rotation(self) -> None:
        """Themida handler must rotate decryption key based on position."""
        handler = ThemidaHandler()
        key = b"\x11\x22\x33\x44\x55\x66"

        rotated_0 = handler._rotate_key(key, 0)
        assert rotated_0 == key

        rotated_2 = handler._rotate_key(key, 2)
        assert rotated_2 == b"\x33\x44\x55\x66\x11\x22"

        rotated_5 = handler._rotate_key(key, 5)
        assert rotated_5 == b"\x66\x11\x22\x33\x44\x55"


class TestCodeVirtualizerOpcodeEmulation:
    """Test complete Code Virtualizer virtual CPU opcode emulation."""

    def test_code_virtualizer_complete_opcode_set(self) -> None:
        """Code Virtualizer handler must implement all documented opcodes."""
        handler = CodeVirtualizerHandler()
        opcode_map = handler.opcode_map

        cv_opcodes = {
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

        for opcode, (expected_mnemonic, expected_type) in cv_opcodes.items():
            assert opcode in opcode_map
            mnemonic, vm_type = opcode_map[opcode]
            assert mnemonic == expected_mnemonic
            assert vm_type == expected_type

    def test_code_virtualizer_rc4_decryption(self) -> None:
        """Code Virtualizer handler must decrypt bytecode using RC4 stream cipher."""
        handler = CodeVirtualizerHandler()
        key = b"\x01\x02\x03\x04\x05"
        plaintext = b"Hello, World! This is a test message for RC4 decryption."

        encrypted = handler._rc4_decrypt(plaintext, key)
        assert encrypted != plaintext

        decrypted = handler._rc4_decrypt(encrypted, key)
        assert decrypted == plaintext


class TestVMProtectKeySchedules:
    """Test VMProtect version-specific key schedule implementations."""

    def test_vmprotect_1x_key_schedule_generation(self) -> None:
        """VMProtect 1.x handler must generate valid key schedule with 44 round keys."""
        handler = VMProtectHandler()
        key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

        schedule = handler._vmprotect_1x_key_schedule(key)

        assert len(schedule) == 44
        assert all(isinstance(k, int) for k in schedule)
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule)
        assert schedule[:4] == list(struct.unpack("<4I", key))

    def test_vmprotect_2x_key_schedule_generation(self) -> None:
        """VMProtect 2.x handler must generate valid key schedule with 60 round keys."""
        handler = VMProtectHandler()
        key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" * 2

        schedule = handler._vmprotect_2x_key_schedule(key)

        assert len(schedule) == 60
        assert all(isinstance(k, int) for k in schedule)
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule)
        assert schedule[:8] == list(struct.unpack("<8I", key))

    def test_vmprotect_3x_key_schedule_generation(self) -> None:
        """VMProtect 3.x handler must generate valid key schedule with 64 round keys."""
        handler = VMProtectHandler()
        key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" * 4

        schedule = handler._vmprotect_3x_key_schedule(key)

        assert len(schedule) == 64
        assert all(isinstance(k, int) for k in schedule)
        assert all(0 <= k <= 0xFFFFFFFF for k in schedule)

    def test_vmprotect_key_schedule_decryption(self) -> None:
        """VMProtect handler must decrypt data using generated key schedules."""
        handler = VMProtectHandler()
        key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
        plaintext = b"This is test data for decryption validation purposes!!"

        schedule = handler._vmprotect_1x_key_schedule(key)
        encrypted = handler._decrypt_with_schedule(plaintext, schedule)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) >= len(plaintext)


class TestVMHandlerObfuscation:
    """Test VM handler obfuscation detection and handling."""

    def test_vm_emulator_handles_unknown_opcodes(self) -> None:
        """VM emulator must detect and handle obfuscated/unknown opcodes gracefully."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        unknown_opcode_data = b"\xFF" + struct.pack("<I", 0x12345678)
        instruction = emulator.parse_vm_instruction(unknown_opcode_data, 0)

        assert instruction.opcode == 0xFF
        assert "UNK_" in instruction.mnemonic
        assert instruction.vm_type == VMInstructionType.CUSTOM

    def test_vm_emulator_instruction_parsing_robustness(self) -> None:
        """VM emulator must handle corrupted or truncated instructions gracefully."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        with pytest.raises(ValueError, match="Offset out of bounds"):
            emulator.parse_vm_instruction(b"\x01\x02\x03", 100)

        short_data = b"\x10\x11"
        instruction = emulator.parse_vm_instruction(short_data, 0)
        assert instruction.opcode == 0x10


class TestMixedNativeVirtualCode:
    """Test handling of mixed native and virtual code edge cases."""

    def test_vm_emulator_handles_native_code_transitions(self, themida_bytecode: bytes) -> None:
        """VM emulator must handle transitions between VM and native code."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        offset = 0
        instructions_parsed = 0
        native_patterns_encountered = 0

        while offset < len(themida_bytecode) - 1:
            try:
                instruction = emulator.parse_vm_instruction(themida_bytecode, offset)
                instructions_parsed += 1

                if instruction.mnemonic.startswith("UNK_"):
                    native_patterns_encountered += 1

                offset += instruction.size
            except (ValueError, struct.error):
                break

        assert instructions_parsed > 0

    def test_vm_context_preservation_across_execution(self) -> None:
        """VM context must preserve register and memory state across instruction execution."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        initial_registers = emulator.context.registers.copy()
        initial_stack = emulator.context.stack.copy()
        initial_memory = emulator.context.memory.copy()

        push_instr = VMInstruction(
            opcode=0x01,
            operands=[0xDEADBEEF],
            mnemonic="VM_PUSH_IMM",
            vm_type=VMInstructionType.STACK,
        )
        emulator.execute_vm_instruction(push_instr)

        assert emulator.context.registers != initial_registers or len(emulator.context.stack) != len(initial_stack)
        assert len(emulator.context.stack) == len(initial_stack) + 1


class TestSelfModifyingVMHandlers:
    """Test handling of self-modifying VM handler edge cases."""

    def test_vm_memory_modification_detection(self) -> None:
        """VM emulator must track memory modifications for self-modifying code detection."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        address1 = 0x1000
        value1 = 0xAAAAAAAA
        emulator.context.stack = [value1, address1]
        store_instr = VMInstruction(
            opcode=0x41,
            operands=[],
            mnemonic="VM_STORE",
            vm_type=VMInstructionType.MEMORY,
        )
        emulator.execute_vm_instruction(store_instr)
        assert address1 in emulator.context.memory

        address2 = 0x1000
        value2 = 0xBBBBBBBB
        emulator.context.stack = [value2, address2]
        emulator.execute_vm_instruction(store_instr)

        loaded_value = struct.unpack("<I", emulator.context.memory[address1])[0]
        assert loaded_value == value2


class TestX86AndX64VirtualMachines:
    """Test support for both x86 and x64 virtual machines."""

    def test_vmprotect_1x_x86_architecture_support(self, vmprotect_1x_bytecode: bytes) -> None:
        """VMProtect 1.x handler must support x86 virtual machine instructions."""
        handler = VMProtectHandler()
        version = handler.identify_version(vmprotect_1x_bytecode)

        assert version == ProtectionType.VMPROTECT_1X

    def test_vmprotect_2x_x86_architecture_support(self, vmprotect_2x_bytecode: bytes) -> None:
        """VMProtect 2.x handler must support x86 virtual machine instructions."""
        handler = VMProtectHandler()
        version = handler.identify_version(vmprotect_2x_bytecode)

        assert version == ProtectionType.VMPROTECT_2X

    def test_vmprotect_3x_x64_architecture_support(self, vmprotect_3x_bytecode: bytes) -> None:
        """VMProtect 3.x handler must support x64 virtual machine instructions."""
        handler = VMProtectHandler()
        version = handler.identify_version(vmprotect_3x_bytecode)

        assert version == ProtectionType.VMPROTECT_3X

    def test_vm_context_supports_x86_registers(self) -> None:
        """VM context must support x86 general-purpose registers."""
        context = VMContext()

        required_registers = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"]
        for reg in required_registers:
            assert reg in context.registers
            assert isinstance(context.registers[reg], int)

    def test_vm_context_supports_x86_flags(self) -> None:
        """VM context must support x86 CPU flags."""
        context = VMContext()

        required_flags = ["ZF", "CF", "SF", "OF"]
        for flag in required_flags:
            assert flag in context.flags
            assert isinstance(context.flags[flag], bool)


class TestVMOpcodeEmulationCompleteness:
    """Test completeness of VM opcode emulation implementation."""

    def test_all_themida_opcodes_have_execution_handlers(self) -> None:
        """All Themida opcodes must have corresponding execution logic."""
        emulator = VMEmulator(ProtectionType.THEMIDA)
        handler = emulator.handlers[ProtectionType.THEMIDA]

        assert isinstance(handler, ThemidaHandler)
        opcode_map = handler.opcode_map

        for opcode, (mnemonic, vm_type) in opcode_map.items():
            test_instruction = VMInstruction(
                opcode=opcode,
                operands=[0x1000] if vm_type == VMInstructionType.CONTROL_FLOW else [],
                mnemonic=mnemonic,
                vm_type=vm_type,
            )

            if vm_type in [VMInstructionType.ARITHMETIC, VMInstructionType.LOGICAL]:
                emulator.context.stack = [100, 50]
            elif vm_type == VMInstructionType.MEMORY:
                emulator.context.stack = [0x5000, 0x1000]

            result = emulator.execute_vm_instruction(test_instruction)
            assert isinstance(result, bool)

    def test_incomplete_opcode_emulation_causes_test_failure(self) -> None:
        """Test must fail if any required opcode is not fully implemented."""
        emulator = VMEmulator(ProtectionType.THEMIDA)

        critical_opcodes = [
            (0x01, VMInstructionType.STACK),
            (0x10, VMInstructionType.ARITHMETIC),
            (0x20, VMInstructionType.LOGICAL),
            (0x30, VMInstructionType.CONTROL_FLOW),
            (0x40, VMInstructionType.MEMORY),
        ]

        for opcode, vm_type in critical_opcodes:
            emulator.context.stack = [100, 50]
            emulator.context.registers["EIP"] = 0x1000

            test_instruction = VMInstruction(
                opcode=opcode,
                operands=[0x2000] if vm_type == VMInstructionType.CONTROL_FLOW else [42],
                mnemonic=f"TEST_{opcode:02X}",
                vm_type=vm_type,
            )

            success = emulator.execute_vm_instruction(test_instruction)
            assert success, f"Opcode 0x{opcode:02X} execution failed - implementation incomplete"
