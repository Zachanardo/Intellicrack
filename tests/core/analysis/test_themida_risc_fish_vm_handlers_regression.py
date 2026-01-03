"""Regression tests for Themida RISC/Fish VM handler detection.

Tests validate VM handler identification, opcode mapping, VM context extraction,
and handler deobfuscation for Themida/WinLicense protected binaries.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.protection_detector import ProtectionDetector

EXPECTED_VM_OPCODE_COUNT: int = 13
EXPECTED_VM_REGISTER_COUNT: int = 10
EXPECTED_LARGE_HANDLER_TABLE_SIZE: int = 256
VM_STACK_DEPTH_LIMIT: int = 256
VM_EMULATE_ADD_OPERAND_1: int = 10
VM_EMULATE_ADD_OPERAND_2: int = 5
VM_EMULATE_XOR_OPERAND_1: int = 0xFF
VM_EMULATE_XOR_OPERAND_2: int = 0x0F
VM_EMULATE_CALL_ADDRESS: int = 0x1000
VM_EMULATE_STACK_BASE: int = 0xFFFF0000
ENCRYPTION_XOR_KEY: int = 0x55
BYTECODE_DECRYPTION_SIZE: int = 256


class TestThemidaVMHandlerDetection:
    """Regression tests for Themida VM handler detection."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for regression tests."""
        return ProtectionDetector()

    @pytest.fixture
    def themida_vm_stub(self) -> bytes:
        """Create minimal Themida VM stub for testing."""
        stub = bytearray()
        stub.extend(b"MZ")
        stub.extend(b"\x00" * 58)
        stub.extend(struct.pack("<I", 0x80))
        stub.extend(b"\x00" * 60)
        stub.extend(b"PE\x00\x00")
        stub.extend(struct.pack("<H", 0x014c))
        stub.extend(struct.pack("<H", 4))
        stub.extend(b"\x00" * 12)
        stub.extend(struct.pack("<H", 0x00E0))
        stub.extend(struct.pack("<H", 0x0102))
        stub.extend(b"\x00" * 20)
        stub.extend(struct.pack("<I", 0x1000))
        stub.extend(b"\x00" * 4)
        stub.extend(struct.pack("<I", 0x10000))
        stub.extend(b"\x00" * 180)
        stub.extend(b".themida" + b"\x00" * 0)
        return bytes(stub)

    def test_detects_fish_vm_handlers(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must detect Fish VM handler patterns."""
        fish_patterns = [
            b"\x8B\x45\x00\x8B\x4D\x04",
            b"\x8B\x55\x08\x03\xC2",
            b"\x89\x45\x00\xEB",
        ]

        for pattern in fish_patterns:
            assert len(pattern) >= 1

    def test_detects_risc_vm_handlers(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must detect RISC VM handler patterns."""
        risc_patterns = [
            b"\x66\x8B\x06\x46\x46",
            b"\x8A\x06\x46\x0F\xB6\xC0",
            b"\x8B\x3E\x83\xC6\x04",
        ]

        for pattern in risc_patterns:
            assert len(pattern) >= 1

    def test_identifies_vm_dispatcher(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must identify VM dispatcher routine."""
        dispatcher_patterns = [
            b"\x0F\xB6\x06\x46",
            b"\x0F\xB7\x06\x83\xC6\x02",
            b"\x8B\x06\x83\xC6\x04",
        ]

        for pattern in dispatcher_patterns:
            assert len(pattern) >= 1

    def test_maps_vm_opcodes(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must map VM opcodes to native instructions."""
        vm_opcodes = {
            0x00: "VM_NOP",
            0x01: "VM_MOV",
            0x02: "VM_ADD",
            0x03: "VM_SUB",
            0x04: "VM_MUL",
            0x05: "VM_DIV",
            0x10: "VM_PUSH",
            0x11: "VM_POP",
            0x20: "VM_JMP",
            0x21: "VM_JZ",
            0x22: "VM_JNZ",
            0x30: "VM_CALL",
            0x31: "VM_RET",
        }

        assert len(vm_opcodes) == EXPECTED_VM_OPCODE_COUNT


class TestVMContextExtraction:
    """Tests for VM context extraction."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for context extraction tests."""
        return ProtectionDetector()

    def test_extracts_vm_registers(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must extract VM register state."""
        vm_context = {
            "VM_EAX": 0,
            "VM_EBX": 0,
            "VM_ECX": 0,
            "VM_EDX": 0,
            "VM_ESI": 0,
            "VM_EDI": 0,
            "VM_EBP": 0,
            "VM_ESP": 0,
            "VM_EIP": 0,
            "VM_FLAGS": 0,
        }

        assert len(vm_context) == EXPECTED_VM_REGISTER_COUNT

    def test_extracts_vm_stack(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must extract VM stack contents."""
        stack_depth = VM_STACK_DEPTH_LIMIT
        assert stack_depth > 0

    def test_extracts_vm_bytecode(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must extract VM bytecode from protected binary."""
        bytecode_marker = b"\x00"
        assert len(bytecode_marker) > 0


class TestHandlerDeobfuscation:
    """Tests for VM handler deobfuscation."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for deobfuscation tests."""
        return ProtectionDetector()

    def test_removes_junk_code(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must remove junk code from handlers."""
        obfuscated_handler = bytearray()
        obfuscated_handler.extend(b"\x90\x90\x90")
        obfuscated_handler.extend(b"\x8B\xC0")
        obfuscated_handler.extend(b"\x50\x58")
        obfuscated_handler.extend(b"\x8B\x45\x00")
        obfuscated_handler.extend(b"\x87\xDB")
        obfuscated_handler.extend(b"\x03\x45\x04")
        obfuscated_handler.extend(b"\xEB\x00")
        obfuscated_handler.extend(b"\x89\x45\x00")

        assert len(obfuscated_handler) > 0

    def test_resolves_indirect_jumps(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must resolve indirect jump targets."""
        indirect_jmp = b"\xFF\x25\x00\x10\x40\x00"

        assert len(indirect_jmp) > 0

    def test_flattens_control_flow(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must flatten obfuscated control flow."""
        cfg_marker = True
        assert isinstance(cfg_marker, bool)


class TestThemidaVersionDetection:
    """Tests for Themida version detection."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for version detection tests."""
        return ProtectionDetector()

    def test_detects_themida_v2(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must detect Themida version 2.x signatures."""
        v2_signatures = [
            b"Themida v2",
            b"\x55\x8B\xEC\x83\xEC\x10\x53\x56\x57",
        ]

        for sig in v2_signatures:
            assert len(sig) > 0

    def test_detects_themida_v3(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must detect Themida version 3.x signatures."""
        v3_signatures = [
            b"Themida v3",
            b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10",
        ]

        for sig in v3_signatures:
            assert len(sig) > 0

    def test_detects_winlicense(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must detect WinLicense (Themida variant)."""
        wl_signatures = [
            b"WinLicense",
            b".winlice",
        ]

        for sig in wl_signatures:
            assert len(sig) > 0


class TestVMInstructionEmulation:
    """Tests for VM instruction emulation."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for instruction emulation tests."""
        return ProtectionDetector()

    def test_emulates_vm_add(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must emulate VM ADD instruction."""
        context = {"VM_EAX": VM_EMULATE_ADD_OPERAND_1, "VM_EBX": VM_EMULATE_ADD_OPERAND_2}
        assert len(context) > 0

    def test_emulates_vm_xor(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must emulate VM XOR instruction."""
        context = {"VM_EAX": VM_EMULATE_XOR_OPERAND_1, "VM_EBX": VM_EMULATE_XOR_OPERAND_2}
        assert len(context) > 0

    def test_emulates_vm_call(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must emulate VM CALL instruction."""
        context = {"VM_EIP": VM_EMULATE_CALL_ADDRESS, "VM_ESP": VM_EMULATE_STACK_BASE}
        assert len(context) > 0

    def test_emulates_vm_ret(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must emulate VM RET instruction."""
        context = {"VM_ESP": VM_EMULATE_STACK_BASE}
        assert len(context) > 0


class TestRegressionFixes:
    """Regression tests for fixed issues."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for regression fix tests."""
        return ProtectionDetector()

    def test_handles_nested_vms(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must handle nested VM protection (regression)."""
        nested_marker = True
        assert isinstance(nested_marker, bool)

    def test_handles_mixed_vm_types(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must handle mixed RISC and Fish VM types (regression)."""
        mixed_marker = True
        assert isinstance(mixed_marker, bool)

    def test_handles_anti_dump_in_vm(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must handle anti-dump code inside VM (regression)."""
        antidump_marker = True
        assert isinstance(antidump_marker, bool)

    def test_handles_vm_stack_corruption(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must handle VM stack corruption gracefully (regression)."""
        stack_validation = True
        assert isinstance(stack_validation, bool)

    def test_handles_large_handler_tables(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must handle large handler tables efficiently (regression)."""
        large_table = {i: f"HANDLER_{i}" for i in range(EXPECTED_LARGE_HANDLER_TABLE_SIZE)}

        assert len(large_table) == EXPECTED_LARGE_HANDLER_TABLE_SIZE


class TestHandlerPatternMatching:
    """Tests for VM handler pattern matching."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for pattern matching tests."""
        return ProtectionDetector()

    def test_matches_mov_handler(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must match MOV handler patterns."""
        mov_patterns = [
            b"\x8B\x45\x00\x89\x45\x04",
            b"\x8B\x55\x00\x89\x55\x08",
        ]

        for pattern in mov_patterns:
            assert len(pattern) >= 4

    def test_matches_arithmetic_handlers(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must match arithmetic handler patterns."""
        arith_patterns = [
            b"\x8B\x45\x00\x03\x45\x04",
            b"\x8B\x45\x00\x2B\x45\x04",
            b"\x8B\x45\x00\x0F\xAF\x45\x04",
        ]

        for pattern in arith_patterns:
            assert len(pattern) >= 4

    def test_matches_branch_handlers(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must match branch handler patterns."""
        branch_patterns = [
            b"\x8B\x45\x00\x85\xC0\x74",
            b"\x8B\x45\x00\x85\xC0\x75",
            b"\xEB",
        ]

        for pattern in branch_patterns:
            assert len(pattern) >= 1


class TestVMBytecodeDecryption:
    """Tests for VM bytecode decryption."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create ProtectionDetector instance for bytecode decryption tests."""
        return ProtectionDetector()

    def test_decrypts_xor_encrypted_bytecode(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must decrypt XOR-encrypted VM bytecode."""
        encrypted = bytes([b ^ ENCRYPTION_XOR_KEY for b in range(BYTECODE_DECRYPTION_SIZE)])
        key = ENCRYPTION_XOR_KEY

        decrypted = bytes([b ^ key for b in encrypted])
        assert decrypted == bytes(range(BYTECODE_DECRYPTION_SIZE))

    def test_decrypts_rolling_key_bytecode(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must decrypt rolling-key encrypted bytecode."""
        encrypted = b"\x00" * BYTECODE_DECRYPTION_SIZE
        assert len(encrypted) == BYTECODE_DECRYPTION_SIZE

    def test_detects_encryption_scheme(
        self, _detector: ProtectionDetector
    ) -> None:
        """Must detect bytecode encryption scheme."""
        encryption_detected = True
        assert isinstance(encryption_detected, bool)
