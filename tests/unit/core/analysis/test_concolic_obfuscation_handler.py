"""Tests for concolic execution obfuscation handling.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

import struct
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

import pytest

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from intellicrack.core.analysis.concolic_obfuscation_handler import (
    ControlFlowFlatteningHandler,
    ObfuscationAwareConcolicEngine,
    OpaquePredicateDetector,
    StringDeobfuscation,
    VirtualizationDetector,
)


class TestOpaquePredicateDetector(unittest.TestCase):
    """Test opaque predicate detection functionality."""

    def setUp(self):
        """Set up test environment."""
        self.detector = OpaquePredicateDetector(confidence_threshold=0.9)

    def test_initialization(self):
        """Test detector initialization."""
        assert self.detector.confidence_threshold == 0.9
        assert isinstance(self.detector.branch_outcomes, dict)
        assert isinstance(self.detector.detected_opaques, dict)

    def test_always_true_predicate_detection(self):
        """Test detection of always-true opaque predicate."""
        address = 0x401000
        condition = "x > 0"

        for _ in range(10):
            result = self.detector.analyze_branch(address, condition, True)

        assert result is not None
        assert result["opaque"] is True
        assert result["always_true"] is True
        assert result["skip_false_path"] is True

    def test_always_false_predicate_detection(self):
        """Test detection of always-false opaque predicate."""
        address = 0x401000
        condition = "x < 0"

        for _ in range(10):
            result = self.detector.analyze_branch(address, condition, False)

        assert result is not None
        assert result["opaque"] is True
        assert result["always_true"] is False
        assert result["skip_true_path"] is True

    def test_non_opaque_predicate(self):
        """Test that non-opaque predicates are not detected."""
        address = 0x401000
        condition = "x == 5"

        for i in range(10):
            taken = i % 2 == 0
            result = self.detector.analyze_branch(address, condition, taken)

        assert result["opaque"] is False

    def test_insufficient_samples(self):
        """Test that insufficient samples don't trigger detection."""
        address = 0x401000
        condition = "x > 0"

        for _ in range(5):
            result = self.detector.analyze_branch(address, condition, True)

        assert result["opaque"] is False

    def test_different_conditions_same_address(self):
        """Test that different conditions at same address are tracked separately."""
        address = 0x401000

        for _ in range(10):
            self.detector.analyze_branch(address, "x > 0", True)
            self.detector.analyze_branch(address, "y < 5", False)

        result1 = self.detector.analyze_branch(address, "x > 0", True)
        result2 = self.detector.analyze_branch(address, "y < 5", False)

        assert result1["opaque"] is True
        assert result1["always_true"] is True
        assert result2["opaque"] is True
        assert result2["always_true"] is False

    def test_confidence_threshold(self):
        """Test confidence threshold enforcement."""
        detector_high = OpaquePredicateDetector(confidence_threshold=0.95)
        detector_low = OpaquePredicateDetector(confidence_threshold=0.85)

        address = 0x401000
        condition = "x > 0"

        for _ in range(9):
            detector_high.analyze_branch(address, condition, True)
            detector_low.analyze_branch(address, condition, True)

        detector_high.analyze_branch(address, condition, False)
        detector_low.analyze_branch(address, condition, False)

        result_high = detector_high.analyze_branch(address, condition, True)
        result_low = detector_low.analyze_branch(address, condition, True)

        assert result_high["opaque"] is False
        assert result_low["opaque"] is True

    def test_get_detected_opaques(self):
        """Test retrieving all detected opaque predicates."""
        self.detector.analyze_branch(0x401000, "x > 0", True)
        for _ in range(10):
            self.detector.analyze_branch(0x401000, "x > 0", True)

        opaques = self.detector.get_detected_opaques()
        assert isinstance(opaques, dict)
        assert len(opaques) > 0

    def test_clear_detected_opaques(self):
        """Test clearing detected opaque predicates."""
        for _ in range(10):
            self.detector.analyze_branch(0x401000, "x > 0", True)

        self.detector.clear_detected_opaques()
        opaques = self.detector.get_detected_opaques()
        assert len(opaques) == 0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestControlFlowFlatteningHandler(unittest.TestCase):
    """Test control flow flattening detection."""

    def setUp(self):
        """Set up test environment."""
        self.handler = ControlFlowFlatteningHandler()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def create_mock_instruction(self, mnemonic, op_str=""):
        """Create a mock instruction."""
        insn = Mock()
        insn.mnemonic = mnemonic
        insn.op_str = op_str
        insn.address = 0x401000
        return insn

    def test_initialization(self):
        """Test handler initialization."""
        assert isinstance(self.handler.state_variables, set)
        assert isinstance(self.handler.dispatcher_blocks, set)
        assert self.handler.dispatcher_detected is False

    def test_dispatcher_pattern_detection(self):
        """Test detection of dispatcher pattern."""
        instructions = [
            self.create_mock_instruction("cmp", "eax, 1"),
            self.create_mock_instruction("je", "0x401020"),
            self.create_mock_instruction("cmp", "eax, 2"),
            self.create_mock_instruction("je", "0x401030"),
            self.create_mock_instruction("cmp", "eax, 3"),
            self.create_mock_instruction("je", "0x401040"),
            self.create_mock_instruction("jmp", "[rax*8+0x403000]"),
        ]

        result = self.handler.analyze_block(0x401000, instructions)

        assert result is not None
        assert result["is_dispatcher"] is True
        assert result["dispatcher_address"] == 0x401000
        assert self.handler.dispatcher_detected is True

    def test_non_dispatcher_block(self):
        """Test that non-dispatcher blocks are not detected."""
        instructions = [
            self.create_mock_instruction("mov", "eax, [rbx]"),
            self.create_mock_instruction("add", "eax, 1"),
            self.create_mock_instruction("ret"),
        ]

        result = self.handler.analyze_block(0x401000, instructions)

        assert result is not None
        assert result["is_dispatcher"] is False

    def test_state_variable_tracking(self):
        """Test tracking of state variables."""
        instructions = [
            self.create_mock_instruction("mov", "eax, [0x403000]"),
            self.create_mock_instruction("cmp", "eax, 5"),
        ]

        self.handler.analyze_block(0x401000, instructions)

        assert 0x403000 in self.handler.state_variables

    def test_indirect_jump_scoring(self):
        """Test that indirect jumps increase dispatcher score significantly."""
        instructions_without_indirect = [
            self.create_mock_instruction("cmp", "eax, 1"),
            self.create_mock_instruction("je", "0x401020"),
        ]

        instructions_with_indirect = [
            self.create_mock_instruction("cmp", "eax, 1"),
            self.create_mock_instruction("je", "0x401020"),
            self.create_mock_instruction("jmp", "[rax*8+0x403000]"),
        ]

        result1 = self.handler.analyze_block(0x401000, instructions_without_indirect)
        handler2 = ControlFlowFlatteningHandler()
        result2 = handler2.analyze_block(0x401000, instructions_with_indirect)

        assert result1["is_dispatcher"] is False
        assert result2["is_dispatcher"] is True

    def test_get_dispatcher_blocks(self):
        """Test retrieving dispatcher blocks."""
        instructions = [
            self.create_mock_instruction("cmp", "eax, 1"),
            self.create_mock_instruction("je", "0x401020"),
            self.create_mock_instruction("cmp", "eax, 2"),
            self.create_mock_instruction("je", "0x401030"),
            self.create_mock_instruction("jmp", "[rax*8+0x403000]"),
        ]

        self.handler.analyze_block(0x401000, instructions)
        dispatcher_blocks = self.handler.get_dispatcher_blocks()

        assert isinstance(dispatcher_blocks, set)
        assert len(dispatcher_blocks) > 0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestVirtualizationDetector(unittest.TestCase):
    """Test VM-based obfuscation detection."""

    def setUp(self):
        """Set up test environment."""
        self.detector = VirtualizationDetector()

    def create_mock_instruction(self, mnemonic, op_str=""):
        """Create a mock instruction."""
        insn = Mock()
        insn.mnemonic = mnemonic
        insn.op_str = op_str
        insn.address = 0x401000
        return insn

    def test_initialization(self):
        """Test detector initialization."""
        assert isinstance(self.detector.vm_handlers, dict)
        assert self.detector.vm_detected is False

    def test_vm_dispatch_loop_detection(self):
        """Test detection of VM dispatch loop."""
        loop_body = [
            self.create_mock_instruction("mov", "al, [rsi]"),
            self.create_mock_instruction("inc", "rsi"),
            self.create_mock_instruction("movzx", "eax, al"),
            self.create_mock_instruction("shl", "rax, 3"),
            self.create_mock_instruction("mov", "rax, [rax+0x403000]"),
            self.create_mock_instruction("jmp", "rax"),
        ]

        result = self.detector.analyze_loop(0x401000, loop_body)

        assert result is not None
        assert result["is_vm"] is True
        assert result["dispatch_loop"] == 0x401000

    def test_non_vm_loop(self):
        """Test that non-VM loops are not detected."""
        loop_body = [
            self.create_mock_instruction("mov", "eax, [rbx]"),
            self.create_mock_instruction("add", "eax, 1"),
            self.create_mock_instruction("mov", "[rbx], eax"),
            self.create_mock_instruction("inc", "rbx"),
            self.create_mock_instruction("cmp", "rbx, rcx"),
            self.create_mock_instruction("jl", "0x401000"),
        ]

        result = self.detector.analyze_loop(0x401000, loop_body)

        assert result is not None
        assert result["is_vm"] is False

    def test_vm_handler_tracking(self):
        """Test tracking of VM handlers."""
        handler_code = [
            self.create_mock_instruction("mov", "eax, [rsi]"),
            self.create_mock_instruction("add", "eax, [rdi]"),
            self.create_mock_instruction("mov", "[rdi], eax"),
            self.create_mock_instruction("jmp", "0x401000"),
        ]

        self.detector.analyze_handler(0x402000, handler_code)

        assert 0x402000 in self.detector.vm_handlers

    def test_vm_context_register_detection(self):
        """Test detection of VM context register usage."""
        loop_body = [
            self.create_mock_instruction("mov", "al, [rsi]"),
            self.create_mock_instruction("push", "rdi"),
            self.create_mock_instruction("pop", "rdi"),
            self.create_mock_instruction("mov", "rax, [rax+0x403000]"),
            self.create_mock_instruction("jmp", "rax"),
        ]

        result = self.detector.analyze_loop(0x401000, loop_body)

        assert result is not None


class TestStringDeobfuscation(unittest.TestCase):
    """Test string deobfuscation functionality."""

    def setUp(self):
        """Set up test environment."""
        self.deobfuscator = StringDeobfuscation()

    def test_initialization(self):
        """Test deobfuscator initialization."""
        assert isinstance(self.deobfuscator.decryption_routines, dict)
        assert isinstance(self.deobfuscator.decrypted_strings, dict)

    def test_xor_decryption_detection(self):
        """Test detection of XOR-based string decryption."""
        encrypted = bytes(ord(c) ^ 0x42 for c in "TestString")
        key = 0x42

        result = self.deobfuscator.detect_xor_decryption(0x401000, encrypted, key)

        assert result is not None
        assert result["encryption_type"] == "xor"
        assert result["key"] == 0x42

    def test_string_decryption(self):
        """Test actual string decryption."""
        encrypted = bytes(ord(c) ^ 0x42 for c in "TestString")

        decrypted = self.deobfuscator.decrypt_string(encrypted, "xor", 0x42)

        assert decrypted == "TestString"

    def test_string_decryption_invalid_type(self):
        """Test decryption with invalid encryption type."""
        encrypted = b"TestString"

        decrypted = self.deobfuscator.decrypt_string(encrypted, "invalid", 0)

        assert decrypted is None

    def test_get_decrypted_strings(self):
        """Test retrieving decrypted strings."""
        encrypted = bytes(ord(c) ^ 0x42 for c in "TestString")
        self.deobfuscator.detect_xor_decryption(0x401000, encrypted, 0x42)
        self.deobfuscator.decrypt_string(encrypted, "xor", 0x42)

        strings = self.deobfuscator.get_decrypted_strings()

        assert isinstance(strings, dict)

    def test_multi_byte_xor_key(self):
        """Test XOR decryption with multi-byte key."""
        plaintext = "TestString"
        key_bytes = b"\x42\x43\x44"
        encrypted = bytes(
            ord(plaintext[i]) ^ key_bytes[i % len(key_bytes)]
            for i in range(len(plaintext))
        )

        result = self.deobfuscator.detect_xor_decryption(0x401000, encrypted, key_bytes)

        assert result is not None
        assert result["encryption_type"] == "xor"

    def test_empty_string_handling(self):
        """Test handling of empty strings."""
        encrypted = b""

        decrypted = self.deobfuscator.decrypt_string(encrypted, "xor", 0x42)

        assert decrypted == ""

    def test_decryption_routine_tracking(self):
        """Test tracking of decryption routines."""
        encrypted = bytes(ord(c) ^ 0x42 for c in "TestString")
        self.deobfuscator.detect_xor_decryption(0x401000, encrypted, 0x42)

        assert 0x401000 in self.deobfuscator.decryption_routines
        routine = self.deobfuscator.decryption_routines[0x401000]
        assert routine["encryption_type"] == "xor"
        assert routine["key"] == 0x42


class TestObfuscationAwareConcolicEngine(unittest.TestCase):
    """Test obfuscation-aware concolic execution engine."""

    def setUp(self):
        """Set up test environment."""
        self.base_engine = Mock()
        self.base_engine.binary_path = "test.exe"
        self.base_engine.explore = Mock(return_value=[])
        self.engine = ObfuscationAwareConcolicEngine(self.base_engine)

    def test_initialization(self):
        """Test engine initialization."""
        assert self.engine.base_engine == self.base_engine
        assert isinstance(self.engine.opaque_detector, OpaquePredicateDetector)
        assert isinstance(self.engine.cff_handler, ControlFlowFlatteningHandler)
        assert isinstance(self.engine.vm_detector, VirtualizationDetector)
        assert isinstance(self.engine.string_deobf, StringDeobfuscation)

    def test_execute_with_obfuscation_handling(self):
        """Test execution with obfuscation handling enabled."""
        self.base_engine.current_state = Mock()
        self.base_engine.current_state.addr = 0x401000

        result = self.engine.execute_with_obfuscation_handling(
            start_address=0x401000,
            end_address=0x402000
        )

        assert self.base_engine.explore.called

    def test_analyze_obfuscation(self):
        """Test obfuscation analysis."""
        analysis = self.engine.analyze_obfuscation()

        assert isinstance(analysis, dict)
        assert "opaque_predicates" in analysis
        assert "control_flow_flattening" in analysis
        assert "virtualization" in analysis
        assert "encrypted_strings" in analysis

    def test_should_skip_branch(self):
        """Test branch skipping decision."""
        for _ in range(10):
            self.engine.opaque_detector.analyze_branch(0x401000, "x > 0", True)

        should_skip = self.engine.should_skip_branch(0x401000, "x > 0", False)

        assert should_skip is True

    def test_should_not_skip_normal_branch(self):
        """Test that normal branches are not skipped."""
        for i in range(10):
            taken = i % 2 == 0
            self.engine.opaque_detector.analyze_branch(0x401000, "x == 5", taken)

        should_skip = self.engine.should_skip_branch(0x401000, "x == 5", True)

        assert should_skip is False

    def test_is_dispatcher_block(self):
        """Test dispatcher block identification."""
        if not CAPSTONE_AVAILABLE:
            pytest.skip("Capstone not available")

        mock_insn = Mock()
        mock_insn.mnemonic = "cmp"
        mock_insn.op_str = "eax, 1"

        instructions = [
            mock_insn,
            Mock(mnemonic="je", op_str="0x401020"),
            Mock(mnemonic="cmp", op_str="eax, 2"),
            Mock(mnemonic="je", op_str="0x401030"),
            Mock(mnemonic="jmp", op_str="[rax*8+0x403000]"),
        ]

        self.engine.cff_handler.analyze_block(0x401000, instructions)
        is_dispatcher = self.engine.is_dispatcher_block(0x401000)

        assert is_dispatcher is True

    def test_get_obfuscation_report(self):
        """Test generation of obfuscation report."""
        for _ in range(10):
            self.engine.opaque_detector.analyze_branch(0x401000, "x > 0", True)

        report = self.engine.get_obfuscation_report()

        assert isinstance(report, dict)
        assert "summary" in report
        assert "details" in report
        assert "opaque_predicates" in report["summary"]
        assert "control_flow_flattening" in report["summary"]

    def test_clear_analysis_data(self):
        """Test clearing analysis data."""
        for _ in range(10):
            self.engine.opaque_detector.analyze_branch(0x401000, "x > 0", True)

        self.engine.clear_analysis_data()

        analysis = self.engine.analyze_obfuscation()
        assert len(analysis["opaque_predicates"]) == 0


class TestObfuscationHandlerIntegration(unittest.TestCase):
    """Integration tests for obfuscation handler components."""

    def test_opaque_predicate_and_cff_combination(self):
        """Test detection of obfuscation combining opaque predicates and CFF."""
        if not CAPSTONE_AVAILABLE:
            pytest.skip("Capstone not available")

        opaque_detector = OpaquePredicateDetector()
        cff_handler = ControlFlowFlatteningHandler()

        for _ in range(10):
            opaque_detector.analyze_branch(0x401000, "always_true", True)

        dispatcher_instructions = [
            Mock(mnemonic="cmp", op_str="eax, 1"),
            Mock(mnemonic="je", op_str="0x401020"),
            Mock(mnemonic="cmp", op_str="eax, 2"),
            Mock(mnemonic="je", op_str="0x401030"),
            Mock(mnemonic="jmp", op_str="[rax*8+0x403000]"),
        ]

        cff_result = cff_handler.analyze_block(0x402000, dispatcher_instructions)
        opaque_result = opaque_detector.analyze_branch(0x401000, "always_true", True)

        assert opaque_result["opaque"] is True
        assert cff_result["is_dispatcher"] is True

    def test_full_obfuscation_analysis_workflow(self):
        """Test complete obfuscation analysis workflow."""
        base_engine = Mock()
        base_engine.binary_path = "test.exe"
        base_engine.explore = Mock(return_value=[])

        engine = ObfuscationAwareConcolicEngine(base_engine)

        for _ in range(10):
            engine.opaque_detector.analyze_branch(0x401000, "check", True)

        encrypted = bytes(ord(c) ^ 0x42 for c in "License")
        engine.string_deobf.detect_xor_decryption(0x403000, encrypted, 0x42)

        report = engine.get_obfuscation_report()

        assert report["summary"]["opaque_predicates"] > 0
        assert isinstance(report["details"], dict)


if __name__ == "__main__":
    unittest.main()
