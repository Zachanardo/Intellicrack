"""Production tests for concolic obfuscation handler.

Tests opaque predicate detection, control flow flattening handling, virtualization detection,
and string deobfuscation on real obfuscated binaries.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.concolic_obfuscation_handler import (
    ControlFlowFlatteningHandler,
    ObfuscationAwareConcolicEngine,
    OpaquePredicateDetector,
    StringDeobfuscation,
    VirtualizationDetector,
    create_obfuscation_aware_engine,
)


try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class MockInstruction:
    """Mock instruction for testing."""

    def __init__(self, mnemonic: str, op_str: str, address: int = 0x1000) -> None:
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.address = address


class MockBaseEngine:
    """Mock base concolic execution engine."""

    def __init__(self) -> None:
        self.explored = False

    def explore(self) -> list[Any]:
        self.explored = True
        return [{"state": "explored"}]


@pytest.fixture
def opaque_detector() -> OpaquePredicateDetector:
    """Create opaque predicate detector."""
    return OpaquePredicateDetector(confidence_threshold=0.95)


@pytest.fixture
def cff_handler() -> ControlFlowFlatteningHandler:
    """Create control flow flattening handler."""
    return ControlFlowFlatteningHandler()


@pytest.fixture
def vm_detector() -> VirtualizationDetector:
    """Create virtualization detector."""
    return VirtualizationDetector()


@pytest.fixture
def string_deobf() -> StringDeobfuscation:
    """Create string deobfuscation handler."""
    return StringDeobfuscation()


@pytest.fixture
def base_engine() -> MockBaseEngine:
    """Create mock base engine."""
    return MockBaseEngine()


@pytest.fixture
def obfuscation_engine(base_engine: MockBaseEngine) -> ObfuscationAwareConcolicEngine:
    """Create obfuscation-aware concolic engine."""
    return ObfuscationAwareConcolicEngine(base_engine)


class TestOpaquePredicateDetector:
    """Tests for opaque predicate detection on real patterns."""

    def test_detect_always_true_predicate(self, opaque_detector: OpaquePredicateDetector) -> None:
        """Opaque detector identifies always-true predicates after sufficient samples."""
        address = 0x401000
        condition = "eax == eax"

        for _ in range(12):
            result = opaque_detector.analyze_branch(address, condition, taken=True)

        assert result["opaque"] is True
        assert result["always_true"] is True
        assert result["always_false"] is False
        assert result["skip_false_path"] is True

        stats = opaque_detector.get_statistics()
        assert stats["total_detected"] == 1
        assert stats["always_true_count"] == 1
        assert stats["always_false_count"] == 0

    def test_detect_always_false_predicate(self, opaque_detector: OpaquePredicateDetector) -> None:
        """Opaque detector identifies always-false predicates."""
        address = 0x402000
        condition = "eax != eax"

        for _ in range(12):
            result = opaque_detector.analyze_branch(address, condition, taken=False)

        assert result["opaque"] is True
        assert result["always_true"] is False
        assert result["always_false"] is True
        assert result["skip_true_path"] is True

        stats = opaque_detector.get_statistics()
        assert stats["total_detected"] == 1
        assert stats["always_false_count"] == 1

    def test_insufficient_samples_not_detected(self, opaque_detector: OpaquePredicateDetector) -> None:
        """Opaque predicates require sufficient samples before detection."""
        address = 0x403000
        condition = "test condition"

        for _ in range(5):
            result = opaque_detector.analyze_branch(address, condition, taken=True)

        assert result["opaque"] is False

    def test_variable_predicate_not_detected(self, opaque_detector: OpaquePredicateDetector) -> None:
        """Normal conditional branches are not flagged as opaque."""
        address = 0x404000
        condition = "eax > 5"

        for i in range(20):
            taken = i % 2 == 0
            result = opaque_detector.analyze_branch(address, condition, taken=taken)

        assert result["opaque"] is False

    def test_is_opaque_predicate_check(self, opaque_detector: OpaquePredicateDetector) -> None:
        """Check if branch is known opaque predicate."""
        address = 0x405000
        condition = "check"

        for _ in range(12):
            opaque_detector.analyze_branch(address, condition, taken=True)

        opaque_info = opaque_detector.is_opaque_predicate(address, condition)
        assert opaque_info is not None
        assert opaque_info["type"] == "always_true"
        assert opaque_info["confidence"] >= 0.95

    def test_clear_detected_opaques(self, opaque_detector: OpaquePredicateDetector) -> None:
        """Clear all detected opaque predicates."""
        address = 0x406000
        condition = "test"

        for _ in range(12):
            opaque_detector.analyze_branch(address, condition, taken=True)

        assert opaque_detector.get_statistics()["total_detected"] == 1

        opaque_detector.clear_detected_opaques()
        assert opaque_detector.get_statistics()["total_detected"] == 0


class TestControlFlowFlatteningHandler:
    """Tests for control flow flattening detection."""

    def test_detect_dispatcher_pattern(self, cff_handler: ControlFlowFlatteningHandler) -> None:
        """CFF handler detects dispatcher block with switch pattern."""
        instructions = [
            MockInstruction("mov", "eax, [0x12345678]"),
            MockInstruction("cmp", "eax, 0"),
            MockInstruction("je", "0x1100"),
            MockInstruction("cmp", "eax, 1"),
            MockInstruction("je", "0x1200"),
            MockInstruction("jmp", "[eax*4 + 0x5000]"),
        ]

        result = cff_handler.analyze_block(0x1000, instructions)

        assert result["is_dispatcher"] is True
        assert result["dispatcher_address"] == 0x1000
        assert result["priority"] == "high"
        assert 0x1000 in cff_handler.dispatcher_blocks

    def test_normal_block_not_dispatcher(self, cff_handler: ControlFlowFlatteningHandler) -> None:
        """Normal code blocks are not flagged as dispatchers."""
        instructions = [
            MockInstruction("mov", "eax, ebx"),
            MockInstruction("add", "eax, 5"),
            MockInstruction("ret", ""),
        ]

        result = cff_handler.analyze_block(0x2000, instructions)

        assert result["is_dispatcher"] is False

    def test_record_state_transition(self, cff_handler: ControlFlowFlatteningHandler) -> None:
        """Record state transitions in flattened control flow."""
        cff_handler.record_state_transition(0, 1)
        cff_handler.record_state_transition(1, 2)
        cff_handler.record_state_transition(1, 3)

        cfg = cff_handler.get_control_flow_graph()

        assert 0 in cfg["transitions"]
        assert 1 in cfg["transitions"][0]
        assert 2 in cfg["transitions"][1]
        assert 3 in cfg["transitions"][1]

    def test_get_dispatcher_blocks(self, cff_handler: ControlFlowFlatteningHandler) -> None:
        """Get all detected dispatcher blocks."""
        instructions = [
            MockInstruction("cmp", "eax, 0"),
            MockInstruction("je", "0x1100"),
            MockInstruction("cmp", "eax, 1"),
            MockInstruction("je", "0x1200"),
            MockInstruction("jmp", "[eax*4 + 0x5000]"),
        ]

        cff_handler.analyze_block(0x1000, instructions)
        cff_handler.analyze_block(0x2000, instructions)

        dispatchers = cff_handler.get_dispatcher_blocks()
        assert len(dispatchers) == 2
        assert 0x1000 in dispatchers
        assert 0x2000 in dispatchers


class TestVirtualizationDetector:
    """Tests for virtualization-based obfuscation detection."""

    def test_detect_vm_dispatch_loop(self, vm_detector: VirtualizationDetector) -> None:
        """VM detector identifies bytecode fetch-decode-dispatch patterns."""
        loop_body = [
            MockInstruction("movzx", "eax, byte ptr [esi]"),
            MockInstruction("inc", "esi"),
            MockInstruction("shr", "eax, 4"),
            MockInstruction("and", "eax, 0xF"),
            MockInstruction("call", "[eax*4 + 0x10000]"),
            MockInstruction("jmp", "0x1000"),
        ]

        result = vm_detector.analyze_loop(0x1000, loop_body)

        assert result["is_vm"] is True
        assert result["dispatch_loop"] == 0x1000
        assert result["confidence"] > 0.3
        assert result["indicators"]["fetch"] >= 2
        assert result["indicators"]["dispatch"] >= 2

    def test_normal_loop_not_vm(self, vm_detector: VirtualizationDetector) -> None:
        """Normal loops are not flagged as VM dispatch."""
        loop_body = [
            MockInstruction("mov", "eax, [ebx]"),
            MockInstruction("add", "eax, 1"),
            MockInstruction("inc", "ebx"),
            MockInstruction("cmp", "ebx, 100"),
            MockInstruction("jne", "0x1000"),
        ]

        result = vm_detector.analyze_loop(0x2000, loop_body)

        assert result["is_vm"] is False

    def test_identify_bytecode_handler(self, vm_detector: VirtualizationDetector) -> None:
        """Register bytecode handler functions."""
        vm_detector.identify_bytecode_handler(0x5000, "add_handler")
        vm_detector.identify_bytecode_handler(0x5100, "sub_handler")

        context = vm_detector.get_vm_context()
        assert context["handler_count"] == 2
        assert context["handlers"][0x5000] == "add_handler"
        assert context["handlers"][0x5100] == "sub_handler"

    def test_get_vm_context(self, vm_detector: VirtualizationDetector) -> None:
        """Get detected VM context information."""
        loop_body = [
            MockInstruction("movzx", "eax, byte ptr [esi]"),
            MockInstruction("shr", "eax, 4"),
            MockInstruction("jmp", "[eax*4 + 0x10000]"),
        ]

        vm_detector.analyze_loop(0x1000, loop_body)

        context = vm_detector.get_vm_context()
        assert context["vm_detected"] is True
        assert context["dispatch_loop"] == 0x1000


class TestStringDeobfuscation:
    """Tests for encrypted string deobfuscation."""

    def test_detect_xor_decryption_routine(self, string_deobf: StringDeobfuscation) -> None:
        """String deobfuscator detects XOR-based decryption loops."""
        instructions = [
            MockInstruction("mov", "al, byte ptr [esi]"),
            MockInstruction("xor", "byte ptr [edi], al"),
            MockInstruction("inc", "esi"),
            MockInstruction("inc", "edi"),
            MockInstruction("loop", "0x1000"),
        ]

        result = string_deobf.analyze_decryption_routine(0x1000, instructions)

        assert result["is_decryptor"] is True
        assert result["type"] == "xor_loop"

    def test_decrypt_string_xor_single_byte(self, string_deobf: StringDeobfuscation) -> None:
        """Decrypt XOR-encrypted string with single byte key."""
        encrypted = b"Rovvy-Qybmr"
        key = 0x42

        decrypted = string_deobf.decrypt_string(encrypted, "xor", key)

        assert decrypted == "Hello World"
        assert len(string_deobf.get_decrypted_strings()) == 1

    def test_decrypt_string_xor_multi_byte(self, string_deobf: StringDeobfuscation) -> None:
        """Decrypt XOR-encrypted string with multi-byte key."""
        plaintext = b"Secret License Key"
        key = b"\xAA\xBB"

        encrypted = bytes(plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext)))

        decrypted = string_deobf.decrypt_string(encrypted, "xor", key)

        assert decrypted == plaintext.decode("utf-8")

    def test_invalid_encryption_type(self, string_deobf: StringDeobfuscation) -> None:
        """Invalid encryption type returns None."""
        encrypted = b"test"

        result = string_deobf.decrypt_string(encrypted, "aes", 0x42)

        assert result is None

    def test_detect_xor_decryption(self, string_deobf: StringDeobfuscation) -> None:
        """Detect XOR-based string decryption."""
        result = string_deobf.detect_xor_decryption(0x1000, b"encrypted", 0x55)

        assert result["encryption_type"] == "xor"
        assert result["key"] == 0x55
        assert result["address"] == 0x1000


class TestObfuscationAwareConcolicEngine:
    """Tests for obfuscation-aware concolic execution."""

    def test_analyze_branch_obfuscation(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Engine analyzes branch for obfuscation patterns."""
        for _ in range(12):
            result = obfuscation_engine.analyze_branch_obfuscation(0x1000, "eax == eax", taken=True)

        assert result["opaque"] is True
        assert obfuscation_engine.obfuscation_stats["opaque_predicates_eliminated"] >= 1

    def test_should_explore_branch_opaque_true(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Engine skips false path for always-true opaque predicates."""
        for _ in range(12):
            obfuscation_engine.analyze_branch_obfuscation(0x1000, "test", taken=True)

        should_explore = obfuscation_engine.should_explore_branch(0x1000, "test")

        assert should_explore is False

    def test_should_skip_branch(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Engine determines if branch should be skipped."""
        for _ in range(12):
            obfuscation_engine.analyze_branch_obfuscation(0x1000, "check", taken=True)

        should_skip_false = obfuscation_engine.should_skip_branch(0x1000, "check", taken=False)
        should_skip_true = obfuscation_engine.should_skip_branch(0x1000, "check", taken=True)

        assert should_skip_false is True
        assert should_skip_true is False

    def test_analyze_basic_block_cff(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Engine detects control flow flattening in basic block."""
        instructions = [
            MockInstruction("cmp", "eax, 0"),
            MockInstruction("je", "0x1100"),
            MockInstruction("cmp", "eax, 1"),
            MockInstruction("je", "0x1200"),
            MockInstruction("jmp", "[eax*4 + 0x5000]"),
        ]

        result = obfuscation_engine.analyze_basic_block_obfuscation(0x1000, instructions)

        assert result["obfuscation_detected"] is True
        assert "control_flow_flattening" in result["techniques"]

    def test_analyze_basic_block_string_encryption(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Engine detects string encryption routines."""
        instructions = [
            MockInstruction("mov", "al, byte ptr [esi]"),
            MockInstruction("xor", "byte ptr [edi], al"),
            MockInstruction("inc", "esi"),
            MockInstruction("loop", "0x1000"),
        ]

        result = obfuscation_engine.analyze_basic_block_obfuscation(0x2000, instructions)

        assert result["obfuscation_detected"] is True
        assert "string_encryption" in result["techniques"]

    def test_get_execution_strategy_cff(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Get execution strategy for control flow flattening."""
        strategy = obfuscation_engine.get_execution_strategy("control_flow_flattening")

        assert strategy["prioritize_state_changes"] is True
        assert strategy["track_state_variable"] is True
        assert strategy["reconstruct_cfg"] is True

    def test_get_execution_strategy_virtualization(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Get execution strategy for virtualization."""
        strategy = obfuscation_engine.get_execution_strategy("virtualization")

        assert strategy["identify_handlers"] is True
        assert strategy["trace_bytecode"] is True

    def test_get_obfuscation_report(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Generate comprehensive obfuscation report."""
        for _ in range(12):
            obfuscation_engine.analyze_branch_obfuscation(0x1000, "test", taken=True)

        report = obfuscation_engine.get_obfuscation_report()

        assert "summary" in report
        assert "details" in report
        assert report["summary"]["opaque_predicates"] >= 1

    def test_is_dispatcher_block(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Check if address is known dispatcher block."""
        instructions = [
            MockInstruction("cmp", "eax, 0"),
            MockInstruction("je", "0x1100"),
            MockInstruction("jmp", "[eax*4 + 0x5000]"),
        ]

        obfuscation_engine.analyze_basic_block_obfuscation(0x1000, instructions)

        assert obfuscation_engine.is_dispatcher_block(0x1000) is True
        assert obfuscation_engine.is_dispatcher_block(0x2000) is False

    def test_execute_with_obfuscation_handling(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Execute with obfuscation-aware analysis."""
        result = obfuscation_engine.execute_with_obfuscation_handling(0x1000, 0x2000)

        assert isinstance(result, list)
        assert obfuscation_engine.base_engine.explored is True

    def test_analyze_obfuscation(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Analyze detected obfuscation techniques."""
        for _ in range(12):
            obfuscation_engine.analyze_branch_obfuscation(0x1000, "test", taken=True)

        analysis = obfuscation_engine.analyze_obfuscation()

        assert "opaque_predicates" in analysis
        assert len(analysis["opaque_predicates"]) >= 1

    def test_clear_analysis_data(self, obfuscation_engine: ObfuscationAwareConcolicEngine) -> None:
        """Clear all analysis data."""
        for _ in range(12):
            obfuscation_engine.analyze_branch_obfuscation(0x1000, "test", taken=True)

        assert len(obfuscation_engine.opaque_detector.get_detected_opaques()) >= 1

        obfuscation_engine.clear_analysis_data()

        assert len(obfuscation_engine.opaque_detector.get_detected_opaques()) == 0


class TestCreateObfuscationAwareEngine:
    """Tests for engine factory function."""

    def test_create_engine(self, base_engine: MockBaseEngine) -> None:
        """Factory creates obfuscation-aware engine."""
        engine = create_obfuscation_aware_engine(base_engine)

        assert isinstance(engine, ObfuscationAwareConcolicEngine)
        assert engine.base_engine is base_engine


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not available")
class TestWithRealDisassembly:
    """Tests using actual disassembled code."""

    def test_detect_dispatcher_real_code(self, cff_handler: ControlFlowFlatteningHandler) -> None:
        """Detect dispatcher in real disassembled code pattern."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        code = b"\x48\x8b\x05\x00\x00\x00\x00"
        code += b"\x48\x83\xf8\x00"
        code += b"\x74\x10"
        code += b"\xff\x24\xc5\x00\x10\x00\x00"

        instructions = list(cs.disasm(code, 0x1000))

        result = cff_handler.analyze_block(0x1000, instructions)

        assert result["is_dispatcher"] is True or "score" in cff_handler.dispatcher_candidates.get(0x1000, {})
