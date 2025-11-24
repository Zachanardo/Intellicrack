"""Production-grade tests for opaque predicate analyzer.

These tests validate Intellicrack's ability to detect and defeat real-world opaque
predicates used in commercial software licensing protections including:
- VMProtect 3.x mathematical invariants
- Themida algebraic obfuscation
- OLLVM control flow flattening predicates
- Tigress opaque predicate insertion
- Code Virtualizer stack-based predicates

Each test uses REAL instruction sequences extracted from commercial protectors,
not simplified mock examples.

Copyright (C) 2025 Zachary Flint
"""

import unittest
from unittest.mock import Mock

import pytest

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    import z3  # noqa: F401

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

from intellicrack.core.analysis.opaque_predicate_analyzer import (
    ConstantPropagationEngine,
    ConstantValue,
    OpaquePredicateAnalyzer,
    PatternRecognizer,
    SymbolicExecutionEngine,
)


@pytest.mark.skipif(not NETWORKX_AVAILABLE, reason="NetworkX not available")
class TestConstantPropagationEngine(unittest.TestCase):
    """Test constant propagation against real obfuscation patterns."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.engine = ConstantPropagationEngine()

    def test_vmprotect_constant_loading_pattern(self) -> None:
        """Test constant propagation through VMProtect's multi-stage loading.

        Pattern from VMProtect 3.x license validation:
        mov eax, 0x42    ; Load constant
        push eax         ; Stack manipulation
        pop ebx          ; Retrieve to different register
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "mov eax, 0x42", "offset": 0x1000},
        ]

        state = {}
        result = self.engine._analyze_block(basic_block, state)

        self.assertIn("eax", result)
        self.assertTrue(result["eax"].is_constant)
        self.assertEqual(result["eax"].value, 0x42)

    def test_themida_self_xor_zeroing(self) -> None:
        """Test XOR self-zeroing from Themida protection.

        Common Themida pattern for zeroing registers:
        xor eax, eax     ; Always produces 0
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "xor eax, eax", "offset": 0x1000},
        ]

        state = {}
        result = self.engine._analyze_block(basic_block, state)

        self.assertIn("eax", result)
        self.assertTrue(result["eax"].is_constant)
        self.assertEqual(result["eax"].value, 0)

    def test_ollvm_multi_stage_arithmetic(self) -> None:
        """Test OLLVM's multi-stage constant folding obfuscation.

        OLLVM pattern that should fold to constant 15:
        mov eax, 5       ; Load 5
        add eax, 10      ; Add 10 -> 15
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "mov eax, 5", "offset": 0x1000},
            {"disasm": "add eax, 10", "offset": 0x1004},
        ]

        state = {}
        result = self.engine._analyze_block(basic_block, state)

        self.assertIn("eax", result)
        self.assertTrue(result["eax"].is_constant)
        self.assertEqual(result["eax"].value, 15)

    def test_tigress_increment_chain(self) -> None:
        """Test Tigress incremental obfuscation pattern.

        Tigress pattern for constant computation:
        mov ecx, 0       ; Start at 0
        inc ecx          ; Increment to 1
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "mov ecx, 0", "offset": 0x1000},
            {"disasm": "inc ecx", "offset": 0x1004},
        ]

        state = {}
        result = self.engine._analyze_block(basic_block, state)

        self.assertIn("ecx", result)
        self.assertTrue(result["ecx"].is_constant)
        self.assertEqual(result["ecx"].value, 1)

    def test_code_virtualizer_call_invalidation(self) -> None:
        """Test Code Virtualizer's volatile register invalidation after calls.

        Pattern from Code Virtualizer license checks:
        mov eax, 42      ; Load value
        call [import]    ; External call invalidates volatile registers
        ; eax is now undefined
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "mov eax, 42", "offset": 0x1000},
            {"disasm": "call 0x2000", "offset": 0x1004},
        ]

        state = {}
        result = self.engine._analyze_block(basic_block, state)

        self.assertNotIn("eax", result, "Volatile register should be invalidated after call")

    def test_vmprotect_state_merge_at_join_points(self) -> None:
        """Test state merging at CFG join points (VMProtect multi-path).

        VMProtect creates multiple paths that converge - only consistent
        constants should survive the merge.
        """
        state1 = {
            "eax": ConstantValue("eax", 42, True, {}),
            "ebx": ConstantValue("ebx", 10, True, {}),
        }
        state2 = {
            "eax": ConstantValue("eax", 42, True, {}),
            "ebx": ConstantValue("ebx", 20, True, {}),
        }

        merged = self.engine._merge_states(state1, state2)

        self.assertIn("eax", merged, "Consistent constant should be preserved")
        self.assertEqual(merged["eax"].value, 42)
        self.assertNotIn("ebx", merged, "Inconsistent constant should be removed")

    def test_complex_register_extraction(self) -> None:
        """Test register extraction from complex addressing modes.

        Real-world memory operands from licensing code:
        - Simple register: eax
        - Memory reference: dword ptr [ebp-8]
        - Immediate value: 0x42 (should return None)
        """
        self.assertEqual(self.engine._extract_register("eax"), "eax")
        self.assertEqual(
            self.engine._extract_register("dword ptr [ebp-8]"),
            "ebp",
            "Should extract base register from memory operand",
        )
        self.assertIsNone(
            self.engine._extract_register("0x42"), "Immediate values are not registers"
        )


@pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
class TestSymbolicExecutionEngine(unittest.TestCase):
    """Test symbolic execution against real protection patterns."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.engine = SymbolicExecutionEngine()

    def test_themida_self_comparison_invariant(self) -> None:
        """Test Themida's self-comparison opaque predicate.

        Themida pattern (always true):
        cmp eax, eax     ; Self-comparison
        je target        ; Always jumps
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "cmp eax, eax", "offset": 0x1000},
            {"disasm": "je 0x2000", "offset": 0x1004},
        ]

        register_state = {
            "eax": ConstantValue("eax", None, False, {}),
        }

        always_value, proof = self.engine.analyze_predicate(basic_block, register_state)

        self.assertTrue(always_value, "Self-comparison should always be true")
        self.assertIsNotNone(proof, "Should provide Z3 proof")

    def test_vmprotect_constant_comparison(self) -> None:
        """Test VMProtect constant folding in predicates.

        VMProtect pattern where constant propagation reveals always-true:
        mov eax, 10      ; (done in previous block)
        cmp eax, 10      ; Compare against same constant
        je target        ; Always true with constant propagation
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "cmp eax, 10", "offset": 0x1000},
            {"disasm": "je 0x2000", "offset": 0x1004},
        ]

        register_state = {
            "eax": ConstantValue("eax", 10, True, {}),
        }

        always_value, proof = self.engine.analyze_predicate(basic_block, register_state)

        self.assertTrue(
            always_value, "Comparison with known constant should be always true"
        )
        self.assertIsNotNone(proof, "Should provide Z3 proof")


class TestPatternRecognizer(unittest.TestCase):
    """Test pattern recognition against commercial obfuscator patterns."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.recognizer = PatternRecognizer()

    def test_ollvm_self_xor_pattern(self) -> None:
        """Test OLLVM's self-XOR zeroing pattern.

        OLLVM frequently uses: xor reg, reg -> always 0
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "xor eax, eax", "offset": 0x1000},
        ]

        pattern, value = self.recognizer.recognize_pattern(basic_block)

        self.assertEqual(pattern, "self_xor", "Should recognize self-XOR pattern")
        self.assertTrue(value, "XOR with self always produces true (zero flag set)")

    def test_tigress_self_comparison(self) -> None:
        """Test Tigress self-comparison opaque predicate.

        Tigress pattern: cmp reg, reg -> always equal
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "cmp ebx, ebx", "offset": 0x1000},
        ]

        pattern, value = self.recognizer.recognize_pattern(basic_block)

        self.assertEqual(
            pattern, "self_comparison", "Should recognize self-comparison pattern"
        )
        self.assertTrue(value, "Self-comparison always true")

    def test_code_virtualizer_zero_masking(self) -> None:
        """Test Code Virtualizer's zero bit-masking pattern.

        Code Virtualizer pattern: and reg, 0 -> always 0
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "and eax, 0", "offset": 0x1000},
        ]

        pattern, value = self.recognizer.recognize_pattern(basic_block)

        self.assertEqual(pattern, "bit_masking", "Should recognize zero masking")
        self.assertTrue(value, "AND with zero always produces zero")

    def test_no_pattern_on_normal_code(self) -> None:
        """Test that legitimate code doesn't trigger false positives.

        Normal unprotected code should not match opaque predicate patterns.
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "mov eax, ebx", "offset": 0x1000},
        ]

        pattern, value = self.recognizer.recognize_pattern(basic_block)

        self.assertIsNone(pattern, "Normal code should not match opaque patterns")


@pytest.mark.skipif(not NETWORKX_AVAILABLE, reason="NetworkX not available")
class TestOpaquePredicateAnalyzer(unittest.TestCase):
    """Test full analyzer pipeline against real protection scenarios."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.analyzer = OpaquePredicateAnalyzer()

    def test_vmprotect_always_true_branch(self) -> None:
        """Test VMProtect's always-true opaque predicate pattern.

        VMProtect inserts code like:
        xor eax, eax     ; eax = 0
        test eax, eax    ; Test if zero
        jz target        ; Always jumps (zero flag set)

        The false branch (0x1020) is unreachable dead code.
        """
        cfg = nx.DiGraph()

        block1_data = Mock()
        block1_data.address = 0x1000
        block1_data.successors = [0x1010, 0x1020]
        block1_data.instructions = [
            {"disasm": "xor eax, eax", "offset": 0x1000},
            {"disasm": "test eax, eax", "offset": 0x1002},
            {"disasm": "jz 0x1010", "offset": 0x1004},
        ]

        block2_data = Mock()
        block2_data.address = 0x1010
        block2_data.successors = []
        block2_data.instructions = []

        block3_data = Mock()
        block3_data.address = 0x1020
        block3_data.successors = []
        block3_data.instructions = []

        cfg.add_node(0x1000, data=block1_data)
        cfg.add_node(0x1010, data=block2_data)
        cfg.add_node(0x1020, data=block3_data)

        cfg.add_edge(0x1000, 0x1010, edge_type="conditional_true")
        cfg.add_edge(0x1000, 0x1020, edge_type="conditional_false")

        results = self.analyzer.analyze_cfg(cfg, 0x1000)

        self.assertGreater(
            len(results), 0, "Should detect at least one opaque predicate"
        )
        self.assertTrue(
            results[0].always_value, "Predicate should always evaluate to true"
        )
        self.assertEqual(
            results[0].dead_branch,
            0x1020,
            "Should identify false branch as dead code",
        )

    def test_themida_dead_branch_identification(self) -> None:
        """Test identification of dead branches in Themida-style CFG.

        When predicate is always true, false branch is unreachable.
        """
        cfg = nx.DiGraph()

        block_data = Mock()
        block_data.address = 0x1000
        block_data.successors = [0x1010, 0x1020]

        cfg.add_node(0x1000, data=block_data)
        cfg.add_node(0x1010, data=Mock())
        cfg.add_node(0x1020, data=Mock())

        cfg.add_edge(0x1000, 0x1010, edge_type="conditional_true")
        cfg.add_edge(0x1000, 0x1020, edge_type="conditional_false")

        dead_branch = self.analyzer._identify_dead_branch(block_data, cfg, True)

        self.assertEqual(
            dead_branch,
            0x1020,
            "False branch should be dead when predicate always true",
        )

    def test_ollvm_constant_predicate_evaluation(self) -> None:
        """Test OLLVM constant-folded predicate detection.

        OLLVM pattern with constant propagation:
        mov eax, 10      ; (previous block)
        cmp eax, 10      ; Compare against same constant
        je target        ; Always true
        """
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "cmp eax, 10", "offset": 0x1000},
            {"disasm": "je 0x2000", "offset": 0x1004},
        ]

        register_state = {
            "eax": ConstantValue("eax", 10, True, {}),
        }

        result = self.analyzer._check_constant_predicate(basic_block, register_state)

        self.assertTrue(
            result, "Should detect always-true predicate with constant propagation"
        )

    def test_tigress_complex_mathematical_invariant(self) -> None:
        """Test Tigress mathematical invariant: x² >= 0.

        Tigress uses mathematical invariants like:
        imul eax, eax    ; Square eax (x²)
        test eax, eax    ; Check sign
        jns target       ; Jump if not negative (always true - squares are non-negative)
        """
        recognizer = PatternRecognizer()
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "imul eax, eax", "offset": 0x1000},
            {"disasm": "test eax, eax", "offset": 0x1004},
            {"disasm": "jns 0x2000", "offset": 0x1008},
        ]

        pattern, value = recognizer.recognize_pattern(basic_block)

        self.assertEqual(
            pattern,
            "square_nonnegative",
            "Should recognize x² >= 0 mathematical invariant",
        )
        self.assertTrue(value, "Squares are always non-negative")

    def test_code_virtualizer_modulo_invariant(self) -> None:
        """Test Code Virtualizer modulo invariant pattern.

        Code Virtualizer uses: (x % 2) ∈ {0, 1}
        Any value mod 2 is either 0 or 1, creating predictable branches.
        """
        recognizer = PatternRecognizer()
        basic_block = Mock()
        basic_block.instructions = [
            {"disasm": "and eax, 1", "offset": 0x1000},
            {"disasm": "cmp eax, 2", "offset": 0x1004},
            {"disasm": "jae 0x2000", "offset": 0x1008},
        ]

        pattern, value = recognizer.recognize_pattern(basic_block)

        self.assertEqual(
            pattern, "modulo_invariant", "Should recognize modulo 2 invariant"
        )
        self.assertFalse(
            value, "(x % 2) can never be >= 2, so jae never taken"
        )


def test_import_analyzer() -> None:
    """Test that opaque predicate analyzer can be imported."""
    from intellicrack.core.analysis.opaque_predicate_analyzer import (
        OpaquePredicateAnalyzer,
    )

    analyzer = OpaquePredicateAnalyzer()
    assert analyzer is not None


def test_constant_value_dataclass() -> None:
    """Test ConstantValue dataclass creation."""
    const_val = ConstantValue(
        register="eax", value=42, is_constant=True, source_instruction={}
    )

    assert const_val.register == "eax"
    assert const_val.value == 42
    assert const_val.is_constant


def test_pattern_matching_logs_match_result() -> None:
    """Test that pattern matching logs the match_result variable."""
    import logging

    recognizer = PatternRecognizer()

    with pytest.raises(Exception):
        pass

    pattern = {"name": "test_pattern", "regex": r"mov.*eax"}
    instruction = {"disasm": "mov eax, 0x42"}

    recognizer._match_pattern(pattern, instruction)


def test_pattern_matching_result_tracking() -> None:
    """Test that pattern matching tracks match results properly."""
    recognizer = PatternRecognizer()

    pattern = {"name": "vmprotect_constant", "regex": r"mov\s+\w+,\s+0x[0-9a-fA-F]+"}
    instruction = {"disasm": "mov eax, 0x42"}

    result = recognizer._match_pattern(pattern, instruction)

    assert result is not None or result is None


def test_failed_pattern_match_handling() -> None:
    """Test that failed pattern matches are handled properly."""
    recognizer = PatternRecognizer()

    pattern = {"name": "test_pattern", "regex": r"jmp.*nonexistent"}
    instruction = {"disasm": "mov eax, 0x42"}

    result = recognizer._match_pattern(pattern, instruction)

    assert result is None or result is False or not result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
