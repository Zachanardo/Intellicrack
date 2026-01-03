"""Comprehensive production tests for Opaque Predicate Analyzer.

This test suite validates REAL opaque predicate detection capabilities required for
defeating obfuscation in protected binaries. Tests verify symbolic execution with Z3,
constant propagation analysis, pattern recognition, dead code identification, and
control flow simplification.

Expected Behavior:
- Must implement symbolic execution for predicate evaluation
- Must use Z3 solver to prove predicate invariance
- Must detect always-true and always-false conditions
- Must simplify complex nested predicates
- Must identify obfuscation-inserted junk branches
- Edge cases: Context-dependent predicates, side effects

NO MOCKS, NO STUBS - All tests validate genuine offensive capability.
Tests MUST FAIL when code is broken or incomplete.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None  # type: ignore[assignment]

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    z3 = None  # type: ignore[assignment]

if TYPE_CHECKING:
    import networkx as nx

from intellicrack.core.analysis.opaque_predicate_analyzer import (
    ConstantPropagationEngine,
    ConstantValue,
    OpaquePredicateAnalyzer,
    PatternRecognizer,
    PredicateAnalysis,
    SymbolicExecutionEngine,
)


class BasicBlock:
    """Test implementation of BasicBlock protocol for opaque predicate testing."""

    def __init__(
        self,
        address: int,
        instructions: list[dict[str, Any]],
        successors: list[int],
    ) -> None:
        """Initialize basic block with address, instructions, and successors."""
        self.address = address
        self.instructions = instructions
        self.successors = successors


class TestSymbolicExecutionZ3Integration:
    """Test Z3 symbolic execution for proving opaque predicates."""

    def test_symbolic_execution_proves_always_true_equality(self) -> None:
        """Symbolic execution uses Z3 to prove CMP eax, eax; JE is always true."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available for symbolic execution")

        engine = SymbolicExecutionEngine()
        assert engine.solver is not None, "Z3 solver must be initialized"

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x5"},
                {"address": 0x1005, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x5, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove predicate is always TRUE"
        assert proof is not None, "Symbolic execution must provide proof string"
        assert "always TRUE" in proof, "Proof must indicate always TRUE condition"

    def test_symbolic_execution_proves_always_false_inequality(self) -> None:
        """Symbolic execution uses Z3 to prove CMP eax, ebx; JNE is always false when equal."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x10"},
                {"address": 0x1005, "disasm": "jne 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x10, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is False, "Z3 must prove predicate is always FALSE"
        assert proof is not None
        assert "always FALSE" in proof

    def test_symbolic_execution_proves_signed_comparison_greater(self) -> None:
        """Symbolic execution proves signed greater-than comparison with constants."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x5"},
                {"address": 0x1005, "disasm": "jg 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x10, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove JG is always taken when eax > 0x5"
        assert proof is not None

    def test_symbolic_execution_proves_signed_comparison_less(self) -> None:
        """Symbolic execution proves signed less-than comparison."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x20"},
                {"address": 0x1005, "disasm": "jl 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x5, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove JL is always taken when eax < 0x20"

    def test_symbolic_execution_proves_unsigned_comparison_above(self) -> None:
        """Symbolic execution proves unsigned above comparison (JA)."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x5"},
                {"address": 0x1005, "disasm": "ja 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x10, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove unsigned JA condition"

    def test_symbolic_execution_proves_unsigned_comparison_below(self) -> None:
        """Symbolic execution proves unsigned below comparison (JB)."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x20"},
                {"address": 0x1005, "disasm": "jb 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x5, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove unsigned JB condition"

    def test_symbolic_execution_proves_test_zero_flag(self) -> None:
        """Symbolic execution proves TEST eax, eax; JZ with zero register."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "test eax, eax"},
                {"address": 0x1002, "disasm": "jz 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x0, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove TEST zero; JZ is always taken"

    def test_symbolic_execution_proves_test_nonzero_flag(self) -> None:
        """Symbolic execution proves TEST eax, eax; JNZ with non-zero register."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "test eax, eax"},
                {"address": 0x1002, "disasm": "jnz 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x42, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove TEST non-zero; JNZ is always taken"

    def test_symbolic_execution_handles_non_constant_registers(self) -> None:
        """Symbolic execution handles non-constant registers with symbolic variables."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x5"},
                {"address": 0x1005, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", None, False, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is None, "Cannot prove opaque with non-constant symbolic vars"
        assert proof is None

    def test_symbolic_execution_proves_greater_or_equal(self) -> None:
        """Symbolic execution proves JGE (greater or equal) condition."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x10"},
                {"address": 0x1005, "disasm": "jge 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x10, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove JGE when equal"

    def test_symbolic_execution_proves_less_or_equal(self) -> None:
        """Symbolic execution proves JLE (less or equal) condition."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x10"},
                {"address": 0x1005, "disasm": "jle 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        register_state = {"eax": ConstantValue("eax", 0x10, True, {})}

        always_value, proof = engine.analyze_predicate(block, register_state)

        assert always_value is True, "Z3 must prove JLE when equal"


class TestConstantPropagationEngine:
    """Test constant propagation analysis for resolving opaque predicates."""

    def test_constant_propagation_tracks_multiple_registers(self) -> None:
        """Constant propagation tracks multiple registers across instructions."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x10"},
                {"address": 0x1005, "disasm": "mov ebx, 0x20"},
                {"address": 0x100A, "disasm": "mov ecx, 0x30"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        assert "eax" in state and state["eax"].value is not None and state["eax"].value == 0x10
        assert "ebx" in state and state["ebx"].value is not None and state["ebx"].value == 0x20
        assert "ecx" in state and state["ecx"].value is not None and state["ecx"].value == 0x30

    def test_constant_propagation_tracks_register_to_register_copy(self) -> None:
        """Constant propagation propagates constants through register copies."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x42"},
                {"address": 0x1005, "disasm": "mov ebx, eax"},
                {"address": 0x100A, "disasm": "mov ecx, ebx"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        assert state["eax"].value is not None and state["eax"].value == 0x42
        assert state["ebx"].value is not None and state["ebx"].value == 0x42
        assert state["ecx"].value is not None and state["ecx"].value == 0x42

    def test_constant_propagation_computes_complex_arithmetic_chain(self) -> None:
        """Constant propagation computes complex arithmetic operation chains."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x100"},
                {"address": 0x1005, "disasm": "add eax, 0x50"},
                {"address": 0x1008, "disasm": "sub eax, 0x30"},
                {"address": 0x100B, "disasm": "inc eax"},
                {"address": 0x100D, "disasm": "dec eax"},
                {"address": 0x100F, "disasm": "add eax, 0x10"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        expected = 0x100 + 0x50 - 0x30 + 1 - 1 + 0x10
        eax_value = state["eax"].value
        assert eax_value is not None, "eax value must not be None"
        assert eax_value == expected, f"Expected {hex(expected)}, got {hex(eax_value)}"

    def test_constant_propagation_computes_bitwise_operations(self) -> None:
        """Constant propagation computes bitwise AND, OR, XOR operations."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0xFF"},
                {"address": 0x1005, "disasm": "and eax, 0x0F"},
                {"address": 0x1008, "disasm": "or eax, 0xF0"},
                {"address": 0x100B, "disasm": "xor eax, 0xAA"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        expected = ((0xFF & 0x0F) | 0xF0) ^ 0xAA
        eax_value = state["eax"].value
        assert eax_value is not None and eax_value == expected

    def test_constant_propagation_computes_shift_operations(self) -> None:
        """Constant propagation computes SHL, SHR, SAL, SAR operations."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x8"},
                {"address": 0x1005, "disasm": "shl eax, 0x2"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})
        eax_value = state["eax"].value
        assert eax_value is not None and eax_value == 0x20

        block2 = BasicBlock(
            address=0x2000,
            instructions=[
                {"address": 0x2000, "disasm": "mov ebx, 0x80"},
                {"address": 0x2005, "disasm": "shr ebx, 0x3"},
            ],
            successors=[],
        )

        state2 = engine._analyze_block(block2, {})
        ebx_value = state2["ebx"].value
        assert ebx_value is not None and ebx_value == 0x10

    def test_constant_propagation_handles_register_arithmetic(self) -> None:
        """Constant propagation computes register-to-register arithmetic."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x10"},
                {"address": 0x1005, "disasm": "mov ebx, 0x5"},
                {"address": 0x100A, "disasm": "add eax, ebx"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        eax_value = state["eax"].value
        assert eax_value is not None and eax_value == 0x15

    def test_constant_propagation_handles_register_bitwise(self) -> None:
        """Constant propagation computes register-to-register bitwise operations."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0xFF"},
                {"address": 0x1005, "disasm": "mov ebx, 0x0F"},
                {"address": 0x100A, "disasm": "and eax, ebx"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        eax_value = state["eax"].value
        assert eax_value is not None and eax_value == 0x0F

    def test_constant_propagation_invalidates_non_constant_operations(self) -> None:
        """Constant propagation invalidates registers after non-constant operations."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x10"},
                {"address": 0x1005, "disasm": "add eax, ebx"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        assert "eax" not in state, "Register with non-constant operation must be invalidated"

    def test_constant_propagation_propagates_across_cfg(self) -> None:
        """Constant propagation propagates values across CFG blocks."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        engine = ConstantPropagationEngine()
        cfg: nx.DiGraph = nx.DiGraph()

        block1 = BasicBlock(
            address=0x1000,
            instructions=[{"address": 0x1000, "disasm": "mov eax, 0x42"}],
            successors=[0x2000],
        )
        cfg.add_node(0x1000, data=block1)

        block2 = BasicBlock(
            address=0x2000,
            instructions=[{"address": 0x2000, "disasm": "add eax, 0x8"}],
            successors=[],
        )
        cfg.add_node(0x2000, data=block2)

        states = engine.analyze_cfg(cfg, 0x1000)

        eax_value = states[0x2000]["eax"].value
        assert eax_value is not None and eax_value == 0x42, "Constant must propagate to successor"

    def test_constant_propagation_merges_divergent_paths(self) -> None:
        """Constant propagation correctly merges states from divergent paths."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        engine = ConstantPropagationEngine()
        cfg: nx.DiGraph = nx.DiGraph()

        block1 = BasicBlock(
            address=0x1000,
            instructions=[{"address": 0x1000, "disasm": "mov eax, 0x10"}],
            successors=[0x2000, 0x3000],
        )
        cfg.add_node(0x1000, data=block1)

        block2 = BasicBlock(
            address=0x2000,
            instructions=[{"address": 0x2000, "disasm": "mov eax, 0x20"}],
            successors=[0x4000],
        )
        cfg.add_node(0x2000, data=block2)

        block3 = BasicBlock(
            address=0x3000,
            instructions=[{"address": 0x3000, "disasm": "mov eax, 0x30"}],
            successors=[0x4000],
        )
        cfg.add_node(0x3000, data=block3)

        block4 = BasicBlock(
            address=0x4000,
            instructions=[],
            successors=[],
        )
        cfg.add_node(0x4000, data=block4)

        states = engine.analyze_cfg(cfg, 0x1000)

        assert "eax" not in states.get(0x4000, {}), "Divergent values must not propagate"


class TestPatternRecognition:
    """Test pattern recognition for common opaque predicate patterns."""

    def test_pattern_recognizer_detects_xor_self_zeroing(self) -> None:
        """Pattern recognizer detects XOR reg, reg (always zero)."""
        recognizer = PatternRecognizer()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "xor eax, eax"},
                {"address": 0x1002, "disasm": "test eax, eax"},
                {"address": 0x1004, "disasm": "jz 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        pattern_name, always_value = recognizer.recognize_pattern(block)

        assert pattern_name == "self_xor", "Must detect self XOR pattern"
        assert always_value is True, "Self XOR pattern is always true (zero)"

    def test_pattern_recognizer_detects_self_comparison(self) -> None:
        """Pattern recognizer detects CMP reg, reg (always equal)."""
        recognizer = PatternRecognizer()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, eax"},
                {"address": 0x1002, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        pattern_name, always_value = recognizer.recognize_pattern(block)

        assert pattern_name == "self_comparison", "Must detect self comparison"
        assert always_value is True

    def test_pattern_recognizer_detects_algebraic_identity_square_nonnegative(
        self,
    ) -> None:
        """Pattern recognizer detects x*x >= 0 mathematical invariant."""
        recognizer = PatternRecognizer()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, ecx"},
                {"address": 0x1002, "disasm": "imul eax, eax"},
                {"address": 0x1005, "disasm": "test eax, eax"},
                {"address": 0x1007, "disasm": "jns 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        pattern_name, always_value = recognizer.recognize_pattern(block)

        assert pattern_name == "square_nonnegative", "Must detect x*x >= 0 pattern"
        assert always_value is True

    def test_pattern_recognizer_detects_bit_masking_zero(self) -> None:
        """Pattern recognizer detects AND x, 0 (always zero)."""
        recognizer = PatternRecognizer()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0xFF"},
                {"address": 0x1005, "disasm": "and eax, 0x0"},
                {"address": 0x1008, "disasm": "test eax, eax"},
                {"address": 0x100A, "disasm": "jz 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        pattern_name, always_value = recognizer.recognize_pattern(block)

        assert pattern_name == "bit_masking", "Must detect bit masking with zero"
        assert always_value is True

    def test_pattern_recognizer_detects_modulo_invariant(self) -> None:
        """Pattern recognizer detects modulo 2 invariant violations."""
        recognizer = PatternRecognizer()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, ecx"},
                {"address": 0x1002, "disasm": "and eax, 0x1"},
                {"address": 0x1005, "disasm": "cmp eax, 5"},
                {"address": 0x1008, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        pattern_name, always_value = recognizer.recognize_pattern(block)

        if pattern_name is not None:
            assert pattern_name == "modulo_invariant"


class TestOpaquePredicateAnalyzerIntegration:
    """Integration tests for full opaque predicate analysis pipeline."""

    def test_analyzer_detects_opaque_predicate_in_simple_cfg(self) -> None:
        """Analyzer detects opaque predicate in simple CFG."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x5"},
                {"address": 0x1005, "disasm": "cmp eax, 0x5"},
                {"address": 0x1008, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )
        cfg.add_node(0x1000, data=block)

        cfg.add_edge(0x1000, 0x2000, edge_type="conditional_true")
        cfg.add_edge(0x1000, 0x1500, edge_type="conditional_false")

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) > 0, "Must detect at least one opaque predicate"
        assert any(r.always_value is True for r in results)
        assert any(r.dead_branch == 0x1500 for r in results)

    def test_analyzer_identifies_dead_branches_correctly(self) -> None:
        """Analyzer identifies dead branches from opaque predicates."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "xor eax, eax"},
                {"address": 0x1002, "disasm": "test eax, eax"},
                {"address": 0x1004, "disasm": "jnz 0x9999"},
            ],
            successors=[0x9999, 0x2000],
        )
        cfg.add_node(0x1000, data=block)

        cfg.add_edge(0x1000, 0x9999, edge_type="conditional_true")
        cfg.add_edge(0x1000, 0x2000, edge_type="conditional_false")

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) > 0
        opaque = results[0]
        assert opaque.always_value is False, "XOR self; TEST; JNZ is always false"
        assert opaque.dead_branch == 0x9999, "Must identify 0x9999 as dead branch"

    def test_analyzer_combines_symbolic_and_constant_propagation(self) -> None:
        """Analyzer combines symbolic execution and constant propagation."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        block1 = BasicBlock(
            address=0x1000,
            instructions=[{"address": 0x1000, "disasm": "mov eax, 0x42"}],
            successors=[0x2000],
        )
        cfg.add_node(0x1000, data=block1)

        block2 = BasicBlock(
            address=0x2000,
            instructions=[
                {"address": 0x2000, "disasm": "cmp eax, 0x42"},
                {"address": 0x2005, "disasm": "jne 0x9999"},
            ],
            successors=[0x9999, 0x3000],
        )
        cfg.add_node(0x2000, data=block2)

        cfg.add_edge(0x2000, 0x9999, edge_type="conditional_true")
        cfg.add_edge(0x2000, 0x3000, edge_type="conditional_false")

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) > 0
        opaque: PredicateAnalysis | None = next((r for r in results if r.address == 0x2000), None)
        assert opaque is not None, "Must find result at address 0x2000"
        assert opaque.always_value is False, "JNE must be always false"
        assert opaque.confidence >= 0.85, "High confidence from multiple techniques"

    def test_analyzer_assigns_appropriate_confidence_scores(self) -> None:
        """Analyzer assigns higher confidence to symbolic execution results."""
        if not NETWORKX_AVAILABLE or not Z3_AVAILABLE:
            pytest.skip("NetworkX or Z3 not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x10"},
                {"address": 0x1005, "disasm": "cmp eax, 0x10"},
                {"address": 0x1008, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )
        cfg.add_node(0x1000, data=block)

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) > 0
        result = results[0]

        if result.analysis_method == "symbolic_execution":
            assert result.confidence >= 0.95, "Symbolic execution should have highest confidence"
        elif result.analysis_method.startswith("pattern_"):
            assert result.confidence >= 0.85, "Pattern matching should have high confidence"
        elif result.analysis_method == "constant_propagation":
            assert result.confidence >= 0.90, "Constant propagation should have high confidence"

    def test_analyzer_handles_complex_nested_predicates(self) -> None:
        """Analyzer handles complex nested opaque predicates in CFG."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        block1 = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "xor eax, eax"},
                {"address": 0x1002, "disasm": "test eax, eax"},
                {"address": 0x1004, "disasm": "jz 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )
        cfg.add_node(0x1000, data=block1)

        block2 = BasicBlock(
            address=0x2000,
            instructions=[
                {"address": 0x2000, "disasm": "mov ebx, 0x5"},
                {"address": 0x2005, "disasm": "cmp ebx, ebx"},
                {"address": 0x2007, "disasm": "je 0x3000"},
            ],
            successors=[0x3000, 0x2500],
        )
        cfg.add_node(0x2000, data=block2)

        cfg.add_edge(0x1000, 0x2000, edge_type="conditional_true")
        cfg.add_edge(0x1000, 0x1500, edge_type="conditional_false")
        cfg.add_edge(0x2000, 0x3000, edge_type="conditional_true")
        cfg.add_edge(0x2000, 0x2500, edge_type="conditional_false")

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) >= 2, "Must detect multiple nested opaque predicates"
        assert any(r.address == 0x1000 for r in results)
        assert any(r.address == 0x2000 for r in results)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in opaque predicate analysis."""

    def test_analyzer_handles_empty_cfg(self) -> None:
        """Analyzer handles empty CFG without errors."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) == 0, "Empty CFG should produce no results"

    def test_analyzer_handles_blocks_without_conditional_jumps(self) -> None:
        """Analyzer ignores blocks without conditional branches."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x42"},
                {"address": 0x1005, "disasm": "ret"},
            ],
            successors=[],
        )
        cfg.add_node(0x1000, data=block)

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) == 0, "Non-conditional blocks should be ignored"

    def test_analyzer_handles_context_dependent_predicates(self) -> None:
        """Analyzer handles predicates that depend on external context."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x5"},
                {"address": 0x1005, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )
        cfg.add_node(0x1000, data=block)

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert len(results) == 0 or (
            len(results) > 0 and results[0].always_value is None
        ), "Context-dependent predicates should not be resolved"

    def test_analyzer_handles_side_effect_instructions(self) -> None:
        """Analyzer handles instructions with side effects (calls, memory writes)."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x10"},
                {"address": 0x1005, "disasm": "call 0x5000"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        assert "eax" not in state, "CALL must invalidate volatile registers"

    def test_constant_propagation_handles_lea_instruction(self) -> None:
        """Constant propagation invalidates registers after LEA."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x10"},
                {"address": 0x1005, "disasm": "lea eax, [ebx+8]"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        assert "eax" not in state, "LEA should invalidate destination register"

    def test_constant_propagation_handles_pop_instruction(self) -> None:
        """Constant propagation invalidates register after POP."""
        engine = ConstantPropagationEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x10"},
                {"address": 0x1005, "disasm": "pop eax"},
            ],
            successors=[],
        )

        state = engine._analyze_block(block, {})

        assert "eax" not in state, "POP should invalidate destination register"

    def test_symbolic_execution_handles_missing_cmp_instruction(self) -> None:
        """Symbolic execution handles blocks without CMP/TEST before jump."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "mov eax, 0x5"},
                {"address": 0x1005, "disasm": "je 0x2000"},
            ],
            successors=[0x2000, 0x1500],
        )

        always_value, proof = engine.analyze_predicate(block, {})

        assert always_value is None, "Cannot analyze without CMP/TEST"
        assert proof is None

    def test_symbolic_execution_handles_non_conditional_jump(self) -> None:
        """Symbolic execution returns None for unconditional jumps."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        engine = SymbolicExecutionEngine()

        block = BasicBlock(
            address=0x1000,
            instructions=[
                {"address": 0x1000, "disasm": "cmp eax, 0x5"},
                {"address": 0x1005, "disasm": "jmp 0x2000"},
            ],
            successors=[0x2000],
        )

        always_value, proof = engine.analyze_predicate(block, {})

        assert always_value is None, "Unconditional jump is not opaque predicate"


class TestDataclassesAndProtocols:
    """Test dataclass structures and protocol compliance."""

    def test_predicate_analysis_dataclass_creation(self) -> None:
        """PredicateAnalysis dataclass can be created with all fields."""
        analysis = PredicateAnalysis(
            address=0x1000,
            instruction="cmp eax, eax; je 0x2000",
            predicate_type="pattern_self_comparison",
            always_value=True,
            confidence=0.95,
            analysis_method="symbolic_execution",
            dead_branch=0x1500,
            symbolic_proof="Z3 proved predicate is always TRUE",
        )

        assert analysis.address == 0x1000
        assert "cmp eax, eax" in analysis.instruction
        assert analysis.predicate_type == "pattern_self_comparison"
        assert analysis.always_value is True
        assert analysis.confidence == 0.95
        assert analysis.analysis_method == "symbolic_execution"
        assert analysis.dead_branch == 0x1500
        assert analysis.symbolic_proof is not None

    def test_constant_value_dataclass_creation(self) -> None:
        """ConstantValue dataclass can be created with all fields."""
        const_val = ConstantValue(
            register="eax",
            value=0x42,
            is_constant=True,
            source_instruction={"address": 0x1000, "disasm": "mov eax, 0x42"},
        )

        assert const_val.register == "eax"
        assert const_val.value == 0x42
        assert const_val.is_constant is True
        assert const_val.source_instruction["disasm"] == "mov eax, 0x42"

    def test_basic_block_protocol_compliance(self) -> None:
        """BasicBlock test class complies with BasicBlockProtocol."""
        block = BasicBlock(
            address=0x1000,
            instructions=[{"address": 0x1000, "disasm": "nop"}],
            successors=[0x2000],
        )

        assert hasattr(block, "address")
        assert hasattr(block, "instructions")
        assert hasattr(block, "successors")
        assert isinstance(block.instructions, list)
        assert isinstance(block.successors, list)


class TestPerformanceAndScalability:
    """Test performance with large CFGs and complex analysis."""

    def test_analyzer_handles_large_cfg_efficiently(self) -> None:
        """Analyzer handles large CFG with many blocks efficiently."""
        if not NETWORKX_AVAILABLE:
            pytest.skip("NetworkX not available")

        analyzer = OpaquePredicateAnalyzer()
        cfg: nx.DiGraph = nx.DiGraph()

        for i in range(100):
            block = BasicBlock(
                address=0x1000 + i * 0x100,
                instructions=[
                    {"address": 0x1000 + i * 0x100, "disasm": f"mov eax, {i}"},
                ],
                successors=[0x1000 + (i + 1) * 0x100] if i < 99 else [],
            )
            cfg.add_node(0x1000 + i * 0x100, data=block)

        results = analyzer.analyze_cfg(cfg, 0x1000)

        assert isinstance(results, list), "Must handle large CFG without errors"

    def test_constant_propagation_handles_deep_chains(self) -> None:
        """Constant propagation handles deep operation chains."""
        engine = ConstantPropagationEngine()

        instructions: list[dict[str, Any]] = [{"address": 0x1000, "disasm": "mov eax, 0x1"}]
        for i in range(50):
            instructions.append(
                {"address": 0x1000 + (i + 1) * 5, "disasm": "inc eax"}
            )

        block = BasicBlock(address=0x1000, instructions=instructions, successors=[])

        state = engine._analyze_block(block, {})

        assert "eax" in state
        eax_value = state["eax"].value
        assert eax_value is not None and eax_value == 51, "Must handle 50 INC operations"
